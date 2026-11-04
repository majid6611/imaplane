#!/usr/bin/env python3
"""Relative cost of the buffered and spooled transfer paths (phase 4).

Measures wall time, CPU time (user+system), file-system block I/O, peak RSS, protocol
commands and fsync calls of the IMAPLANE process for the same work done three ways:
  buffered  stream_threshold_bytes unset (today's default)
  hybrid    threshold 64 KiB (small messages buffered, large spooled)
  spooled   threshold 0 (every non-empty message through the spool)
Large scenario: one message of each size. Small scenario: many 2 KiB messages.

All numbers come from a loopback Python TLS server on this machine, so they show RELATIVE cost
between the paths, not real-network throughput, and server speed bounds the absolute figures.
Usage: python3 tests/local/stream_perf.py BINARY [--large 64 256] [--small 300] [--repeats 3] [--json F]
GNU time and strace are required. Loopback only; no Docker, real credentials or mail.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.argv, _argv = sys.argv[:1], sys.argv[1:]
from e2e import ProtocolServer, command, PASSWORD  # noqa: E402
sys.argv = [sys.argv[0]] + _argv
from freshness import require_fresh  # noqa: E402

MODES = [('buffered', None), ('hybrid', 65536), ('spooled', 0)]


def parse_time(stderr):
    def grab(pattern, cast=float):
        return cast(re.search(pattern, stderr).group(1))
    return {
        'user_s': grab(r'User time \(seconds\): ([\d.]+)'),
        'sys_s': grab(r'System time \(seconds\): ([\d.]+)'),
        'rss_mib': grab(r'Maximum resident set size \(kbytes\): (\d+)', int) / 1024,
        'fs_in_blocks': grab(r'File system inputs: (\d+)', int),
        'fs_out_blocks': grab(r'File system outputs: (\d+)', int),
    }


def run_once(binary, work, cert, key, password, bodies, threshold, label, syncs=False):
    server = ProtocolServer(str(cert), str(key), 'rev1')
    server.messages['source'] = list(bodies)
    state = work / f'state-{label}-{time.monotonic_ns()}'
    cfg = work / f'{label}-{time.monotonic_ns()}.toml'
    text = f'state_dir = "{state}"\ntimeout_seconds = 120\nmax_message_bytes = {max(len(b) for b in bodies) + 4096}\n'
    if threshold is not None:
        text += f'stream_threshold_bytes = {threshold}\nspool_allow_memory_backed = true\n'
    for role in ('source', 'destination'):
        text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
    text += '[[folders]]\nsource = "台北/📬"\ndestination = "台北/📬"\n'
    cfg.write_text(text)
    argv = [str(binary), 'migrate', '--config', str(cfg), '--json']
    if syncs:
        trace = work / f'strace-{time.monotonic_ns()}.txt'
        argv = ['strace', '-f', '-c', '-o', str(trace), '-e', 'trace=fsync,fdatasync,sync_file_range'] + argv
    started = time.monotonic()
    p = subprocess.run(['/usr/bin/time', '-v'] + argv, capture_output=True, text=True, timeout=1800)
    wall = time.monotonic() - started
    assert p.returncode == 0 and json.loads(p.stdout)['complete'], (p.returncode, p.stderr[-400:])
    assert server.messages['destination'] == list(bodies), 'copy is not exact'
    verbs = {}
    for _, verb, _ in server.events:
        verbs[verb.decode()] = verbs.get(verb.decode(), 0) + 1
    result = parse_time(p.stderr)
    result.update(wall_s=wall, commands=sum(verbs.values()), appends=verbs.get('APPEND', 0), verbs=verbs)
    if syncs:
        text = trace.read_text()
        result['sync_calls'] = sum(int(m.group(1)) for m in re.finditer(r'^\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)\s+(?:\d+\s+)?(?:fsync|fdatasync|sync_file_range)\s*$', text, re.M))
    server.close()
    return result


def median(runs, key):
    return statistics.median(r[key] for r in runs)


def provenance(binary, workdir):
    """Everything needed to reproduce and audit a result."""
    def sh(*a):
        return subprocess.run(a, capture_output=True, text=True).stdout.strip()
    root = Path(__file__).resolve().parents[2]
    cpu = next((l.split(':', 1)[1].strip() for l in open('/proc/cpuinfo') if l.startswith('model name')), 'unknown')
    return {'git_commit': sh('git', '-C', str(root), 'rev-parse', 'HEAD'), 'git_dirty': bool(sh('git', '-C', str(root), 'status', '--porcelain')),
            'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(), 'kernel': platform.release(), 'machine': platform.machine(),
            'cpu': cpu, 'cpus': os.cpu_count(), 'python': platform.python_version(), 'filesystem': sh('findmnt', '-no', 'FSTYPE', '-T', str(workdir)),
            'mem_total_mib': int(next(l.split()[1] for l in open('/proc/meminfo') if l.startswith('MemTotal')) ) // 1024,
            'date_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'argv': _argv,
            'method': 'interleaved A/B rounds, median of repeats, loopback Python TLS fixture; relative cost only'}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('--large', type=int, nargs='*', default=[64, 256], help='single-message sizes in MiB')
    ap.add_argument('--small', type=int, default=300, help='number of 2 KiB messages (0 to skip)')
    ap.add_argument('--sweep', type=int, nargs='*', default=[], help='single-message sizes in MiB around the threshold: buffered vs spooled')
    ap.add_argument('--repeats', type=int, default=3)
    ap.add_argument('--json')
    args = ap.parse_args()
    binary = Path(args.binary).resolve()
    require_fresh(binary)
    out = {'note': 'loopback Python server: relative cost only', 'large': {}, 'small': {}, 'sweep': {}}
    with tempfile.TemporaryDirectory(prefix='imaplane-perf-') as tmp:
        work = Path(tmp); os.chmod(work, 0o700)
        cert, key = work / 'tls.crt', work / 'tls.key'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        password = work / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
        out['provenance'] = provenance(binary, work)
        header = f'{"mode":>9} {"wall s":>8} {"CPU s":>7} {"MiB/s":>8} {"peak RSS":>9} {"disk wr MiB":>12} {"disk rd MiB":>12} {"commands":>9}'
        for mib in args.large:
            body = b'Subject: big\r\n\r\n' + os.urandom(mib << 20)
            print(f'\n== one {mib} MiB message (median of {args.repeats})'); print(header)
            out['large'][mib] = {}
            modes = MODES[::2]    # buffered and spooled; hybrid is identical for a single large message
            runs = {name: [] for name, _ in modes}
            for _ in range(args.repeats):         # interleaved, so machine drift hits every mode equally
                for name, threshold in modes:
                    runs[name].append(run_once(binary, work, cert, key, password, [body], threshold, f'{name}{mib}'))
            for name, _ in modes:
                row = {k: median(runs[name], k) for k in ('wall_s', 'user_s', 'sys_s', 'rss_mib', 'fs_in_blocks', 'fs_out_blocks', 'commands', 'appends')}
                out['large'][mib][name] = row
                cpu = row['user_s'] + row['sys_s']
                print(f'{name:>9} {row["wall_s"]:8.2f} {cpu:7.2f} {mib / row["wall_s"]:8.1f} {row["rss_mib"]:8.1f}M {row["fs_out_blocks"] * 512 / 2**20:12.1f} {row["fs_in_blocks"] * 512 / 2**20:12.1f} {row["commands"]:9.0f}')
        if args.sweep:
            print(f'\n== single-message size sweep, buffered vs spooled (median of {args.repeats})')
            print(f'{"MiB":>6} {"buffered s":>11} {"spooled s":>10} {"buf CPU s":>10} {"spool CPU s":>12} {"buf RSS":>9} {"spool RSS":>10}  faster')
            for mib in args.sweep:
                body = b'Subject: sweep\r\n\r\n' + os.urandom(max(1, int(mib * (1 << 20))) - 16)
                runs = {'buffered': [], 'spooled': []}
                for _ in range(args.repeats):
                    for name, threshold in (('buffered', None), ('spooled', 0)):
                        runs[name].append(run_once(binary, work, cert, key, password, [body], threshold, f'sweep-{name}{mib}'))
                row = {n: {k: median(runs[n], k) for k in ('wall_s', 'user_s', 'sys_s', 'rss_mib')} for n in runs}
                out['sweep'][mib] = row
                b, sp = row['buffered'], row['spooled']
                print(f'{mib:6d} {b["wall_s"]:11.3f} {sp["wall_s"]:10.3f} {b["user_s"] + b["sys_s"]:10.3f} {sp["user_s"] + sp["sys_s"]:12.3f} {b["rss_mib"]:8.1f}M {sp["rss_mib"]:9.1f}M  {"spooled" if sp["wall_s"] < b["wall_s"] else "buffered"}')
        bodies = [b'Subject: m%d\r\n\r\n' % i + os.urandom(2048) for i in range(args.small)]
        print(f'\n== {args.small} messages of 2 KiB (median of {args.repeats})'); print(header + f' {"msgs/s":>8} {"fsyncs":>7}')
        runs = {name: [] for name, _ in MODES}
        for _ in range(args.repeats if args.small else 0):             # interleaved A/B/C rounds
            for name, threshold in MODES:
                runs[name].append(run_once(binary, work, cert, key, password, bodies, threshold, f'small-{name}'))
        for name, threshold in (MODES if args.small else []):
            sync_run = run_once(binary, work, cert, key, password, bodies[:100], threshold, f'sync-{name}', syncs=True)
            row = {k: median(runs[name], k) for k in ('wall_s', 'user_s', 'sys_s', 'rss_mib', 'fs_in_blocks', 'fs_out_blocks', 'commands', 'appends')}
            row['spread_wall_s'] = [round(r['wall_s'], 2) for r in runs[name]]
            row['sync_calls_per_100_messages'] = sync_run.get('sync_calls')
            out['small'][name] = row
            cpu = row['user_s'] + row['sys_s']
            print(f'{name:>9} {row["wall_s"]:8.2f} {cpu:7.2f} {"":>8} {row["rss_mib"]:8.1f}M {row["fs_out_blocks"] * 512 / 2**20:12.1f} {row["fs_in_blocks"] * 512 / 2**20:12.1f} {row["commands"]:9.0f} {args.small / row["wall_s"]:8.1f} {row["sync_calls_per_100_messages"]!s:>7}   runs {row["spread_wall_s"]}')
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
