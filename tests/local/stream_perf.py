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
import json
import os
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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('--large', type=int, nargs='*', default=[64, 256], help='single-message sizes in MiB')
    ap.add_argument('--small', type=int, default=300, help='number of 2 KiB messages')
    ap.add_argument('--repeats', type=int, default=3)
    ap.add_argument('--json')
    args = ap.parse_args()
    binary = Path(args.binary).resolve()
    require_fresh(binary)
    out = {'note': 'loopback Python server: relative cost only', 'large': {}, 'small': {}}
    with tempfile.TemporaryDirectory(prefix='imaplane-perf-') as tmp:
        work = Path(tmp); os.chmod(work, 0o700)
        cert, key = work / 'tls.crt', work / 'tls.key'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        password = work / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
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
        bodies = [b'Subject: m%d\r\n\r\n' % i + os.urandom(2048) for i in range(args.small)]
        print(f'\n== {args.small} messages of 2 KiB (median of {args.repeats})'); print(header + f' {"msgs/s":>8} {"fsyncs":>7}')
        runs = {name: [] for name, _ in MODES}
        for _ in range(args.repeats):             # interleaved A/B/C rounds
            for name, threshold in MODES:
                runs[name].append(run_once(binary, work, cert, key, password, bodies, threshold, f'small-{name}'))
        for name, threshold in MODES:
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
