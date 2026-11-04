#!/usr/bin/env python3
"""Large-message soak (phase 5A): the biggest message the configuration allows, spooled.

For each size, against the lean fixture (no message is ever held in memory by the fixture):
  migrate  fresh transfer through the disk spool, peak RSS measured by GNU time
  verify   read-back of the destination copy by streaming digest (source not contacted)
  resume   a second migrate, which re-verifies the confirmed message
Checks: exact content (digest computed independently by the fixture), journal state, no spool
residue, the source saw only read verbs, and peak RSS at or below the streaming target.
`max_message_bytes` is 1 GiB (the configured maximum), so the largest message is 1000 MiB.

Usage: python3 tests/local/stream_soak.py BINARY [--sizes 256 512 1000] [--json FILE]
Needs GNU time and free disk of about twice the message size. Loopback only.
"""
import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.argv, _argv = sys.argv[:1], sys.argv[1:]
from e2e import command, PASSWORD, ROOT  # noqa: E402
sys.argv = [sys.argv[0]] + _argv
from freshness import require_fresh  # noqa: E402
from lean_server import LeanServer, FOLDER  # noqa: E402

READ_ONLY_VERBS = {'CAPABILITY', 'AUTHENTICATE', 'LIST', 'EXAMINE', 'UID', 'LOGOUT', 'NOOP'}
RSS_TARGET_MIB = 40.0


def timed(binary, action, cfg):
    started = time.monotonic()
    p = subprocess.run(['/usr/bin/time', '-v', str(binary), action, '--config', str(cfg), '--json'], capture_output=True, text=True, timeout=3600)
    wall = time.monotonic() - started
    assert p.returncode == 0, (action, p.returncode, p.stdout[-400:], p.stderr[-400:])
    report = json.loads(p.stdout)
    assert report['complete'], (action, report)
    grab = lambda pat, cast=float: cast(re.search(pat, p.stderr).group(1))
    return {'wall_s': round(wall, 2), 'rss_mib': round(grab(r'Maximum resident set size \(kbytes\): (\d+)', int) / 1024, 1),
            'cpu_s': round(grab(r'User time \(seconds\): ([\d.]+)') + grab(r'System time \(seconds\): ([\d.]+)'), 2),
            'disk_written_mib': round(grab(r'File system outputs: (\d+)', int) * 512 / 2**20, 1)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('--sizes', type=int, nargs='+', default=[256, 512, 1000], help='message sizes in MiB (at most 1000)')
    ap.add_argument('--json')
    args = ap.parse_args()
    binary = Path(args.binary).resolve()
    require_fresh(binary)
    failures, results = [], {}
    with tempfile.TemporaryDirectory(prefix='imaplane-soak-') as tmp:
        work = Path(tmp); os.chmod(work, 0o700)
        cert, key = work / 'tls.crt', work / 'tls.key'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        password = work / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
        print(f'{"MiB":>6} {"phase":>7} {"wall s":>8} {"MiB/s":>7} {"CPU s":>7} {"peak RSS":>9} {"disk wr MiB":>12}  result')
        for mib in args.sizes:
            free = shutil.disk_usage(work).free / 2**20
            if free < 2.2 * mib:
                failures.append(f'{mib} MiB: only {free:.0f} MiB free'); print(f'{mib:6d} SKIPPED: only {free:.0f} MiB free disk'); continue
            size = mib << 20
            server = LeanServer(str(cert), str(key), [size])
            state = work / f'state{mib}'
            cfg = work / f'c{mib}.toml'
            text = f'state_dir = "{state}"\ntimeout_seconds = 120\nmax_message_bytes = 1073741824\nread_attempts = 2\nstream_threshold_bytes = 0\n'
            for role in ('source', 'destination'):
                text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
            text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
            cfg.write_text(text)
            results[mib] = {}
            try:
                for phase, action in (('migrate', 'migrate'), ('verify', 'verify'), ('resume', 'migrate')):
                    r = timed(binary, action, cfg)
                    results[mib][phase] = r
                    ok = r['rss_mib'] <= RSS_TARGET_MIB
                    if not ok:
                        failures.append(f'{mib} MiB {phase}: peak RSS {r["rss_mib"]} MiB exceeds {RSS_TARGET_MIB}')
                    print(f'{mib:6d} {phase:>7} {r["wall_s"]:8.1f} {mib / r["wall_s"]:7.1f} {r["cpu_s"]:7.1f} {r["rss_mib"]:8.1f}M {r["disk_written_mib"]:12.1f}  {"ok" if ok else "OVER TARGET"}', flush=True)
                checks = {
                    'destination digest equals the source digest': server.destination_matches_source(),
                    'exactly one APPEND, none on resume': len(server.dest) == 1 and sum(v == 'APPEND' for _, v in server.events) == 1,
                    'journal confirmed': sqlite3.connect(state / 'journal.sqlite3').execute('select state from transfers').fetchall() == [('confirmed',)],
                    'no spool residue': sorted(p.name for p in state.iterdir() if not p.name.startswith(('journal.sqlite3', 'job.lock'))) == [],
                    'source saw only read verbs': server.source_verbs() <= READ_ONLY_VERBS,
                    'fixture had no errors': not server.errors,
                }
                for name, ok in checks.items():
                    if not ok:
                        failures.append(f'{mib} MiB: {name}')
                        print(f'       FAILED: {name}')
            finally:
                server.close()
                shutil.rmtree(state, ignore_errors=True)
    if args.json:
        Path(args.json).write_text(json.dumps({'target_rss_mib': RSS_TARGET_MIB, 'results': results, 'failures': failures}, indent=1))
    print('PASS' if not failures else 'FAIL\n  - ' + '\n  - '.join(failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
