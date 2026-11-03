#!/usr/bin/env python3
"""Peak-RSS harness for large-message transfers (see docs/STREAMING_DESIGN.md).

Runs `imaplane migrate` once per size against a loopback TLS scripted server holding a
single message of that size, measures the IMAPLANE process's peak resident set with GNU
time, checks the copy is exact, and applies a profile:

  current    regression ceiling for today's in-memory path: RSS <= 25 + 2.3 x N MiB.
             Keeps memory from silently getting worse. Used by the dedicated CI job.
  streaming  the design targets: RSS <= 40 MiB for N <= 256, <= 48 MiB above, and an RSS
             slope between the two largest sizes of at most 0.02 MiB per MiB of message.
             Expected to FAIL until the streaming path exists.

Usage: python3 tests/local/memory.py [BINARY] [--sizes 16 64 256] [--profile current]
       [--threshold-bytes N] [--repeats 1] [--json FILE] [--report-only]
A manual soak uses --sizes 1000 (the configured cap is 1 GiB including headers) and
needs roughly 4x that much free RAM for the Python fixture, not for IMAPLANE.
Loopback only; no Docker, real credentials or real mail. Peak RSS is IMAPLANE only.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.argv, _argv = sys.argv[:1], sys.argv[1:]   # e2e reads argv at import; give it none
from e2e import ProtocolServer, command, PASSWORD  # noqa: E402
sys.argv = [sys.argv[0]] + _argv

ROOT = Path(__file__).resolve().parents[2]
BASELINE_MIB = 1


def limit_current(mib):
    return 25 + 2.3 * mib


def limit_streaming(mib):
    return 40 if mib <= 256 else 48


def measure(binary, mib, workdir, cert, key, password, threshold, repeats):
    """Return (peak RSS in MiB over repeats, seconds). Raises AssertionError if the copy is wrong."""
    body = b'Subject: big\r\n\r\n' + os.urandom(mib << 20)
    want = hashlib.sha256(body).hexdigest()
    peaks, seconds = [], 0.0
    for attempt in range(repeats):
        server = ProtocolServer(str(cert), str(key), 'rev1')
        server.messages['source'] = [body]
        cfg = workdir / f'm{mib}-{attempt}.toml'
        text = f'state_dir = "{workdir}/state{mib}-{attempt}"\ntimeout_seconds = 120\nmax_message_bytes = {(mib + 2) << 20}\n'
        if threshold is not None:
            text += f'stream_threshold_bytes = {threshold}\n'
        for role in ('source', 'destination'):
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
        text += '[[folders]]\nsource = "台北/📬"\ndestination = "台北/📬"\n'
        cfg.write_text(text)
        started = time.monotonic()
        p = subprocess.run(['/usr/bin/time', '-v', str(binary), 'migrate', '--config', str(cfg), '--json'],
                           capture_output=True, text=True, timeout=1800)
        seconds = time.monotonic() - started
        try:
            assert p.returncode == 0, f'exit {p.returncode}: {p.stdout[-300:]} {p.stderr.split(chr(9) + "Command being timed")[0][-400:].strip()}'
            assert json.loads(p.stdout)['complete'], 'migration not complete'
            stored = server.messages['destination']
            assert len(stored) == 1 and hashlib.sha256(stored[0]).hexdigest() == want, 'destination copy is not exact'
            peaks.append(int(re.search(r'Maximum resident set size \(kbytes\): (\d+)', p.stderr).group(1)) / 1024)
        finally:
            server.close()
            shutil.rmtree(workdir / f'state{mib}-{attempt}', ignore_errors=True)
    return max(peaks), seconds


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary', nargs='?', default=str(ROOT / 'target/release/imaplane'))
    ap.add_argument('--sizes', type=int, nargs='+', default=[16, 64, 256], help='message sizes in MiB')
    ap.add_argument('--profile', choices=['current', 'streaming'], default='current')
    ap.add_argument('--threshold-bytes', type=int, help='writes stream_threshold_bytes into the config (streaming builds only)')
    ap.add_argument('--repeats', type=int, default=1, help='runs per size; the worst peak is used')
    ap.add_argument('--json', help='write results here')
    ap.add_argument('--report-only', action='store_true', help='print measurements and exit 0 regardless of the profile')
    args = ap.parse_args()
    binary = Path(args.binary).resolve()
    if not binary.is_file() or not Path('/usr/bin/time').exists():
        print('need the IMAPLANE binary and GNU time (/usr/bin/time)', file=sys.stderr)
        return 2
    limit = limit_current if args.profile == 'current' else limit_streaming
    with tempfile.TemporaryDirectory(prefix='imaplane-memory-') as tmp:
        work = Path(tmp); os.chmod(work, 0o700)
        cert, key = work / 'tls.crt', work / 'tls.key'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        password = work / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
        rows, failures = [], []
        try:
            baseline, _ = measure(binary, BASELINE_MIB, work, cert, key, password, args.threshold_bytes, args.repeats)
        except AssertionError as exc:
            print(f'baseline run failed, so nothing can be measured: {str(exc)[:400]}', file=sys.stderr)
            return 2
        print(f'profile={args.profile}  binary={binary.name}  baseline ({BASELINE_MIB} MiB message): {baseline:.1f} MiB', flush=True)
        print(f'{"MiB":>6} {"peak RSS":>10} {"x msg":>7} {"limit":>8} {"seconds":>8}  result')
        for mib in args.sizes:
            try:
                peak, secs = measure(binary, mib, work, cert, key, password, args.threshold_bytes, args.repeats)
            except AssertionError as exc:
                failures.append(f'{mib} MiB: {exc}')
                print(f'{mib:6d}  FAILED to transfer correctly: {exc}', flush=True)
                continue
            ok = peak <= limit(mib)
            if not ok:
                failures.append(f'{mib} MiB: peak {peak:.1f} MiB exceeds {limit(mib):.1f} MiB')
            rows.append({'mib': mib, 'peak_rss_mib': round(peak, 1), 'limit_mib': round(limit(mib), 1), 'seconds': round(secs, 1), 'ok': ok})
            print(f'{mib:6d} {peak:9.1f}M {peak / mib:6.2f}x {limit(mib):7.1f}M {secs:8.1f}  {"ok" if ok else "OVER LIMIT"}', flush=True)
        slope = None
        if len(rows) >= 2:
            (a, b) = sorted(rows, key=lambda r: r['mib'])[-2:]
            slope = (b['peak_rss_mib'] - a['peak_rss_mib']) / (b['mib'] - a['mib'])
            print(f'RSS slope between {a["mib"]} and {b["mib"]} MiB: {slope:.3f} MiB per MiB of message')
            if args.profile == 'streaming' and slope > 0.02:
                failures.append(f'slope {slope:.3f} exceeds 0.02')
        if args.json:
            Path(args.json).write_text(json.dumps({'profile': args.profile, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                                                   'baseline_mib': round(baseline, 1), 'slope': slope, 'rows': rows, 'failures': failures}, indent=1))
    if failures:
        print('FAIL' + (' (ignored: --report-only)' if args.report_only else ''))
        for f in failures: print('  -', f)
        return 0 if args.report_only else 1
    print('PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
