#!/usr/bin/env python3
"""Container memory limits and page-cache accounting (phase 5A).

IMAPLANE runs in a Docker container with a hard memory limit (no swap) and a disk-backed bind
mount as its state and spool directory, against the lean fixture on the host. File writes to the
spool are charged to the container's cgroup as page cache, so this checks what plain RSS cannot:
that a spool far larger than the limit does not get the process OOM-killed because the kernel can
reclaim clean cache, and that the same limit really does kill the buffered path (the control).

Reported from inside the container (cgroup v2): memory.peak (anonymous memory plus charged page
cache), memory.events (oom, oom_kill, high, max) and memory.stat anon/file at the end.
Needs Docker with cgroup v2 and an image that can run the binary. Prints SKIPPED if unavailable.
  IMAPLANE_TEST_IMAGE=imaplane-dev:1.85.1 python3 tests/local/stream_cgroup.py target/release/imaplane
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

sys.argv, _argv = sys.argv[:1], sys.argv[1:]
from e2e import command, PASSWORD  # noqa: E402
sys.argv = [sys.argv[0]] + _argv
from freshness import require_fresh  # noqa: E402
from lean_server import LeanServer, FOLDER  # noqa: E402

IMAGE = os.environ.get('IMAPLANE_TEST_IMAGE', 'imaplane-dev:1.85.1')
UID, GID = os.getuid(), os.getgid()


def docker(*a, check=True):
    return subprocess.run(['docker', *a], capture_output=True, text=True, timeout=1800, check=check)


def run_limited(binary, work, limit, threshold, action='migrate'):
    name = 'imaplane-cg-' + uuid.uuid4().hex[:8]
    script = ('/imaplane {a} --config /w/c.toml --json > /w/out.json 2>/w/err.txt; echo EXIT=$?; '
              'echo PEAK=$(cat /sys/fs/cgroup/memory.peak); '
              'echo EVENTS=$(tr "\\n" " " < /sys/fs/cgroup/memory.events); '
              'echo STAT=$(grep -E "^(anon|file|file_dirty|file_writeback) " /sys/fs/cgroup/memory.stat | tr "\\n" " ")').format(a=action)
    p = docker('run', '--rm', '--name', name, '--network', 'host', '--user', f'{UID}:{GID}', '--memory', limit, '--memory-swap', limit,
               '-v', f'{work}:/w', '-v', f'{binary}:/imaplane:ro', IMAGE, 'sh', '-c', script, check=False)
    out = p.stdout
    get = lambda key: re.search(rf'^{key}=(.*)$', out, re.M).group(1)
    events = dict(re.findall(r'(\w+) (\d+)', get('EVENTS')))
    stat = dict(re.findall(r'(\w+) (\d+)', get('STAT')))
    return {'exit': int(get('EXIT')), 'peak_mib': int(get('PEAK')) / 2**20, 'events': {k: int(v) for k, v in events.items()},
            'anon_mib': int(stat.get('anon', 0)) / 2**20, 'file_mib': int(stat.get('file', 0)) / 2**20,
            'dirty_mib': int(stat.get('file_dirty', 0)) / 2**20, 'report': (work / 'out.json').read_text() if (work / 'out.json').stat().st_size else ''}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('--json')
    args = ap.parse_args()
    binary = Path(args.binary).resolve()
    require_fresh(binary)
    try:
        docker('image', 'inspect', IMAGE)
        if docker('info', '--format', '{{.CgroupVersion}}').stdout.strip() != '2':
            raise OSError('cgroup v2 required')
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f'SKIPPED: docker, image {IMAGE} or cgroup v2 unavailable ({exc})'); return 0
    failures, rows = [], []
    with tempfile.TemporaryDirectory(prefix='imaplane-cgroup-') as tmp:
        root = Path(tmp); os.chmod(root, 0o700)
        cert, key = root / 'tls.crt', root / 'tls.key'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        scenarios = [  # label, message MiB, limit, threshold (None = buffered), expectation
            ('spooled, 1000 MiB message, 64m limit', 1000, '64m', 0, 'ok'),
            ('spooled, 1000 MiB message, 32m limit', 1000, '32m', 0, 'ok'),
            ('spooled, 256 MiB message, 24m limit', 256, '24m', 0, 'ok'),
            ('buffered (control), 256 MiB message, 256m limit', 256, '256m', None, 'oom'),
            ('buffered (control), 1000 MiB message, 512m limit', 1000, '512m', None, 'oom'),
        ]
        print(f'{"scenario":<52} {"exit":>5} {"peak":>8} {"anon":>7} {"cache":>8} {"oom_kill":>9}  result')
        for label, mib, limit, threshold, want in scenarios:
            work = root / uuid.uuid4().hex[:6]; work.mkdir(); work.chmod(0o700)
            (work / 'password').write_text(PASSWORD); (work / 'password').chmod(0o600)
            (work / 'tls.crt').write_bytes(cert.read_bytes()); (work / 'tls.crt').chmod(0o600)
            server = LeanServer(str(cert), str(key), [mib << 20])
            text = 'state_dir = "/w/state"\ntimeout_seconds = 120\nmax_message_bytes = 1073741824\nread_attempts = 2\n'
            if threshold is not None:
                text += f'stream_threshold_bytes = {threshold}\n'
            for role in ('source', 'destination'):
                text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "/w/password"\nca_file = "/w/tls.crt"\n'
            text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
            (work / 'c.toml').write_text(text)
            try:
                r = run_limited(binary, work, limit, threshold)
            finally:
                server.close()
            oom = r['events'].get('oom_kill', 0)
            if want == 'ok':
                ok = r['exit'] == 0 and oom == 0 and server.destination_matches_source() and '"complete": true' in r['report']
            else:
                ok = r['exit'] != 0 and oom >= 1 and not server.dest
            rows.append({'scenario': label, **{k: v for k, v in r.items() if k != 'report'}, 'expected': want, 'ok': ok})
            if not ok:
                failures.append(label)
            print(f'{label:<52} {r["exit"]:5d} {r["peak_mib"]:7.1f}M {r["anon_mib"]:6.1f}M {r["file_mib"]:7.1f}M {oom:9d}  {"ok" if ok else "FAILED"}', flush=True)
    if args.json:
        Path(args.json).write_text(json.dumps({'rows': rows, 'failures': failures}, indent=1))
    print('PASS' if not failures else 'FAIL: ' + ', '.join(failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
