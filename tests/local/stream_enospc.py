#!/usr/bin/env python3
"""Genuine ENOSPC against a small real tmpfs (phase 4): the spool fails cleanly, safely and once.

IMAPLANE runs inside a container with an 8 MiB tmpfs as its spool directory (host networking
to a loopback scripted TLS server). Two scenarios:
  1. A message larger than the free space is refused BEFORE any download (free-space check).
  2. A message that fits when the transfer starts, but the tmpfs is filled by another process
     part-way through the stream: the write fails with a real ENOSPC.
In both, nothing is written to the journal or the destination, the failure is not retried as a
connection error, and a rerun with space available completes with exactly one APPEND.

Needs Docker and an image that can run the binary (the dev image that built it):
  IMAPLANE_TEST_IMAGE=imaplane-dev:1.85.1 python3 tests/local/stream_enospc.py target/release/imaplane
Prints SKIPPED and exits 0 if Docker or the image is unavailable. Loopback-only; no real mail.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from e2e import PASSWORD, ProtocolServer, command, ROOT

BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'target/release/imaplane').resolve()
from freshness import require_fresh
require_fresh(BINARY)
IMAGE = os.environ.get('IMAPLANE_TEST_IMAGE', 'imaplane-dev:1.85.1')
FOLDER = '台北/📬'
UID, GID = os.getuid(), os.getgid()
FAILED = []


def docker(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, timeout=300, check=check)


try:
    docker('image', 'inspect', IMAGE)
except (OSError, subprocess.CalledProcessError):
    print(f'SKIPPED: docker or image {IMAGE} is unavailable'); sys.exit(0)


def check(name):
    def wrap(fn):
        try:
            fn(); print('PASS', name, flush=True)
        except BaseException as exc:
            FAILED.append(name); print('FAIL', name, '->', repr(exc)[:900], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-enospc-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    (root / 'password').write_text(PASSWORD); (root / 'password').chmod(0o600)
    servers = []

    def fixture(body):
        server = ProtocolServer(str(cert), str(key), 'rev1'); servers.append(server)
        server.messages['source'] = [body]
        work = root / f'w{len(servers)}'; work.mkdir(); work.chmod(0o700)
        text = ('state_dir = "/w/state"\ntimeout_seconds = 30\nmax_message_bytes = 33554432\nread_attempts = 2\n'
                'stream_threshold_bytes = 0\nspool_dir = "/spool"\nspool_allow_memory_backed = true\n')
        for role in ['source', 'destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "/w/password"\nca_file = "/w/tls.crt"\n'
        text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
        (work / 'c.toml').write_text(text)
        for name in ('password', 'tls.crt'):
            (work / name).write_bytes((root / name).read_bytes()); (work / name).chmod(0o600)
        return server, work

    def start(work):
        name = 'imaplane-enospc-' + uuid.uuid4().hex[:8]
        docker('run', '-d', '--name', name, '--network', 'host', '--user', f'{UID}:{GID}', '-v', f'{work}:/w',
               '-v', f'{BINARY}:/imaplane:ro', '--tmpfs', f'/spool:size=8m,mode=0700,uid={UID},gid={GID}',
               IMAGE, '/imaplane', 'migrate', '--config', '/w/c.toml', '--json')
        return name

    def finish(name):
        code = int(docker('wait', name).stdout.strip())
        out = docker('logs', name, check=False).stdout
        docker('rm', '-f', name, check=False)
        return code, json.loads(out)

    def body_fetches(s): return sum(v == b'UID' and b'BODY.PEEK[]' in a[0] and b'<0.' not in a[0] for u, v, a in s.events if u == 'source')   # whole-body reads, not the small partial probe
    def appends(s): return sum(v == b'APPEND' for _, v, _ in s.events)
    def rows(work):
        db = work / 'state' / 'journal.sqlite3'
        return sqlite3.connect(db).execute('select count(*) from transfers').fetchone()[0] if db.exists() else 0

    @check('a message larger than the free space is refused before any download')
    def _():
        body = b'Subject: big\r\n\r\n' + os.urandom(16 << 20)
        s, work = fixture(body)
        code, report = finish(start(work))
        e = report['entries'][0]
        assert code == 2 and e['result'] == 'failed' and 'spool unavailable' in e['detail'] and 'not enough space' in e['detail'], (code, report)
        assert body_fetches(s) == 0, 'the check must happen before the body is downloaded'
        assert rows(work) == 0 and appends(s) == 0

    @check('a real ENOSPC part-way through the stream is a clean, non-retried failure; a rerun then completes once')
    def _():
        body = b'Subject: fits-at-first\r\n\r\n' + os.urandom(6 << 20)
        s, work = fixture(body)
        s.pause_source_fetch_at = 2 << 20                                       # stream 2 MiB, then wait
        name = start(work)
        assert s.source_paused.wait(120), 'the source never reached the pause point'
        docker('exec', name, 'sh', '-c', 'dd if=/dev/zero of=/spool/junk bs=1M count=5 2>/dev/null; sync')
        s.resume_source_fetch.set()
        code, report = finish(name)
        e = report['entries'][0]
        assert code == 2 and e['result'] == 'failed' and 'spool unavailable' in e['detail'] and 'space' in e['detail'], (code, report)
        assert 'nothing was written' in e['detail']
        assert body_fetches(s) == 1, 'ENOSPC must not be retried as a connection problem'
        assert rows(work) == 0 and appends(s) == 0 and not s.messages['destination']
        s.pause_source_fetch_at = None
        code, report = finish(start(work))                                      # a fresh, empty tmpfs
        assert code == 0 and report['complete'] and appends(s) == 1 and s.messages['destination'] == [body]

    assert all(not s.errors for s in servers), [s.errors for s in servers]
    for server in servers: server.close()

print('FAILED: ' + str(FAILED) if FAILED else 'all ENOSPC checks passed')
sys.exit(1 if FAILED else 0)
