#!/usr/bin/env python3
"""Spool filesystem compatibility matrix (phase 5A).

For every filesystem that can be exercised WITHOUT privileged access, an independent probe asks the
kernel whether O_TMPFILE works there, then a real spooled migration runs with spool_dir on it.
IMAPLANE must agree with the probe: complete with an exact copy and no residue where O_TMPFILE
works, and fail closed (no journal row, no APPEND, a message naming the cause) where it does not.
Memory-backed filesystems must be refused unless explicitly allowed.

Covered here: the host filesystem (whatever it is, reported), overlayfs (a container's writable
layer), tmpfs (refusal and explicit opt-in), and a bind mount of the host filesystem. Not covered,
and reported as UNTESTED: any filesystem that needs privileged mkfs or mount (XFS, Btrfs, NFS, ...).
Usage: IMAPLANE_TEST_IMAGE=imaplane-dev:1.85.1 python3 tests/local/stream_fs.py BINARY
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

sys.argv, _argv = sys.argv[:1], sys.argv[1:]
from e2e import ProtocolServer, command, PASSWORD  # noqa: E402
sys.argv = [sys.argv[0]] + _argv
from freshness import require_fresh  # noqa: E402

BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release/imaplane').resolve()
require_fresh(BINARY)
IMAGE = os.environ.get('IMAPLANE_TEST_IMAGE', 'imaplane-dev:1.85.1')
UID, GID = os.getuid(), os.getgid()
FOLDER = '台北/📬'
BODIES = [b'Subject: a\r\n\r\n' + os.urandom(3 << 20), b'Subject: b\r\n\r\n' + os.urandom(100_000)]
FAILED, ROWS = [], []


def fs_type(path):
    """The mounted filesystem type (findmnt), since statfs reports ext2/ext3/ext4 all as 'ext2/ext3'."""
    found = subprocess.run(['findmnt', '-no', 'FSTYPE', '-T', str(path)], capture_output=True, text=True).stdout.strip()
    return found or subprocess.run(['stat', '-f', '-c', '%T', str(path)], capture_output=True, text=True).stdout.strip()


def probe_o_tmpfile(path):
    try:
        fd = os.open(path, os.O_TMPFILE | os.O_RDWR | os.O_EXCL, 0o600)
        os.write(fd, b'x'); os.close(fd)
        return True
    except OSError:
        return False


def docker(*a, check=True):
    return subprocess.run(['docker', *a], capture_output=True, text=True, timeout=600, check=check)


with tempfile.TemporaryDirectory(prefix='imaplane-fs-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    servers = []

    def config(server, state, spool, allow):
        text = f'state_dir = "{state}"\ntimeout_seconds = 30\nmax_message_bytes = 16777216\nread_attempts = 2\nstream_threshold_bytes = 0\nspool_dir = "{spool}"\n'
        if allow:
            text += 'spool_allow_memory_backed = true\n'
        for role in ('source', 'destination'):
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "PW"\nca_file = "CA"\n'
        return text + f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'

    def fresh_server():
        s = ProtocolServer(str(cert), str(key), 'rev1'); servers.append(s)
        s.messages['source'] = list(BODIES)
        return s

    def record(label, fstype, probe, outcome, expected, ok, note=''):
        ROWS.append((label, fstype, probe, outcome, expected, ok, note))
        if not ok:
            FAILED.append(label)

    def judge(label, fstype, probe, server, report, rows, allow_memory=False, memory_backed=False):
        """Compare IMAPLANE's behavior to what the independent probe says it should be."""
        if memory_backed and not allow_memory:
            expected = 'refused (memory-backed)'
            ok = (not report['complete']) and 'memory-backed' in report['entries'][0]['detail'] and rows == 0 and not server.messages['destination']
            outcome = 'refused' if ok else 'UNEXPECTED'
        elif probe:
            expected = 'complete, exact copy'
            ok = report['complete'] and server.messages['destination'] == BODIES and rows == 2
            outcome = 'complete' if ok else 'UNEXPECTED'
        else:
            expected = 'fail closed (unsupported)'
            ok = (not report['complete']) and 'anonymous temporary files' in report['entries'][0]['detail'] and rows == 0 and not server.messages['destination']
            outcome = 'failed closed' if ok else 'UNEXPECTED'
        record(label, fstype, 'yes' if probe else 'no', outcome, expected, ok)

    # ------------------------------------------------------------------ host (native) scenarios
    pw = root / 'password'; pw.write_text(PASSWORD); pw.chmod(0o600)

    def run_native(label, spool, allow=False):
        s = fresh_server()
        state = root / uuid.uuid4().hex[:6]
        cfg = root / (state.name + '.toml')
        cfg.write_text(config(s, state, spool, allow).replace('PW', str(pw)).replace('CA', str(cert)))
        p = subprocess.run([str(BINARY), 'migrate', '--config', str(cfg), '--json'], capture_output=True, text=True, timeout=300)
        report = json.loads(p.stdout)
        db = state / 'journal.sqlite3'
        rows = sqlite3.connect(db).execute('select count(*) from transfers').fetchone()[0] if db.exists() else 0
        left = sorted(x.name for x in Path(spool).iterdir()) if Path(spool).is_dir() else []
        assert left == [] or all(n.startswith(('journal', 'job.lock')) for n in left), f'residue in spool dir: {left}'
        return s, report, rows

    host_spool = root / 'spool'; host_spool.mkdir(); host_spool.chmod(0o700)
    ftype, probe = fs_type(host_spool), probe_o_tmpfile(host_spool)
    s, report, rows = run_native('host', host_spool)
    judge(f'host filesystem ({ftype})', ftype, probe, s, report, rows)

    shm = Path('/dev/shm')
    if shm.is_dir():
        shm_spool = Path(tempfile.mkdtemp(dir=shm)); shm_spool.chmod(0o700)
        try:
            ftype, probe = fs_type(shm_spool), probe_o_tmpfile(shm_spool)
            s, report, rows = run_native('shm', shm_spool)
            judge(f'host {ftype} /dev/shm, default', ftype, probe, s, report, rows, allow_memory=False, memory_backed=True)
            s, report, rows = run_native('shm-allowed', shm_spool, allow=True)
            judge(f'host {ftype} /dev/shm, spool_allow_memory_backed', ftype, probe, s, report, rows, allow_memory=True, memory_backed=True)
        finally:
            for x in shm_spool.iterdir(): x.unlink()
            shm_spool.rmdir()

    # ------------------------------------------------------------------ container scenarios
    try:
        docker('image', 'inspect', IMAGE)
        have_docker = True
    except (OSError, subprocess.CalledProcessError):
        have_docker = False
        print(f'NOTE: docker or image {IMAGE} unavailable; container filesystems are UNTESTED')

    def run_container(label, spool_in_container, extra_args, allow=False, host_bind=None):
        s = fresh_server()
        work = root / uuid.uuid4().hex[:6]; work.mkdir(); work.chmod(0o700)
        (work / 'password').write_text(PASSWORD); (work / 'password').chmod(0o600)
        (work / 'tls.crt').write_bytes(cert.read_bytes()); (work / 'tls.crt').chmod(0o600)
        cfg = config(s, '/w/state', spool_in_container, allow).replace('PW', '/w/password').replace('CA', '/w/tls.crt')
        (work / 'c.toml').write_text(cfg)
        mounts = ['-v', f'{work}:/w', '-v', f'{BINARY}:/imaplane:ro'] + (['-v', f'{host_bind}:{spool_in_container}'] if host_bind else [])
        probe_script = ("python3 -c \"import os,sys; "
                        "p=sys.argv[1]\ntry:\n fd=os.open(p, os.O_TMPFILE|os.O_RDWR|os.O_EXCL, 0o600); os.write(fd,b'x'); print('PROBE=yes')\n"
                        "except OSError: print('PROBE=no')\" " + spool_in_container)
        script = f'mkdir -p -m 700 {spool_in_container}; stat -f -c "TYPE=%T" {spool_in_container}; {probe_script}; /imaplane migrate --config /w/c.toml --json > /w/out.json; echo EXIT=$?'
        p = docker('run', '--rm', '--network', 'host', '--user', f'{UID}:{GID}', *mounts, *extra_args, IMAGE, 'sh', '-c', script, check=False)
        text = p.stdout
        ftype = text.split('TYPE=')[1].split()[0]
        probe = 'PROBE=yes' in text
        report = json.loads((work / 'out.json').read_text())
        db = work / 'state' / 'journal.sqlite3'
        rows = sqlite3.connect(db).execute('select count(*) from transfers').fetchone()[0] if db.exists() else 0
        return s, report, rows, ftype, probe

    if have_docker:
        s, report, rows, ftype, probe = run_container('overlay', '/tmp/spool', [])
        judge(f'container writable layer ({ftype})', ftype, probe, s, report, rows)
        bind = root / 'bind'; bind.mkdir(); bind.chmod(0o700)
        s, report, rows, ftype, probe = run_container('bind', '/bindspool', [], host_bind=bind)
        judge(f'bind mount of the host filesystem ({ftype})', ftype, probe, s, report, rows)
        tm = ['--tmpfs', f'/tmpfsspool:size=64m,mode=0700,uid={UID},gid={GID}']
        s, report, rows, ftype, probe = run_container('tmpfs', '/tmpfsspool', tm)
        judge(f'container {ftype}, default', ftype, probe, s, report, rows, allow_memory=False, memory_backed=True)
        s, report, rows, ftype, probe = run_container('tmpfs-allowed', '/tmpfsspool', tm, allow=True)
        judge(f'container {ftype}, spool_allow_memory_backed', ftype, probe, s, report, rows, allow_memory=True, memory_backed=True)

    for server in servers: server.close()

print(f'{"filesystem":<56} {"O_TMPFILE":>9}  {"IMAPLANE":<14} expected')
for label, fstype, probe, outcome, expected, ok, note in ROWS:
    print(f'{label:<56} {probe:>9}  {outcome:<14} {expected}  {"" if ok else "<-- FAILED"}')
print('UNTESTED (need privileged mkfs/mount or are absent from this kernel): XFS, Btrfs, NFS, FUSE filesystems')
print('PASS' if not FAILED else 'FAIL: ' + ', '.join(FAILED))
sys.exit(1 if FAILED else 0)
