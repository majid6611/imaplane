#!/usr/bin/env python3
"""Spool disk exhaustion must not compromise the journal (phase 5A).

By default the spool lives in the same directory, hence the same filesystem, as the journal, so a
spool that fills the disk could in principle starve the journal of the space SQLite needs. This
test runs IMAPLANE in a container whose state AND spool share a small real tmpfs, then fills that
tmpfs completely at three precise moments (the scripted server pauses the transfer there):

  A  after the spool is complete, BEFORE the journal's prepare commit
  B  after the prepare commit, BEFORE the literal authorization commit
  C  after the APPEND succeeded, BEFORE the acknowledgement commit (shared disk)
  C2 the same, but with the journal on its own small filesystem that is full (spool elsewhere)

Required in every case: SQLite integrity_check passes, no impossible state, the failure is a clean
error (no panic), no body byte is sent without a durable authorization, no duplicate APPEND ever
happens, and once space is available again the documented procedure finishes the work.

Needs Docker and an image that can run the binary; prints SKIPPED otherwise.
  IMAPLANE_TEST_IMAGE=imaplane-dev:1.85.1 python3 tests/local/stream_diskfull.py target/release/imaplane
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
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
BODY = b'Subject: disk-full\r\n\r\n' + os.urandom(5 << 20)
FAILED = []


def docker(*a, check=True):
    return subprocess.run(['docker', *a], capture_output=True, text=True, timeout=600, check=check)


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


with tempfile.TemporaryDirectory(prefix='imaplane-diskfull-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')

    class Box:
        """One container with a small shared state+spool tmpfs, and the fixture it talks to."""
        def __init__(self, shared=True):
            self.server = ProtocolServer(str(cert), str(key), 'rev1')
            self.server.messages['source'] = [BODY]
            self.work = root / uuid.uuid4().hex[:6]; self.work.mkdir(); self.work.chmod(0o700)
            (self.work / 'password').write_text(PASSWORD); (self.work / 'password').chmod(0o600)
            (self.work / 'tls.crt').write_bytes(cert.read_bytes()); (self.work / 'tls.crt').chmod(0o600)
            text = 'state_dir = "/data/state"\ntimeout_seconds = 60\nmax_message_bytes = 16777216\nread_attempts = 2\nstream_threshold_bytes = 0\nspool_allow_memory_backed = true\n'
            if not shared:
                text += 'spool_dir = "/spool"\n'                         # the spool gets its own filesystem
            for role in ('source', 'destination'):
                text += f'[{role}]\nhost = "localhost"\nport = {self.server.port}\nusername = "{role}"\npassword_file = "/w/password"\nca_file = "/w/tls.crt"\n'
            text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
            (self.work / 'c.toml').write_text(text)
            self.name = 'imaplane-df-' + uuid.uuid4().hex[:8]
            mounts = ['--tmpfs', f'/data:size={8 if shared else 2}m,mode=0700,uid={UID},gid={GID}']
            if not shared:
                mounts += ['--tmpfs', f'/spool:size=16m,mode=0700,uid={UID},gid={GID}']
            docker('run', '-d', '--name', self.name, '--network', 'host', '--user', f'{UID}:{GID}', '-v', f'{self.work}:/w', '-v', f'{BINARY}:/imaplane:ro',
                   *mounts, IMAGE, 'sleep', 'infinity')

        def sh(self, script, check=True):
            return docker('exec', self.name, 'sh', '-c', script, check=check)

        def fill(self):
            self.sh('dd if=/dev/zero of=/data/junk bs=64k 2>/dev/null; true')
            free = int(self.sh("df -k /data | awk 'NR==2{print $4}'").stdout)
            assert free < 64, f'the disk is not full ({free} KiB free)'

        def free_up(self):
            self.sh('rm -f /data/junk')

        def start(self, action='migrate', extra=''):
            return subprocess.Popen(['docker', 'exec', self.name, 'sh', '-c', f'/imaplane {action} --config /w/c.toml --json {extra}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def finish(self, p):
            out, err = p.communicate(timeout=300)
            assert 'panicked' not in err and 'RUST_BACKTRACE' not in err, err[-300:]
            return p.returncode, (json.loads(out) if out.strip().startswith('{') else None), err

        def db(self, sql):
            script = f"import sqlite3,json; c=sqlite3.connect('/data/state/journal.sqlite3'); print(json.dumps(c.execute({sql!r}).fetchall()))"
            return json.loads(docker('exec', self.name, 'python3', '-c', script).stdout)

        def integrity(self):
            assert self.db('PRAGMA integrity_check') == [['ok']], 'journal integrity'
            states = [r[0] for r in self.db('select state from transfers')]
            assert all(s in ('planned', 'uncertain', 'accepted', 'confirmed') for s in states), states
            return states

        def listing(self):
            return sorted(self.sh('ls -A /data/state').stdout.split())

        def appends(self):
            return sum(v == b'APPEND' for _, v, _ in self.server.events)

        def close(self):
            self.server.close(); docker('rm', '-f', self.name, check=False)

    @check('A: disk full after the spool completes, before the prepare commit: clean error, journal intact, nothing sent')
    def _():
        b = Box()
        try:
            s = b.server; s.pause_source_fetch_at = 1 << 20; s.pause_dest_noop = True
            p = b.start()
            assert s.source_paused.wait(60); time.sleep(2.6)            # idle long enough to trigger the liveness probe
            s.resume_source_fetch.set()
            assert s.hooks['dest_noop'][0].wait(60), 'the spool never completed'
            b.fill(); s.hooks['dest_noop'][1].set()
            code, report, err = b.finish(p)
            assert code not in (0,) and 'imaplane:' in err, (code, err[-300:])
            assert b.appends() == 0 and not s.messages['destination'], 'nothing may be sent without a durable prepare'
            b.free_up()
            assert b.integrity() == [] and b.listing() == ['job.lock', 'journal.sqlite3'], b.listing()
            s.pause_dest_noop = False; s.pause_source_fetch_at = None
            code, report, _ = b.finish(b.start())
            assert code == 0 and report['complete'] and b.appends() == 1 and s.messages['destination'] == [BODY]
            assert b.integrity() == ['confirmed']
        finally:
            b.close()

    @check('B: disk full after prepare, before the authorization commit: no body byte sent; prepared evidence allows the audited recover')
    def _():
        b = Box()
        try:
            s = b.server; s.pause_continuation = True
            p = b.start()
            assert s.hooks['continuation'][0].wait(60), 'the APPEND was never reached'
            b.fill(); s.hooks['continuation'][1].set()
            code, report, err = b.finish(p)
            assert code == 2 and [e['result'] for e in report['entries']] == ['uncertain'], (code, report)
            assert s.messages['destination'] == [], 'a literal was sent without a durable authorization'
            b.free_up()
            assert b.integrity() == ['uncertain']
            assert b.db('select phase from append_attempts') == [['prepared']], 'authorization must not have been recorded'
            s.errors.clear(); s.pause_continuation = False
            code, report, _ = b.finish(b.start('recover', f"--folder '{FOLDER}' --uid 1"))
            assert code == 2 and report['entries'][0]['result'] == 'retry_authorized'
            code, report, _ = b.finish(b.start())
            assert code == 0 and report['complete'] and s.messages['destination'] == [BODY]
            assert b.appends() == 2, 'one APPEND that sent nothing, then exactly one real one'
            assert b.integrity() == ['confirmed']
        finally:
            b.close()

    @check('C: the spool is released before the first post-APPEND journal write, so a full spool cannot block the acknowledgement')
    def _():
        b = Box()
        try:
            s = b.server; s.pause_append_reply = True
            p = b.start()
            assert s.hooks['append_reply'][0].wait(60), 'the APPEND was never reached'
            b.fill(); s.hooks['append_reply'][1].set()                   # the disk is completely full while the reply is pending
            code, report, err = b.finish(p)
            # The 5 MiB spool is dropped before the acknowledgement commit, which frees the space it needs.
            assert code == 0 and report['complete'] and s.messages['destination'] == [BODY], (code, report, err[-200:])
            b.free_up()
            assert b.integrity() == ['confirmed'] and b.appends() == 1
        finally:
            b.close()

    @check('C2: journal filesystem full after the APPEND succeeded: stays uncertain, no replay, resolved manually once space returns')
    def _():
        b = Box(shared=False)
        try:
            s = b.server; s.pause_append_reply = True
            p = b.start()
            assert s.hooks['append_reply'][0].wait(60), 'the APPEND was never reached'
            b.fill(); s.hooks['append_reply'][1].set()                   # only the journal filesystem is full; the spool is elsewhere
            code, report, err = b.finish(p)
            assert code not in (0,) and 'imaplane:' in err, (code, err[-300:])
            assert s.messages['destination'] == [BODY], 'the message was committed by the server'
            b.free_up()
            assert b.integrity() == ['uncertain'], 'the acknowledgement could not be written, so the record must stay uncertain'
            s.pause_append_reply = False
            code, report, _ = b.finish(b.start())
            e = report['entries'][0]
            assert code == 2 and e['result'] == 'uncertain' and e['candidate_uids'] == [1], report
            assert b.appends() == 1, 'no automatic replay'
            code, report, _ = b.finish(b.start('resolve', f"--folder '{FOLDER}' --uid 1 --destination-uid 1"))
            assert report['entries'][0]['result'] == 'confirmed' and b.integrity() == ['confirmed'] and b.appends() == 1
            assert b.sh('ls -A /spool').stdout.split() == [], 'no spool residue'
        finally:
            b.close()

print('FAILED: ' + str(FAILED) if FAILED else 'all disk-exhaustion checks passed')
sys.exit(1 if FAILED else 0)
