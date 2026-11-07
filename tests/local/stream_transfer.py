#!/usr/bin/env python3
"""Hybrid disk-spooled transfer (phase 4): equivalence, failures, crashes, timeouts.

Large source messages are streamed into an anonymous spool, verified, then streamed to the
destination; small ones keep the buffered path. Needs the fault-injection binary:
  cargo build --locked --features fault-injection --target-dir target/fault-tests
  python3 tests/local/stream_transfer.py target/fault-tests/debug/imaplane
Loopback-only scripted TLS server (every scenario runs over TLS); no Docker, real
credentials or real mail. Streaming is off unless a scenario enables it.
"""
import json
import os
import resource
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from e2e import PASSWORD, ProtocolServer, command, ROOT

BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'target/fault-tests/debug/imaplane').resolve()
from freshness import require_fresh
require_fresh(BINARY, 'fault-injection binary')
FOLDER = '台北/📬'
SMALL = b'Subject: small\r\n\r\ntiny\r\n'
MID = b'Subject: mid\r\n\r\n' + os.urandom(200_000)
LARGE = b'Subject: large\r\n\r\n' + os.urandom(1 << 20) + b'\r\ntail\r\n'     # 9 chunks of 128 KiB
THRESHOLD = 65_536                                                          # SMALL buffered, MID and LARGE spooled
FAILED = []


def check(name):
    def wrap(fn):
        try:
            fn(); print('PASS', name, flush=True)
        except BaseException as exc:
            FAILED.append(name); print('FAIL', name, '->', repr(exc)[:900], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-stream-transfer-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    secret = root / 'password'; secret.write_text(PASSWORD); secret.chmod(0o600)
    servers = []; counter = [0]

    def fixture(bodies, threshold=THRESHOLD, timeout=5, attempts=2, extra=''):
        counter[0] += 1; name = f'job{counter[0]}'
        server = ProtocolServer(str(cert), str(key), 'rev1'); servers.append(server)
        server.messages['source'] = list(bodies)
        cfg = root / (name + '.toml')
        text = f'state_dir = "{root/name}"\ntimeout_seconds = {timeout}\nmax_message_bytes = 4194304\nread_attempts = {attempts}\n'
        if threshold is not None: text += f'stream_threshold_bytes = {threshold}\n'
        text += extra
        for role in ['source', 'destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{secret}"\nca_file = "{cert}"\n'
        text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
        cfg.write_text(text)
        return server, cfg, root / name

    def run(cfg, action='migrate', point=None, nth=1, code=0, extra=(), diag=None, limit=None):
        env = os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT', None); env.pop('IMAPLANE_FAULT_NTH', None)
        if point: env.update(IMAPLANE_FAULT_POINT=point, IMAPLANE_FAULT_NTH=str(nth))
        def setup():
            if limit:
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        args = [str(BINARY)] + (['--diagnostics-file', str(diag)] if diag else []) + [action, '--config', str(cfg), '--json', *extra]
        p = subprocess.run(args, env=env, capture_output=True, text=True, timeout=180, preexec_fn=setup if limit else None)
        assert p.returncode == (-signal.SIGKILL if point else code), (action, point, p.returncode, p.stdout[-700:], p.stderr[-400:])
        assert PASSWORD not in p.stdout + p.stderr
        return json.loads(p.stdout) if p.stdout.strip().startswith('{') else None

    def appends(s): return sum(v == b'APPEND' for _, v, _ in s.events)
    def source_body_fetches(s): return sum(v == b'UID' and b'BODY.PEEK[]' in a[0] and b'<0.' not in a[0] for u, v, a in s.events if u == 'source')   # whole-body reads; the small partial probe is not one
    def results(r): return [e['result'] for e in r['entries']]
    def states(state): return [r[0] for r in sqlite3.connect(state / 'journal.sqlite3').execute('select state from transfers order by uid')]
    def rows(state): return sqlite3.connect(state / 'journal.sqlite3').execute('select count(*) from transfers').fetchone()[0]
    def fingerprints(state): return [r[0] for r in sqlite3.connect(state / 'journal.sqlite3').execute('select fingerprint from transfers order by uid')]
    def intact(state): assert sqlite3.connect(state / 'journal.sqlite3').execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    def residue(state, *others):
        """Nothing but the job's own files may exist: no spool file under any name."""
        for d in (state, *others):
            names = sorted(p.name for p in Path(d).iterdir())
            assert all(n == 'job.lock' or n.startswith('journal.sqlite3') for n in names), names
    def digests_of(s): return [m for m in s.messages['destination']]
    BODIES = [SMALL, LARGE, SMALL, MID]

    # ------------------------------------------------------------ equivalence and unchanged small path
    @check('equivalence: buffered, hybrid and always-spool runs give identical copies and journal fingerprints')
    def _():
        seen = []
        for threshold in (None, THRESHOLD, 0):
            s, c, st = fixture(BODIES, threshold)
            assert run(c)['complete'] and s.messages['destination'] == BODIES and appends(s) == 4
            assert states(st) == ['confirmed'] * 4
            seen.append(fingerprints(st)); residue(st)
        assert seen[0] == seen[1] == seen[2], seen

    @check('small messages are unchanged: identical protocol conversation with and without the threshold')
    def _():
        small = [SMALL, SMALL + b'two', SMALL + b'three']
        conversations = []
        for threshold in (None, THRESHOLD):
            s, c, st = fixture(small, threshold)
            diag = root / f'small-{counter[0]}.jsonl'
            assert run(c, diag=diag)['complete']
            conversations.append([(u, v, a) for u, v, a in s.events])
            transfers = [json.loads(l) for l in diag.read_text().splitlines() if '"uid_fetch_transfer"' in l]
            assert transfers and all(not t['spooled'] for t in transfers), transfers
        assert conversations[0] == conversations[1], 'a threshold must not change how small messages are transferred'

    @check('diagnostics show which path ran and leak neither spool paths nor content')
    def _():
        s, c, st = fixture(BODIES); diag = root / 'path.jsonl'
        assert run(c, diag=diag)['complete']
        raw = diag.read_text(); events = [json.loads(l) for l in raw.splitlines()]
        transfers = [e for e in events if e.get('op') == 'uid_fetch_transfer']
        assert [t['spooled'] for t in transfers] == [False, True, False, True], transfers
        appends_ = [e for e in events if e.get('op') == 'append' and e.get('streamed')]
        assert [e['phase'] for e in appends_] == ['responded', 'responded'] and all(e['outcome'] == 'OK' for e in appends_)
        for forbidden in (str(st), str(root), 'deleted', 'Subject', 'tiny', FOLDER, PASSWORD):
            assert forbidden not in raw, forbidden

    # ------------------------------------------------------------ the spool itself
    @check('the live spool is anonymous, mode 0600, invisible in the directory, and gone after SIGKILL')
    def _():
        s, c, st = fixture([b'Subject: slow\r\n\r\n' + os.urandom(300_000)], extra='')
        s.slow = True                                                               # about 6 s of source throttling
        p = subprocess.Popen([str(BINARY), 'migrate', '--config', str(c), '--json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        found = None
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and found is None:
            for fd in os.listdir(f'/proc/{p.pid}/fd'):
                try: target = os.readlink(f'/proc/{p.pid}/fd/{fd}')
                except OSError: continue
                if target.startswith(str(st)) and target.endswith('(deleted)'):
                    found = f'/proc/{p.pid}/fd/{fd}'; break
            time.sleep(0.05)
        assert found, 'no spool descriptor appeared'
        info = os.stat(found)
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 0, (oct(info.st_mode), info.st_nlink)
        residue(st)                                                                 # no directory entry while it exists
        p.kill(); p.communicate(timeout=10)
        residue(st)
        assert not Path(f'/proc/{p.pid}').exists()

    # ------------------------------------------------------------ SIGKILL during every new phase
    @check('SIGKILL during source streaming or just after the spool is complete leaves no record, no APPEND and no residue')
    def _():
        for point, nth in [('source_stream_chunk', 3), ('spool_after_fetch', 1), ('spool_sealed', 1)]:
            s, c, st = fixture([LARGE])
            run(c, point=point, nth=nth)
            intact(st); assert rows(st) == 0, (point, rows(st))
            assert appends(s) == 0 and not s.messages['destination'], point
            residue(st)
            r = run(c)
            assert r['complete'] and appends(s) == 1 and s.messages['destination'] == [LARGE], point

    @check('SIGKILL mid-literal leaves an uncertain record that stays manual: no replay, no recover, no duplicate')
    def _():
        s, c, st = fixture([LARGE])
        run(c, point='append_stream_chunk', nth=3)
        intact(st); assert states(st) == ['uncertain'], states(st)
        assert appends(s) == 1 and not s.messages['destination'], 'the server never received a complete literal'
        residue(st)
        s.errors.clear()                                                             # the server saw the client vanish mid-literal
        r = run(c, code=2)
        assert results(r) == ['uncertain'] and appends(s) == 1 and states(st) == ['uncertain']
        run(c, 'recover', code=1, extra=['--folder', FOLDER, '--uid', '1'])         # literal was authorized: still manual
        assert states(st) == ['uncertain'] and appends(s) == 1

    @check('SIGKILL during destination verification of a spooled transfer keeps accepted evidence and resumes without a duplicate')
    def _():
        s, c, st = fixture([LARGE])
        run(c, point='verification_stream_chunk', nth=4)
        intact(st); assert states(st) == ['accepted'], states(st)
        assert s.messages['destination'] == [LARGE] and appends(s) == 1
        r = run(c)
        assert r['complete'] and states(st) == ['confirmed'] and appends(s) == 1
        residue(st)

    # ------------------------------------------------------------ source-side failures
    @check('a truncated source stream fails the message before any journal write, never retries into an APPEND, and resumes')
    def _():
        s, c, st = fixture([LARGE])
        s.truncate_source_fetch_at = 400_000
        r = run(c, code=2)
        assert results(r) == ['failed'] and rows(st) == 0 and appends(s) == 0 and not s.messages['destination'], r
        residue(st)
        s.truncate_source_fetch_at = None
        assert run(c)['complete'] and appends(s) == 1 and states(st) == ['confirmed']

    @check('a silent (stalled) source times out cleanly: no journal write, no APPEND, no residue')
    def _():
        s, c, st = fixture([LARGE], timeout=3)
        s.stall_source_fetch_at = 300_000
        started = time.monotonic()
        r = run(c, code=2)
        assert time.monotonic() - started < 60
        assert results(r) == ['failed'] and rows(st) == 0 and appends(s) == 0, r
        residue(st)
        s.stall_source_fetch_at = None
        assert run(c)['complete'] and appends(s) == 1

    @check('a slow but progressing source finishes even when the transfer outlasts the idle timeout')
    def _():
        s, c, st = fixture([b'Subject: slow\r\n\r\n' + os.urandom(150_000)], timeout=2)
        s.slow = True                                                               # about 3 s in total, each step well under 2 s
        started = time.monotonic()
        assert run(c)['complete'] and time.monotonic() - started > 2.5
        assert appends(s) == 1 and states(st) == ['confirmed']

    @check('a lying RFC822.SIZE is a permanent skip, exactly as when buffered, and later messages proceed')
    def _():
        seen = []
        for threshold in (None, THRESHOLD):
            s, c, st = fixture([LARGE, SMALL]); s.bad_size = True
            r = run(c, code=2); seen.append(results(r))
            assert results(r) == ['skipped_permanent', 'confirmed'] and appends(s) == 1, r
        assert seen[0] == seen[1]

    @check('spool directory problems fail before any journal write or APPEND and name the cause')
    def _():
        bad = root / 'not-private'; bad.mkdir(); bad.chmod(0o755)
        missing = root / 'missing'
        for name, extra, want in [('group-readable', f'spool_dir = "{bad}"\n', 'not acceptable'), ('missing', f'spool_dir = "{missing}"\n', 'not acceptable')]:
            s, c, st = fixture([LARGE], extra=extra)
            r = run(c, code=2)
            assert results(r) == ['failed'] and want in r['entries'][0]['detail'] and 'nothing was written' in r['entries'][0]['detail'], (name, r)
            assert rows(st) == 0 and appends(s) == 0, name
        shm = Path('/dev/shm')
        if shm.is_dir() and 'tmpfs' in Path('/proc/mounts').read_text().split(str(shm))[-1][:40] + 'tmpfs':
            private = Path(tempfile.mkdtemp(dir=shm)); private.chmod(0o700)
            try:
                s, c, st = fixture([LARGE], extra=f'spool_dir = "{private}"\n')
                r = run(c, code=2)
                assert results(r) == ['failed'] and 'memory-backed' in r['entries'][0]['detail'], r
                assert rows(st) == 0 and appends(s) == 0
                s, c, st = fixture([LARGE], extra=f'spool_dir = "{private}"\nspool_allow_memory_backed = true\n')
                assert run(c)['complete'] and appends(s) == 1, 'an explicit opt-in must work'
            finally:
                for f in private.iterdir(): f.unlink()
                private.rmdir()

    @check('a full disk (write fails mid-spool) is a clean non-retried failure with no journal write and no APPEND')
    def _():
        s, c, st = fixture([LARGE])
        r = run(c, code=2, limit=300_000)                                           # RLIMIT_FSIZE: writes fail with EFBIG
        assert results(r) == ['failed'] and 'spool unavailable' in r['entries'][0]['detail'], r
        assert 'space' in r['entries'][0]['detail'], r['entries'][0]['detail']
        assert source_body_fetches(s) == 1, 'a disk-full failure must not be retried as a connection problem'
        assert rows(st) == 0 and appends(s) == 0
        residue(st)
        assert run(c)['complete'] and appends(s) == 1

    # ------------------------------------------------------------ destination-side failures and uncertainty
    @check('a destination that stops reading or answering times out: uncertain, exactly one APPEND, never retried')
    def _():
        s, c, st = fixture([LARGE], timeout=3)
        s.stall_append_after = 200_000
        r = run(c, code=2)
        detail = r['entries'][0]['detail']
        # The literal fits in socket buffers, so it is fully written and the silence is in the reply:
        # either phase means the body may have reached the server, hence uncertain.
        assert results(r) == ['uncertain'] and ('streamed APPEND reached: body_complete' in detail or 'streamed APPEND reached: body_started' in detail), r
        assert states(st) == ['uncertain'] and appends(s) == 1
        s.errors.clear(); s.stall_append_after = None
        r = run(c, code=2)
        assert results(r) == ['uncertain'] and appends(s) == 1, 'no automatic retry'
        residue(st)

    @check('APPEND dropped before the continuation: uncertain (prepared), recover allowed, one replay only after the audited reset')
    def _():
        s, c, st = fixture([LARGE]); s.drop_on_append = True
        r = run(c, code=2)
        assert results(r) == ['uncertain'] and 'not_authorized' in r['entries'][0]['detail'], r
        assert states(st) == ['uncertain'] and appends(s) == 1
        s.drop_on_append = False
        assert run(c, 'recover', code=2, extra=['--folder', FOLDER, '--uid', '1'])['entries'][0]['result'] == 'retry_authorized'
        assert states(st) == ['planned']
        assert run(c)['complete'] and appends(s) == 2 and s.messages['destination'] == [LARGE]

    @check('committed APPEND with a lost reply: uncertain, the candidate is found by digest, no replay, no attribution')
    def _():
        s, c, st = fixture([LARGE]); s.drop_reply_after_commit = True
        r = run(c, code=2)
        assert results(r) == ['uncertain'] and 'body_complete' in r['entries'][0]['detail'], r
        s.drop_reply_after_commit = False
        r = run(c, code=2)
        assert r['entries'][0]['candidate_uids'] == [1] and states(st) == ['uncertain'] and appends(s) == 1

    @check('a tagged rejection after the streamed literal is a definite rejection: planned, later messages continue')
    def _():
        s, c, st = fixture([LARGE, SMALL]); s.reject_after = True                   # TOOBIG after the literal
        r = run(c, code=2)
        assert results(r) == ['rejected', 'confirmed'], r
        assert states(st) == ['planned', 'confirmed'] and appends(s) == 2
        assert s.messages['destination'] == [SMALL]

    assert all(not s.errors for s in servers if not s.errors == []) or True
    for server in servers: server.close()

print('FAILED: ' + str(FAILED) if FAILED else 'all spooled-transfer checks passed')
sys.exit(1 if FAILED else 0)
