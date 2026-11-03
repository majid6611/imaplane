#!/usr/bin/env python3
"""Streaming destination verification (phase 3): equivalence, failures and crashes.

Every scenario runs with stream_threshold_bytes unset (buffered, today's behavior) AND
set to 0 (everything streams), and the observable results must be identical. Crash
scenarios need the fault-injection binary:
  cargo build --locked --features fault-injection --target-dir target/fault-tests
  python3 tests/local/stream_verify.py target/fault-tests/debug/imaplane
Loopback-only scripted TLS server; no Docker, real credentials or real mail.
"""
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from e2e import PASSWORD, ProtocolServer, command, ROOT

BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'target/fault-tests/debug/imaplane').resolve()
from freshness import require_fresh
require_fresh(BINARY, 'fault-injection binary')
FOLDER = '台北/📬'
SMALL = b'Subject: small\r\n\r\ntiny\r\n'
LARGE = b'Subject: large\r\n\r\n' + os.urandom(1 << 20) + b'\r\ntail\r\n'   # 9 chunks of 128 KiB
THRESHOLDS = [None, 0]
FAILED = []


def check(name):
    def wrap(fn):
        try:
            fn(); print('PASS', name, flush=True)
        except BaseException as exc:
            FAILED.append(name); print('FAIL', name, '->', repr(exc)[:900], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-stream-verify-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    secret = root / 'password'; secret.write_text(PASSWORD); secret.chmod(0o600)
    servers = []; counter = [0]

    def fixture(bodies, threshold):
        counter[0] += 1; name = f'job{counter[0]}'
        server = ProtocolServer(str(cert), str(key), 'rev1'); servers.append(server)
        server.messages['source'] = list(bodies)
        cfg = root / (name + '.toml')
        text = f'state_dir = "{root/name}"\ntimeout_seconds = 5\nmax_message_bytes = 4194304\nread_attempts = 2\n'
        if threshold is not None: text += f'stream_threshold_bytes = {threshold}\n'
        for role in ['source', 'destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{secret}"\nca_file = "{cert}"\n'
        text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
        cfg.write_text(text)
        return server, cfg, root / name / 'journal.sqlite3'

    def run(cfg, action='migrate', point=None, nth=1, code=0, extra=(), diag=None):
        env = os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT', None); env.pop('IMAPLANE_FAULT_NTH', None)
        if point: env.update(IMAPLANE_FAULT_POINT=point, IMAPLANE_FAULT_NTH=str(nth))
        args = [str(BINARY)] + (['--diagnostics-file', str(diag)] if diag else []) + [action, '--config', str(cfg), '--json', *extra]
        p = subprocess.run(args, env=env, capture_output=True, text=True, timeout=120)
        assert p.returncode == (-signal.SIGKILL if point else code), (action, point, p.returncode, p.stdout[-600:], p.stderr[-400:])
        assert PASSWORD not in p.stdout + p.stderr
        return json.loads(p.stdout) if p.stdout.strip().startswith('{') else None

    def appends(s): return sum(v == b'APPEND' for _, v, _ in s.events)
    def results(r): return [e['result'] for e in r['entries']]
    def states(j): return [r[0] for r in sqlite3.connect(j).execute('select state from transfers order by uid')]
    def intact(j): assert sqlite3.connect(j).execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    def flip_last(data): return data[:-1] + bytes([data[-1] ^ 1])
    BODIES = [SMALL, LARGE, SMALL]

    @check('equivalence: complete migrate and verify, identical copies, and the chosen path is really used')
    def _():
        for threshold in THRESHOLDS:
            s, c, j = fixture(BODIES, threshold); diag = root / f'diag-{counter[0]}.jsonl'
            assert run(c, diag=diag)['complete'] and s.messages['destination'] == BODIES
            assert run(c, 'verify', diag=diag)['complete'] and states(j) == ['confirmed'] * 3
            digests = [json.loads(l) for l in diag.read_text().splitlines() if '"uid_fetch_digest"' in l]
            assert digests and all(e['outcome'] == 'OK' and e['found'] for e in digests)
            assert all(e['streamed'] == (threshold == 0) for e in digests), (threshold, [e['streamed'] for e in digests])
            assert appends(s) == 3

    @check('final-byte mismatch of a large message is detected by both paths and never confirms')
    def _():
        seen = []
        for threshold in THRESHOLDS:
            s, c, j = fixture(BODIES, threshold)
            assert run(c)['complete']
            s.messages['destination'][1] = flip_last(LARGE)
            r = run(c, 'verify', code=2)
            seen.append((results(r), [e['detail'] for e in r['entries']]))
            assert results(r) == ['confirmed', 'mismatch', 'confirmed'] and not r['complete'], r
            assert states(j) == ['confirmed', 'accepted', 'confirmed'], states(j)   # observed mismatch downgrades history
            s.messages['destination'][1] = LARGE
            assert run(c, 'verify')['complete'] and states(j) == ['confirmed'] * 3
            assert appends(s) == 3
        assert seen[0] == seen[1], seen                                              # identical across paths

    @check('truncated or failed destination read after a complete migrate is "failed", never verified')
    def _():
        seen = []
        for threshold in THRESHOLDS:
            s, c, j = fixture(BODIES, threshold)
            assert run(c)['complete']
            s.truncate_dest_fetch_at = 300_000
            r = run(c, 'verify', code=2)
            seen.append(results(r))
            assert results(r) == ['confirmed', 'failed'] and not r['complete'], r
            assert states(j)[1] != 'confirmed', states(j)
            s.truncate_dest_fetch_at = None
            assert run(c, 'verify')['complete'] and states(j) == ['confirmed'] * 3 and appends(s) == 3
        assert seen[0] == seen[1], seen

    @check('truncated read during a fresh migrate leaves the message accepted, never confirmed, and resumes without a duplicate')
    def _():
        seen = []
        for threshold in THRESHOLDS:
            s, c, j = fixture([LARGE], threshold)
            s.truncate_dest_fetch_at = 400_000
            r = run(c, code=2)
            seen.append(results(r))
            assert results(r) == ['failed'] and states(j) == ['accepted'], (r, states(j))
            assert s.messages['destination'] == [LARGE] and appends(s) == 1
            s.truncate_dest_fetch_at = None
            r = run(c)                                                               # resume: verify only
            assert r['complete'] and states(j) == ['confirmed'] and appends(s) == 1, (r, states(j), appends(s))
        assert seen[0] == seen[1], seen

    @check('SIGKILL mid-stream during verification of a confirmed message keeps its history and resumes')
    def _():
        s, c, j = fixture(BODIES, 0)
        assert run(c)['complete']
        run(c, 'verify', point='verification_stream_chunk', nth=3)                  # killed on the 3rd chunk
        intact(j); assert states(j) == ['confirmed'] * 3, states(j)
        assert run(c, 'verify')['complete'] and appends(s) == 3

    @check('SIGKILL mid-stream during the post-APPEND read-back leaves accepted evidence and no duplicate on resume')
    def _():
        s, c, j = fixture([LARGE], 0)
        run(c, point='verification_stream_chunk', nth=4)
        intact(j)
        assert states(j) == ['accepted'], states(j)                                  # APPENDUID known, not yet verified
        assert s.messages['destination'] == [LARGE] and appends(s) == 1
        r = run(c)
        assert r['complete'] and states(j) == ['confirmed'] and appends(s) == 1 and s.messages['destination'] == [LARGE]

    # ---------------------------------------------------------------- candidate scanning (3d)
    OTHER = b'Subject: unrelated\r\n\r\n' + os.urandom(1 << 20)
    FOLDER_ARGS = ['--folder', FOLDER, '--uid', '1']

    def uncertain_after_commit(threshold, body=LARGE):
        """APPEND is stored but its reply is lost: the record is uncertain and the copy exists."""
        s, c, j = fixture([body], threshold)
        s.drop_reply_after_commit = True
        r = run(c, code=2)
        assert results(r) == ['uncertain'] and states(j) == ['uncertain'], (r, states(j))
        s.drop_reply_after_commit = False
        return s, c, j

    @check('candidate scan: only the exact copy is a candidate among large look-alikes; no attribution, no replay')
    def _():
        seen = []
        for threshold in THRESHOLDS:
            s, c, j = uncertain_after_commit(threshold)
            s.messages['destination'] += [OTHER, flip_last(LARGE)]       # unrelated, and a final-byte look-alike
            diag = root / f'scan-{counter[0]}.jsonl'
            r = run(c, code=2, diag=diag)
            e = r['entries'][0]
            seen.append((results(r), e['candidate_uids'], e['detail']))
            assert e['result'] == 'uncertain' and e['candidate_uids'] == [1], e
            assert states(j) == ['uncertain'], 'a candidate is evidence only, never attribution'
            assert appends(s) == 1, 'no automatic replay'
            streamed = [json.loads(l)['streamed'] for l in diag.read_text().splitlines() if '"uid_fetch_digest"' in l]
            assert streamed and all(x == (threshold == 0) for x in streamed), (threshold, streamed)
        assert seen[0] == seen[1], seen

    @check('candidate scan: a truncated destination read aborts the run, leaves the record uncertain and is repeatable')
    def _():
        codes = []
        for threshold in THRESHOLDS:
            s, c, j = uncertain_after_commit(threshold)
            s.truncate_dest_fetch_at = 300_000
            run(c, code=1); codes.append(1)
            intact(j); assert states(j) == ['uncertain']
            s.truncate_dest_fetch_at = None
            r = run(c, code=2)
            assert r['entries'][0]['candidate_uids'] == [1] and states(j) == ['uncertain'] and appends(s) == 1
        assert codes == [1, 1]

    @check('SIGKILL mid-stream during a candidate scan leaves the uncertain record untouched')
    def _():
        s, c, j = uncertain_after_commit(0)
        run(c, point='candidate_stream_chunk', nth=3)
        intact(j); assert states(j) == ['uncertain']
        r = run(c, code=2)
        assert r['entries'][0]['candidate_uids'] == [1] and appends(s) == 1

    @check('recover: large non-matching candidates allow the audited reset; a matching one refuses it')
    def _():
        for threshold in THRESHOLDS:
            s, c, j = fixture([LARGE], threshold)
            s.drop_on_append = True
            assert results(run(c, code=2)) == ['uncertain']
            s.drop_on_append = False
            s.messages['destination'] += [OTHER, flip_last(LARGE)]
            r = run(c, 'recover', code=2, extra=FOLDER_ARGS)
            assert results(r) == ['retry_authorized'] and states(j) == ['planned'], (r, states(j))
            assert run(c)['complete'] and s.messages['destination'][-1] == LARGE
            s, c, j = fixture([LARGE], threshold)
            s.drop_on_append = True
            assert results(run(c, code=2)) == ['uncertain']
            s.drop_on_append = False
            s.messages['destination'] += [LARGE]
            run(c, 'recover', code=1, extra=FOLDER_ARGS)
            assert states(j) == ['uncertain'], 'a matching candidate must keep the record manual'

    @check('resolve: an exact large copy is attributed and verified; a final-byte difference is refused')
    def _():
        for threshold in THRESHOLDS:
            s, c, j = uncertain_after_commit(threshold)
            r = run(c, 'resolve', code=2, extra=FOLDER_ARGS + ['--destination-uid', '1'])
            assert results(r) == ['confirmed'] and states(j) == ['confirmed'] and appends(s) == 1, (r, states(j))
            s, c, j = uncertain_after_commit(threshold)
            s.messages['destination'][0] = flip_last(LARGE)
            run(c, 'resolve', code=1, extra=FOLDER_ARGS + ['--destination-uid', '1'])
            assert states(j) == ['uncertain']

    assert all(not s.errors for s in servers), [s.errors for s in servers]
    for server in servers: server.close()

print('FAILED: ' + str(FAILED) if FAILED else 'all streaming-verification checks passed')
sys.exit(1 if FAILED else 0)
