#!/usr/bin/env python3
"""Schema 5 (phase I0) end to end: an interrupted schema-4 job is upgraded and then completes.

For buffered and forced-spool transfers: migrate is SIGKILLed after the second confirmed message
(fault-injection binary), the journal is upgraded to schema 5 with the real upgrade function, and the
ordinary commands (`status`, `migrate`, `verify`) must finish the job with exactly one APPEND per
message, read-only source access and no leftover files. A second ordinary run must change nothing.
Also checks that a job which is never upgraded stays at schema 4 through the same runs.

  python3 tests/local/schema5_e2e.py target/fault-tests/debug/imaplane target/debug/examples/upgrade_v5
Loopback-only scripted TLS server; no Docker, real credentials or real mail.
"""
import json
import os
import random
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from e2e import PASSWORD, ProtocolServer, command
from freshness import require_fresh
from stream_stress import FOLDER, Violation, check_invariants

binary = Path(sys.argv[1]).resolve()
helper = Path(sys.argv[2]).resolve()
require_fresh(binary, 'fault-injection binary')
FAILED = []


def check(name):
    def wrap(fn):
        try:
            fn(); print('PASS', name, flush=True)
        except BaseException as exc:
            FAILED.append(name); print('FAIL', name, '->', repr(exc)[:600], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-s5-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    password = root / 'password'; password.write_text(PASSWORD); password.chmod(0o600)

    def scenario(name, threshold, upgrade):
        rng = random.Random(name)
        bodies = [b'Subject: s5 %d\r\n\r\n' % i + rng.randbytes(40_000 + 1000 * i) for i in range(4)]
        server = ProtocolServer(str(cert), str(key), 'rev1'); server.messages['source'] = list(bodies)
        state = root / name; cfg = root / f'{name}.toml'; journal = state / 'journal.sqlite3'
        text = f'state_dir = "{state}"\ntimeout_seconds = 10\nmax_message_bytes = 4194304\nread_attempts = 2\n'
        if threshold is not None:
            text += f'stream_threshold_bytes = {threshold}\nspool_allow_memory_backed = true\n'
        for role in ('source', 'destination'):
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
        text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
        cfg.write_text(text)

        def run(action, fault=None, extra=()):
            env = os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT', None); env.pop('IMAPLANE_FAULT_NTH', None)
            if fault:
                env.update(IMAPLANE_FAULT_POINT=fault[0], IMAPLANE_FAULT_NTH=str(fault[1]))
            p = subprocess.run([str(binary), action, '--config', str(cfg), '--json', *extra], env=env, capture_output=True, text=True, timeout=120)
            server.errors.clear()
            run.last_stderr = p.stderr[-400:]
            return p.returncode, p.stdout

        def version(): return sqlite3.connect(journal).execute('PRAGMA user_version').fetchone()[0]
        def states(): return [r[0] for r in sqlite3.connect(journal).execute('select state from transfers order by uid')]
        try:
            code, _ = run('migrate', fault=('after_confirm', 2))
            assert code == -9 and states().count('confirmed') == 2, (code, run.last_stderr)
            assert version() == 4
            if upgrade:
                out = subprocess.run([str(helper), str(journal)], capture_output=True, text=True, check=True).stdout.strip()
                assert out == 'upgraded' and version() == 5
                tables = {r[0] for r in sqlite3.connect(journal).execute("select name from sqlite_master where type='table'")}
                assert {'scans', 'job_folders', 'verification_events', 'verification_runs'} <= tables
            else:
                assert 'scans' not in {r[0] for r in sqlite3.connect(journal).execute("select name from sqlite_master where type='table'")}
            p = subprocess.run([str(binary), 'status', '--state', str(journal), '--json'], capture_output=True, text=True, timeout=60)
            assert p.returncode in (0, 2) and json.loads(p.stdout)['confirmed'] == 2, (p.returncode, p.stdout, p.stderr[-300:])
            code, out = run('migrate')
            report = json.loads(out)
            assert code == 0 and report['complete'] and states() == ['confirmed'] * 4, (code, states())
            appends = sum(v == b'APPEND' for _, v, _ in server.events)
            assert appends == 4 and server.messages['destination'] == bodies, appends
            check_invariants(server, bodies, journal, state, 0)
            snapshot = sqlite3.connect(journal).execute('select group_concat(state||uid||ifnull(destination_uid,"")) from transfers').fetchone()
            code, out = run('verify')
            assert code == 0 and json.loads(out)['complete']
            code, out = run('migrate')
            assert code == 0 and sum(v == b'APPEND' for _, v, _ in server.events) == 4, 'a repeat run must not append'
            assert sqlite3.connect(journal).execute('select group_concat(state||uid||ifnull(destination_uid,"")) from transfers').fetchone() == snapshot
            assert version() == (5 if upgrade else 4), 'ordinary commands must never change the schema version'
            check_invariants(server, bodies, journal, state, 0)
        finally:
            server.close()

    for label, threshold in [('buffered', None), ('forced-spool', 0)]:
        @check(f'{label}: interrupted schema-4 job, upgraded to schema 5, finishes with one APPEND per message')
        def _(label=label, threshold=threshold):
            scenario(f'{label}-up', threshold, True)

        @check(f'{label}: the same job without the upgrade stays at schema 4')
        def _(label=label, threshold=threshold):
            scenario(f'{label}-v4', threshold, False)

print('FAILED: ' + str(FAILED) if FAILED else 'all schema 5 end-to-end checks passed')
sys.exit(1 if FAILED else 0)
