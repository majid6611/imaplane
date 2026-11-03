#!/usr/bin/env python3
"""Deterministic SIGKILL gates for operator skip/unskip and the schema 3->4 upgrade.

Needs the fault-injection binary:
  cargo build --locked --features fault-injection --target-dir target/fault-tests
  python3 tests/local/skip_crash_matrix.py target/fault-tests/debug/imaplane
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
from e2e import PASSWORD, ProtocolServer, command, ROOT, STREAM_EXTRA

BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'target/fault-tests/debug/imaplane').resolve()
FOLDER = '台北/📬'
body = b'Subject: fixture\r\n\r\nbytes\r\n'
three = [body + b'0', body + b'1', body + b'2']

with tempfile.TemporaryDirectory(prefix='imaplane-skip-crash-') as tmp:
    root = Path(tmp)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    secret = root / 'password'; secret.write_text(PASSWORD); secret.chmod(0o600)
    servers = []; counter = [0]

    def fixture():
        counter[0] += 1; name = f'job{counter[0]}'
        server = ProtocolServer(str(cert), str(key), 'rev1'); servers.append(server)
        server.messages['source'] = list(three)
        cfg = root / (name + '.toml')
        text = f'state_dir = "{root/name}"\ntimeout_seconds = 5\nmax_message_bytes = 262144\nread_attempts = 4\n{STREAM_EXTRA}'
        for role in ['source', 'destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{secret}"\nca_file = "{cert}"\n'
        text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
        cfg.write_text(text)
        return server, cfg, root / name / 'journal.sqlite3'

    def run(cfg, action='migrate', point=None, code=0, extra=()):
        env = os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT', None); env.pop('IMAPLANE_FAULT_NTH', None)
        if point: env.update(IMAPLANE_FAULT_POINT=point, IMAPLANE_FAULT_NTH='1')
        p = subprocess.run([str(BINARY), action, '--config', str(cfg), '--json', *extra], env=env, capture_output=True, text=True, timeout=90)
        assert p.returncode == (-signal.SIGKILL if point else code), (action, point, p.returncode, p.stdout, p.stderr)
        assert PASSWORD not in p.stdout + p.stderr
        return json.loads(p.stdout) if p.stdout else None

    def appends(s): return sum(v == b'APPEND' for _, v, _ in s.events)
    def results(r): return [e['result'] for e in r['entries']]
    def skip_args(uid=2, reason='ticket 42'): return ['--folder', FOLDER, '--uid', str(uid), '--reason', reason]
    def db(path, sql): return sqlite3.connect(path).execute(sql).fetchall()
    def intact(path):
        assert db(path, 'PRAGMA integrity_check') == [('ok',)]
        assert db(path, "select count(*) from transfers where state='uncertain'") == [(0,)], 'no transition may be left uncertain'

    def rejected_job():
        """Message 1 confirmed, message 2 durably rejected (CANNOT), message 3 untouched."""
        s, cfg, j = fixture(); s.rejection_script = [None, b'CANNOT']
        r = run(cfg, code=2); assert results(r) == ['confirmed', 'rejected'], r
        return s, cfg, j

    # ---- skip: killed before / after its single commit -------------------------------
    for point, durable in [('skip_before_commit', False), ('after_skip', True)]:
        s, cfg, j = rejected_job()
        run(cfg, 'skip', point=point, extra=skip_args())
        intact(j)
        assert db(j, 'select count(*) from operator_skip_events') == [(1 if durable else 0,)]
        assert db(j, "select count(*) from transfers where uid=2 and state='planned'") == [(1,)], 'skip never changes transfer state'
        before = appends(s)
        if durable:
            run(cfg, 'skip', code=1, extra=skip_args())           # no double skip
            r = run(cfg, code=2)
            assert results(r) == ['confirmed', 'skipped_by_operator', 'confirmed'] and not r['complete'], r
            assert appends(s) - before == 1 and s.messages['destination'] == [three[0], three[2]]
        else:
            r = run(cfg)                                          # skip left no trace: normal path
            assert r['complete'] and appends(s) - before == 2
            assert sorted(s.messages['destination']) == sorted(three)
        print('PASS', point, '- atomic skip; no duplicates; skipped message never reported as migrated', flush=True)

    # ---- unskip: killed before / after its single commit -----------------------------
    for point, durable in [('unskip_before_commit', False), ('after_unskip', True)]:
        s, cfg, j = rejected_job()
        run(cfg, 'skip', code=2, extra=skip_args())
        run(cfg, 'unskip', point=point, extra=skip_args(reason='provider fixed'))
        intact(j)
        assert db(j, 'select action from operator_skip_events order by rowid') == ([('skip',), ('unskip',)] if durable else [('skip',)])
        before = appends(s)
        r = run(cfg, code=0 if durable else 2)
        if durable:
            assert r['complete'] and appends(s) - before == 2 and sorted(s.messages['destination']) == sorted(three)
        else:
            assert results(r) == ['confirmed', 'skipped_by_operator', 'confirmed'] and appends(s) - before == 1
        print('PASS', point, '- atomic unskip; skip state exactly as committed; no duplicates', flush=True)

    # ---- schema 3 -> 4 upgrade killed at every step -----------------------------------
    for point, backups, version in [('before_upgrade_backup', 0, 3), ('after_upgrade_backup', 1, 3),
                                    ('skip_schema_upgrade_before_commit', 1, 3), ('after_skip_schema_upgrade', 1, 4)]:
        s, cfg, j = fixture()
        run(cfg)
        assert len(s.messages['destination']) == 3
        with sqlite3.connect(j) as conn:
            conn.execute('DROP TABLE operator_skip_events'); conn.execute('PRAGMA user_version=3')
        made = appends(s)
        run(cfg, point=point)
        intact(j)
        assert db(j, 'PRAGMA user_version') == [(version,)], point
        saved = sorted(j.parent.glob('journal.sqlite3.v3.bak*'))
        assert len(saved) == backups, (point, saved)
        for path in saved:
            assert db(path, 'PRAGMA user_version') == [(3,)]
            assert db(path, "select count(*) from transfers where state='confirmed'") == [(3,)]
        assert db(j, "select count(*) from transfers where state='confirmed'") == [(3,)], 'legacy evidence preserved'
        assert run(cfg)['complete']                                # resumes and upgrades
        assert db(j, 'PRAGMA user_version') == [(4,)]
        assert appends(s) == made and sorted(s.messages['destination']) == sorted(three), 'no extra APPEND'
        print('PASS schema 3->4 upgrade killed at', point, '- backup, integrity, evidence and resume', flush=True)

    assert all(not s.errors for s in servers), [s.errors for s in servers]
    for server in servers: server.close()
print('PASS skip/unskip/upgrade crash matrix')
