#!/usr/bin/env python3
"""C1 (APPEND rejection semantics + operator skip) and U1 (idle destination) regressions.

Loopback-only scripted TLS server; no Docker, real credentials or real mail.
Usage: python3 tests/local/c1_u1.py [path/to/imaplane]
Every check runs and is reported; the exit status is nonzero if any check fails.
"""
import json
import sqlite3
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from e2e import BIN, PASSWORD, ProtocolServer, command, STREAM_EXTRA

RESULTS = []


def check(name):
    def wrap(fn):
        try:
            fn()
            RESULTS.append((name, None)); print('PASS', name)
        except BaseException as exc:  # report every check, not only the first failure
            RESULTS.append((name, exc)); print('FAIL', name, '->', repr(exc)[:3000])
            if not isinstance(exc, AssertionError): traceback.print_exc()
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-c1u1-') as temporary:
    root = Path(temporary)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    secret = root / 'password'; secret.write_text(PASSWORD); secret.chmod(0o600)
    servers = []
    counter = [0]

    def fixture(bodies, timeout=5):
        counter[0] += 1; name = f'job{counter[0]}'
        server = ProtocolServer(str(cert), str(key), 'rev1'); servers.append(server)
        server.messages['source'] = bodies
        config = root / (name + '.toml')
        text = f'state_dir = "{root/name}"\ntimeout_seconds = {timeout}\nmax_message_bytes = 262144\nread_attempts = 4\n{STREAM_EXTRA}'
        for role in ['source', 'destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{secret}"\nca_file = "{cert}"\n'
        text += '[[folders]]\nsource = "台北/📬"\ndestination = "台北/📬"\n'
        config.write_text(text)
        return server, config, root / name / 'journal.sqlite3'

    def cli(config, *args, expected=None):
        p = subprocess.run([str(BIN), *args, '--config', str(config)], capture_output=True, text=True, timeout=60)
        assert PASSWORD not in p.stdout + p.stderr and 'PRIVATE' not in p.stdout + p.stderr, 'secret or server text leaked'
        if expected is not None: assert p.returncode == expected, (p.returncode, p.stdout, p.stderr)
        return p

    def migrate(config, expected=None):
        p = cli(config, 'migrate', '--json', expected=expected)
        return json.loads(p.stdout)

    def appends(server): return sum(v == b'APPEND' for user, v, args in server.events)
    def noops(server): return sum(v == b'NOOP' for user, v, args in server.events)
    def results(report): return [e['result'] for e in report['entries']]
    def evidence(journal): return [r[0] for r in sqlite3.connect(journal).execute('select evidence from append_rejections')]
    body = b'Subject: fixture\r\n\r\nbytes\r\n'
    three = [body + b'0', body + b'1', body + b'2']

    # ---- C1: rejection semantics -------------------------------------------------
    for code, scope in [(b'NOPERM', 'mailbox'), (b'NONEXISTENT', 'mailbox'), (b'TRYCREATE', 'mailbox'),
                        (b'AUTHENTICATIONFAILED', 'account'), (b'AUTHORIZATIONFAILED', 'account'),
                        (b'EXPIRED', 'account'), (b'PRIVACYREQUIRED', 'account')]:
        @check(f'C1 {code.decode()} is {scope}-scoped: stop, name the scope, keep exact code as evidence')
        def _(code=code, scope=scope):
            s, c, j = fixture(three); s.rejection_script = [None, code]
            r = migrate(c, 2)
            assert results(r) == ['confirmed', 'rejected'], r
            assert r['halt_reason'] and scope in r['halt_reason'] and 'unclassified' not in r['halt_reason'], r['halt_reason']
            assert any(code.decode() in e for e in evidence(j)), evidence(j)
            assert appends(s) == 2 and len(s.messages['destination']) == 1
            assert sqlite3.connect(j).execute("select count(*) from transfers where state='uncertain'").fetchone()[0] == 0

    for code in [b'CANNOT', b'SERVERBUG', b'X-VENDOR-ODD', b'-']:
        @check(f'C1 ambiguous/unknown ({code.decode()}) keeps the conservative stop')
        def _(code=code):
            s, c, j = fixture(three); s.rejection_script = [None, code]
            r = migrate(c, 2)
            assert results(r) == ['confirmed', 'rejected'], r
            assert r['halt_reason'] and 'operator review' in r['halt_reason'], r['halt_reason']
            assert appends(s) == 2 and len(s.messages['destination']) == 1

    @check('C1 CONTENTREJECTED is message-specific: later messages continue, nothing is replayed')
    def _():
        s, c, j = fixture(three); s.rejection_script = [None, b'CONTENTREJECTED']
        r = migrate(c, 2)
        assert results(r) == ['confirmed', 'rejected', 'confirmed'] and r['halt_reason'] is None, r
        assert not r['complete'] and appends(s) == 3

    # ---- C1: operator skip ---------------------------------------------------------
    def halted_job():
        s, c, j = fixture(three); s.rejection_script = [None, b'CANNOT']
        migrate(c, 2); return s, c, j

    @check('C1 skip refuses a message with no rejection evidence, a confirmed one and a missing reason')
    def _():
        s, c, j = halted_job()
        for uid, reason in [('3', 'never attempted'), ('1', 'already confirmed')]:
            p = cli(c, 'skip', '--folder', '台北/📬', '--uid', uid, '--reason', reason, '--json')
            assert p.returncode != 0 and 'skipped' not in p.stdout, (uid, p.returncode, p.stdout, p.stderr)
        p = cli(c, 'skip', '--folder', '台北/📬', '--uid', '2', '--json')
        assert p.returncode != 0, 'reason must be mandatory'

    @check('C1 skip is audited, never counts as migrated, is not retried and keeps the run incomplete')
    def _():
        s, c, j = halted_job()
        p = cli(c, 'skip', '--folder', '台北/📬', '--uid', '2', '--reason', 'ticket 42: provider cannot store it', '--json')
        assert p.returncode == 2, (p.returncode, p.stdout, p.stderr)
        assert json.loads(p.stdout)['entries'][0]['result'] == 'skipped_by_operator'
        before = appends(s)
        r = migrate(c, 2)
        assert results(r) == ['confirmed', 'skipped_by_operator', 'confirmed'], r
        assert not r['complete'] and appends(s) - before == 1, 'only the third message may be appended'
        assert s.messages['destination'] == [three[0], three[2]]
        db = sqlite3.connect(j)
        assert db.execute("select count(*) from transfers where state='confirmed'").fetchone()[0] == 2
        assert db.execute("select count(*) from transfers where uid=2 and state='planned'").fetchone()[0] == 1
        assert 'ticket 42' in json.dumps(db.execute('select * from operator_skip_events').fetchall())
        again = migrate(c, 2); assert not again['complete'] and appends(s) - before == 1
        summary = json.loads(subprocess.run([str(BIN), 'status', '--state', str(j), '--json'], capture_output=True, text=True).stdout)
        assert summary['skipped'] == 1 and summary['confirmed'] == 2, summary

    @check('C1 unskip restores the message to the normal path; it is then appended exactly once')
    def _():
        s, c, j = halted_job()
        cli(c, 'skip', '--folder', '台北/📬', '--uid', '2', '--reason', 'temporary', '--json', expected=2)
        p = cli(c, 'unskip', '--folder', '台北/📬', '--uid', '2', '--reason', 'provider fixed', '--json')
        assert p.returncode == 2, (p.returncode, p.stdout, p.stderr)
        r = migrate(c, 0)
        assert r['complete'] and sorted(s.messages['destination']) == sorted(three) and appends(s) == 4, (r, appends(s))
        assert len(sqlite3.connect(j).execute('select * from operator_skip_events').fetchall()) == 2

    @check('C1 skip refuses uncertain and authorized records')
    def _():
        s, c, j = fixture(three); s.reject_once = True; s.wrong_rejection_tag = True
        r = migrate(c, 2); assert results(r)[0] == 'uncertain', r
        p = cli(c, 'skip', '--folder', '台北/📬', '--uid', '1', '--reason', 'nope', '--json')
        assert p.returncode != 0 and 'skipped_by_operator' not in p.stdout, (p.stdout, p.stderr)

    # ---- U1: idle destination ------------------------------------------------------
    big = [body + bytes([48 + i]) * 150000 for i in range(3)]

    @check('U1 idle destination dropped during slow source read is detected before any APPEND is prepared')
    def _():
        s, c, j = fixture(big, timeout=8); s.slow = True; s.idle_drop = 1.0
        r = migrate(c, 0)
        assert r['complete'] and results(r) == ['confirmed'] * 3, r
        assert s.messages['destination'] == big and appends(s) == 3, 'exactly one APPEND per message'
        assert noops(s) >= 1, 'liveness probe expected'
        assert sqlite3.connect(j).execute("select count(*) from transfers where state='uncertain'").fetchone()[0] == 0

    @check('U1 fast migrations send no extra NOOP (protocol exchange counters stay unchanged)')
    def _():
        s, c, j = fixture(three)
        assert migrate(c, 0)['complete'] and noops(s) == 0

    @check('U1 residual: death between a successful probe and APPEND stays uncertain and is never resent')
    def _():
        s, c, j = fixture([body]); s.drop_on_append = True
        r = migrate(c, 2); assert results(r) == ['uncertain'], r
        again = migrate(c, 2); assert results(again) == ['uncertain'], again
        assert appends(s) == 1 and not s.messages['destination']

    assert all(not s.errors for s in servers), [s.errors for s in servers]
    for server in servers: server.close()

failed = [(n, e) for n, e in RESULTS if e is not None]
print(f'{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed')
sys.exit(1 if failed else 0)
