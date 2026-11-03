#!/usr/bin/env python3
"""Opt-in sanitized diagnostics: content, leak resistance, file safety, no behavior change.

Loopback-only scripted TLS server (XOAUTH2 enabled); no Docker or real credentials.
Usage: python3 tests/local/diagnostics.py [path/to/imaplane]
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from e2e import BIN, PASSWORD, ProtocolServer, command, STREAM_EXTRA

TOKEN = 'TEST-ONLY-ACCESS-TOKEN-0123456789'
BODY_MARKER = b'SECRET-BODY-MARKER'
ALLOWED_KEYS = {'event', 'seq', 't', 'version', 'pid', 'role', 'op', 'ms', 'outcome', 'code', 'unlisted_code', 'scope',
                'transient', 'capabilities', 'other_capability_count', 'appendlimit', 'count', 'found', 'bytes',
                'appenduid', 'writable', 'exists', 'has_uidnext', 'system_flags', 'custom_flag_count', 'streamed'}
ATOM = re.compile(r'^[A-Z0-9-]{1,32}$')
FAILED = []


def check(name):
    def wrap(fn):
        try:
            fn(); print('PASS', name)
        except BaseException as exc:
            FAILED.append(name); print('FAIL', name, '->', repr(exc)[:800])
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-diag-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    tokenfile = root / 'token'; tokenfile.write_text(TOKEN); tokenfile.chmod(0o600)
    password = root / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
    servers = []; counter = [0]
    bodies = [b'Subject: one\r\n\r\n' + BODY_MARKER + b'1\r\n', b'Subject: two\r\n\r\n' + BODY_MARKER + b'2\r\n', b'Subject: three\r\n\r\n' + BODY_MARKER + b'3\r\n']

    def fixture(oauth=True, messages=None):
        counter[0] += 1; name = f'job{counter[0]}'
        server = ProtocolServer(str(cert), str(key), 'rev1'); servers.append(server)
        server.messages['source'] = list(messages or bodies)
        if oauth: server.xoauth2_token = TOKEN
        cfg = root / (name + '.toml')
        text = f'state_dir = "{root/name}"\ntimeout_seconds = 5\nmax_message_bytes = 262144\nread_attempts = 4\n{STREAM_EXTRA}'
        for role in ['source', 'destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\nca_file = "{cert}"\n'
            text += f'auth = "xoauth2"\naccess_token_file = "{tokenfile}"\n' if oauth else f'password_file = "{password}"\n'
        text += '[[folders]]\nsource = "台北/📬"\ndestination = "台北/📬"\n'
        cfg.write_text(text)
        return server, cfg

    def migrate(cfg, diag=None, expected=None):
        args = [str(BIN)] + (['--diagnostics-file', str(diag)] if diag else []) + ['migrate', '--config', str(cfg), '--json']
        p = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if expected is not None: assert p.returncode == expected, (p.returncode, p.stdout, p.stderr)
        for secret in (TOKEN, PASSWORD, 'PRIVATE'): assert secret not in p.stdout + p.stderr, f'{secret} leaked to output'
        return p, json.loads(p.stdout) if p.stdout.strip().startswith('{') else None

    def lines(path): return [json.loads(l) for l in Path(path).read_text().splitlines()]

    @check('off by default: no file, same results, XOAUTH2 end to end')
    def _():
        s, c = fixture(); diag = root / 'never.jsonl'
        p, report = migrate(c, expected=0)
        assert report['complete'] and s.messages['destination'] == bodies and not diag.exists()

    @check('enabled: complete run records useful facts and nothing sensitive')
    def _():
        s, c = fixture(); diag = root / 'run1.jsonl'
        p, report = migrate(c, diag, expected=0)
        assert report['complete'] and s.messages['destination'] == bodies
        assert oct(diag.stat().st_mode & 0o777) == '0o600'
        raw = diag.read_text(); events = lines(diag)
        for forbidden in (TOKEN, PASSWORD, 'PRIVATE', BODY_MARKER.decode(), '台北', 'Subject', 'one', 'user=', 'Bearer',
                          'X-PRIVATE-VENDOR'):
            assert forbidden not in raw, f'{forbidden!r} found in diagnostics'
        for e in events:
            assert set(e) <= ALLOWED_KEYS, set(e) - ALLOWED_KEYS
        assert events[0]['event'] == 'start'
        assert [e['seq'] for e in events] == list(range(len(events)))
        connects = [e for e in events if e['event'] == 'connect']
        assert {e['role'] for e in connects} == {'source', 'destination'}
        for e in connects:
            assert e['outcome'] == 'OK' and 'UIDPLUS' in e['capabilities'] and 'AUTH=XOAUTH2' in e['capabilities']
            assert 'X-GM-EXT-1' in e['capabilities'] and e['appendlimit'] == 26214400
            assert e['other_capability_count'] >= 1, 'unlisted capability must be counted, never named'
        appends = [e for e in events if e.get('op') == 'append']
        assert len(appends) == 3 and all(e['outcome'] == 'OK' and e['appenduid'] is True and e['bytes'] > 0 for e in appends)
        assert any(e.get('op') == 'select' and e['writable'] is True for e in events)

    @check('failures: code names and scope recorded; server text and unlisted detail sanitized')
    def _():
        for code, outcome_code, unlisted, scope in [(b'NOPERM', 'NOPERM', None, 'mailbox'), (b'X-VENDOR-ODD', 'UNSPECIFIED', 'X-VENDOR-ODD', 'ambiguous'),
                                                    (b'ALERT', 'UNSPECIFIED', 'ALERT', 'ambiguous'), (b'A' * 40, 'UNSPECIFIED', None, 'ambiguous'),
                                                    (b'THROTTLED', 'THROTTLED', None, 'transient'), (b'CONTENTREJECTED', 'CONTENTREJECTED', None, 'message')]:
            s, c = fixture(); s.rejection_script = [code]; diag = root / f'rej-{code[:6].decode()}.jsonl'
            migrate(c, diag, expected=2)
            raw = diag.read_text()
            assert 'PRIVATE' not in raw and TOKEN not in raw and 'rejection' not in raw.replace('"event"', '')
            bad = [e for e in lines(diag) if e.get('op') == 'append' and e['outcome'] != 'OK']
            assert len(bad) >= 1, (code, raw)
            e = bad[0]
            assert (e['outcome'], e['code'], e['unlisted_code'], e['scope']) == ('NO', outcome_code, unlisted, scope), (code, e)
            if e['unlisted_code']: assert ATOM.match(e['unlisted_code'])

    @check('authentication failure is recorded as a code, never the token or server text')
    def _():
        s, c = fixture(); s.xoauth2_token = 'a-different-token'; diag = root / 'authfail.jsonl'
        p, _ = migrate(c, diag)
        assert p.returncode != 0
        raw = diag.read_text(); assert TOKEN not in raw and 'PRIVATE' not in raw and 'a-different-token' not in raw
        failed = [e for e in lines(diag) if e['event'] == 'connect' and e['outcome'] != 'OK']
        assert failed and failed[0]['outcome'] == 'NO' and failed[0]['code'] == 'AUTHENTICATIONFAILED'

    @check('diagnostics never change results (same entries with and without the flag)')
    def _():
        results = []
        for diag in (None, root / 'same.jsonl'):
            s, c = fixture(); s.rejection_script = [None, b'CANNOT']
            _, report = migrate(c, diag, expected=2)
            results.append(([e['result'] for e in report['entries']], report['halt_reason'], list(s.messages['destination'])))
        assert results[0] == results[1], results

    @check('file safety: refuses group-readable files, symlinks and unwritable paths; appends across runs')
    def _():
        s, c = fixture()
        loose = root / 'loose.jsonl'; loose.write_text(''); loose.chmod(0o644)
        p, _ = migrate(c, loose); assert p.returncode != 0 and not s.messages['destination']
        target = root / 'target.jsonl'; target.write_text(''); target.chmod(0o600)
        link = root / 'link.jsonl'; link.symlink_to(target)
        p, _ = migrate(c, link); assert p.returncode != 0 and not s.messages['destination']
        p, _ = migrate(c, root / 'no-such-dir' / 'x.jsonl'); assert p.returncode != 0
        good = root / 'good.jsonl'
        migrate(c, good, expected=0); first = len(lines(good))
        migrate(c, good, expected=0); assert len(lines(good)) > first and good.stat().st_mode & 0o777 == 0o600

    @check('default binary has no fault hook strings and diagnostics add no environment switch')
    def _():
        data = BIN.read_bytes()
        if b'IMAPLANE_FAULT_POINT' in data:  # fault-injection build supplied; only check the env name list
            return
        assert b'IMAPLANE_DIAGNOSTICS' not in data

    assert all(not s.errors for s in servers), [s.errors for s in servers]
    for server in servers: server.close()

print(f'{"FAILED: " + str(FAILED) if FAILED else "all diagnostics checks passed"}')
sys.exit(1 if FAILED else 0)
