"""Offline tests for scripts/imap_snapshot.py, scripts/oauth_token.py and scripts/provider_lab.py.

No network beyond a loopback fake token endpoint, and no Docker. Run with:
  python3 -m unittest discover -s tests/local -p 'test_*.py'
"""
import base64
import hashlib
import http.server
import io
import json
import os
import stat
import sys
import tempfile
import threading
import tomllib
import unittest
import urllib.parse
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import imap_snapshot as snap  # noqa: E402
import oauth_token as oauth  # noqa: E402
import provider_lab as lab  # noqa: E402


def private(path, text):
    Path(path).write_text(text)
    os.chmod(path, 0o600)
    return str(path)


class SnapshotReadOnly(unittest.TestCase):
    def test_only_read_commands_and_peek_fetch_are_allowed(self):
        ok = [('CAPABILITY', ()), ('LOGIN', ('u', 'p')), ('AUTHENTICATE', ('XOAUTH2',)), ('LIST', ('""', '*')),
              ('EXAMINE', ('INBOX',)), ('NOOP', ()), ('LOGOUT', ()), ('UID', ('SEARCH', None, 'ALL')),
              ('UID', ('FETCH', '5', '(UID FLAGS INTERNALDATE RFC822.SIZE)')),
              ('UID', ('FETCH', '5', '(UID FLAGS INTERNALDATE BODY.PEEK[])'))]
        for name, args in ok:
            snap.check_command(name, args)
        bad = [('SELECT', ('INBOX',)), ('APPEND', ('INBOX',)), ('STORE', ('1', '+FLAGS', '(\\Deleted)')), ('EXPUNGE', ()),
               ('DELETE', ('INBOX',)), ('CREATE', ('x',)), ('COPY', ('1', 'x')), ('RENAME', ('a', 'b')),
               ('UID', ('STORE', '1', '+FLAGS', '(\\Seen)')), ('UID', ('COPY', '1', 'x')), ('UID', ('EXPUNGE', '1')),
               ('UID', ('FETCH', '5', '(BODY[])')), ('UID', ('FETCH', '5', '(RFC822)')),
               ('UID', ('FETCH', '5', '(UID BODY[HEADER])')), ('UID', ('FETCH', '5', '(BODY.PEEK[] FLAGS) STORE'))]
        for name, args in bad:
            with self.assertRaises(snap.ReadOnlyViolation, msg=(name, args)):
                snap.check_command(name, args)

    def test_class_actually_guards_the_wire_method(self):
        self.assertEqual(snap.ReadOnlyIMAP._command.__qualname__, 'ReadOnlyIMAP._command')
        with self.assertRaises(snap.ReadOnlyViolation):
            snap.ReadOnlyIMAP._command(object.__new__(snap.ReadOnlyIMAP), 'STORE', '1')


class SnapshotSecrets(unittest.TestCase):
    def test_secret_files_must_be_private_regular_files(self):
        with tempfile.TemporaryDirectory() as d:
            good = private(Path(d) / 'ok', 'secret\n')
            self.assertEqual(snap.read_secret(good), 'secret')
            loose = Path(d) / 'loose'; loose.write_text('x'); loose.chmod(0o644)
            with self.assertRaises(SystemExit): snap.read_secret(str(loose))
            link = Path(d) / 'link'; link.symlink_to(good)
            self.assertEqual(snap.read_secret(str(link)), 'secret')  # symlink to a private file is fine
            big = private(Path(d) / 'big', 'x' * 20000)
            with self.assertRaises(SystemExit): snap.read_secret(big)

    def test_xoauth2_string_and_error_challenge(self):
        self.assertEqual(snap.xoauth2_string('a@b', 'tok'), b'user=a@b\x01auth=Bearer tok\x01\x01')
        responder = snap.XOAuth2('a@b', 'tok')
        self.assertEqual(responder(b''), b'user=a@b\x01auth=Bearer tok\x01\x01')
        self.assertEqual(responder(b'{"status":"401"}'), b'')  # never resend the token

    def test_snapshot_files_are_private_and_hold_no_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 's.json'
            snap.write_private(str(out), {'version': 1, 'folders': {}})
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)


def message(uid, body, date='2020-01-02T03:04:05+00:00', flags=()):
    return {'uid': uid, 'size': len(body), 'declared_size': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'internaldate': date, 'flags': sorted(flags)}


def snapshot(**folders):
    return {'version': 1, 'folders': {n: {'uidvalidity': 7, 'uidnext': 99, 'messages': m} for n, m in folders.items()}}


class SnapshotCompare(unittest.TestCase):
    def test_same_detects_every_kind_of_source_change(self):
        a = snapshot(INBOX=[message(1, b'a'), message(2, b'b', flags=['\\Seen'])])
        self.assertEqual(snap.compare_same(a, json.loads(json.dumps(a))), [])
        cases = {
            'disappeared': snapshot(INBOX=[message(1, b'a')]),
            'appeared': snapshot(INBOX=[message(1, b'a'), message(2, b'b', flags=['\\Seen']), message(3, b'c')]),
            'sha256 changed': snapshot(INBOX=[message(1, b'A'), message(2, b'b', flags=['\\Seen'])]),
            'flags changed': snapshot(INBOX=[message(1, b'a'), message(2, b'b')]),
            'internaldate changed': snapshot(INBOX=[message(1, b'a', date='2021-01-01T00:00:00+00:00'), message(2, b'b', flags=['\\Seen'])]),
        }
        for word, after in cases.items():
            self.assertTrue(any(word in p for p in snap.compare_same(a, after)), word)
        moved = json.loads(json.dumps(a)); moved['folders']['INBOX']['uidvalidity'] = 8
        self.assertTrue(any('UIDVALIDITY' in p for p in snap.compare_same(a, moved)))

    def test_copy_requires_exact_multiplicity_dates_and_transferred_flags(self):
        twin = b'identical twin'
        source = snapshot(INBOX=[message(1, b'one', flags=['\\Seen', '$kw']), message(2, twin), message(3, twin)])
        good = snapshot(Dest=[message(9, b'one', flags=['\\Seen']), message(8, twin), message(7, twin)])
        problems, notes = snap.compare_copy(source, good, [('INBOX', 'Dest')])
        self.assertEqual(problems, [])
        self.assertTrue(any('custom keyword' in n for n in notes))
        merged = snapshot(Dest=[message(9, b'one', flags=['\\Seen']), message(8, twin)])  # provider de-duplicated
        problems, _ = snap.compare_copy(source, merged, [('INBOX', 'Dest')])
        self.assertTrue(any('missing' in p for p in problems))
        rebuilt = snapshot(Dest=[message(9, b'one', flags=['\\Seen']), message(8, twin), message(7, twin + b' ')])  # byte-rebuilt copy
        problems, _ = snap.compare_copy(source, rebuilt, [('INBOX', 'Dest')])
        self.assertTrue(any('extra' in p for p in problems) or any('missing' in p for p in problems))
        wrong = snapshot(Dest=[message(9, b'one', date='1999-12-31T23:59:58+00:00', flags=['\\Seen']), message(8, twin), message(7, twin)])
        problems, _ = snap.compare_copy(source, wrong, [('INBOX', 'Dest')])
        self.assertTrue(any('INTERNALDATE' in p for p in problems))
        flagless = snapshot(Dest=[message(9, b'one'), message(8, twin), message(7, twin)])
        problems, _ = snap.compare_copy(source, flagless, [('INBOX', 'Dest')])
        self.assertTrue(any('flags' in p for p in problems))
        extra = snapshot(Dest=good['folders']['Dest']['messages'] + [message(1, b'preexisting')])
        self.assertTrue(snap.compare_copy(source, extra, [('INBOX', 'Dest')])[0])
        self.assertEqual(snap.compare_copy(source, extra, [('INBOX', 'Dest')], allow_extra=True)[0], [])
        self.assertTrue(snap.compare_copy(source, good, [('INBOX', 'Nope')])[0])

    def test_deleted_and_recent_flags_are_not_compared(self):
        source = snapshot(A=[message(1, b'x', flags=['\\Seen', '\\Deleted', '\\Recent'])])
        dest = snapshot(A=[message(5, b'x', flags=['\\Seen'])])
        self.assertEqual(snap.compare_copy(source, dest, [('A', 'A')])[0], [])


class FakeProvider(http.server.BaseHTTPRequestHandler):
    """Loopback OAuth token endpoint that verifies PKCE and the client secret."""
    log = []

    def do_POST(self):  # noqa: N802
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode()).items()}
        type(self).log.append(form)
        server = self.server
        if form.get('grant_type') == 'authorization_code':
            expected = base64.urlsafe_b64encode(hashlib.sha256(form['code_verifier'].encode()).digest()).rstrip(b'=').decode()
            ok = form['code'] == 'AUTHCODE' and expected == server.challenge and form.get('client_secret') == 'CLIENT-SECRET'
            body = {'access_token': 'ACCESS-1', 'refresh_token': 'REFRESH-1', 'expires_in': 3599,
                    'scope': server.granted_scope} if ok else {'error': 'invalid_grant'}
        elif form.get('grant_type') == 'refresh_token':
            ok = form['refresh_token'] == server.valid_refresh
            body = {'access_token': f'ACCESS-{len(type(self).log)}', 'expires_in': 3599} if ok else {'error': 'invalid_grant'}
        else:
            ok, body = False, {'error': 'unsupported_grant_type'}
        data = json.dumps(body).encode()
        self.send_response(200 if ok else 400)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class OAuthFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.d = Path(self.tmp.name)
        self.provider = http.server.HTTPServer(('127.0.0.1', 0), FakeProvider)
        self.provider.valid_refresh = 'REFRESH-1'; self.provider.granted_scope = 'https://mail.google.com/'
        self.provider.challenge = None
        FakeProvider.log = []
        threading.Thread(target=self.provider.serve_forever, daemon=True).start()
        self.token_url = f'http://127.0.0.1:{self.provider.server_address[1]}/token'
        self.client = private(self.d / 'client.json', json.dumps({'installed': {'client_id': 'cid.apps.example', 'client_secret': 'CLIENT-SECRET'}}))

    def tearDown(self):
        self.provider.shutdown(); self.provider.server_close(); self.tmp.cleanup()

    def args(self, *extra, cmd='authorize'):
        return oauth.parser().parse_args([cmd, '--provider', 'google', '--client-json', self.client,
                                          '--refresh-token-file', str(self.d / 'refresh'), '--token-url', self.token_url, *extra])

    def browse(self, state_override=None, **extra):
        """Play the browser: read the printed URL, then hit the loopback redirect."""
        printed = []

        def announce(text):
            printed.append(text)
            match = next((w for w in text.split() if w.startswith('https://accounts.google.com')), None)
            if match is None:
                return
            query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(match).query))
            self.assertEqual((query['code_challenge_method'], query['access_type'], query['scope']), ('S256', 'offline', 'https://mail.google.com/'))
            self.assertNotIn('client_secret', query)
            self.provider.challenge = query['code_challenge']
            params = {'state': state_override or query['state'], **({'code': 'AUTHCODE'} if 'error' not in extra else {}), **extra}
            threading.Thread(target=lambda: urllib.request.urlopen(query['redirect_uri'] + '/?' + urllib.parse.urlencode(params)).read(), daemon=True).start()
        return announce, printed

    def test_authorize_stores_tokens_privately_and_never_prints_them(self):
        announce, printed = self.browse()
        args = self.args('--access-token-file', str(self.d / 'access'), '--login-hint', 'test@example.com')
        self.assertEqual(oauth.authorize(args, announce=announce, wait=20), 0)
        self.assertEqual((self.d / 'refresh').read_text(), 'REFRESH-1')
        self.assertEqual((self.d / 'access').read_text(), 'ACCESS-1')
        for name in ('refresh', 'access'):
            self.assertEqual(stat.S_IMODE((self.d / name).stat().st_mode), 0o600)
        blob = '\n'.join(printed)
        for secret in ('REFRESH-1', 'ACCESS-1', 'CLIENT-SECRET', 'AUTHCODE'):
            self.assertNotIn(secret, blob)

    def test_state_mismatch_error_and_scope_shortfall_save_nothing(self):
        announce, _ = self.browse(state_override='forged')
        with self.assertRaises(oauth.OAuthError): oauth.authorize(self.args(), announce=announce, wait=20)
        announce, _ = self.browse(error='access_denied')
        with self.assertRaises(oauth.OAuthError) as cm: oauth.authorize(self.args(), announce=announce, wait=20)
        self.assertIn('access_denied', str(cm.exception))
        self.provider.granted_scope = 'openid email'
        announce, _ = self.browse()
        with self.assertRaises(oauth.OAuthError) as cm: oauth.authorize(self.args(), announce=announce, wait=20)
        self.assertIn('scope', str(cm.exception))
        self.assertFalse((self.d / 'refresh').exists())

    def test_refresh_rotates_the_access_file_atomically_and_invalid_grant_is_final(self):
        private(self.d / 'refresh', 'REFRESH-1')
        args = self.args('--access-token-file', str(self.d / 'access'), cmd='refresh')
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(oauth.refresh(args, announce=print), 0)
        self.assertTrue((self.d / 'access').read_text().startswith('ACCESS-'))
        self.assertEqual(stat.S_IMODE((self.d / 'access').stat().st_mode), 0o600)
        self.assertNotIn('ACCESS-', out.getvalue())
        self.assertEqual([p.name for p in self.d.iterdir() if p.name.startswith('.token-')], [])
        self.provider.valid_refresh = 'something-else'
        before = (self.d / 'access').read_text()
        looping = self.args('--access-token-file', str(self.d / 'access'), '--loop', cmd='refresh')
        with self.assertRaises(oauth.OAuthError) as cm: oauth.refresh(looping, announce=lambda t: None, sleep=lambda s: None, iterations=3)
        self.assertIn('invalid_grant', str(cm.exception))
        self.assertEqual((self.d / 'access').read_text(), before, 'a failed refresh must keep the previous token')

    def test_loop_survives_transient_failure_and_keeps_old_token(self):
        private(self.d / 'refresh', 'REFRESH-1')
        args = self.args('--access-token-file', str(self.d / 'access'), '--loop', cmd='refresh')
        oauth.refresh_once(args)
        before = (self.d / 'access').read_text()
        args.token_url = 'http://127.0.0.1:9/unreachable'
        sleeps = []
        oauth.refresh(args, announce=lambda t: None, sleep=sleeps.append, iterations=2)
        self.assertEqual(sleeps, [60])
        self.assertEqual((self.d / 'access').read_text(), before)

    def test_endpoint_and_file_hardening(self):
        for url in ('http://accounts.example.com/token', 'ftp://127.0.0.1/x', 'http://localhost/x'):
            with self.assertRaises(oauth.OAuthError): oauth.check_url(url)
        oauth.check_url('https://oauth2.googleapis.com/token'); oauth.check_url('http://127.0.0.1:1/token')
        loose = self.d / 'loose.json'; loose.write_text('{}'); loose.chmod(0o644)
        with self.assertRaises(oauth.OAuthError): oauth.read_private(str(loose), 'client')
        private(self.d / 'web.json', json.dumps({'web': {'client_id': 'x'}}))
        args = oauth.parser().parse_args(['refresh', '--provider', 'google', '--client-json', str(self.d / 'web.json'),
                                          '--refresh-token-file', 'r', '--access-token-file', 'a'])
        with self.assertRaises(oauth.OAuthError): oauth.load_client(args)

    def test_main_reports_only_safe_error_codes(self):
        private(self.d / 'refresh', 'REFRESH-1'); self.provider.valid_refresh = 'x'
        err = io.StringIO()
        with redirect_stderr(err):
            code = oauth.main(['refresh', '--provider', 'google', '--client-json', self.client, '--refresh-token-file', str(self.d / 'refresh'),
                               '--access-token-file', str(self.d / 'access'), '--token-url', self.token_url])
        self.assertEqual(code, 1)
        self.assertIn('invalid_grant', err.getvalue())
        for secret in ('REFRESH-1', 'CLIENT-SECRET'):
            self.assertNotIn(secret, err.getvalue())


class LabTools(unittest.TestCase):
    def test_corpus_is_deterministic_synthetic_and_covers_the_guide(self):
        a, b = lab.corpus(), lab.corpus()
        self.assertEqual([(f, d, x, fl, t) for f, d, x, fl, t in a], [(f, d, x, fl, t) for f, d, x, fl, t in b])
        descriptions = ' | '.join(d for _, d, *_ in a)
        for needle in ('no Message-ID', 'UTF-8', 'bare LF', '8-bit', 'nested', 'inline', '1 MiB', 'duplicate A', 'duplicate B', '1999', 'flag combination', 'keyword', 'Unicode'):
            self.assertIn(needle, descriptions)
        twins = [x for _, d, x, *_ in a if d.startswith('duplicate')]
        self.assertEqual(len(twins), 2); self.assertEqual(twins[0], twins[1])
        self.assertEqual(len({hashlib.sha256(x).digest() for _, _, x, *_ in a}), len(a) - 1)
        for _, _, data, *_ in a:
            self.assertNotIn(b'@gmail.com', data); self.assertNotIn(b'@outlook', data)
        self.assertEqual(len(lab.corpus(include_large=True, oversize_bytes=5000)), len(a) + 2)

    def test_modified_utf7_folder_names(self):
        self.assertEqual(lab.utf7('INBOX'), 'INBOX')
        self.assertEqual(lab.utf7('A&B'), 'A&-B')
        self.assertEqual(lab.utf7('Éléments'), '&AMk-l&AOk-ments')

    def fake_lab(self, d, roles=('source', 'destination')):
        Path(d, 'password').write_text('lab-password')
        (Path(d) / 'lab.json').write_text(json.dumps({'version': 1, 'user': 'lab', 'containers': {r: f'{lab.PREFIX}{r}-test' for r in roles},
                                                      'ports': {r: 40000 + i for i, r in enumerate(roles)}}))

    def test_generated_configs_for_all_four_directions(self):
        with tempfile.TemporaryDirectory() as d:
            self.fake_lab(d)
            for direction, host, provider_side in [('gmail-to-dovecot', 'imap.gmail.com', 'source'), ('dovecot-to-gmail', 'imap.gmail.com', 'destination'),
                                                   ('m365-to-dovecot', 'outlook.office365.com', 'source'), ('dovecot-to-m365', 'outlook.office365.com', 'destination')]:
                out = Path(d) / f'{direction}.toml'
                with redirect_stdout(io.StringIO()):
                    lab.main(['config', '--dir', d, '--direction', direction, '--provider-user', 'disposable@example.test',
                              '--token-file', str(Path(d) / 'access.token'), '--state-dir', str(Path(d) / 'state'), '--out', str(out)])
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
                cfg = tomllib.loads(out.read_text())
                other = 'destination' if provider_side == 'source' else 'source'
                self.assertEqual((cfg[provider_side]['host'], cfg[provider_side]['port'], cfg[provider_side]['auth']), (host, 993, 'xoauth2'))
                self.assertIn('access_token_file', cfg[provider_side]); self.assertNotIn('password_file', cfg[provider_side])
                self.assertEqual(cfg[other]['host'], 'localhost'); self.assertEqual(cfg[other]['username'], 'lab')
                self.assertIn('password_file', cfg[other]); self.assertIn('ca_file', cfg[other])
                self.assertEqual(cfg['folders'], [{'source': 'INBOX', 'destination': 'INBOX'}])
                self.assertNotIn('lab-password', out.read_text())
                with self.assertRaises(SystemExit):  # refuses to overwrite
                    lab.main(['config', '--dir', d, '--direction', direction, '--provider-user', 'x', '--token-file', 't', '--state-dir', 's', '--out', str(out)])

    def test_config_needs_the_right_dovecot_role_and_teardown_never_touches_foreign_containers(self):
        with tempfile.TemporaryDirectory() as d:
            self.fake_lab(d, roles=('source',))
            with self.assertRaises(SystemExit):  # gmail-to-dovecot needs a destination Dovecot
                lab.main(['config', '--dir', d, '--direction', 'gmail-to-dovecot', '--provider-user', 'x', '--token-file', 't', '--state-dir', 's', '--out', str(Path(d) / 'c.toml')])
        calls = []
        real = lab.subprocess.run
        lab.subprocess.run = lambda args, **kw: calls.append(args)
        try:
            lab.teardown({'containers': {'a': 'someone-elses-database', 'b': lab.PREFIX + 'destination-1'}})
        finally:
            lab.subprocess.run = real
        self.assertEqual(calls, [['docker', 'rm', '-f', lab.PREFIX + 'destination-1']])

    def test_seed_refuses_a_lab_without_a_source(self):
        with tempfile.TemporaryDirectory() as d:
            self.fake_lab(d, roles=('destination',))
            with self.assertRaises(SystemExit): lab.main(['seed', '--dir', d])


if __name__ == '__main__':
    unittest.main()
