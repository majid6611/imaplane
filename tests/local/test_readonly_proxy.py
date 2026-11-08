"""Offline unit tests for scripts/readonly_imap_proxy.py: the command guard, the virtual-mailbox rewriting and the
XOAUTH2 username substitution. No network."""
import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import readonly_imap_proxy as p  # noqa: E402


def g(text, cut=1000):
    return p.guard(text.encode() + b'\r\n', cut)


class Guard(unittest.TestCase):
    def test_every_write_or_state_changing_command_is_refused(self):
        for cmd in ['APPEND INBOX {10}', 'STORE 1 +FLAGS (\\Seen)', 'UID STORE 1 +FLAGS (\\Deleted)', 'EXPUNGE', 'UID EXPUNGE 1',
                    'COPY 1 X', 'UID COPY 1 X', 'MOVE 1 X', 'UID MOVE 1 X', 'SELECT INBOX', 'CREATE X', 'DELETE X', 'RENAME A B',
                    'SUBSCRIBE X', 'UNSUBSCRIBE X', 'LOGIN u p', 'CLOSE', 'COMPRESS DEFLATE', 'IDLE', 'STARTTLS', 'SETMETADATA X',
                    'FETCH 1 (FLAGS)', 'SEARCH ALL', 'UID FOO 1']:
            ok, why = g('a1 ' + cmd)
            self.assertFalse(ok, cmd)
            self.assertTrue(why)

    def test_the_commands_imaplane_needs_are_allowed(self):
        for cmd in ['CAPABILITY', 'NOOP', 'LOGOUT', 'LIST "" "*"', 'EXAMINE "INBOX"', 'EXAMINE INBOX', 'UNSELECT',
                    'AUTHENTICATE XOAUTH2 abc', 'UID FETCH 1:* (UID)', 'UID FETCH 7 (UID RFC822.SIZE)',
                    'UID FETCH 7 (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[]<0.131072>)',
                    'UID FETCH 7 (UID FLAGS INTERNALDATE BODY.PEEK[])', 'UID SEARCH ALL', 'ENABLE UTF8=ACCEPT', 'ID NIL']:
            self.assertTrue(g('a1 ' + cmd)[0], cmd)

    def test_fetch_items_that_would_mark_a_message_read_are_refused(self):
        for items in ['(BODY[])', '(UID BODY[1])', '(RFC822)', '(UID RFC822.TEXT)', '(BINARY[1])', '(body[])']:
            self.assertFalse(g('a1 UID FETCH 5 ' + items)[0], items)
        for items in ['(UID RFC822.SIZE)', '(BODY.PEEK[HEADER])', '(UID FLAGS INTERNALDATE)']:
            self.assertTrue(g('a1 UID FETCH 5 ' + items)[0], items)

    def test_only_inbox_and_only_uids_inside_the_slice(self):
        self.assertFalse(g('a1 EXAMINE "[Gmail]/All Mail"')[0])
        self.assertFalse(g('a1 EXAMINE {5}')[0])
        self.assertFalse(g('a1 UID FETCH 1001 (UID)', cut=1000)[0])
        self.assertFalse(g('a1 UID FETCH 5,1001:1010 (UID)', cut=1000)[0])
        self.assertTrue(g('a1 UID FETCH 1000 (UID)', cut=1000)[0])
        self.assertTrue(g('a1 UID FETCH 1001:* (UID)', cut=1000)[0])   # a range to the end is filtered, not refused

    def test_only_xoauth2_authentication(self):
        self.assertFalse(g('a1 AUTHENTICATE PLAIN abc')[0])
        self.assertFalse(p.guard(b'garbage\r\n', 1)[0])


class Rewrite(unittest.TestCase):
    def setUp(self):
        self.sl = p.Slice([5, 9, 12, 40, 41, 80], 4)     # virtual mailbox: UIDs 5, 9, 12, 40

    def test_slice(self):
        self.assertEqual((self.sl.cut, self.sl.exists), (40, 4))

    def test_exists_uidnext_and_inventory(self):
        self.assertEqual(p.rewrite_server_line(b'* 6 EXISTS\r\n', self.sl), b'* 4 EXISTS\r\n')
        self.assertEqual(p.rewrite_server_line(b'* OK [UIDNEXT 99] Predicted next UID.\r\n', self.sl), b'* OK [UIDNEXT 41] Predicted next UID.\r\n')
        self.assertEqual(p.rewrite_server_line(b'* 3 FETCH (UID 12)\r\n', self.sl), b'* 3 FETCH (UID 12)\r\n')
        self.assertIsNone(p.rewrite_server_line(b'* 5 FETCH (UID 41)\r\n', self.sl))
        self.assertIsNone(p.rewrite_server_line(b'* 6 FETCH (UID 80)\r\n', self.sl))
        self.assertEqual(p.rewrite_server_line(b'* SEARCH 5 9 41 80\r\n', self.sl), b'* SEARCH 5 9\r\n')
        self.assertEqual(p.rewrite_server_line(b'* SEARCH\r\n', self.sl), b'* SEARCH\r\n')
        # other lines, and full FETCH responses of an allowed message, pass untouched
        for line in [b'* OK [UIDVALIDITY 1] x\r\n', b'* 3 FETCH (UID 12 RFC822.SIZE 10)\r\n', b'* FLAGS (\\Seen)\r\n']:
            self.assertEqual(p.rewrite_server_line(line, self.sl), line)

    def test_xoauth2_username_substitution_keeps_the_token_and_ignores_other_lines(self):
        raw = b'user=placeholder\x01auth=Bearer TOKEN123\x01\x01'
        out = base64.b64decode(p.rewrite_auth(base64.b64encode(raw), 'real@example.test'))
        self.assertEqual(out, b'user=real@example.test\x01auth=Bearer TOKEN123\x01\x01')
        self.assertEqual(p.rewrite_auth(b'', 'x'), b'')
        self.assertEqual(p.rewrite_auth(b'!!notbase64!!', 'x'), b'!!notbase64!!')
        self.assertEqual(p.rewrite_auth(base64.b64encode(b'something else'), 'x'), base64.b64encode(b'something else'))




class Confined(unittest.TestCase):
    F = 'IMAPLANE-Test'

    def c(self, text):
        return p.guard(text.encode() + b'\r\n', 0, self.F)

    def test_only_the_one_mailbox_can_be_created_selected_or_appended_to(self):
        for ok in ['CREATE "IMAPLANE-Test"', 'SELECT "IMAPLANE-Test"', 'EXAMINE "IMAPLANE-Test"', 'STATUS "IMAPLANE-Test" (MESSAGES)',
                   'APPEND "IMAPLANE-Test" (\\Seen) "02-Jan-2020 03:04:05 +0000" {120}', 'APPEND "IMAPLANE-Test" {5}', 'CLOSE',
                   'LIST "" "*"', 'UID FETCH 1:* (UID)', 'UID FETCH 3 (UID FLAGS INTERNALDATE BODY.PEEK[])', 'UID SEARCH ALL', 'LOGOUT']:
            self.assertTrue(self.c('a1 ' + ok)[0], ok)
        for bad in ['CREATE "Other"', 'SELECT INBOX', 'EXAMINE "[Gmail]/All Mail"', 'STATUS INBOX (MESSAGES)', 'APPEND "INBOX" {5}',
                    'APPEND "IMAPLANE-Test" {5+}', 'APPEND IMAPLANE-Test2 {5}', 'DELETE "IMAPLANE-Test"', 'RENAME "IMAPLANE-Test" X',
                    'STORE 1 +FLAGS (\\Deleted)', 'UID STORE 1 +FLAGS (\\Deleted)', 'EXPUNGE', 'UID EXPUNGE 1', 'COPY 1 "IMAPLANE-Test"',
                    'UID COPY 1 "IMAPLANE-Test"', 'MOVE 1 X', 'UID MOVE 1 X', 'LOGIN u p', 'SUBSCRIBE "IMAPLANE-Test"', 'SELECT {13}',
                    'UID FETCH 1 (BODY[])', 'UID FETCH 1 (RFC822)', 'SETACL x y z', 'COMPRESS DEFLATE']:
            self.assertFalse(self.c('a1 ' + bad)[0], bad)


class ConfinedTwoFolders(unittest.TestCase):
    def test_two_confined_folders(self):
        g = lambda t: p.guard(t.encode() + b'\r\n', 0, ['Exp-A', 'Exp-B'])
        for ok in ['CREATE "Exp-A"', 'CREATE "Exp-B"', 'APPEND "Exp-B" {5}', 'EXAMINE "Exp-A"']:
            self.assertTrue(g('a1 ' + ok)[0], ok)
        for bad in ['CREATE "Exp-C"', 'APPEND "IMAPLANE-Test" {5}', 'APPEND "INBOX" {5}', 'EXAMINE INBOX']:
            self.assertFalse(g('a1 ' + bad)[0], bad)


class ConfinedReadOnlyExtras(unittest.TestCase):
    def test_extra_readonly_folders_can_only_be_examined(self):
        g = lambda t: p.guard(t.encode() + b'\r\n', 0, 'IMAPLANE-Test', ['[Gmail]/All Mail'])
        self.assertTrue(g('a1 EXAMINE "[Gmail]/All Mail"')[0])
        self.assertTrue(g('a1 STATUS "[Gmail]/All Mail" (MESSAGES)')[0])
        self.assertFalse(g('a1 SELECT "[Gmail]/All Mail"')[0])
        self.assertFalse(g('a1 APPEND "[Gmail]/All Mail" {3}')[0])
        self.assertFalse(g('a1 EXAMINE INBOX')[0])
        self.assertTrue(g('a1 UID FETCH 1:* (UID X-GM-MSGID X-GM-THRID X-GM-LABELS FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')[0])


class ProxyEndToEnd(unittest.TestCase):
    """The real proxy in confined-write mode against a fake TLS upstream: exact literal bytes, the APPEND cap, refused
    commands that never reach the upstream, and the username substitution."""

    def test_confined_proxy(self):
        import os, shutil, socket, ssl, subprocess, tempfile, threading, json
        if not shutil.which('openssl'):
            self.skipTest('openssl is not available')
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(t / 'k.pem'), '-out', str(t / 'c.pem'),
                            '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                           check=True, capture_output=True)
            seen, appended = [], []
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(t / 'c.pem', t / 'k.pem')
            lst = socket.socket(); lst.bind(('127.0.0.1', 0)); lst.listen(4)

            def upstream():
                while True:
                    try:
                        raw, _ = lst.accept()
                    except OSError:
                        return
                    try:
                        c = sctx.wrap_socket(raw, server_side=True); f = c.makefile('rb')
                        c.sendall(b'* OK fake\r\n')
                        while True:
                            line = f.readline()
                            if not line:
                                break
                            seen.append(line)
                            tag, verb = (line.rstrip(b'\r\n').split(b' ') + [b''])[:2]
                            if verb == b'APPEND':
                                n = int(line.strip().rsplit(b'{', 1)[1][:-1])
                                c.sendall(b'+ go\r\n')
                                body = f.read(n); f.readline()
                                appended.append(body)
                                c.sendall(tag + b' OK [APPENDUID 1 %d] done\r\n' % len(appended))
                            elif verb == b'LOGOUT':
                                c.sendall(b'* BYE\r\n' + tag + b' OK bye\r\n'); break
                            else:
                                c.sendall(tag + b' OK done\r\n')
                    except (OSError, ssl.SSLError):
                        pass
            threading.Thread(target=upstream, daemon=True).start()
            os.environ['IMAP_PROXY_USER'] = 'real@example.test'
            ready = t / 'ready'
            argv = ['--upstream', 'localhost', '--upstream-port', str(lst.getsockname()[1]), '--upstream-ca', str(t / 'c.pem'), '--cert', str(t / 'c.pem'),
                    '--key', str(t / 'k.pem'), '--confine-folder', 'IMAPLANE-Test', '--max-appends', '2', '--summary', str(t / 's.json'), '--ready-file', str(ready)]
            threading.Thread(target=p.main, args=(argv,), daemon=True).start()
            for _ in range(100):
                if ready.exists() and ready.read_text():
                    break
                import time; time.sleep(0.05)
            port = int(ready.read_text())
            cctx = ssl.create_default_context(cafile=str(t / 'c.pem'))
            c = cctx.wrap_socket(socket.create_connection(('127.0.0.1', port)), server_hostname='localhost'); f = c.makefile('rb')
            f.readline()

            def cmd(text):
                c.sendall(text.encode() + b'\r\n'); return f.readline()

            auth = base64.b64encode(b'user=placeholder\x01auth=Bearer T0K\x01\x01').decode()
            self.assertIn(b'OK', cmd(f'a0 AUTHENTICATE XOAUTH2 {auth}'))
            sent = [l for l in seen if l.startswith(b'a0 AUTHENTICATE')][0].split(b' ')[3]
            self.assertEqual(base64.b64decode(sent), b'user=real@example.test\x01auth=Bearer T0K\x01\x01')
            self.assertIn(b'OK', cmd('a1 CREATE "IMAPLANE-Test"'))
            literal = b'Subject: x\r\n\r\nbinary \x00\xff\r\n\r\nend'
            for i, tag in enumerate(['a2', 'a3']):
                c.sendall(f'{tag} APPEND "IMAPLANE-Test" (\\Seen) "02-Jan-2020 03:04:05 +0000" {{{len(literal)}}}\r\n'.encode())
                self.assertTrue(f.readline().startswith(b'+'))
                c.sendall(literal + b'\r\n')
                self.assertIn(b'APPENDUID', f.readline())
            self.assertEqual(appended, [literal, literal])
            # the third APPEND is over the cap; writes elsewhere and every destructive command are refused and never forwarded
            before = len(seen)
            for text in ['a4 APPEND "IMAPLANE-Test" {3}', 'a5 APPEND "INBOX" {3}', 'a6 STORE 1 +FLAGS (\\Deleted)', 'a7 EXPUNGE',
                         'a8 DELETE "IMAPLANE-Test"', 'a9 SELECT INBOX', 'b1 UID STORE 1 +FLAGS (\\Seen)', 'b2 UID COPY 1 INBOX']:
                self.assertIn(b'BAD proxy', cmd(text), text)
            self.assertEqual(len(seen), before, 'a refused command reached the upstream')
            self.assertEqual(len(appended), 2)
            self.assertIn(b'BYE', cmd('z LOGOUT'))
            c.close()


if __name__ == '__main__':
    unittest.main()
