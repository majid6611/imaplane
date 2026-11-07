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


if __name__ == '__main__':
    unittest.main()
