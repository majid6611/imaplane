#!/usr/bin/env python3
"""Controlled Gmail de-duplication experiments E0-E5 (Python standard library only).

Talks ONLY to a confined-write guard proxy (scripts/readonly_imap_proxy.py --confine-folder A --confine-folder B
--readonly-folder "[Gmail]/All Mail" --max-appends 12), which refuses everything except CREATE/EXAMINE/APPEND on the two
experiment labels, EXAMINE of All Mail, searches and PEEK fetches. At most 11 tiny synthetic messages are appended; an APPEND is
never retried. After every step it records, for both labels and for All Mail, UIDVALIDITY/UIDNEXT/message counts and per message the
UID, X-GM-MSGID, X-GM-THRID, flags, INTERNALDATE, size, labels and the SHA-256 of the exact bytes. Nothing is deleted or changed.

  gmail_dedup_experiments.py --port P --label-a NAME --label-b NAME --token-file F --out DIR
"""
import argparse
import hashlib
import imaplib
import json
import os
import re
import ssl
import sys
import time
import datetime as dt

ALL_MAIL = '[Gmail]/All Mail'
MAX_APPENDS = 11


def build(message_id, body, date, subject='IMAPLANE dedup experiment'):
    head = []
    if message_id is not None:
        head.append(f'Message-ID: {message_id}')
    head += ['From: IMAPLANE Synthetic <synthetic.sender@example.invalid>', 'To: Test <recipient@example.invalid>',
             f'Subject: {subject}', f'Date: {date.strftime("%a, %d %b %Y %H:%M:%S +0000")}', 'MIME-Version: 1.0',
             'Content-Type: text/plain; charset=utf-8', '']
    return ('\r\n'.join(head) + '\r\n' + body + '\r\n').encode()


def D(y, m, d):
    return dt.datetime(y, m, d, 12, 0, 0, tzinfo=dt.timezone.utc)


class Session:
    def __init__(self, port, token):
        ctx = ssl.create_default_context(cafile=os.path.expanduser('~/.config/imaplane/gmail-test/proxy.crt'))
        self.c = imaplib.IMAP4_SSL('localhost', port, ssl_context=ctx, timeout=60)
        self.c.authenticate('XOAUTH2', lambda _: f'user=experimenter\x01auth=Bearer {token}\x01\x01'.encode())

    def examine(self, folder):
        typ, _ = self.c.select(f'"{folder}"', readonly=True)       # imaplib sends EXAMINE for readonly=True
        assert typ == 'OK', (folder, typ)
        info = {}
        for k in ('EXISTS', 'UIDVALIDITY', 'UIDNEXT', 'HIGHESTMODSEQ'):
            r = self.c.response(k)[1]
            info[k] = r[0].decode() if r and r[0] else None
        return info

    def fetch_rows(self, uids):
        rows = []
        for u in uids:
            u = u.decode() if isinstance(u, bytes) else str(u)
            typ, r = self.c.uid('fetch', u, '(FLAGS INTERNALDATE RFC822.SIZE MODSEQ X-GM-MSGID X-GM-THRID X-GM-LABELS BODY.PEEK[])')
            meta = r[0][0].decode(); raw = r[0][1]
            g = lambda pat: (re.search(pat, meta) or [None, None])[1]
            hdr = raw.split(b'\r\n\r\n', 1)[0].decode(errors='replace')
            mid = re.search(r'(?im)^message-id:\s*(.*)$', hdr)
            labels = re.search(r'X-GM-LABELS \((.*?)\)', meta)
            rows.append(dict(uid=int(u), msgid=g(r'X-GM-MSGID (\d+)'), thrid=g(r'X-GM-THRID (\d+)'), modseq=g(r'MODSEQ \((\d+)\)'),
                             flags=g(r'FLAGS \(([^)]*)\)'), internaldate=g(r'INTERNALDATE "([^"]+)"'), size=int(g(r'RFC822.SIZE (\d+)')),
                             labels=labels.group(1) if labels else '', message_id=mid.group(1).strip() if mid else None,
                             sha256=hashlib.sha256(raw).hexdigest()))
        return rows

    def label_view(self, folder):
        info = self.examine(folder)
        typ, x = self.c.uid('search', None, 'ALL')
        return {'info': info, 'messages': self.fetch_rows(x[0].split())}

    def search_all_mail(self, ids):
        out = {}
        self.examine(ALL_MAIL)
        for mid in ids:
            needle = mid.strip('<>')
            typ, x = self.c.uid('search', None, 'X-GM-RAW', f'"rfc822msgid:{needle}"')
            out[mid] = self.fetch_rows(x[0].split())
        return out

    def append(self, folder, flags, date, raw):
        typ, data = self.c.append(f'"{folder}"', f'({flags})' if flags else None, imaplib.Time2Internaldate(date.timestamp()), raw)
        return typ, [d.decode() if isinstance(d, bytes) else str(d) for d in data]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--label-a', required=True)
    ap.add_argument('--label-b', required=True)
    ap.add_argument('--token-file', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--resume-after-e0', action='store_true', help='labels and E0 already exist from an interrupted run (1 APPEND done)')
    a = ap.parse_args()
    A, B = a.label_a, a.label_b
    os.makedirs(a.out, mode=0o700, exist_ok=True)
    token = open(a.token_file).read().strip()
    s = Session(a.port, token)
    log = open(os.path.join(a.out, 'steps.jsonl'), 'a', buffering=1)
    os.chmod(os.path.join(a.out, 'steps.jsonl'), 0o600)
    typ, boxes = s.c.list()
    existing = [b.decode() for b in boxes]
    present = any(f'"{A}"' in b or f'"{B}"' in b for b in existing)
    if present and not a.resume_after_e0:
        sys.exit('REFUSED: an experiment label already exists; will not write into pre-existing labels')
    if not present:
        if a.resume_after_e0:
            sys.exit('REFUSED: --resume-after-e0 but the labels do not exist')
        for name in (A, B):
            typ, _ = s.c.create(f'"{name}"'); assert typ == 'OK'
    appended = ['E0 control (done in the interrupted run)'] if a.resume_after_e0 else []
    ids_seen = ['<exp-0@example.invalid>'] if a.resume_after_e0 else []

    def snapshot(step, extra=None):
        snap = {'step': step, 'time': time.time(), 'A': s.label_view(A), 'B': s.label_view(B), 'allmail_info': s.examine(ALL_MAIL),
                'allmail_by_message_id': s.search_all_mail(ids_seen)}
        if extra:
            snap.update(extra)
        log.write(json.dumps(snap) + '\n')
        return snap

    def do(step, folder, flags, date, message_id, body, subject='IMAPLANE dedup experiment', raw=None):
        assert len(appended) < MAX_APPENDS, 'append budget reached'
        raw = raw if raw is not None else build(message_id, body, date, subject)
        if message_id is not None and message_id not in ids_seen:
            ids_seen.append(message_id)
        t0 = time.time()
        typ, resp = s.append(folder, flags, date, raw)           # never retried
        appended.append(step)
        # E5: how soon does a Message-ID search find what was just appended?
        t_hit, hits = None, []
        if message_id is not None:
            for _ in range(60):
                found = s.search_all_mail([message_id])[message_id]
                if found:
                    t_hit, hits = time.time() - t0, found; break
                time.sleep(0.25)
        snapshot(step, {'appended_to': folder, 'append_response': resp, 'append_ok': typ, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'flags_sent': flags, 'internaldate_sent': date.isoformat(), 'message_id_sent': message_id,
                        'search_first_hit_s': t_hit, 'n_appended_so_far': len(appended)})
        print(f'{step}: {typ} {resp}  search-hit-after={t_hit if t_hit is None else round(t_hit, 2)}s', flush=True)

    if a.resume_after_e0:
        snapshot('RESUME: state after E0 (its APPEND response was lost when the first run stopped)')
    else:
        snapshot('S0 after CREATE of both labels')
        do('E0 control', A, '\\Seen', D(2020, 1, 1), '<exp-0@example.invalid>', 'control message')
    m1 = build('<exp-1@example.invalid>', 'identical bytes test', D(2020, 2, 1))
    do('E1a identical bytes -> A (Seen Flagged)', A, '\\Seen \\Flagged', D(2020, 2, 1), '<exp-1@example.invalid>', None, raw=m1)
    do('E1b identical bytes -> B (Answered, other date)', B, '\\Answered', D(2020, 3, 1), '<exp-1@example.invalid>', None, raw=m1)
    do('E2a same-ID different body -> A (first)', A, '\\Seen', D(2020, 4, 1), '<exp-2@example.invalid>', 'ALPHA body of the first message')
    do('E2b same-ID different body -> A (second)', A, '\\Flagged', D(2020, 5, 1), '<exp-2@example.invalid>', 'BRAVO a different body in the second message')
    do('E3a same-ID different body -> A (first)', A, '\\Seen', D(2020, 6, 1), '<exp-3@example.invalid>', 'ALPHA3 body in label A')
    do('E3b same-ID different body -> B (second)', B, '\\Draft', D(2020, 7, 1), '<exp-3@example.invalid>', 'BRAVO3 different body in label B')
    do('E4a Message-ID original', A, '\\Seen', D(2020, 8, 1), '<exp-4@example.invalid>', 'variant v1')
    do('E4b Message-ID upper-case variant, different body', A, '\\Flagged', D(2020, 9, 1), '<EXP-4@EXAMPLE.INVALID>', 'variant v2 (case differs)')
    do('E4c Message-ID without angle brackets, different body', A, '\\Answered', D(2020, 10, 1), 'exp-4@example.invalid', 'variant v3 (no angle brackets)')
    do('E4d no Message-ID header', A, '\\Seen', D(2020, 11, 1), None, 'a message without any Message-ID')
    final = snapshot('FINAL')
    print('appends performed:', len(appended), '(hard cap 12)')
    json.dump({'appended_steps': appended, 'count': len(appended)}, open(os.path.join(a.out, 'summary.json'), 'w'))
    s.c.logout()


if __name__ == '__main__':
    main()
