#!/usr/bin/env python3
"""Deterministic benchmark datasets. The same seed always yields byte-identical messages.

Profiles
  mixed      ~3,000 messages in 11 folders (nested, Unicode, empty): small/medium/attachment/large mail,
             8-bit and long-line bodies, messages without Message-ID, empty bodies, every common flag
             and some keywords, 2015-2024 dates in assorted time zones, and four kinds of
             duplicate-looking mail (see DUPLICATES below).
  scale-N    N small messages (2-6 KB) over INBOX and two folders, flags and dates, no special cases.

A dataset is a list of records: {folder, flags, date (aware datetime), body (bytes, CRLF)}, plus a
manifest of sha256 per record that the independent verifier compares against what the servers hold.

DUPLICATES (mixed profile), all in the manifest so the verifier can tell a faithful copy from a
silently dropped or a doubled message:
  exact      byte-identical message, same flags and date, twice in one folder (40 pairs)
  same-id    same Message-ID, different bodies (30 pairs)
  same-body  same bytes, different date and flags (30 pairs)
  cross      the same message in two folders (40 pairs)
"""
import base64
import datetime as dt
import hashlib
import random

WORDS = ('alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec '
         'romeo sierra tango uniform victor whiskey xray yankee zulu invoice meeting report budget schedule '
         'project review contract delivery shipment account password reset notification update summary').split()
FLAG_CHOICES = [[], [], ['\\Seen'], ['\\Seen'], ['\\Seen'], ['\\Seen', '\\Answered'], ['\\Flagged'], ['\\Seen', '\\Flagged'],
                ['\\Draft'], ['\\Seen', '$Forwarded'], ['$Label1'], ['\\Seen', 'Work'], ['\\Answered', '\\Flagged', '\\Seen']]
ZONES = [0, 3600, -28800, 19800, -18000, 32400, -3600, 7200]
FOLDERS_MIXED = {  # folder -> share of messages
    'INBOX': 30, 'Sent': 12, 'Drafts': 3, 'Work': 14, 'Work/Projects': 10, 'Work/Projects/2023/Q1': 8,
    'Archive/2019': 9, 'Archive/2020': 9, 'Archive/Résumé': 5, 'Empty': 0,
}


def lorem(rng, n):
    return ' '.join(rng.choice(WORDS) for _ in range(n))


def wrap(text, width=76):
    return '\r\n'.join(text[i:i + width] for i in range(0, len(text), width))


def rfc_date(d):
    return d.strftime('%a, %d %b %Y %H:%M:%S %z')


def build(rng, index, kind, when, with_id=True, subject_extra=''):
    """One RFC 822 message (CRLF) of a given kind."""
    subject = f'{lorem(rng, 4)} #{index}{subject_extra}'
    h = [f'From: {rng.choice(WORDS)}.{rng.choice(WORDS)}@example.org', f'To: {rng.choice(WORDS)}@example.net',
         f'Date: {rfc_date(when)}', f'Subject: {subject}']
    if with_id:
        h.append(f'Message-ID: <{index}.{rng.getrandbits(48):012x}@bench.example>')
    h.append('MIME-Version: 1.0')
    if kind == 'small':
        h += ['Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 7bit']
        body = wrap(lorem(rng, rng.randint(40, 400)))
    elif kind == 'medium':
        b = f'=_alt{rng.getrandbits(32):08x}'
        h += [f'Content-Type: multipart/alternative; boundary="{b}"']
        text = wrap(lorem(rng, rng.randint(3000, 9000)))
        body = (f'--{b}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n--{b}\r\n'
                f'Content-Type: text/html; charset=utf-8\r\n\r\n<html><body><p>{text.replace(chr(13) + chr(10), "</p><p>")}</p></body></html>\r\n--{b}--')
    elif kind == 'attachment':
        b = f'=_mix{rng.getrandbits(32):08x}'
        h += [f'Content-Type: multipart/mixed; boundary="{b}"']
        raw = rng.randbytes(rng.randint(150_000, 650_000))
        body = (f'--{b}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{wrap(lorem(rng, 80))}\r\n--{b}\r\n'
                f'Content-Type: application/octet-stream; name="file{index}.bin"\r\nContent-Disposition: attachment; filename="file{index}.bin"\r\n'
                f'Content-Transfer-Encoding: base64\r\n\r\n{wrap(base64.b64encode(raw).decode())}\r\n--{b}--')
    elif kind == 'large':
        b = f'=_big{rng.getrandbits(32):08x}'
        h += [f'Content-Type: multipart/mixed; boundary="{b}"']
        raw = rng.randbytes(rng.randint(2_500_000, 5_500_000))
        body = (f'--{b}\r\nContent-Type: text/plain\r\n\r\nlarge attachment follows\r\n--{b}\r\n'
                f'Content-Type: application/zip; name="archive{index}.zip"\r\nContent-Transfer-Encoding: base64\r\n\r\n{wrap(base64.b64encode(raw).decode())}\r\n--{b}--')
    elif kind == '8bit':
        h += ['Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit']
        body = wrap('Grüße aus Zürich — café, naïve, 日本語のテキスト, Привет мир. ' * rng.randint(2, 30))
    elif kind == 'longlines':
        h += ['Content-Type: text/plain; charset=utf-8']
        body = (lorem(rng, 400) + ' ') * 3 + 'X' * rng.randint(2000, 6000)
    elif kind == 'empty':
        h += ['Content-Type: text/plain']
        body = ''
    else:
        raise ValueError(kind)
    return ('\r\n'.join(h) + '\r\n\r\n' + body + '\r\n').encode('utf-8')


def rand_date(rng):
    base = dt.datetime(2015, 1, 1) + dt.timedelta(seconds=rng.randrange(0, 10 * 365 * 86400))
    return base.replace(tzinfo=dt.timezone(dt.timedelta(seconds=rng.choice(ZONES))))


def mixed(seed=20260101, total=3000):
    rng = random.Random(f'mixed-{seed}')
    shares = {f: s for f, s in FOLDERS_MIXED.items() if s}
    weight = sum(shares.values())
    kinds = (['small'] * 60 + ['medium'] * 23 + ['attachment'] * 10 + ['8bit'] * 2 + ['longlines'] * 2 + ['empty'] * 1 + ['large'] * 1)
    records, index = [], 0

    def add(folder, flags, when, body):
        records.append({'folder': folder, 'flags': flags, 'date': when, 'body': body})

    for folder, share in shares.items():
        for _ in range(round(total * share / weight)):
            index += 1
            kind = rng.choice(kinds)
            when = rand_date(rng)
            add(folder, list(rng.choice(FLAG_CHOICES)), when, build(rng, index, kind, when, with_id=rng.random() > 0.02))
    # a few \Deleted messages: IMAPLANE never copies that flag (documented difference); counted separately
    for i in range(30):
        r = records[rng.randrange(len(records))]
        if '\\Deleted' not in r['flags']:
            r['flags'] = sorted(set(r['flags']) | {'\\Deleted'})
    folders = list(shares)
    # DUPLICATES
    for _ in range(40):   # exact
        folder, when = rng.choice(folders), rand_date(rng); index += 1
        body, flags = build(rng, index, 'small', when), list(rng.choice(FLAG_CHOICES))
        add(folder, flags, when, body); add(folder, list(flags), when, body)
    for _ in range(30):   # same Message-ID, different bodies
        folder = rng.choice(folders); index += 1
        for variant in range(2):
            when = rand_date(rng)
            msg = build(rng, index, 'small', when).replace(b'Message-ID: <', b'Message-ID: <same.', 1)
            msg = msg.replace(b'@bench.example>', b'@dup.example>', 1)
            msg = msg.replace(b'Subject: ', f'Subject: v{variant} '.encode(), 1)
            ident = [l for l in msg.split(b'\r\n') if l.startswith(b'Message-ID:')][0]
            msg = msg.replace(ident, b'Message-ID: <shared-' + str(index).encode() + b'@dup.example>', 1)
            add(folder, list(rng.choice(FLAG_CHOICES)), when, msg)
    for _ in range(30):   # same body, different date and flags
        folder = rng.choice(folders); index += 1
        body = build(rng, index, 'small', rand_date(rng))
        add(folder, ['\\Seen'], rand_date(rng), body); add(folder, [], rand_date(rng), body)
    for _ in range(40):   # across folders
        a, b = rng.sample(folders, 2); index += 1
        when = rand_date(rng); body = build(rng, index, 'small', when); flags = list(rng.choice(FLAG_CHOICES))
        add(a, flags, when, body); add(b, list(flags), when, body)
    rng.shuffle(records)   # arrival order is not folder-grouped, like real delivery
    return records, list(FOLDERS_MIXED)


def scale(n, seed=20260101):
    rng = random.Random(f'scale-{n}-{seed}')
    folders = ['INBOX', 'Work', 'Archive/Old']
    records = []
    for i in range(n):
        when = rand_date(rng)
        records.append({'folder': folders[0] if i % 5 < 3 else folders[1 + (i % 5) - 3], 'flags': list(rng.choice(FLAG_CHOICES)), 'date': when,
                        'body': build(rng, i + 1, 'small', when)})
    return records, folders


def new_mail(n, folders, seed):
    """`n` fresh messages (never in the original dataset) for the incremental-with-new-mail steps."""
    rng = random.Random(f'new-{seed}')
    out = []
    for i in range(n):
        when = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(minutes=rng.randrange(0, 100000))
        kind = rng.choice(['small'] * 6 + ['medium'] * 3 + ['attachment'])
        out.append({'folder': rng.choice(folders[:4]), 'flags': list(rng.choice(FLAG_CHOICES)), 'date': when,
                    'body': build(rng, 900000 + seed * 10000 + i, kind, when)})
    return out


def profile(name, seed=20260101):
    if name == 'mixed':
        return mixed(seed)
    if name.startswith('scale-'):
        return scale(int(name.split('-', 1)[1]), seed)
    raise ValueError(name)


def manifest(records):
    """Comparable view: (folder, sha256 of bytes, normalized flags, internaldate epoch)."""
    return [(r['folder'], hashlib.sha256(r['body']).hexdigest(), tuple(sorted(r['flags'])), int(r['date'].timestamp())) for r in records]


if __name__ == '__main__':
    import sys
    recs, folders = profile(sys.argv[1] if len(sys.argv) > 1 else 'mixed')
    total = sum(len(r['body']) for r in recs)
    print(f'{len(recs)} messages, {total / 1e6:.1f} MB, folders {folders}')
    print('largest', max(len(r["body"]) for r in recs), 'smallest', min(len(r["body"]) for r in recs))
