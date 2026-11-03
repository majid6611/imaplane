#!/usr/bin/env python3
"""Independent, read-only IMAP snapshot and comparison helper (Python stdlib only).

It deliberately shares no code with IMAPLANE so that it can check IMAPLANE's work.

  imap_snapshot.py list     ...connection...               list folder names
  imap_snapshot.py capture  ...connection... --folder F... --out FILE
  imap_snapshot.py same     BEFORE.json AFTER.json         source must be unchanged
  imap_snapshot.py copy     SOURCE.json DEST.json --map SRC=DST ...

Connection: --host H [--port 993] --user U (--password-file F | --token-file F)
[--ca-file F]. Secrets are read from 0600/0400 files, never from argv or the
environment, and are never printed or written to snapshots.

Read-only by construction: only CAPABILITY, AUTHENTICATE, LOGIN, LIST, EXAMINE,
NOOP, LOGOUT and UID SEARCH/FETCH are possible, and FETCH may use only BODY.PEEK.
Snapshots contain UIDs, sizes, SHA-256 digests, dates, flags and folder names; they
hold no message text but are still sensitive. Created files are mode 0600.

Exit status: 0 success / identical, 1 difference found, 2 usage or connection error.
"""
import argparse
import collections
import datetime as dt
import hashlib
import imaplib
import json
import os
import re
import ssl
import stat
import sys
import tempfile

SNAPSHOT_VERSION = 1
MAX_SECRET_BYTES = 16384
# Flags IMAPLANE transfers; \Recent is session-only and \Deleted is omitted on purpose.
COMPARED_FLAGS = {'\\seen', '\\answered', '\\flagged', '\\draft'}
ALLOWED_COMMANDS = {'CAPABILITY', 'AUTHENTICATE', 'LOGIN', 'LIST', 'EXAMINE', 'NOOP', 'LOGOUT', 'UID'}
ALLOWED_UID_SUBCOMMANDS = {'SEARCH', 'FETCH'}
FETCH_ITEMS = re.compile(r'^\((?:UID|FLAGS|INTERNALDATE|RFC822\.SIZE|BODY\.PEEK\[\])(?: (?:UID|FLAGS|INTERNALDATE|RFC822\.SIZE|BODY\.PEEK\[\]))*\)$')


class ReadOnlyViolation(Exception):
    pass


def check_command(name, args):
    """Raise unless this exact command is one a read-only snapshot may send."""
    name = name.upper()
    if name not in ALLOWED_COMMANDS:
        raise ReadOnlyViolation(f'command {name} is not allowed')
    if name == 'UID':
        sub = str(args[0]).upper() if args else ''
        if sub not in ALLOWED_UID_SUBCOMMANDS:
            raise ReadOnlyViolation(f'UID {sub} is not allowed')
        if sub == 'FETCH' and not FETCH_ITEMS.match(str(args[-1])):
            raise ReadOnlyViolation('FETCH items must be non-mutating (BODY.PEEK only)')


class ReadOnlyIMAP(imaplib.IMAP4_SSL):
    def _command(self, name, *args):
        check_command(name, args)
        return super()._command(name, *args)


def read_secret(path):
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.getuid():
        raise SystemExit(f'{path}: secret files must be regular, owned by you and mode 0600/0400')
    with open(path, 'rb') as f:
        data = f.read(MAX_SECRET_BYTES + 1)
    if len(data) > MAX_SECRET_BYTES:
        raise SystemExit(f'{path}: too large for a secret')
    return data.decode('utf-8').strip('\r\n')


def xoauth2_string(user, token):
    return f'user={user}\x01auth=Bearer {token}\x01\x01'.encode()


class XOAuth2:
    """One-shot SASL responder. A Google JSON error challenge gets an EMPTY reply."""
    def __init__(self, user, token):
        self.user, self.token, self.sent = user, token, False

    def __call__(self, challenge):
        if self.sent:
            return b''
        self.sent = True
        return xoauth2_string(self.user, self.token)


def connect(args):
    context = ssl.create_default_context(cafile=args.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    conn = ReadOnlyIMAP(args.host, args.port, ssl_context=context, timeout=args.timeout)
    if args.token_file:
        conn.authenticate('XOAUTH2', XOAuth2(args.user, read_secret(args.token_file)))
    else:
        conn.login(args.user, read_secret(args.password_file))
    return conn


def quote(name):
    return '"' + name.replace('\\', '\\\\').replace('"', '\\"') + '"'


def parse_flags(text):
    m = re.search(rb'FLAGS \(([^)]*)\)', text)
    return sorted(f for f in (m.group(1).decode('ascii', 'replace').split() if m else []) if f.lower() != '\\recent')


def internaldate(text):
    m = re.search(rb'INTERNALDATE "([^"]+)"', text)
    if not m:
        return None
    parsed = imaplib.Internaldate2tuple(b'INTERNALDATE "' + m.group(1) + b'"')
    return dt.datetime(*parsed[:6], tzinfo=dt.timezone.utc).isoformat() if parsed else None


def capture_folder(conn, name, max_bytes):
    typ, _ = conn.select(quote(name), readonly=True)  # EXAMINE
    if typ != 'OK':
        raise SystemExit(f'cannot EXAMINE {name!r}')
    validity = int(conn.response('UIDVALIDITY')[1][0])
    nxt = conn.response('UIDNEXT')[1][0]
    typ, data = conn.uid('SEARCH', None, 'ALL')
    uids = [int(u) for u in data[0].split()] if typ == 'OK' and data and data[0] else []
    messages = []
    for uid in uids:
        typ, parts = conn.uid('FETCH', str(uid), '(UID FLAGS INTERNALDATE RFC822.SIZE)')
        meta = next((p for p in parts if isinstance(p, bytes)), b'')
        m = re.search(rb'RFC822\.SIZE (\d+)', meta)
        declared = int(m.group(1)) if m else None
        if declared is not None and declared > max_bytes:
            raise SystemExit(f'{name!r} UID {uid}: {declared} bytes exceeds --max-message-bytes')
        typ, parts = conn.uid('FETCH', str(uid), '(UID FLAGS INTERNALDATE BODY.PEEK[])')
        if typ != 'OK':
            raise SystemExit(f'{name!r} UID {uid}: fetch failed')
        head, body = next(p for p in parts if isinstance(p, tuple))
        messages.append({'uid': uid, 'size': len(body), 'declared_size': declared,
                         'sha256': hashlib.sha256(body).hexdigest(),
                         'internaldate': internaldate(head), 'flags': parse_flags(head)})
    return {'uidvalidity': validity, 'uidnext': int(nxt) if nxt else None, 'messages': messages}


def write_private(path, obj):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.snapshot-')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(obj, f, indent=1, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load(path):
    with open(path) as f:
        snap = json.load(f)
    if snap.get('version') != SNAPSHOT_VERSION:
        raise SystemExit(f'{path}: unsupported snapshot version')
    return snap


def compared_flags(flags):
    return sorted(f for f in flags if f.lower() in COMPARED_FLAGS)


def compare_same(before, after):
    """The source must be byte-for-byte and metadata-identical. Returns difference strings."""
    problems = []
    for name in sorted(set(before['folders']) | set(after['folders'])):
        a, b = before['folders'].get(name), after['folders'].get(name)
        if a is None or b is None:
            problems.append(f'{name!r}: present in only one snapshot')
            continue
        if a['uidvalidity'] != b['uidvalidity']:
            problems.append(f'{name!r}: UIDVALIDITY {a["uidvalidity"]} -> {b["uidvalidity"]}')
        ua, ub = {m['uid']: m for m in a['messages']}, {m['uid']: m for m in b['messages']}
        for uid in sorted(set(ua) - set(ub)):
            problems.append(f'{name!r}: UID {uid} disappeared')
        for uid in sorted(set(ub) - set(ua)):
            problems.append(f'{name!r}: UID {uid} appeared')
        for uid in sorted(set(ua) & set(ub)):
            for field in ('sha256', 'internaldate', 'flags'):
                if ua[uid][field] != ub[uid][field]:
                    problems.append(f'{name!r}: UID {uid} {field} changed')
    return problems


def compare_copy(source, dest, mapping, allow_extra=False):
    """Every source message must exist at the destination with the same multiplicity,
    INTERNALDATE and transferred flags. Returns (problems, notes)."""
    problems, notes = [], []
    for src, dst in mapping:
        s, d = source['folders'].get(src), dest['folders'].get(dst)
        if s is None or d is None:
            problems.append(f'{src!r} -> {dst!r}: folder missing from a snapshot')
            continue
        groups_s, groups_d = collections.defaultdict(list), collections.defaultdict(list)
        for m in s['messages']:
            groups_s[m['sha256']].append(m)
        for m in d['messages']:
            groups_d[m['sha256']].append(m)
        for digest in sorted(set(groups_s) | set(groups_d)):
            ms, md = groups_s.get(digest, []), groups_d.get(digest, [])
            label = f'{src!r} -> {dst!r} sha256 {digest[:12]}'
            if len(ms) > len(md):
                problems.append(f'{label}: {len(ms) - len(md)} copy(ies) missing (source has {len(ms)}, destination {len(md)})')
            elif len(md) > len(ms):
                (notes if allow_extra else problems).append(f'{label}: destination has {len(md) - len(ms)} extra copy(ies)')
            key = lambda m: (m['internaldate'] or '', compared_flags(m['flags']))
            for a, b in zip(sorted(ms, key=key), sorted(md, key=key)):
                if a['internaldate'] != b['internaldate']:
                    problems.append(f'{label}: INTERNALDATE {a["internaldate"]} != {b["internaldate"]}')
                if compared_flags(a['flags']) != compared_flags(b['flags']):
                    problems.append(f'{label}: flags {compared_flags(a["flags"])} != {compared_flags(b["flags"])}')
                kept = {f for f in a['flags'] if not f.startswith('\\')} - {f for f in b['flags']}
                if kept:
                    notes.append(f'{label}: {len(kept)} custom keyword(s) not present at destination (informational)')
    return problems, notes


def add_connection(p):
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=993)
    p.add_argument('--user', required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--password-file')
    group.add_argument('--token-file', help='OAuth2 access token file (XOAUTH2)')
    p.add_argument('--ca-file')
    p.add_argument('--timeout', type=float, default=60)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('list'); add_connection(p)
    p = sub.add_parser('capture'); add_connection(p)
    p.add_argument('--folder', action='append', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--max-message-bytes', type=int, default=64 * 1024 * 1024)
    p = sub.add_parser('same'); p.add_argument('before'); p.add_argument('after')
    p = sub.add_parser('copy'); p.add_argument('source'); p.add_argument('dest')
    p.add_argument('--map', action='append', required=True, metavar='SRC=DST')
    p.add_argument('--allow-extra-destination', action='store_true')
    args = ap.parse_args(argv)
    try:
        if args.cmd == 'list':
            conn = connect(args)
            typ, data = conn.list()
            for line in data:
                print(line.decode('utf-8', 'replace'))
            conn.logout()
            return 0
        if args.cmd == 'capture':
            conn = connect(args)
            snap = {'version': SNAPSHOT_VERSION, 'captured_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                    'host': args.host, 'folders': {}}
            for name in args.folder:
                snap['folders'][name] = capture_folder(conn, name, args.max_message_bytes)
            conn.logout()
            write_private(args.out, snap)
            for name, f in snap['folders'].items():
                print(f'{name!r}: UIDVALIDITY {f["uidvalidity"]}, {len(f["messages"])} message(s)')
            return 0
        if args.cmd == 'same':
            problems = compare_same(load(args.before), load(args.after))
            print('\n'.join(problems) if problems else 'IDENTICAL: source unchanged')
            return 1 if problems else 0
        mapping = []
        for item in args.map:
            if '=' not in item:
                raise SystemExit(f'--map expects SRC=DST, got {item!r}')
            mapping.append(tuple(item.split('=', 1)))
        problems, notes = compare_copy(load(args.source), load(args.dest), mapping, args.allow_extra_destination)
        print('\n'.join(['MISMATCH:'] + problems) if problems else 'MATCH: every source message is at the destination')
        for note in notes:
            print('note:', note)
        return 1 if problems else 0
    except (imaplib.IMAP4.error, ReadOnlyViolation, OSError, ssl.SSLError) as exc:
        # Exception text from imaplib can contain server data; report only the type.
        print(f'error: {type(exc).__name__}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
