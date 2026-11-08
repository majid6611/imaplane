#!/usr/bin/env python3
"""Read-only, count-limited IMAP guard proxy for provider tests (Python standard library only).

IMAPLANE has no "first N messages" option. To test a real provider with a bounded, read-only slice of a
mailbox WITHOUT changing the migration engine, point IMAPLANE's *source* at this proxy:

  readonly_imap_proxy.py --upstream imap.gmail.com --listen-port 0 --cert C --key K \
        --token-file T --count 1000 --summary OUT.json            (the real username is read from the
                                                                  environment variable IMAP_PROXY_USER)

What it guarantees (and what the unit tests in tests/local/test_readonly_proxy.py check):
  * ALLOWLIST: only CAPABILITY, NOOP, LOGOUT, ID, ENABLE, NAMESPACE, LIST, LSUB, STATUS, EXAMINE INBOX,
    UNSELECT, AUTHENTICATE XOAUTH2, and UID FETCH / UID SEARCH are forwarded. Anything else (APPEND, STORE,
    EXPUNGE, COPY, MOVE, SELECT, CREATE, DELETE, RENAME, SUBSCRIBE, LOGIN, CLOSE, COMPRESS, ...) is refused with a
    tagged BAD and is never sent upstream.
  * UID FETCH may not use a body item that sets \\Seen: BODY[...] without PEEK, RFC822, RFC822.TEXT are refused.
    Explicit UIDs beyond the virtual mailbox are refused.
  * ONLY INBOX may be examined.
  * VIRTUAL MAILBOX: at start it reads (read-only) the INBOX UID list upstream and exposes only the oldest
    --count messages: EXISTS, UIDNEXT and every UID inventory response are rewritten to that slice, so the
    client sees a consistent smaller mailbox. Message bytes are passed through untouched.
  * The client's XOAUTH2 username is a placeholder; the proxy substitutes the real one, so the real address
    never has to be written to an IMAPLANE configuration or journal. Tokens are forwarded, never logged.
  * CONFINED-WRITE MODE (--confine-folder NAME --max-appends N): for the destination of a provider test. CREATE, SELECT,
    EXAMINE, STATUS, APPEND and CLOSE are allowed only for that single mailbox, at most N APPENDs are forwarded in the
    proxy's lifetime (a hard cap on how many messages can ever be written), and STORE, EXPUNGE, COPY, MOVE, DELETE,
    RENAME and every other mailbox stay refused, so existing mail and labels cannot be touched. With --max-appends 0 the
    proxy forwards NO write-capable command (CREATE, APPEND and CLOSE are refused as well) but still allows SELECT/EXAMINE/
    STATUS/LIST/UNSELECT and the read-only UID FETCH/SEARCH, so an existing job can be re-checked or verified with zero writes.
  * Nothing sensitive is logged: only per-verb counts, blocked counts and byte totals go to the summary.
"""
import argparse
import base64
import json
import os
import re
import socket
import ssl
import sys
import threading

NO_WRITE_REFUSED = ('CREATE', 'APPEND', 'CLOSE')
ALLOWED_VERBS = {'CAPABILITY', 'NOOP', 'LOGOUT', 'ID', 'ENABLE', 'NAMESPACE', 'LIST', 'LSUB', 'STATUS', 'EXAMINE',
                 'UNSELECT', 'AUTHENTICATE', 'UID'}
LITERAL_OK_VERBS = {'LIST', 'LSUB', 'STATUS', 'EXAMINE'}      # mailbox names may arrive as literals
MAX_LITERAL = 4096
CLIENT_LITERAL = re.compile(rb'\{(\d+)\+?\}\r\n$')
SERVER_LITERAL = re.compile(rb'\{(\d+)\}\r\n$')
FORBIDDEN_FETCH = re.compile(r'(?<![A-Z.])BODY\s*\[|(?<![A-Z.])RFC822(?![.A-Z])|RFC822\.TEXT|BINARY\s*\[', re.I)


def split_command(line):
    """b'a1 UID FETCH 1:* (UID)\\r\\n' -> ('a1', 'UID', 'FETCH 1:* (UID)') ; None when malformed."""
    text = line.rstrip(b'\r\n').decode('latin-1')
    parts = text.split(' ', 2)
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1].upper(), parts[2] if len(parts) > 2 else ''


def beyond_slice(spec, cut):
    """True when a UID set names a UID above `cut`. An open-ended range ('n:*') is allowed whatever n is, because
    the server's answer is filtered to the slice; single UIDs and closed ranges must lie inside it."""
    for element in spec.split(','):
        low, sep, high = element.partition(':')
        if not re.fullmatch(r'\d+|\*', low) or (sep and not re.fullmatch(r'\d+|\*', high)):
            return True                                  # not a plain UID set: refuse
        if sep and high == '*':
            continue
        if any(n.isdigit() and int(n) > cut for n in (low, high)):
            return True
    return False


CONFINED_EXTRA = {'CREATE', 'SELECT', 'APPEND', 'CLOSE'}
APPEND_RE = re.compile(r'^(?P<name>"[^"]*"|[^ ]+)(?: \([^)]*\))?(?: "[^"]*")? \{(?P<n>\d+)(?P<plus>\+?)\}$')


def confined_set(confine):
    return {confine} if isinstance(confine, str) else set(confine)


def mailbox_name(text):
    text = text.strip()
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] == '"' else text


def guard(line, cut, confine=None, extra_ro=(), no_write=False):
    """Decide one client command line. Returns (allowed, reason). `cut` is the highest UID the client may name.
    With `confine` (a mailbox name) the proxy is in confined-write mode: in addition to the read-only commands it
    allows CREATE, SELECT, EXAMINE, STATUS, APPEND and CLOSE, but ONLY for that one mailbox; everything else that
    could change a mailbox (STORE, EXPUNGE, COPY, MOVE, DELETE, RENAME, ...) stays refused.
    With `no_write` (the proxy's --max-appends 0) CREATE, APPEND and CLOSE are refused too: SELECT, EXAMINE, STATUS, LIST and the
    read-only UID FETCH/SEARCH remain, which is what a verification or duplicate-check run needs. CLOSE is refused because it
    silently expunges any \\Deleted message of a writable selection; UNSELECT leaves the mailbox without that effect."""
    parsed = split_command(line)
    if parsed is None:
        return False, 'malformed command'
    tag, verb, rest = parsed
    if confine is not None:
        if verb not in ALLOWED_VERBS | CONFINED_EXTRA:
            return False, f'{verb} is not allowed (confined proxy)'
        if no_write and verb in NO_WRITE_REFUSED:
            return False, f'{verb} is not allowed (--max-appends 0: no write-capable command)'
        if verb in ('CREATE', 'SELECT', 'EXAMINE', 'STATUS'):
            name = (re.match(r'"[^"]*"|\S+', rest) or re.match('', '')).group(0) if verb == 'STATUS' else rest
            allowed = confined_set(confine) | (set(extra_ro) if verb in ('EXAMINE', 'STATUS') else set())
            if name.strip().startswith('{') or mailbox_name(name) not in allowed:
                return False, f'{verb} is only allowed on {sorted(confined_set(confine))}'
        elif verb == 'APPEND':
            m = APPEND_RE.match(rest)
            if not m or mailbox_name(m.group('name')) not in confined_set(confine):
                return False, f'APPEND is only allowed into {sorted(confined_set(confine))} with a synchronizing literal'
            if m.group('plus'):
                return False, 'non-synchronizing literals are not allowed'
        elif verb == 'AUTHENTICATE':
            if rest.split(' ')[0].upper() != 'XOAUTH2':
                return False, 'only AUTHENTICATE XOAUTH2 is allowed'
        elif verb == 'UID':
            sub, _, args = rest.partition(' ')
            if sub.upper() == 'FETCH':
                if FORBIDDEN_FETCH.search(args.partition(' ')[2]):
                    return False, 'FETCH item would set \\Seen or is not a PEEK read'
            elif sub.upper() != 'SEARCH':
                return False, f'UID {sub.upper()} is not allowed (confined proxy)'
        return True, ''
    if verb not in ALLOWED_VERBS:
        return False, f'{verb} is not allowed (read-only proxy)'
    if verb == 'AUTHENTICATE':
        if rest.split(' ')[0].upper() != 'XOAUTH2':
            return False, 'only AUTHENTICATE XOAUTH2 is allowed'
    elif verb == 'EXAMINE':
        name = rest.strip()
        if name.startswith('{'):
            return False, 'EXAMINE with a literal is not allowed'
        if name.strip('"').upper() != 'INBOX':
            return False, 'only INBOX may be examined'
    elif verb == 'UID':
        sub, _, args = rest.partition(' ')
        sub = sub.upper()
        if sub == 'FETCH':
            spec, _, items = args.partition(' ')
            if FORBIDDEN_FETCH.search(items):
                return False, 'FETCH item would set \\Seen or is not a PEEK read'
            if beyond_slice(spec, cut):
                return False, 'UID beyond the virtual mailbox'
        elif sub == 'SEARCH':
            pass
        else:
            return False, f'UID {sub} is not allowed (read-only proxy)'
    return True, ''


def rewrite_auth(b64, user):
    """Replace the username in an XOAUTH2 initial response / continuation line. Anything that does not decode to
    an XOAUTH2 string (for example the empty line after an error challenge) is passed through unchanged."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except ValueError:
        return b64
    if not raw.startswith(b'user=') or b'\x01auth=' not in raw:
        return b64
    rest = raw[raw.index(b'\x01auth='):]
    return base64.b64encode(b'user=' + user.encode() + rest)


class Slice:
    """The virtual mailbox: the oldest `count` UIDs of the real INBOX."""

    def __init__(self, uids, count):
        self.uids = sorted(uids)[:count]
        self.cut = self.uids[-1] if self.uids else 0
        self.exists = len(self.uids)


def rewrite_server_line(line, sl):
    """Rewrite one complete untagged server line for the virtual mailbox; return None to drop it."""
    m = re.fullmatch(rb'\* (\d+) EXISTS\r\n', line)
    if m:
        return b'* %d EXISTS\r\n' % sl.exists
    m = re.fullmatch(rb'(\* OK \[UIDNEXT )(\d+)(\].*\r\n)', line, re.S)
    if m:
        return m.group(1) + b'%d' % (sl.cut + 1) + m.group(3)
    m = re.fullmatch(rb'\* SEARCH((?: \d+)*)\r\n', line)
    if m:                       # UID SEARCH answer: only the slice's UIDs (a plain SEARCH is refused by the guard)
        kept = [n for n in m.group(1).split() if int(n) <= sl.cut]
        return b'* SEARCH' + b''.join(b' ' + n for n in kept) + b'\r\n'
    m = re.fullmatch(rb'\* (\d+) FETCH \(UID (\d+)\)\r\n', line)
    if m and int(m.group(2)) > sl.cut:
        return None
    return line


class Upstream:
    def __init__(self, host, port, ctx):
        self.sock = ctx.wrap_socket(socket.create_connection((host, port), timeout=60), server_hostname=host)
        self.file = self.sock.makefile('rb')
        self.n = 0
        self.greeting = self.file.readline()

    def send(self, data):
        self.sock.sendall(data)

    def line(self):
        return self.file.readline()


def preflight(args, user, token):
    """Read-only look at the real INBOX: its UID list and the total size of the first `count` messages."""
    ctx = ssl.create_default_context()
    up = Upstream(args.upstream, args.upstream_port, ctx)
    counts = {'bytes_total': 0}

    def command(text):
        up.n += 1
        tag = b'p%d' % up.n
        up.send(tag + b' ' + text.encode() + b'\r\n')
        out = []
        while True:
            line = up.line()
            if not line:
                raise RuntimeError('upstream closed during preflight')
            m = SERVER_LITERAL.search(line)
            if m:
                up.file.read(int(m.group(1)))      # never expected here; discard
            if line.startswith(tag + b' '):
                if not line.startswith(tag + b' OK'):
                    raise RuntimeError('preflight command refused: ' + text.split(' ')[0])
                return out
            out.append(line)

    xo = base64.b64encode(f'user={user}\x01auth=Bearer {token}\x01\x01'.encode()).decode()
    up.n += 1
    up.send(b'p%d AUTHENTICATE XOAUTH2 %s\r\n' % (up.n, xo.encode()))
    while True:
        line = up.line()
        if line.startswith(b'p%d ' % up.n):
            if not line.startswith(b'p%d OK' % up.n):
                raise RuntimeError('upstream authentication failed (XOAUTH2)')
            break
    command('EXAMINE "INBOX"')
    uids = sorted(int(m.group(1)) for line in command('UID FETCH 1:* (UID)')
                  for m in [re.match(rb'\* \d+ FETCH \(UID (\d+)\)', line)] if m)
    sl = Slice(uids, args.count)
    sizes = {}
    for i in range(0, len(sl.uids), 200):
        chunk = sl.uids[i:i + 200]
        for line in command('UID FETCH %s (UID RFC822.SIZE)' % ','.join(map(str, chunk))):
            m = re.search(rb'UID (\d+) RFC822\.SIZE (\d+)', line)
            if m:
                sizes[int(m.group(1))] = int(m.group(2))
    up.n += 1
    up.send(b'p%d LOGOUT\r\n' % up.n)
    up.sock.close()
    return sl, {'real_inbox_messages': len(uids), 'virtual_messages': sl.exists, 'virtual_cut_uid': sl.cut,
                'slice_total_bytes': sum(sizes.values()), 'slice_largest_bytes': max(sizes.values() or [0]),
                'slice_sizes_known': len(sizes)}


class Stats:
    flush = staticmethod(lambda: None)    # replaced by main() with the summary writer

    def __init__(self):
        self.lock = threading.Lock()
        self.verbs = {}
        self.blocked = {}
        self.bytes_from_upstream = 0
        self.appends = 0
        self.connections = 0

    def add(self, table, key):
        with self.lock:
            table[key] = table.get(key, 0) + 1


def serve_connection(client, args, sl, user, stats, ctx):
    state = {'auth_tag': None, 'done': False}
    try:
        up = Upstream(args.upstream, args.upstream_port, ctx)
    except OSError:
        client.close()
        return
    cfile = client.makefile('rb')
    with stats.lock:
        stats.connections += 1

    def to_client(data):
        client.sendall(data)

    def pump_server():
        try:
            to_client(up.greeting)
            while True:
                line = up.line()
                if not line:
                    break
                # literal(s): forward raw, never inspect or alter
                m = SERVER_LITERAL.search(line)
                if m:
                    n = int(m.group(1))
                    to_client(line)
                    left = n
                    while left:
                        chunk = up.file.read(min(left, 1 << 16))
                        if not chunk:
                            return
                        to_client(chunk)
                        left -= len(chunk)
                    with stats.lock:
                        stats.bytes_from_upstream += n
                    continue
                if line.startswith(b'* '):
                    out = rewrite_server_line(line, sl) if sl is not None else line
                    if out is not None:
                        to_client(out)
                    continue
                if state['auth_tag'] and line.startswith(state['auth_tag'] + b' '):
                    state['auth_tag'] = None
                ev = state.get('append_ev')
                if ev is not None:
                    if line.startswith(b'+'):
                        state['append_plus'] = True
                        ev.set()
                    elif line.startswith(state['append_tag'] + b' '):
                        ev.set()
                to_client(line)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    pump = threading.Thread(target=pump_server, daemon=True)
    pump.start()
    try:
        while True:
            line = cfile.readline()
            if not line:
                break
            if state['auth_tag']:                     # a SASL continuation line, not a command
                up.send(rewrite_auth(line.strip(), user) + b'\r\n')
                continue
            ok, reason = guard(line, sl.cut if sl is not None else 0, args.confine_folder, args.readonly_folder or (),
                               no_write=args.max_appends == 0)
            parsed = split_command(line)
            tag = parsed[0] if parsed else '*'
            verb = parsed[1] if parsed else '?'
            if not ok:
                stats.add(stats.blocked, verb)
                to_client(f'{tag} BAD proxy: {reason}\r\n'.encode())
                continue
            stats.add(stats.verbs, verb if verb != 'UID' else 'UID ' + parsed[2].split(' ')[0].upper())
            m = CLIENT_LITERAL.search(line)
            if verb == 'APPEND':
                n = int(m.group(1))
                with stats.lock:
                    over = stats.appends >= args.max_appends
                    if not over:
                        stats.appends += 1
                if over or n > args.max_append_bytes:
                    stats.add(stats.blocked, 'APPEND (cap)')
                    to_client(f'{tag} BAD proxy: APPEND cap reached ({args.max_appends} messages, {args.max_append_bytes} bytes each)\r\n'.encode())
                    continue
                state['append_tag'], state['append_plus'] = tag.encode(), False
                state['append_ev'] = threading.Event()
                up.send(line)
                state['append_ev'].wait(120)
                if state['append_plus']:              # the server asked for the literal: forward it exactly
                    left = n
                    while left:
                        chunk = cfile.read(min(left, 1 << 16))
                        if not chunk:
                            return
                        up.send(chunk)
                        left -= len(chunk)
                    up.send(cfile.readline())
                state['append_ev'] = None
                continue
            if m:
                if verb not in LITERAL_OK_VERBS or int(m.group(1)) > MAX_LITERAL:
                    stats.add(stats.blocked, verb)
                    to_client(f'{tag} BAD proxy: literal not allowed\r\n'.encode())
                    continue
            if verb == 'AUTHENTICATE':
                state['auth_tag'] = tag.encode()
                parts = line.rstrip(b'\r\n').split(b' ')
                if len(parts) >= 4:                   # SASL-IR: initial response on the command line
                    parts[3] = rewrite_auth(parts[3], user)
                    line = b' '.join(parts) + b'\r\n'
                up.send(line)
                continue
            up.send(line)
            if m:                                     # forward the literal bytes that follow (name only)
                up.send(cfile.read(int(m.group(1))))
                up.send(cfile.readline())
            if verb == 'LOGOUT':
                pump.join(15)          # let the server's BYE and tagged OK reach the client before closing
                break
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            up.sock.close()
        except OSError:
            pass
        client.close()
        stats.flush()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--upstream', required=True)
    ap.add_argument('--upstream-port', type=int, default=993)
    ap.add_argument('--listen-port', type=int, default=0)
    ap.add_argument('--cert', required=True)
    ap.add_argument('--key', required=True)
    ap.add_argument('--token-file', help='access token file (0600), used only by the preflight (read-only mode)')
    ap.add_argument('--count', type=int, help='read-only mode: expose only the oldest N INBOX messages')
    ap.add_argument('--confine-folder', action='append', help='confined-write mode: allow CREATE/SELECT/APPEND only for this mailbox (repeatable)')
    ap.add_argument('--readonly-folder', action='append', help='confined mode: an additional mailbox that may only be EXAMINEd (repeatable)')
    ap.add_argument('--max-appends', type=int, default=0, help='confined mode: hard cap on APPENDs over the proxy lifetime; 0 = no write-capable command at all (CREATE, APPEND, CLOSE refused), SELECT/EXAMINE and reads still work')
    ap.add_argument('--max-append-bytes', type=int, default=10 << 20)
    ap.add_argument('--upstream-ca', help='extra CA file for the upstream (tests and local rehearsals only)')
    ap.add_argument('--summary', required=True)
    ap.add_argument('--max-slice-bytes', type=int, default=1 << 30, help='refuse to start if the slice is larger')
    ap.add_argument('--ready-file', help='written (with the listening port) once the proxy accepts connections')
    args = ap.parse_args(argv)
    user = os.environ['IMAP_PROXY_USER']
    if args.confine_folder:
        if args.max_appends < 0:
            sys.exit('--max-appends must be >= 0 (0 = no writes, reads only)')
        sl, info = None, {'mode': 'confined-write', 'folder_confined_to': 'set', 'max_appends': args.max_appends}
    else:
        if not args.token_file or not args.count:
            sys.exit('read-only mode needs --token-file and --count')
        st = os.stat(args.token_file)
        if st.st_mode & 0o077 or st.st_uid != os.getuid():
            sys.exit('token file must be private')
        token = open(args.token_file).read().strip()
        sl, info = preflight(args, user, token)
        del token
        if info['slice_total_bytes'] > args.max_slice_bytes:
            sys.exit(f'REFUSED: the slice is {info["slice_total_bytes"]} bytes, above --max-slice-bytes')
    print('preflight:', json.dumps(info), flush=True)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.load_cert_chain(args.cert, args.key)
    client_ctx = ssl.create_default_context(cafile=args.upstream_ca) if args.upstream_ca else ssl.create_default_context()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', args.listen_port))
    listener.listen(8)
    port = listener.getsockname()[1]
    stats = Stats()
    if args.ready_file:
        fd = os.open(args.ready_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(str(port))
    print('listening on 127.0.0.1:%d' % port, flush=True)

    def write_summary():
        out = {'preflight': info, 'connections': stats.connections, 'forwarded_verbs': stats.verbs,
               'blocked_verbs': stats.blocked, 'message_bytes_from_upstream': stats.bytes_from_upstream, 'appends_forwarded': stats.appends}
        fd = os.open(args.summary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(out, f, indent=1)

    stats.flush = write_summary
    try:
        while True:
            raw, _ = listener.accept()
            try:
                client = server_ctx.wrap_socket(raw, server_side=True)
            except (OSError, ssl.SSLError):
                continue
            threading.Thread(target=serve_connection, args=(client, args, sl, user, stats, client_ctx), daemon=True).start()
            write_summary()
    except KeyboardInterrupt:
        pass
    finally:
        write_summary()


if __name__ == '__main__':
    main()
