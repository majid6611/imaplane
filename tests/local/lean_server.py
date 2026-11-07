"""A lean loopback TLS IMAP fixture for very large messages (phase 5A).

The reference fixture (e2e.ProtocolServer) keeps every message, and several copies of a
response, in memory, so it cannot serve a 1 GiB message on a small machine. This fixture holds
no message at all: each source message is generated block by block from a seed, an APPENDed
message is hashed as it arrives and only its digest is kept, and a destination message is served
back by regenerating it if (and only if) its digest matches a known source message. Content that
differs is served as zeros, so verification MUST report a mismatch. Memory use is a few hundred
KiB regardless of message size.

It speaks just what IMAPLANE needs (AUTH PLAIN, CAPABILITY, LIST, SELECT/EXAMINE, UID FETCH for
inventory, size and body, APPEND with UIDPLUS, NOOP, LOGOUT) with the same responses as the
reference fixture. Loopback only; no real credentials or mail.
"""
import base64
import hashlib
import re
import socket
import ssl
import threading
import time

from e2e import utf7

FOLDER = '台北/📬'
DATE = b'02-Jan-2020 03:04:05 +0000'
BLOCK = 1 << 20
_BASE = hashlib.sha256(b'imaplane lean fixture').digest() * (BLOCK // 32)


def blocks(index, size):
    """Yield the bytes of generated message `index`, exactly `size` long, in blocks of 1 MiB."""
    head = b'Subject: lean fixture %d\r\n\r\n' % index
    left, k = size, 0
    first = True
    while left > 0:
        block = bytearray(_BASE)
        block[:16] = hashlib.sha256(b'%d:%d' % (index, k)).digest()[:16]
        data = bytes(block)
        if first:
            data = head + data
            first = False
        data = data[:left]
        yield data
        left -= len(data)
        k += 1


def digest_of(index, size):
    h = hashlib.sha256()
    for b in blocks(index, size):
        h.update(b)
    return h.hexdigest()


class LeanServer:
    def __init__(self, cert, key, sizes, throttle_mib_s=None):
        self.sizes = list(sizes)
        self.expected = [digest_of(i, s) for i, s in enumerate(self.sizes)]
        self.dest = []                       # [{'size': n, 'sha': hex, 'index': int|None}]
        self.events = []                     # (user, VERB) only; never content
        self.errors = []
        self.append_bytes = 0
        self.throttle = throttle_mib_s
        self.append_throttle = None          # MiB/s cap on reading an APPEND literal
        self.fetch_started = threading.Event()    # a source body FETCH began
        self.append_started = threading.Event()   # an APPEND literal began (continuation sent)
        self.verify_started = threading.Event()   # a destination body FETCH began
        self.pause_source_at = None          # stream this many body bytes of a source FETCH, then wait
        self.source_paused = threading.Event()
        self.resume_source = threading.Event()
        self.stopped = False
        self.listener = socket.socket(); self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0)); self.listener.listen(10); self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); self.ctx.load_cert_chain(cert, key)
        self.name_wire = utf7(FOLDER).encode()
        threading.Thread(target=self.serve, daemon=True).start()

    # ------------------------------------------------------------------ plumbing
    def serve(self):
        while not self.stopped:
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.connection, args=(raw,), daemon=True).start()

    def close(self):
        self.stopped = True
        self.resume_source.set()
        self.listener.close()

    def send_body(self, client, source_index, size, user, limit=None):
        """Send the message body (or only its first `limit` bytes, for a partial fetch)."""
        sent = 0
        paused = False
        for data in blocks(source_index, size) if source_index is not None else (b'\0' * min(BLOCK, size - o) for o in range(0, size, BLOCK)):
            if limit is not None:
                if sent >= limit:
                    break
                data = data[:limit - sent]
            if self.pause_source_at is not None and user == 'source' and not paused and sent + len(data) > self.pause_source_at:
                cut = self.pause_source_at - sent
                client.sendall(data[:cut]); sent += cut
                self.source_paused.set()
                self.resume_source.wait(300)
                data = data[cut:]; paused = True
            client.sendall(data); sent += len(data)
            if self.throttle:
                time.sleep(len(data) / (self.throttle * (1 << 20)))

    def message(self, user, uid):
        """(size, source_index or None) of message uid for a user, or None."""
        if user == 'source':
            return (self.sizes[uid - 1], uid - 1) if 1 <= uid <= len(self.sizes) else None
        if 1 <= uid <= len(self.dest):
            m = self.dest[uid - 1]
            return (m['size'], m['index'])
        return None

    # ------------------------------------------------------------------ protocol
    def connection(self, raw):
        try:
            with self.ctx.wrap_socket(raw, server_side=True) as client:
                reader = client.makefile('rb'); client.sendall(b'* OK lean fixture\r\n')
                user = None
                while True:
                    line = reader.readline()
                    if not line:
                        return
                    tag, verb, *args = line.strip().split(b' ', 2)
                    verb = verb.upper()
                    self.events.append((user, verb.decode()))
                    if verb == b'CAPABILITY':
                        client.sendall(b'* CAPABILITY UIDPLUS AUTH=PLAIN IMAP4rev1\r\n')
                    elif verb == b'AUTHENTICATE':
                        client.sendall(b'+ \r\n')
                        user = base64.b64decode(reader.readline()).split(b'\0')[1].decode()
                    elif verb == b'LIST':
                        client.sendall(b'* LIST () "/" {%d}\r\n' % len(self.name_wire) + self.name_wire + b'\r\n')
                    elif verb in (b'EXAMINE', b'SELECT'):
                        assert args[0] == b'"' + self.name_wire + b'"', args
                        count = len(self.sizes) if user == 'source' else len(self.dest)
                        client.sendall(b'* FLAGS (\\Seen)\r\n* %d EXISTS\r\n* OK [PERMANENTFLAGS (\\Seen)] flags\r\n* OK [UIDVALIDITY 77] validity\r\n* OK [UIDNEXT %d] next\r\n' % (count, count + 1))
                        client.sendall(tag + b' OK ' + (b'[READ-ONLY]' if verb == b'EXAMINE' else b'[READ-WRITE]') + b' selected\r\n')
                        continue
                    elif verb == b'UID':
                        m = re.fullmatch(rb'FETCH 1:(?:\d+|\*) \(UID\)', args[0])
                        if m:
                            count = len(self.sizes) if user == 'source' else len(self.dest)
                            for i in range(count):
                                client.sendall(b'* %d FETCH (UID %d)\r\n' % (i + 1, i + 1))
                        else:
                            m = re.fullmatch(rb'FETCH (\d+) (.*)', args[0]); assert m, args
                            uid, request = int(m.group(1)), m.group(2)
                            found = self.message(user, uid)
                            if found:
                                size, index = found
                                if request == b'(UID RFC822.SIZE)':
                                    client.sendall(b'* %d FETCH (UID %d RFC822.SIZE %d)\r\n' % (uid, uid, size))
                                elif re.fullmatch(rb'\(UID FLAGS INTERNALDATE RFC822\.SIZE BODY\.PEEK\[\]<0\.\d+>\)', request):
                                    # single-exchange read of a small message: size, flags, date and the first N bytes
                                    n = min(int(re.search(rb'<0\.(\d+)>', request).group(1)), size)
                                    client.sendall(b'* %d FETCH (UID %d FLAGS (\\Seen) INTERNALDATE "' % (uid, uid) + DATE + b'" RFC822.SIZE %d BODY[]<0> {%d}\r\n' % (size, n))
                                    (self.fetch_started if user == 'source' else self.verify_started).set()
                                    self.send_body(client, index, size, user, limit=n)
                                    client.sendall(b')\r\n')
                                else:
                                    assert request == b'(UID FLAGS INTERNALDATE BODY.PEEK[])', request
                                    client.sendall(b'* %d FETCH (UID %d FLAGS (\\Seen) INTERNALDATE "' % (uid, uid) + DATE + b'" BODY[] {%d}\r\n' % size)
                                    (self.fetch_started if user == 'source' else self.verify_started).set()
                                    self.send_body(client, index, size, user)
                                    client.sendall(b')\r\n')
                    elif verb == b'APPEND':
                        assert user == 'destination'
                        n = int(re.search(rb'\{(\d+)\}$', line.strip()).group(1))
                        client.sendall(b'+ ready\r\n')
                        self.append_started.set()
                        h, left = hashlib.sha256(), n
                        while left:
                            chunk = reader.read(min(left, 1 << 18)); assert chunk
                            h.update(chunk); left -= len(chunk); self.append_bytes += len(chunk)
                            if self.append_throttle:
                                time.sleep(len(chunk) / (self.append_throttle * (1 << 20)))
                        assert reader.read(2) == b'\r\n'
                        sha = h.hexdigest()
                        index = next((i for i, e in enumerate(self.expected) if e == sha and self.sizes[i] == n), None)
                        self.dest.append({'size': n, 'sha': sha, 'index': index})
                        client.sendall(tag + b' OK [APPENDUID 77 %d] appended\r\n' % len(self.dest))
                        continue
                    elif verb == b'NOOP':
                        pass
                    elif verb == b'LOGOUT':
                        client.sendall(b'* BYE\r\n' + tag + b' OK bye\r\n'); return
                    else:
                        raise AssertionError(verb)
                    client.sendall(tag + b' OK complete\r\n')
        except (OSError, ssl.SSLError):
            pass
        except Exception as exc:
            self.errors.append(repr(exc))

    # ------------------------------------------------------------------ checks
    def destination_matches_source(self):
        return [m['sha'] for m in self.dest] == [self.expected[i] for i in range(len(self.dest))] and len(self.dest) == len(self.sizes)

    def source_verbs(self):
        return {v for u, v in self.events if u == 'source'}
