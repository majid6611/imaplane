#!/usr/bin/env python3
"""Disposable Dovecot + TLS fault proxy tests. Requires Docker, Python 3, OpenSSL.
Run after cargo build: python3 tests/local/e2e.py [path/to/imaplane]
No credentials or real mail servers are used. Containers are always removed.
"""
import base64
import contextlib
import fcntl
import hashlib
import imaplib
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'target/debug/imaplane').resolve()
IMAGE = 'dovecot/dovecot:2.3.21@sha256:1c18c756f20d03867077a1b509a6e2e3008ab1eafa56377b6f2eca12dc1ba581'
PASSWORD = 'imaplane-test-only'
# Test-only lever: IMAPLANE_TEST_STREAM_THRESHOLD=0 makes every generated config set
# stream_threshold_bytes, so the whole suite can run in forced-streaming mode.
STREAM_EXTRA = f"stream_threshold_bytes = {os.environ['IMAPLANE_TEST_STREAM_THRESHOLD']}\nspool_allow_memory_backed = true\n" if os.environ.get('IMAPLANE_TEST_STREAM_THRESHOLD') else ''

def command(*args, **kw):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw).stdout.strip()

def utf7(text):
    out, run = '', ''
    def flush(s):
        return '&' + base64.b64encode(s.encode('utf-16be')).decode().rstrip('=').replace('/', ',') + '-' if s else ''
    for ch in text:
        if ' ' <= ch <= '~':
            out += flush(run); run = ''
            out += '&-' if ch == '&' else ch
        else:
            run += ch
    return (out + flush(run))

def quoted(folder):
    return '"' + utf7(folder).replace('\\', '\\\\').replace('"', '\\"') + '"'

class Proxy:
    """TLS on both sides. Commands captured only as verbs, never credentials.
    Drops an APPEND success reply after upstream committed it when armed.
    Can also drop the first source UID FETCH to test reconnect behavior.
    """
    def __init__(self, port, cert, key, drop_append=False, drop_fetch=False, pause_append=False, pause_verify=False, latency_ms=0, drop_body_nth=0, mid_body_nth=0):
        self.drop_body_nth=drop_body_nth; self.body_count=0
        self.mid_body_nth=mid_body_nth; self.append_count=0
        self.partial_received=threading.Event(); self.release_partial=threading.Event()
        self.sessions=[]
        self.latency_ms = latency_ms
        self.round_trips = 0
        self.upstream = port
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(10)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_ctx.load_cert_chain(cert, key)
        self.client_ctx = ssl.create_default_context(cafile=cert)
        self.drop_append, self.drop_fetch = drop_append, drop_fetch
        self.pause_append = pause_append
        self.pause_verify = pause_verify
        self.append_seen = False
        self.verify_waiting = threading.Event()
        self.resume_verify = threading.Event()
        self.append_committed = threading.Event()
        self.resume_append = threading.Event()
        self.commands = []
        self.stopped = False
        self.sockets = []
        self.errors = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
    def exchange(self):
        self.round_trips += 1
        if self.latency_ms: time.sleep(self.latency_ms / 1000)
    def serve(self):
        while not self.stopped:
            try:
                s, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.connection, args=(s,), daemon=True).start()
    def connection(self, raw):
        session=[]; self.sessions.append(session)
        try:
            with self.server_ctx.wrap_socket(raw, server_side=True) as client:
                with self.client_ctx.wrap_socket(socket.create_connection(('127.0.0.1', self.upstream)), server_hostname='localhost') as server:
                    self.sockets.extend([client, server])
                    cf, sf = client.makefile('rb'), server.makefile('rb')
                    client.sendall(sf.readline())
                    while True:
                        line = cf.readline()
                        if not line:
                            return
                        parts = line.split(b' ', 2)
                        if len(parts) < 2:
                            raise AssertionError('invalid client command')
                        tag, verb = parts[:2]
                        verb = verb.strip().upper()
                        session.append(verb.decode())
                        if verb == b'UID' and b'BODY.PEEK' in line:
                            self.body_count+=1
                            if self.body_count==self.drop_body_nth: return
                        # Only protocol verbs + fixed FETCH request attributes are logged.
                        self.commands.append((verb.decode(), parts[2].decode().strip() if verb == b'UID' else ''))
                        if verb == b'UID' and b'FETCH' in line and self.drop_fetch:
                            self.drop_fetch = False
                            return
                        if verb == b'UID' and b'FETCH' in line and self.pause_verify and self.append_seen:
                            self.pause_verify = False
                            self.verify_waiting.set()
                            assert self.resume_verify.wait(30), 'test did not release paused verification'
                        self.exchange()
                        server.sendall(line)
                        append = verb == b'APPEND'
                        if verb == b'AUTHENTICATE':
                            self.exchange()
                            response = sf.readline()
                            client.sendall(response)
                            server.sendall(cf.readline())
                        if append:
                            self.exchange()
                            response = sf.readline()
                            client.sendall(response)
                            if response.startswith(b'+'):
                                size = int(re.search(rb'\{(\d+)\}\r\n$', line).group(1))
                                payload = cf.read(size + 2)
                                if len(payload) != size + 2: return # Expected EOF at pre-literal crash points.
                                self.append_count+=1
                                if self.append_count==self.mid_body_nth:
                                    server.sendall(payload[:max(1,len(payload)//2)])
                                    self.partial_received.set(); self.release_partial.wait(30)
                                    return
                                server.sendall(payload)
                        while True:
                            response = sf.readline()
                            if not response:
                                return
                            if response.startswith(tag + b' ') and append and self.drop_append:
                                assert b' OK ' in response
                                self.drop_append = False
                                return
                            if response.startswith(tag + b' ') and append:
                                self.append_seen = True
                            if response.startswith(tag + b' ') and append and self.pause_append:
                                self.pause_append = False
                                self.append_committed.set()
                                assert self.resume_append.wait(30), 'test did not release paused APPEND'
                            client.sendall(response)
                            # Relay literals verbatim rather than parsing their contents as lines.
                            literal = re.search(rb'\{(\d+)\}\r\n$', response)
                            if literal:
                                n = int(literal.group(1))
                                data = sf.read(n)
                                assert len(data) == n
                                client.sendall(data)
                            if response.startswith(tag + b' '):
                                break
        except (OSError, ssl.SSLError):
            pass
        except Exception as exc:
            self.errors.append(repr(exc))
    def close(self):
        self.stopped = True
        self.release_partial.set()
        self.listener.close()
        for s in self.sockets:
            with contextlib.suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)
                s.close()
        self.thread.join(2)

class ProtocolServer:
    """Protocol fixture for rev1/rev2 negotiation and message transfer over TLS."""
    def __init__(self, cert, key, mode):
        self.mode = mode
        self.listener = socket.socket(); self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); self.listener.bind(('127.0.0.1',0)); self.listener.listen(10)
        self.listener.settimeout(.2); self.port = self.listener.getsockname()[1]
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); self.ctx.load_cert_chain(cert,key)
        self.stopped = False; self.errors = []
        self.missing_inventory = False
        self.body_fetches = {'source': 0, 'destination': 0}  # UID FETCH requests that read a body
        self.meta_fetches = {'source': 0, 'destination': 0}  # metadata-only UID FETCH requests
        self.dest_flags = {}   # destination uid -> flag text served instead of \\Seen
        self.dest_dates = {}   # destination uid -> INTERNALDATE text served instead of the default
        self.dest_size_delta = {}  # destination uid -> bytes added to the RFC822.SIZE of metadata fetches
        self.failed_body = False
        self.events = []
        self.injected = False
        self.reject_once = False
        self.rejection_script = []
        self.reject_after = False
        self.concurrent = False
        self.throttle_once = False
        self.slow = False
        self.append_wait = False
        self.slow_upload = False
        self.bad_size = False
        self.source_fetch_no = False
        self.wrong_rejection_tag = False
        self.restart_once = False
        self.xoauth2_token = None  # when set, AUTH=XOAUTH2 is offered and checked
        self.truncate_dest_fetch_at = None  # destination body FETCH: send this many bytes, then close
        self.drop_reply_after_commit = False  # APPEND is stored but the reply is never sent
        self.truncate_source_fetch_at = None  # source body FETCH: send this many bytes, then close
        self.stall_source_fetch_at = None  # source body FETCH: send this many bytes, then go silent
        self.stall_append_after = None  # APPEND: read this many literal bytes, then stop reading and go silent
        self.pause_source_fetch_at = None  # source body FETCH: send this many bytes, wait for resume_source_fetch, then the rest
        self.source_paused = threading.Event()
        self.resume_source_fetch = threading.Event()
        # Pause hooks (tests): each sets <name>_paused when reached and waits for <name>_resume.
        self.pause_dest_noop = False         # the destination's liveness NOOP (runs right after a long source read)
        self.pause_continuation = False      # APPEND: before sending the + continuation
        self.pause_append_reply = False      # APPEND: after storing the message, before the tagged reply
        self.hooks = {n: (threading.Event(), threading.Event()) for n in ('dest_noop', 'continuation', 'append_reply')}
        self.idle_drop = None  # seconds; destination connection silently closes when idle this long
        self.drop_on_append = False  # destination closes without a reply when APPEND arrives
        self.throttle_code = b'THROTTLED'
        self.list_hook = None  # callable(n): runs on the source when the full UID list is requested (mutate messages)
        self.list_count = 0
        self.source_validity = 77
        self.destination_validity = 77
        self.append_validity = 77
        self.append_uid_override = None
        self.messages = {'source': [b'Subject: protocol fixture\r\n\r\nraw message\r\n'], 'destination': []}
        threading.Thread(target=self.serve,daemon=True).start()
    def serve(self):
        while not self.stopped:
            try: raw, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            threading.Thread(target=self.connection,args=(raw,),daemon=True).start()
    def connection(self, raw):
        try:
            with self.ctx.wrap_socket(raw,server_side=True) as client:
                reader = client.makefile('rb'); client.sendall(b'* OK scripted IMAP fixture\r\n')
                mode = self.mode
                caps = b'UIDPLUS AUTH=PLAIN'
                caps += b' IMAP4rev2' if mode == 'rev2' else b' IMAP4rev1'
                if self.xoauth2_token: caps += b' AUTH=XOAUTH2 APPENDLIMIT=26214400 X-GM-EXT-1 X-PRIVATE-VENDOR'
                if mode.startswith('dual'): caps += b' IMAP4rev2 ENABLE'
                if mode.startswith('utf8'): caps += b' UTF8=ONLY UTF8=ACCEPT ENABLE'
                enabled = mode == 'rev2'
                user = None
                while True:
                    if user == 'destination' and self.idle_drop: client.settimeout(self.idle_drop)
                    line = reader.readline()
                    if not line: return
                    tag, verb, *args = line.strip().split(b' ',2)
                    verb = verb.upper()
                    self.events.append((user, verb, args))
                    if verb == b'CAPABILITY': client.sendall(b'* CAPABILITY '+caps+b'\r\n')
                    elif verb == b'AUTHENTICATE':
                        client.sendall(b'+ \r\n')
                        raw = base64.b64decode(reader.readline())
                        if args and args[0].upper() == b'XOAUTH2':
                            match = re.fullmatch(rb'user=(.*)\x01auth=Bearer (.*)\x01\x01', raw, re.S)
                            if not (self.xoauth2_token and match and match.group(2).decode() == self.xoauth2_token):
                                client.sendall(b'+ '+base64.b64encode(b'{"status":"401"}')+b'\r\n'); reader.readline()
                                client.sendall(tag+b' NO [AUTHENTICATIONFAILED] PRIVATE invalid credentials\r\n'); continue
                            user = match.group(1).decode()
                        else:
                            user = raw.split(b'\0')[1].decode()
                        assert user in self.messages
                        if mode.endswith('bad-auth'):
                            client.sendall(tag+b' NO rejected credential: '+PASSWORD.encode()+b'\r\n')
                            continue
                    elif verb == b'NOOP':
                        if user == 'destination' and self.pause_dest_noop:
                            self.hook('dest_noop')
                    elif verb == b'ENABLE':
                        if not mode.endswith('noack'):
                            enabled = True
                            client.sendall(b'* ENABLED '+args[0]+b'\r\n')
                    elif verb == b'LIST':
                        if self.throttle_once:
                            self.throttle_once = False
                            client.sendall(tag+b' NO ['+self.throttle_code+b'] PRIVATE retry later\r\n'); continue
                        name = '台北/📬'
                        wire = name.encode() if enabled else utf7(name).encode()
                        client.sendall(b'* LIST () "/" {'+str(len(wire)).encode()+b'}\r\n'+wire+b'\r\n')
                    elif verb in [b'EXAMINE',b'SELECT']:
                        name = '台北/📬'
                        expected = name.encode() if enabled else utf7(name).encode()
                        assert args[0] == b'"'+expected+b'"', (mode,args)
                        count = sum(m is not None for m in self.messages[user])  # None marks an expunged message
                        validity = self.source_validity if user == 'source' else self.destination_validity
                        client.sendall(b'* FLAGS (\\Seen)\r\n* '+str(count).encode()+b' EXISTS\r\n* OK [PERMANENTFLAGS (\\Seen)] flags\r\n* OK [UIDVALIDITY '+str(validity).encode()+b'] validity\r\n* OK [UIDNEXT '+str(len(self.messages[user])+1).encode()+b'] next\r\n')
                        client.sendall(tag+b' OK '+(b'[READ-ONLY]' if verb == b'EXAMINE' else b'[READ-WRITE]')+b' selected\r\n')
                        if self.concurrent and user == 'source':
                            self.concurrent = False
                            self.messages[user].append(b'Subject: concurrent delivery\r\n\r\nnew\r\n')
                        continue
                    elif verb == b'UID':
                        if re.fullmatch(rb'FETCH 1:(?:\d+|\*) \(UID\)', args[0]):
                            if user == 'source':
                                self.list_count += 1
                                if self.list_hook: self.list_hook(self.list_count)
                            horizon = args[0].split()[1].split(b':')[1]
                            upper = len(self.messages[user]) if horizon == b'*' else min(int(horizon), len(self.messages[user]))
                            uids = [i+1 for i in range(upper) if self.messages[user][i] is not None]
                            for uid in (uids[:-1] if self.missing_inventory and user == 'source' else uids):
                                client.sendall(b'* '+str(uid).encode()+b' FETCH (UID '+str(uid).encode()+b')\r\n')
                        elif re.fullmatch(rb'FETCH [\d:,]+ \(UID FLAGS INTERNALDATE RFC822\.SIZE\)', args[0]):
                            self.meta_fetches[user] += 1
                            wanted = set()
                            for part in args[0].split()[1].split(b','):
                                lo, _, hi = part.partition(b':')
                                wanted.update(range(int(lo), int(hi or lo) + 1))
                            for uid in sorted(wanted):
                                if uid <= len(self.messages[user]) and self.messages[user][uid-1] is not None:
                                    size = len(self.messages[user][uid-1]) + (self.dest_size_delta.get(uid, 0) if user == 'destination' else 0)
                                    flags = self.dest_flags.get(uid, b'\\Seen') if user == 'destination' else b'\\Seen'
                                    date = self.dest_dates.get(uid, b'02-Jan-2020 03:04:05 +0000') if user == 'destination' else b'02-Jan-2020 03:04:05 +0000'
                                    client.sendall(b'* '+str(uid).encode()+b' FETCH (UID '+str(uid).encode()+b' FLAGS ('+flags+b') INTERNALDATE "'+date+b'" RFC822.SIZE '+str(size).encode()+b')\r\n')
                        else:
                            match = re.fullmatch(rb'FETCH (\d+) (.*)',args[0])
                            assert match, args
                            uid = int(match.group(1)); request = match.group(2)
                            if uid <= len(self.messages[user]) and self.messages[user][uid-1] is not None:
                                body = self.messages[user][uid-1]
                                prefix = b'* '+str(uid).encode()+b' FETCH (UID '+str(uid).encode()
                                if self.source_fetch_no and user=='source':
                                    client.sendall(tag+b' NO [AUTHENTICATIONFAILED] PRIVATE expired token\r\n'); continue
                                if request == b'(UID RFC822.SIZE)':
                                    client.sendall(prefix+b' RFC822.SIZE '+str(len(body) + (1 if self.bad_size and user == 'source' and uid == 1 else 0)).encode()+b')\r\n')
                                else:
                                    assert request == b'(UID FLAGS INTERNALDATE BODY.PEEK[])'
                                    self.body_fetches[user] += 1
                                    if (not self.failed_body and mode.endswith('source-fault') and user == 'source') or (mode.endswith('destination-fault') and user == 'destination'):
                                        self.failed_body = True
                                        if user == 'source':
                                            self.source_validity += 1
                                            client.sendall(prefix+b' BODY[] {999}\r\npartial')
                                        else:
                                            client.sendall(b'* GARBAGE PRIVATE_MAIL_BODY\r\n')
                                        return
                                    if self.restart_once and user == 'source':
                                        self.restart_once = False
                                        self.stopped = True; self.listener.close()
                                        client.sendall(prefix+b' BODY[] {999}\r\npartial')
                                        def restart():
                                            time.sleep(2)
                                            listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                                            listener.bind(('127.0.0.1',self.port)); listener.listen(10); listener.settimeout(.2)
                                            self.listener = listener; self.stopped = False; self.serve()
                                        threading.Thread(target=restart,daemon=True).start()
                                        return
                                    flags = self.dest_flags.get(uid, b'\\Seen') if user == 'destination' else b'\\Seen'
                                    date = self.dest_dates.get(uid, b'02-Jan-2020 03:04:05 +0000') if user == 'destination' else b'02-Jan-2020 03:04:05 +0000'
                                    payload = prefix+b' FLAGS ('+flags+b') INTERNALDATE "'+date+b'" BODY[] {'+str(len(body)).encode()+b'}\r\n'+body+b')\r\n'
                                    if user == 'source' and self.stall_source_fetch_at is not None and len(payload) > self.stall_source_fetch_at:
                                        client.sendall(payload[:self.stall_source_fetch_at]); time.sleep(30); return
                                    if user == 'source' and self.truncate_source_fetch_at is not None and len(payload) > self.truncate_source_fetch_at:
                                        client.sendall(payload[:self.truncate_source_fetch_at]); return
                                    if user == 'destination' and self.truncate_dest_fetch_at is not None and len(payload) > self.truncate_dest_fetch_at:
                                        client.sendall(payload[:self.truncate_dest_fetch_at]); return
                                    if user == 'source' and self.pause_source_fetch_at is not None and len(payload) > self.pause_source_fetch_at:
                                        client.sendall(payload[:self.pause_source_fetch_at]); self.source_paused.set()
                                        assert self.resume_source_fetch.wait(120), 'test never resumed the source'
                                        client.sendall(payload[self.pause_source_fetch_at:])
                                    elif self.slow:
                                        for offset in range(0, len(payload), 4096):
                                            client.sendall(payload[offset:offset+4096]); time.sleep(.08)
                                    else: client.sendall(payload)
                    elif verb == b'APPEND':
                        assert user == 'destination'
                        match = re.search(rb'\{(\d+)\}$',line.strip()); assert match
                        n = int(match.group(1))
                        if self.drop_on_append: return
                        if self.pause_continuation: self.hook('continuation')
                        if self.rejection_script:
                            rejection=self.rejection_script.pop(0)
                            if rejection == b'-':  # code-less NO
                                client.sendall(tag+b' NO PRIVATE rejection\r\n'); continue
                            if rejection:
                                client.sendall(tag+b' NO ['+rejection+b'] PRIVATE rejection\r\n'); continue
                        if self.reject_once:
                            self.reject_once = False
                            client.sendall((b'wrong-tag' if self.wrong_rejection_tag else tag)+b' NO [OVERQUOTA] PRIVATE quota\r\n'); continue
                        client.sendall(b'+ ready\r\n')
                        if self.stall_append_after is not None:
                            reader.read(min(self.stall_append_after, n)); time.sleep(30); return
                        if self.slow_upload:
                            chunks=[]; left=n+2; chunk_number=0
                            while left:
                                part=reader.read(min(left,4096)); assert part
                                chunks.append(part); left-=len(part); chunk_number+=1
                                if chunk_number % 64 == 0: client.sendall(b'* OK upload progress\r\n')
                                time.sleep(.001)
                            data=b''.join(chunks)
                        else: data = reader.read(n+2)
                        assert len(data) == n+2 and data.endswith(b'\r\n')
                        if self.reject_after:
                            self.reject_after = False
                            client.sendall(tag+b' NO [TOOBIG] PRIVATE size\r\n'); continue
                        if self.append_wait:
                            self.injected = True
                            for _ in range(20):
                                client.sendall(b'* OK progress\r\n'); time.sleep(.1)
                        self.messages[user].append(data[:-2])
                        if self.pause_append_reply: self.hook('append_reply')
                        if self.drop_reply_after_commit: return
                        client.sendall(tag+b' OK [APPENDUID '+str(self.append_validity).encode()+b' '+str(self.append_uid_override if self.append_uid_override is not None else len(self.messages[user])).encode()+b'] appended\r\n')
                        continue
                    else:
                        raise AssertionError((mode,verb))
                    client.sendall(tag+b' OK complete\r\n')
        except (OSError,ssl.SSLError): pass
        except Exception as exc: self.errors.append(repr(exc))
    def hook(self, name):
        reached, resume = self.hooks[name]
        reached.set()
        assert resume.wait(120), f'test never resumed the {name} hook'
        reached.clear(); resume.clear()
    def close(self):
        self.stopped = True; self.listener.close()
        for reached, resume in self.hooks.values(): resume.set()


def connect(port, cert, user):
    m = imaplib.IMAP4_SSL('localhost', port, ssl_context=ssl.create_default_context(cafile=cert))
    m.login(user, PASSWORD)
    return m

def select(m, folder):
    assert m.select(quoted(folder), readonly=True)[0] == 'OK'

def snapshot(m, folders):
    result = {}
    for f in folders:
        select(m, f)
        validity = m.response('UIDVALIDITY')[1][0]
        typ, data = m.uid('SEARCH', None, 'ALL')
        assert typ == 'OK'
        rows = []
        for uid in data[0].split():
            typ, fetched = m.uid('FETCH', uid, '(UID FLAGS INTERNALDATE BODY.PEEK[])')
            assert typ == 'OK'
            head, body = next(v for v in fetched if isinstance(v, tuple))
            flags = tuple(sorted(x for x in imaplib.ParseFlags(head) if x != b'\\Recent'))
            date = re.search(rb'INTERNALDATE "([^"]+)"', head).group(1)
            rows.append((uid, hashlib.sha256(body).hexdigest(), flags, date))
        result[f] = (validity, rows)
    return result

def main():
    from freshness import require_fresh
    require_fresh(BIN)
    with tempfile.TemporaryDirectory(prefix='imaplane-e2e-') as tmp:
        tmp = Path(tmp)
        cert, key = tmp / 'tls.crt', tmp / 'tls.key'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        password = tmp / 'password'
        password.write_text(PASSWORD + '\n'); password.chmod(0o600)
        containers, proxies, clients = [], [], []
        try:
            ports = []; starttls_ports = []
            for role in ['source', 'destination']:
                name = f'imaplane-e2e-{role}-{uuid.uuid4().hex[:8]}'
                command('docker', 'run', '-d', '--name', name, '-p', '127.0.0.1::993', '-p', '127.0.0.1::143', '-v', f'{ROOT}/tests/local/dovecot.conf:/etc/dovecot/dovecot.conf:ro', '-v', f'{cert}:/etc/dovecot/tls.crt:ro', '-v', f'{key}:/etc/dovecot/tls.key:ro', IMAGE)
                containers.append(name)
                port = int(command('docker', 'port', name, '993/tcp').rsplit(':', 1)[1])
                ports.append(port)
                starttls_ports.append(int(command('docker','port',name,'143/tcp').rsplit(':',1)[1]))
                for attempt in range(100):
                    try:
                        m = connect(port, str(cert), 'fixture'); m.logout(); break
                    except (OSError, imaplib.IMAP4.error):
                        time.sleep(.1)
                else:
                    raise AssertionError(command('docker', 'logs', name))
            src = connect(ports[0], str(cert), 'source'); clients.append(src)
            dst = connect(ports[1], str(cert), 'destination'); clients.append(dst)
            unicode_folder = '台北/📬 & "quoted" \\ folder'
            folders = ['INBOX', unicode_folder]
            assert src.create(quoted(unicode_folder))[0] == 'OK'
            message = b'From: a@example.test\r\nTo: b@example.test\r\nMessage-ID: <duplicate@example.test>\r\nSubject: test\r\n\r\noriginal body\r\n'
            for _ in range(2):
                assert src.append('INBOX', None, '"02-Jan-2020 03:04:05 +0000"', message)[0] == 'OK'
            binary = b'From: a@example.test\r\nSubject: attachment\r\nContent-Transfer-Encoding: base64\r\n\r\n' + base64.encodebytes(bytes(range(256)) * 4096).replace(b'\n', b'\r\n')
            assert src.append(quoted(unicode_folder), '(\\Seen \\Flagged custom-keyword \\Deleted)', '"12-Feb-2021 04:05:06 +0530"', binary)[0] == 'OK'
            assert dst.append('INBOX', '(\\Seen)', '"01-Jan-2019 00:00:00 +0000"', b'Subject: preexisting\r\n\r\nkeep me\r\n')[0] == 'OK'
            before = snapshot(src, folders)
            before_dst = snapshot(dst, ['INBOX'])
            sp = Proxy(ports[0], str(cert), str(key), drop_fetch=True); proxies.append(sp)
            dp = Proxy(ports[1], str(cert), str(key)); proxies.append(dp)
            def config(name, source_port=sp.port, destination_port=dp.port, folder_list=None, ca=True, limit=64*1024*1024, auth='auto'):
                folder_list = folder_list or [(f,f) for f in folders]
                p = tmp / f'{name}.toml'
                c = f'state_dir = "{tmp / name}"\nmax_message_bytes = {limit}\ntimeout_seconds = 5\n{STREAM_EXTRA}'
                for role, port, user in [('source',source_port,'source'),('destination',destination_port,'destination')]:
                    c += f'[{role}]\nhost = "localhost"\nport = {port}\nusername = "{user}"\npassword_file = "{password}"\nauth = "{auth}"\n'
                    if ca: c += f'ca_file = "{cert}"\n'
                for source, destination in folder_list:
                    c += '\n[[folders]]\nsource = ' + json.dumps(source, ensure_ascii=False) + '\ndestination = ' + json.dumps(destination, ensure_ascii=False) + '\n'
                p.write_text(c)
                return p
            cfg = config('normal')
            def run(*args, code=0):
                p = subprocess.run([str(BIN), *map(str,args)], capture_output=True, text=True, timeout=90)
                assert p.returncode == code, (args, p.returncode, p.stdout, p.stderr)
                assert PASSWORD not in p.stdout + p.stderr
                return json.loads(p.stdout) if p.stdout else None
            # Actual TLS sessions exercise the negotiated wire encoding, including a
            # server returning tagged OK without enabling the requested capability.
            for mode in ['rev1','dual','rev2','utf8','dual-noack','utf8-noack']:
                server = ProtocolServer(str(cert),str(key),mode); proxies.append(server)
                protocol_cfg = config('protocol-'+mode,source_port=server.port,destination_port=server.port,folder_list=[('台北/📬','台北/📬')])
                if mode == 'utf8-noack':
                    run('inspect','--config',protocol_cfg,code=1)
                else:
                    protocol_names = run('inspect','--config',protocol_cfg)
                    assert protocol_names['source'][0]['name'] == '台北/📬'
                    protocol_report = run('migrate','--config',protocol_cfg,'--json')
                    assert protocol_report['complete'] and len(protocol_report['entries']) == 1
                    run('migrate','--config',protocol_cfg,'--json')
                    assert len(server.messages['destination']) == 1
                    run('verify','--config',protocol_cfg,'--json')
                    server.source_validity = 78
                    run('migrate','--config',protocol_cfg,'--json',code=1)
                    assert len(server.messages['destination']) == 1
                    server.source_validity = 77
                    server.destination_validity = 78
                    changed = run('verify','--config',protocol_cfg,'--json',code=2)
                    assert changed['entries'][0]['result'] == 'destination_changed'
                    run('migrate','--config',protocol_cfg,'--json',code=2)
                    assert len(server.messages['destination']) == 1
                    server.destination_validity = 77
                    original = server.messages['destination'][0]
                    server.messages['destination'][0] = b'Subject: corrupted\r\n\r\nchanged\r\n'
                    changed = run('verify','--config',protocol_cfg,'--json',code=2)
                    assert changed['entries'][0]['result'] == 'mismatch'
                    server.messages['destination'][0] = original
                    run('verify','--config',protocol_cfg,'--json')
            for fault in ['source-fault','destination-fault']:
                server = ProtocolServer(str(cert),str(key),'dual-'+fault); proxies.append(server)
                server.messages['source'] *= 2
                fault_cfg = config('fault-'+fault,source_port=server.port,destination_port=server.port,folder_list=[('台北/📬','台北/📬')])
                failed = run('migrate','--config',fault_cfg,'--json',code=2)
                assert len(failed['entries']) == 1 and failed['entries'][0]['result'] == 'failed'
                assert 'PRIVATE_MAIL_BODY' not in json.dumps(failed)
                assert len(server.messages['destination']) == (0 if fault == 'source-fault' else 1)
                if fault == 'destination-fault':
                    server.mode = 'dual'
                    run('migrate','--config',fault_cfg,'--json')
                    assert len(server.messages['destination']) == 2
            missing_uids = ProtocolServer(str(cert),str(key),'dual'); proxies.append(missing_uids)
            missing_uids.missing_inventory = True
            inventory_cfg = config('missing-inventory',source_port=missing_uids.port,destination_port=missing_uids.port,folder_list=[('台北/📬','台北/📬')])
            run('migrate','--config',inventory_cfg,'--json',code=1)
            assert not missing_uids.messages['destination'], 'incomplete inventory was reported as a successful empty migration'
            # A realistic large single-line literal at the configured cap, then one
            # byte over it. The latter must fail before APPEND, not bypass the cap.
            large = ProtocolServer(str(cert),str(key),'dual'); proxies.append(large)
            cap = 16*1024*1024
            large.messages['source'] = [b'Subject: large\r\n\r\n' + b'x'*(cap-len(b'Subject: large\r\n\r\n'))]
            large_cfg = config('large',source_port=large.port,destination_port=large.port,folder_list=[('台北/📬','台北/📬')],limit=cap)
            run('migrate','--config',large_cfg,'--json')
            assert large.messages['destination'] == large.messages['source']
            run('verify','--config',large_cfg,'--json')
            run('migrate','--config',large_cfg,'--json')
            assert len(large.messages['destination']) == 1
            large.messages['source'][0] += b'x'
            large.messages['destination'].clear()
            over_cfg = config('over-limit',source_port=large.port,destination_port=large.port,folder_list=[('台北/📬','台北/📬')],limit=cap)
            over = run('migrate','--config',over_cfg,'--json',code=2)
            assert over['entries'][0]['result'] == 'skipped_permanent' and not large.messages['destination']
            auth_server = ProtocolServer(str(cert),str(key),'dual-bad-auth'); proxies.append(auth_server)
            auth_cfg = config('bad-auth',source_port=auth_server.port,destination_port=auth_server.port,folder_list=[('台北/📬','台北/📬')])
            run('inspect','--config',auth_cfg,code=1)
            hostname_cfg = config('wrong-hostname')
            hostname_cfg.write_text(hostname_cfg.read_text().replace('host = "localhost"','host = "127.0.0.1"'))
            run('inspect','--config',hostname_cfg,code=1)
            discovered = run('inspect','--config',cfg)
            assert any(f['name'] == unicode_folder for f in discovered['source']), (discovered, unicode_folder)
            run('migrate','--config',cfg,'--dry-run')
            assert not (tmp / 'normal').exists()
            assert snapshot(dst, ['INBOX']) == before_dst
            first = run('migrate','--config',cfg,'--json')
            assert first['complete'] and len(first['entries']) == 3
            assert any('\\Deleted' in e['omitted_flags'] for e in first['entries'])
            assert snapshot(src, folders) == before, 'source message data/flags/identity changed'
            copied = snapshot(dst, folders)
            assert len(copied['INBOX'][1]) == 3
            assert copied['INBOX'][1][0] == before_dst['INBOX'][1][0], 'existing destination message changed'
            run('migrate','--config',cfg,'--json')
            assert snapshot(dst, folders) == copied, 'resume duplicated mail'
            run('verify','--config',cfg,'--json')
            assert snapshot(src, folders) == before
            # New arrivals are outside the durable snapshot.
            src.append('INBOX', None, None, b'Subject: later arrival\r\n\r\nlater\r\n')
            after_arrival = snapshot(src,folders)
            run('migrate','--config',cfg,'--json')
            assert snapshot(dst, folders) == copied
            # A destination flag change is drift: reported by verify and migrate, never a demotion,
            # and migrate does not re-upload.
            victim = next(e['destination_uid'] for e in first['entries'] if e['source_folder'] == 'INBOX')
            dst.select('INBOX'); dst.uid('STORE', str(victim), '+FLAGS.SILENT', '(\\Seen)')
            check = run('verify','--config',cfg,'--json')
            assert any(e['result'] == 'drift' and e['level'] == 'full' for e in check['entries']) and check['complete']
            assert not any(e['result'] == 'mismatch' for e in check['entries'])
            again = run('migrate','--config',cfg,'--json')
            assert any(e['result'] == 'drift' for e in again['entries'])
            assert len(snapshot(dst, ['INBOX'])['INBOX'][1]) == 3
            dst.select('INBOX'); dst.uid('STORE', str(victim), '-FLAGS.SILENT', '(\\Seen)')
            run('verify','--config',cfg,'--json')
            # Exclusive lock is acquired before network activity.
            with open(tmp / 'normal/job.lock','r+') as locked:
                fcntl.flock(locked,fcntl.LOCK_EX | fcntl.LOCK_NB)
                run('migrate','--config',cfg,'--json',code=1)
            # Trust failures must never fall back to plaintext.
            bad_tls = config('bad-tls', ca=False)
            run('inspect','--config',bad_tls,code=1)
            # Size limits refuse copying without modifying the source.
            small = config('small', folder_list=[(unicode_folder,'limited')],limit=1024)
            small_report = run('migrate','--config',small,'--json',code=2)
            assert any(e['result'] == 'skipped_permanent' for e in small_report['entries'])
            # LOGIN as well as SASL PLAIN over TLS.
            login = config('login',auth='login')
            run('inspect','--config',login)
            # Drop a successful APPEND confirmation, then prove resume creates no duplicates.
            loss = Proxy(ports[1],str(cert),str(key),drop_append=True); proxies.append(loss)
            loss_cfg = config('loss',destination_port=loss.port,folder_list=[('INBOX','lost-reply')])
            lost = run('migrate','--config',loss_cfg,'--json',code=2)
            assert lost['entries'][0]['result'] == 'uncertain'
            lost_count = len(snapshot(dst,['lost-reply'])['lost-reply'][1])
            resumed = run('migrate','--config',loss_cfg,'--json',code=2)
            uncertain = next(e for e in resumed['entries'] if e['result'] == 'uncertain')
            assert len(uncertain['candidate_uids']) >= 1
            # The other snapshot messages may copy, but the uncertain UID is never blindly retried.
            after_loss = snapshot(dst,['lost-reply'])
            run('migrate','--config',loss_cfg,'--json',code=2)
            assert snapshot(dst,['lost-reply']) == after_loss
            resolved = run('resolve','--config',loss_cfg,'--folder','INBOX','--uid',uncertain['source_uid'],'--destination-uid',uncertain['candidate_uids'][0],'--json',code=2)
            assert resolved['entries'][0]['result'] == 'confirmed'
            run('verify','--config',loss_cfg,'--json')
            assert len(snapshot(dst,['lost-reply'])['lost-reply'][1]) == 3
            # SIGINT lets the in-flight APPEND finish, then stops between operations.
            paused = Proxy(ports[1],str(cert),str(key),pause_append=True); proxies.append(paused)
            paused_cfg = config('interrupt',destination_port=paused.port,folder_list=[('INBOX','interrupt')])
            proc = subprocess.Popen([str(BIN),'migrate','--config',str(paused_cfg),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            assert paused.append_committed.wait(20)
            proc.send_signal(signal.SIGINT)
            time.sleep(.1)
            paused.resume_append.set()
            out, err = proc.communicate(timeout=30)
            assert proc.returncode == 2, (out,err)
            assert json.loads(out)['interrupted']
            run('migrate','--config',paused_cfg,'--json')
            assert len(snapshot(dst,['interrupt'])['interrupt'][1]) == 3
            # SIGKILL while APPEND has committed leaves durable uncertainty.
            killed = Proxy(ports[1],str(cert),str(key),pause_append=True); proxies.append(killed)
            killed_cfg = config('killed',destination_port=killed.port,folder_list=[('INBOX','killed')])
            proc = subprocess.Popen([str(BIN),'migrate','--config',str(killed_cfg),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            assert killed.append_committed.wait(20)
            proc.kill(); proc.communicate(timeout=10); killed.resume_append.set()
            journal = run('status','--state',tmp / 'killed/journal.sqlite3','--json',code=2)
            assert journal['uncertain'] == 1
            recovered = run('migrate','--config',killed_cfg,'--json',code=2)
            u = next(e for e in recovered['entries'] if e['result'] == 'uncertain')
            count_after = len(snapshot(dst,['killed'])['killed'][1])
            run('migrate','--config',killed_cfg,'--json',code=2)
            assert len(snapshot(dst,['killed'])['killed'][1]) == count_after == 3
            run('resolve','--config',killed_cfg,'--folder','INBOX','--uid',u['source_uid'],'--destination-uid',u['candidate_uids'][0],'--json',code=2)
            run('verify','--config',killed_cfg,'--json')
            # Kill after APPENDUID is durably accepted, before destination read-back.
            accepted_proxy = Proxy(ports[1],str(cert),str(key),pause_verify=True); proxies.append(accepted_proxy)
            accepted_cfg = config('accepted',destination_port=accepted_proxy.port,folder_list=[('INBOX','accepted')])
            proc = subprocess.Popen([str(BIN),'migrate','--config',str(accepted_cfg),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            assert accepted_proxy.verify_waiting.wait(20)
            proc.kill(); proc.communicate(timeout=10); accepted_proxy.resume_verify.set()
            journal = run('status','--state',tmp / 'accepted/journal.sqlite3','--json',code=2)
            assert journal['accepted'] == 1 and journal['uncertain'] == 0
            run('migrate','--config',accepted_cfg,'--json')
            assert len(snapshot(dst,['accepted'])['accepted'][1]) == 3
            assert snapshot(src,folders) == after_arrival, 'source changed during recovery tests'
            # Destination deletion is reported, never compensated by a duplicate upload.
            dst.select('INBOX'); dst.uid('STORE',str(victim),'+FLAGS.SILENT','(\\Deleted)'); dst.expunge()
            missing = run('verify','--config',cfg,'--json',code=2)
            assert any(e['result'] == 'missing' for e in missing['entries'])
            run('migrate','--config',cfg,'--json',code=2)
            assert len(snapshot(dst,['INBOX'])['INBOX'][1]) == 2
            # Real Dovecot migration with mandatory STARTTLS at both endpoints.
            real_starttls = config('real-starttls',source_port=starttls_ports[0],destination_port=starttls_ports[1],folder_list=[('INBOX','starttls-real')])
            real_starttls.write_text(real_starttls.read_text().replace('host = "localhost"','security = "starttls"\nhost = "localhost"'))
            run('migrate','--config',real_starttls,'--json')
            run('verify','--config',real_starttls,'--json')
            assert len(snapshot(dst,['starttls-real'])['starttls-real'][1]) == 3
            assert snapshot(src,folders) == after_arrival
            # The source adapter's entire transcript must stay inside this allowlist.
            allowed = {'CAPABILITY','AUTHENTICATE','LOGIN','ENABLE','LIST','EXAMINE','UID'}
            for verb, args in sp.commands:
                assert verb in allowed, (verb,args)
                if verb == 'UID':
                    assert args.startswith(('SEARCH ', 'FETCH ')), args
                    if 'BODY' in args:
                        assert 'BODY.PEEK[]' in args, args
            assert not sp.drop_fetch, 'source retry fault was not exercised'
            assert not loss.drop_append, 'APPEND reply loss was not exercised'
            assert all(not p.errors for p in proxies), [p.errors for p in proxies]
            print('PASS: TLS, authentication, Unicode discovery/copy, literal bytes, dates/flags, duplicates, source immutability, source-read reconnect, snapshot resume, verification mismatch, locking, size limits, lost APPEND reply, audited attribution, source wire allowlist, rev1/rev2 wire negotiation and transfer, UIDVALIDITY changes, content corruption, missing destination messages, SIGINT and SIGKILL')
        finally:
            for p in proxies: p.close()
            for m in clients:
                with contextlib.suppress(Exception): m.logout()
            for name in reversed(containers):
                subprocess.run(['docker','rm','-f',name], stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__ == '__main__':
    main()
