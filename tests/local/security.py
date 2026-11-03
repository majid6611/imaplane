#!/usr/bin/env python3
"""TLS/XOAUTH2/STARTTLS adversarial fixtures; synthetic credentials, no providers."""
import base64
import contextlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'target/debug/imaplane').resolve()
TOKEN = 'synthetic-token-v1'

class Server:
    def __init__(self, cert, key, security='tls', fault=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert,key)
        self.socket = socket.socket(); self.socket.bind(('127.0.0.1',0)); self.socket.listen(8); self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.security, self.fault = security,fault
        self.stop = False; self.errors = []; self.plain_commands = []; self.auth_count = 0
        self.dropped = False; self.token_path = None
        self.expected_token = TOKEN
        threading.Thread(target=self.serve,daemon=True).start()
    def serve(self):
        while not self.stop:
            try: conn,_ = self.socket.accept()
            except socket.timeout: continue
            except OSError: return
            threading.Thread(target=self.connection,args=(conn,),daemon=True).start()
    def connection(self, conn):
        try:
            if self.security == 'starttls':
                conn.sendall(b'* OK clear greeting\r\n')
                f = conn.makefile('rb',buffering=0)
                line = f.readline(); tag,verb,*_ = line.strip().split(b' ')
                self.plain_commands.append(verb)
                assert verb == b'CAPABILITY', line
                caps = b'IMAP4rev1 AUTH=PLAIN' + (b'' if self.fault == 'missing' else b' STARTTLS')
                conn.sendall(b'* CAPABILITY '+caps+b'\r\n'+tag+b' OK caps\r\n')
                line = f.readline()
                if self.fault == 'missing': assert not line; return
                tag,verb,*_ = line.strip().split(b' '); self.plain_commands.append(verb)
                assert verb == b'STARTTLS', line
                if self.fault == 'refuse':
                    conn.sendall(tag+b' NO unavailable\r\n'); assert not f.readline(); return
                conn.sendall(tag+b' OK begin TLS\r\n'); f.close()
                if self.fault == 'downgrade':
                    conn.sendall(b'* OK still plaintext\r\n'); return
            if self.fault == 'slow-handshake':
                for byte in b'\x16\x03\x03\x00\x20' + b'\x00'*32:
                    conn.sendall(bytes([byte])); time.sleep(.6)
                return
            with self.ctx.wrap_socket(conn,server_side=True) as tls:
                f = tls.makefile('rb')
                if self.security == 'tls': tls.sendall(b'* OK encrypted greeting\r\n')
                while True:
                    line = f.readline()
                    if not line: return
                    parts = line.strip().split(b' ',2); tag,verb = parts[:2]
                    if verb == b'CAPABILITY':
                        # Deliberately different from pre-TLS capabilities.
                        caps = b'IMAP4rev1 UIDPLUS AUTH=XOAUTH2 AUTH=PLAIN'
                        if self.fault == 'no-xoauth': caps = b'IMAP4rev1 UIDPLUS AUTH=PLAIN'
                        tls.sendall(b'* CAPABILITY '+caps+b'\r\n')
                    elif verb == b'AUTHENTICATE':
                        assert parts[2] == b'XOAUTH2', 'password fallback attempted'
                        self.auth_count += 1
                        tls.sendall(b'+ \r\n')
                        response = base64.b64decode(f.readline())
                        assert response in [f'user={u}\x01auth=Bearer {self.expected_token}\x01\x01'.encode() for u in ['source','destination']]
                        if self.fault == 'auth':
                            tls.sendall(b'+ '+base64.b64encode(b'{"status":"401"}')+b'\r\n')
                            assert f.readline() == b'\r\n', 'token repeated on error challenge'
                            tls.sendall(tag+b' NO token '+self.expected_token.encode()+b'\r\n')
                            assert not f.readline(); return
                    elif verb == b'LIST':
                        if self.fault == 'reconnect' and not self.dropped:
                            self.dropped = True; self.expected_token = 'renewed-on-reconnect'
                            self.token_path.write_text(self.expected_token+'\n')
                            return
                        if self.fault == 'parse':
                            tls.sendall(b'* INVALID PRIVATE_MAIL_BODY '+self.expected_token.encode()+b'\r\n')
                            return
                    else: raise AssertionError(('unexpected verb',verb))
                    tls.sendall(tag+b' OK complete\r\n')
        except (OSError,ssl.SSLError): pass
        except Exception as exc: self.errors.append(repr(exc))
        finally:
            conn.close()
    def close(self): self.stop = True; self.socket.close()

with tempfile.TemporaryDirectory(prefix='imaplane-security-') as td:
    td = Path(td); cert,key = td/'cert.pem',td/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    token = td/'token'; token.write_text(TOKEN+'\n'); token.chmod(0o600)
    servers = []
    def config(server, trust=True, host='localhost'):
        p = td/'migration.toml'
        text = f'state_dir = "{td}/state"\ntimeout_seconds = 2\n'
        for role in ['source','destination']:
            text += f'[{role}]\nhost = "{host}"\nport = {server.port}\nusername = "{role}"\nauth = "xoauth2"\nsecurity = "{server.security}"\naccess_token_file = "{token}"\n'
            if trust: text += f'ca_file = "{cert}"\n'
        p.write_text(text); return p
    def run(server,code=0,**opts):
        result = subprocess.run([str(BIN),'inspect','--config',str(config(server,**opts))],capture_output=True,text=True,timeout=10)
        assert result.returncode == code,(server.fault,result.returncode,result.stdout,result.stderr)
        assert TOKEN not in result.stdout+result.stderr
        assert 'PRIVATE_MAIL_BODY' not in result.stdout+result.stderr
        if code == 0: assert json.loads(result.stdout) == {'source':[],'destination':[]}
    try:
        for security in ['tls','starttls']:
            s = Server(str(cert),str(key),security); servers.append(s)
            run(s)
            assert s.auth_count == 2
            # Token rotation is consumed on each new connection.
            token.write_text('rotated-token-v2\n'); s.expected_token = 'rotated-token-v2'
            run(s); token.write_text(TOKEN+'\n'); s.expected_token = TOKEN
            run(s,code=1,host='127.0.0.1')
            run(s,code=1,trust=False)
            renewal = Server(str(cert),str(key),security,'reconnect'); renewal.token_path = token; servers.append(renewal)
            run(renewal); assert renewal.auth_count == 3
            token.write_text(TOKEN+'\n')
            for fault in ['auth','no-xoauth','parse']:
                f = Server(str(cert),str(key),security,fault); servers.append(f); run(f,code=1)
        for security in ['tls','starttls']:
            slow = Server(str(cert),str(key),security,'slow-handshake'); servers.append(slow)
            started = time.monotonic(); run(slow,code=1)
            assert time.monotonic()-started < 4, 'TLS handshake deadline did not bound slow peer'
        tls12 = Server(str(cert),str(key)); tls12.ctx.maximum_version = ssl.TLSVersion.TLSv1_2; servers.append(tls12)
        run(tls12)
        expired_key, csr, expired = td/'expired.key',td/'expired.csr',td/'expired.crt'
        subprocess.run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(expired_key),'-out',str(csr),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['openssl','x509','-req','-in',str(csr),'-CA',str(cert),'-CAkey',str(key),'-CAcreateserial','-days','-1','-copy_extensions','copy','-out',str(expired)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        expired_server = Server(str(expired),str(expired_key)); servers.append(expired_server)
        run(expired_server,code=1); assert expired_server.auth_count == 0
        for fault in ['missing','refuse','downgrade']:
            s = Server(str(cert),str(key),'starttls',fault); servers.append(s); run(s,code=1)
            assert s.auth_count == 0
        s = Server(str(cert),str(key)); servers.append(s)
        for invalid in ['abc\x01def','abc def','abc\nxyz','']:
            token.write_text(invalid); run(s,code=1)
        token.write_text(TOKEN); token.chmod(0o644); run(s,code=1); token.chmod(0o600)
        # A FIFO must be rejected without blocking in open(), even without a writer.
        token.unlink(); os.mkfifo(token,0o600); run(s,code=1)
        assert all(not s.errors for s in servers),[s.errors for s in servers]
        assert all(all(v in [b'CAPABILITY',b'STARTTLS'] for v in s.plain_commands) for s in servers)
        print('PASS: XOAUTH2 payloads/error challenge/no fallback/token rotation; STARTTLS upgrade/refusal/downgrade; trust and hostname rejection; no plaintext secrets; sanitized diagnostics; token file validation and FIFO rejection')
    finally:
        for s in servers: s.close()
