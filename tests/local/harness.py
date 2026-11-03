"""Disposable real-Dovecot fixtures. Every endpoint originates from Docker loopback mappings."""
import contextlib
import json
import imaplib
import subprocess
import time
import uuid
from pathlib import Path
from e2e import IMAGE, PASSWORD, ROOT, Proxy, command, connect, snapshot, quoted

class DovecotLab:
    def __init__(self, root):
        self.root=Path(root); self.containers=[]; self.clients=[]; self.proxies=[]; self.folders=[]
        self.cert=self.root/'tls.crt'; self.key=self.root/'tls.key'
        command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(self.key),'-out',str(self.cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost')
        self.password=self.root/'password'; self.password.write_text(PASSWORD); self.password.chmod(0o600)
    def __enter__(self):
        try:
            self.ports=[]
            for role in ['source','destination']:
                name='imaplane-baseline-'+role+'-'+uuid.uuid4().hex[:8]
                command('docker','run','-d','--name',name,'-p','127.0.0.1::993','-v',f'{ROOT}/tests/local/dovecot.conf:/etc/dovecot/dovecot.conf:ro','-v',f'{self.cert}:/etc/dovecot/tls.crt:ro','-v',f'{self.key}:/etc/dovecot/tls.key:ro',IMAGE)
                self.containers.append(name)
                port=int(command('docker','port',name,'993/tcp').rsplit(':',1)[1]); self.ports.append(port)
                for _ in range(100):
                    try:
                        client=connect(port,str(self.cert),'health'); client.logout(); break
                    except (OSError,imaplib.IMAP4.error):
                        # No external endpoint or credentials can be substituted.
                        time.sleep(.1)
                else: raise RuntimeError('disposable Dovecot did not become ready')
            self.source=self.client(0,'source')
            return self
        except BaseException:
            self.__exit__(None,None,None); raise
    def client(self, role, user):
        client=connect(self.ports[role],str(self.cert),user); self.clients.append(client); return client
    def seed(self, bodies, folder='INBOX'):
        if folder not in self.folders:
            if folder != 'INBOX': assert self.source.create(quoted(folder))[0]=='OK'
            self.folders.append(folder)
        for i,body in enumerate(bodies):
            assert self.source.append(quoted(folder),'(\\Seen)' if i%2 else None,'"02-Jan-2020 03:04:05 +0000"',body)[0]=='OK'
        self.before=snapshot(self.source,self.folders)
    def config(self, name, latency_ms=0, proxy_options=None):
        proxies=[Proxy(port,str(self.cert),str(self.key),latency_ms=latency_ms,**(proxy_options if role==1 and proxy_options else {})) for role,port in enumerate(self.ports)]
        self.proxies.extend(proxies)
        destination=self.client(1,name)
        cfg=self.root/(name+'.toml')
        text=f'state_dir = {json.dumps(str(self.root/name))}\ntimeout_seconds = 5\n'
        for role,user,proxy in [('source','source',proxies[0]),('destination',name,proxies[1])]:
            text+=f'[{role}]\nhost = "localhost"\nport = {proxy.port}\nusername = "{user}"\npassword_file = {json.dumps(str(self.password))}\nca_file = {json.dumps(str(self.cert))}\n'
        for folder in self.folders:
            text+='[[folders]]\nsource = '+json.dumps(folder)+'\ndestination = '+json.dumps(folder)+'\n'
        cfg.write_text(text); cfg.chmod(0o600)
        return cfg,destination,proxies
    def check(self, destination):
        assert snapshot(self.source,self.folders)==self.before,'source changed'
        actual=snapshot(destination,self.folders)
        for folder in self.folders:
            assert sorted(row[1:] for row in actual[folder][1])==sorted(row[1:] for row in self.before[folder][1]),'bytes/date/flags/multiplicity differ'
    def __exit__(self,*_):
        for proxy in self.proxies: proxy.close()
        for client in self.clients:
            with contextlib.suppress(Exception): client.logout()
        for name in reversed(self.containers):
            subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
