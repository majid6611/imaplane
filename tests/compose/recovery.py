#!/usr/bin/env python3
"""Deterministic SIGINT/SIGKILL tests around a committed APPEND response."""
import contextlib
import json
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from fixture import LAB, FOLDERS, TOTAL, check_source, check_destination, cli, context, render_config, snapshot, validate_config, write_json

class Gate:
    """Test-only TLS-to-TLS proxy. Waits after APPEND commits but before its OK.
    No application command/body logging. Both TLS hops validate the lab CA.
    """
    def __init__(self):
        self.listener=socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.listener.bind(('127.0.0.1',19993)); self.listener.listen(8); self.listener.settimeout(.2)
        self.server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server.load_cert_chain(LAB/'proxy.crt',LAB/'proxy.key')
        self.upstream=context()
        self.committed=threading.Event(); self.release=threading.Event()
        self.armed=True; self.stop=False; self.sockets=[]; self.errors=[]
        self.thread=threading.Thread(target=self.accept,daemon=True); self.thread.start()
    def accept(self):
        while not self.stop:
            try: raw,_=self.listener.accept()
            except socket.timeout: continue
            except OSError: return
            threading.Thread(target=self.connection,args=(raw,),daemon=True).start()
    def connection(self,raw):
        import re
        try:
            with self.server.wrap_socket(raw,server_side=True) as client:
                with self.upstream.wrap_socket(socket.create_connection(('destination',993),timeout=15),server_hostname='destination') as server:
                    self.sockets.extend([client,server])
                    with client.makefile('rb') as cf, server.makefile('rb') as sf:
                        client.sendall(sf.readline())
                        while True:
                            line=cf.readline()
                            if not line: return
                            tag,verb,*_=line.strip().split(b' ',2)
                            server.sendall(line)
                            if verb==b'AUTHENTICATE':
                                continuation=sf.readline(); client.sendall(continuation)
                                assert continuation.startswith(b'+')
                                server.sendall(cf.readline())
                            if verb==b'APPEND':
                                continuation=sf.readline(); client.sendall(continuation)
                                assert continuation.startswith(b'+')
                                n=int(re.search(rb'\{(\d+)\}\r\n$',line).group(1))
                                body=cf.read(n+2); assert len(body)==n+2
                                server.sendall(body)
                            while True:
                                response=sf.readline()
                                if not response: return
                                if response.startswith(tag+b' ') and verb==b'APPEND' and self.armed:
                                    assert response.startswith(tag+b' OK ')
                                    self.armed=False; self.committed.set()
                                    assert self.release.wait(45),'Gate was not released'
                                client.sendall(response)
                                literal=re.search(rb'\{(\d+)\}\r\n$',response)
                                if literal:
                                    n=int(literal.group(1)); data=sf.read(n); assert len(data)==n
                                    client.sendall(data)
                                if response.startswith(tag+b' '): break
        except (OSError,ssl.SSLError): pass # Expected after SIGKILL, EOF and orderly teardown.
        except Exception as e: self.errors.append(repr(e))
    def close(self):
        self.stop=True; self.release.set(); self.listener.close()
        for s in self.sockets:
            with contextlib.suppress(OSError): s.shutdown(socket.SHUT_RDWR); s.close()
        self.thread.join(2)

def scenario(kind):
    name='interrupt' if kind=='sigint' else 'crash'
    prefix=f'Recovery-{name}/'
    state=LAB/'state'/name
    if state.exists():
        raise RuntimeError('Recovery state already exists; run scripts/lab.sh reset before repeating recovery scenarios')
    config=LAB/f'{name}.toml'
    config.write_text(render_config([(f,prefix+f) for f in FOLDERS],state=f'./state/{name}',proxy=True)); config.chmod(0o600)
    validate_config(config,proxy=True)
    gate=Gate(); process=None
    try:
        process=subprocess.Popen(['/usr/local/bin/imaplane','migrate','--config',str(config),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if not gate.committed.wait(30):
            process.kill(); out,err=process.communicate(timeout=10)
            raise RuntimeError(f'APPEND gate was not reached: {out}\n{err}')
        if kind=='sigint':
            process.send_signal(signal.SIGINT); time.sleep(.15); gate.release.set()
            out,err=process.communicate(timeout=45)
            assert process.returncode==2,(out,err)
            report=json.loads(out); assert report['interrupted'] and not report['complete']
            write_json(LAB/f'reports/{name}-interrupted.json',report)
            (LAB/f'reports/{name}-interrupted.stderr.log').write_text(err)
        else:
            process.kill(); process.communicate(timeout=10); gate.release.set()
            journal=subprocess.run(['/usr/local/bin/imaplane','status','--state',str(state/'journal.sqlite3'),'--json'],capture_output=True,text=True,timeout=15)
            assert journal.returncode==2
            report=json.loads(journal.stdout); assert report['uncertain']==1
            write_json(LAB/'reports/crash-journal.json',report)
        # Same proxy endpoint/port means the journal binding remains unchanged.
        resumed=cli('migrate',config,expected=0 if kind=='sigint' else 2,name=f'{name}-resume',flags=['--json'],proxy=True)
        if kind=='sigkill':
            uncertain=[e for e in resumed['entries'] if e['result']=='uncertain']
            assert len(uncertain)==1 and len(uncertain[0]['candidate_uids'])==1
            before=snapshot('destination',[prefix+f for f in FOLDERS])
            cli('migrate',config,expected=2,name='crash-resume-again',flags=['--json'],proxy=True)
            assert snapshot('destination',[prefix+f for f in FOLDERS])==before,'Uncertain upload was duplicated'
            u=uncertain[0]
            resolved=cli('resolve',config,expected=2,name='crash-resolved',flags=['--folder',u['source_folder'],'--uid',str(u['source_uid']),'--destination-uid',str(u['candidate_uids'][0]),'--json'],proxy=True)
            assert resolved['entries'][0]['result']=='confirmed'
            resumed=cli('migrate',config,name='crash-completed',flags=['--json'],proxy=True)
        assert resumed['complete'] and len(resumed['entries'])==TOTAL
        check_destination(prefix)
        verified=cli('verify',config,name=f'{name}-verification',flags=['--json'],proxy=True)
        assert verified['complete']
        assert not gate.errors,gate.errors
        print(f'PASS {kind}: {TOTAL} confirmed transfers, no duplicate uploads, source unchanged',flush=True)
        return {'signal':kind,'passed':True,'confirmed':TOTAL,'source_unchanged':True,'duplicates_added':False,
                'uncertainty_explicit':kind=='sigkill'}
    finally:
        if process is not None and process.poll() is None:
            process.kill(); process.communicate(timeout=10)
        gate.close()

if __name__=='__main__':
    try:
        if not __debug__: raise RuntimeError('Python optimization must be disabled for lab checks')
        check_source()
        results=[scenario('sigint'),scenario('sigkill')]
        write_json(LAB/'reports/recovery-test.json',{'passed':True,'scenarios':results})
    except Exception as e:
        print(f'LAB RECOVERY FAILURE: {e}',file=sys.stderr); sys.exit(1)
