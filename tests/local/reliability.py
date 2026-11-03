#!/usr/bin/env python3
"""Loopback-only TLS reliability regressions; no Docker or real credentials."""
import json
import signal
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from e2e import BIN, PASSWORD, ProtocolServer, command, STREAM_EXTRA
from freshness import require_fresh
require_fresh(BIN)

with tempfile.TemporaryDirectory(prefix='imaplane-reliability-') as temporary:
    root = Path(temporary)
    cert, key = root/'tls.crt', root/'tls.key'
    command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost')
    secret = root/'password'; secret.write_text(PASSWORD); secret.chmod(0o600)
    servers = []
    def fixture(name, bodies=None, timeout=1, port=None):
        server = ProtocolServer(str(cert),str(key),'rev1'); servers.append(server)
        if bodies is not None: server.messages['source'] = bodies
        config = root/(name+'.toml')
        text = f'state_dir = "{root/name}"\ntimeout_seconds = {timeout}\nmax_message_bytes = 262144\nread_attempts = 4\n{STREAM_EXTRA}'
        for role in ['source','destination']:
            text += f'[{role}]\nhost = "localhost"\nport = {port or server.port}\nusername = "{role}"\npassword_file = "{secret}"\nca_file = "{cert}"\n'
        text += '[[folders]]\nsource = "台北/📬"\ndestination = "台北/📬"\n'
        config.write_text(text)
        return server, config
    def run(config, expected=0):
        p = subprocess.run([str(BIN),'migrate','--config',str(config),'--json'], capture_output=True,text=True,timeout=45)
        assert p.returncode == expected, (p.returncode,p.stdout,p.stderr)
        assert PASSWORD not in p.stdout+p.stderr and 'PRIVATE' not in p.stdout+p.stderr
        return json.loads(p.stdout)
    body = b'Subject: fixture\r\n\r\nbytes\x00\xff\r\n'
    try:
        # A single transfer lasts longer than timeout_seconds while progressing.
        s,c = fixture('slow', [body+b'x'*131072]); s.slow = True; s.append_wait = True
        start = time.monotonic(); assert run(c)['complete']; assert time.monotonic()-start > 3
        assert s.messages['destination'] == s.messages['source']
        print('PASS slow source and APPEND reply progress exceed idle timeout')
        s,c=fixture('slow-upload',[body+b'x'*(16*1024*1024)]); s.slow_upload=True
        c.write_text(c.read_text().replace('max_message_bytes = 262144','max_message_bytes = 33554432'))
        start=time.monotonic(); assert run(c)['complete']; assert time.monotonic()-start > 2
        assert s.messages['destination'] == s.messages['source']
        print('PASS throttled 16 MiB APPEND upload and exact destination bytes')
        for name, mode in [('oversized','size'),('wrong-size','metadata')]:
            bodies = [body+b'x'*262144, body] if mode == 'size' else [body,body+b'later']
            s,c = fixture(name,bodies); s.bad_size = mode == 'metadata'
            report = run(c,2)
            assert [e['result'] for e in report['entries']] == ['skipped_permanent','confirmed']
            assert s.messages['destination'] == [bodies[1]]
            assert not run(c,2)['complete']; assert len(s.messages['destination']) == 1
        print('PASS permanent message isolation and idempotent incomplete resume')
        for name, after in [('quota-before',False),('size-after',True)]:
            s,c = fixture(name,[body,body+b'second'])
            s.reject_once = not after; s.reject_after = after
            report = run(c,2)
            assert [e['result'] for e in report['entries']] == ['rejected','confirmed'], report
            with sqlite3.connect(root/name/'journal.sqlite3') as db:
                assert db.execute('select count(*) from append_rejections').fetchone()[0] == 1
                assert db.execute("select count(*) from transfers where state='uncertain'").fetchone()[0] == 0
            assert run(c)['complete']; assert sorted(s.messages['destination']) == sorted(s.messages['source'])
            run(c); assert len(s.messages['destination']) == 2
        print('PASS tagged rejections before/after literal, durable evidence, safe rerun')
        s,c = fixture('wrong-tag',[body]); s.reject_once=True; s.wrong_rejection_tag=True
        assert run(c,2)['entries'][0]['result'] == 'uncertain'
        assert run(c,2)['entries'][0]['result'] == 'uncertain'
        assert not s.messages['destination']
        assert sum(v == b'APPEND' for user,v,args in s.events) == 1
        print('PASS mismatched rejection tags remain uncertain and are never resent')
        for code in [b'UNAVAILABLE', b'THROTTLED']:
            s,c=fixture('circuit-'+code.decode(),[body+str(i).encode() for i in range(8)])
            s.rejection_script=[code]*8
            start=time.monotonic(); rejected=run(c,2)
            assert rejected['halt_reason'] and 'circuit open' in rejected['halt_reason']
            assert len(rejected['entries'])==3 and all(e['result']=='rejected' for e in rejected['entries'])
            assert time.monotonic()-start>=3
            assert sum(v==b'APPEND' for user,v,args in s.events)==3
            assert sum(v==b'UID' and b'BODY.PEEK' in args[0] for user,v,args in s.events if user=='source')==3
            with sqlite3.connect(root/('circuit-'+code.decode())/'journal.sqlite3') as db:
                assert db.execute("select count(*) from transfers where state='planned'").fetchone()[0]==3
                assert all(code.decode() in row[0] for row in db.execute('select evidence from append_rejections'))
            s.rejection_script=[]
            assert run(c)['complete']; assert len(s.messages['destination'])==8
        s,c=fixture('circuit-reset',[body+str(i).encode() for i in range(5)])
        s.rejection_script=[b'UNAVAILABLE',b'UNAVAILABLE',None,b'UNAVAILABLE',b'UNAVAILABLE']
        reset=run(c,2); assert reset['halt_reason'] is None and len(reset['entries'])==5
        assert run(c)['complete']; assert len(s.messages['destination'])==5
        print('PASS rejection circuit, interruptible backoff, coded journal evidence and successful-APPEND reset')
        for code in [b'TOOBIG',b'OVERQUOTA']:
            bodies=[body+b'x'*100000]*3+[body]*5
            s,c=fixture('head-of-line-'+code.decode(),bodies)
            s.rejection_script=[code]*3
            report=run(c,2)
            assert report['halt_reason'] is None and [e['result'] for e in report['entries']]==['rejected']*3+['confirmed']*5
            assert s.messages['destination']==bodies[3:]
            assert run(c)['complete']; assert len(s.messages['destination'])==8
        print('PASS TOOBIG/OVERQUOTA do not block later smaller messages; no APPEND replay')
        for name in ['wrong-epoch','old-uid']:
            s,c=fixture('append-'+name,[body]*2)
            if name=='wrong-epoch': s.append_validity=78
            else:
                s.messages['destination']=[b'Subject: preexisting\r\n\r\nkeep\r\n']; s.append_uid_override=1
            p=subprocess.run([str(BIN),'migrate','--config',str(c),'--json'],capture_output=True,text=True,timeout=10)
            assert p.returncode==1
            with sqlite3.connect(root/('append-'+name)/'journal.sqlite3') as db:
                assert db.execute("select state from transfers").fetchall()==[('uncertain',)]
            assert sum(v==b'APPEND' for user,v,args in s.events)==1
        print('PASS mismatched APPENDUID epoch/UID lower bound stop before acknowledgement or later APPEND')
        s,c=fixture('session-no',[body]*8); s.source_fetch_no=True
        failed=run(c,2)
        assert len(failed['entries'])==1 and failed['entries'][0]['result']=='failed'
        assert not s.messages['destination']
        s,c=fixture('circuit-signal',[body]*8); s.rejection_script=[b'THROTTLED']*8
        p=subprocess.Popen([str(BIN),'migrate','--config',str(c),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        until=time.monotonic()+10
        while len(s.rejection_script)==8 and time.monotonic()<until: time.sleep(.01)
        assert len(s.rejection_script)==7
        p.send_signal(signal.SIGTERM); out,err=p.communicate(timeout=5)
        interrupted=json.loads(out)
        assert p.returncode==2 and interrupted['interrupted'] and len(interrupted['entries'])==1
        print('PASS session-wide source NO halts safely; SIGTERM interrupts rejection backoff')
        s,c = fixture('delivery',[body]); s.concurrent = True
        assert len(run(c)['entries']) == 1
        assert len(s.messages['source']) == 2 and s.messages['destination'] == [body]
        run(c); assert s.messages['destination'] == [body]
        s,c = fixture('empty',[]); assert run(c)['complete']
        assert not any(v == b'UID' for user,v,args in s.events if user == 'source')
        print('PASS concurrent delivery excluded by UID horizon; empty inventory avoids FETCH')
        for code in [b'THROTTLED',b'UNAVAILABLE',b'INUSE',b'LIMIT']:
            s,c = fixture('retry-'+code.decode(),[body]); s.throttle_once=True; s.throttle_code=code
            start=time.monotonic(); assert run(c)['complete']; assert time.monotonic()-start >= 1
        s,c = fixture('read-restart',[body]); s.restart_once=True
        assert run(c)['complete']; assert s.messages['destination'] == [body]
        print('PASS retryable NO codes, interrupted FETCH, refused reconnects and session restoration')
        # Start with connection refused, then bring the same endpoint online.
        s,c = fixture('restart',[body]); port=s.port
        s.close(); time.sleep(.3)
        p=subprocess.Popen([str(BIN),'migrate','--config',str(c),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        time.sleep(2)
        replacement=ProtocolServer(str(cert),str(key),'rev1'); servers.append(replacement)
        # Rebind its listener before starting a new serve loop.
        replacement.close(); time.sleep(.3)
        replacement.listener=socket.socket(); replacement.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        replacement.listener.bind(('127.0.0.1',port)); replacement.listener.listen(10); replacement.listener.settimeout(.2)
        replacement.stopped=False
        threading.Thread(target=replacement.serve,daemon=True).start()
        out,err=p.communicate(timeout=30); assert p.returncode == 0,(out,err)
        print('PASS server unavailable at startup and recovery through refused connections')
        for sig in [signal.SIGTERM,signal.SIGHUP,signal.SIGINT]:
            s,c = fixture('signal-'+str(sig),[body]); s.append_wait=True
            p=subprocess.Popen([str(BIN),'migrate','--config',str(c),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            until=time.monotonic()+10
            while not s.injected and time.monotonic()<until: time.sleep(.01)
            assert s.injected
            p.send_signal(sig); out,err=p.communicate(timeout=15)
            assert p.returncode == 2,(sig,p.returncode,out,err)
            report=json.loads(out); assert report['interrupted'] and not report['complete']
            assert s.messages['destination'] == [body]
            assert run(c)['complete']; assert len(s.messages['destination']) == 1
        print('PASS SIGTERM/SIGHUP/SIGINT during APPEND, verified completion and duplicate-free resume')
        # Signals while blocked before any TLS handshake bytes are received.
        for sig in [signal.SIGTERM,signal.SIGINT]:
            listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1)
            s,c=fixture('handshake-'+str(sig),[body],port=listener.getsockname()[1])
            p=subprocess.Popen([str(BIN),'migrate','--config',str(c),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            connection,_=listener.accept(); time.sleep(.1); p.send_signal(sig)
            out,err=p.communicate(timeout=5)
            connection.close(); listener.close()
            assert p.returncode == 2,(p.returncode,out,err)
        print('PASS SIGTERM/SIGINT during silent TLS setup')
        assert all(not s.errors for s in servers), [s.errors for s in servers]
    finally:
        for server in servers: server.close()
