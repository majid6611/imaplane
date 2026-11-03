#!/usr/bin/env python3
"""Deterministic SIGKILL matrix against two real, disposable TLS Dovecot servers.
Build with --features fault-injection --target-dir target/fault-tests first.
No production account/configuration is accepted by this harness.
"""
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from harness import DovecotLab
from e2e import PASSWORD, ProtocolServer, ROOT

BINARY=Path(sys.argv[1] if len(sys.argv)>1 else 'target/fault-tests/debug/imaplane').resolve()
from freshness import require_fresh
require_fresh(BINARY, 'fault-injection binary')
POINTS={
 'before_plan':'none','after_plan':'planned','before_metadata':'planned','after_metadata':'planned',
 'before_baseline':'planned','after_baseline':'planned','before_begin_append':'planned',
 'begin_append_before_commit':'planned','after_begin_append':'prepared','before_append':'prepared',
 'after_append_continuation':'prepared','before_authorize_literal':'prepared',
 'authorize_literal_before_commit':'prepared','after_authorize_literal':'ambiguous-empty',
 'before_literal_send':'ambiguous-empty','after_append_reply':'ambiguous-stored',
 'before_acknowledge':'ambiguous-stored','acknowledge_before_commit':'ambiguous-stored',
 'after_acknowledge':'accepted','before_confirm':'accepted','after_confirm':'confirmed',
}
def run(cfg, action='migrate', expected=0, point=None, extra=()):
    env=os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT',None)
    if point: env['IMAPLANE_FAULT_POINT']=point
    p=subprocess.run([str(BINARY),action,'--config',str(cfg),'--json',*extra],env=env,capture_output=True,text=True,timeout=45)
    assert p.returncode==expected,(action,point,p.returncode,p.stdout,p.stderr)
    assert PASSWORD not in p.stdout+p.stderr
    return json.loads(p.stdout) if p.stdout else None

with tempfile.TemporaryDirectory(prefix='imaplane-crash-matrix-') as temporary:
    root=Path(temporary)
    with DovecotLab(root) as lab:
        body=b'From: source@example.test\r\nSubject: duplicate\r\n\r\nunchanged source\r\n'
        lab.seed([body,body,b'Subject: final\r\n\r\nlast\r\n'])
        # The regular (non fault-injection) binary: set IMAPLANE_NORMAL_BINARY explicitly. The
        # repository's target/release or target/debug is used only if it is fresh.
        regular=Path(os.environ.get('IMAPLANE_NORMAL_BINARY',str(ROOT/'target/release/imaplane' if (ROOT/'target/release/imaplane').exists() else ROOT/'target/debug/imaplane')))
        require_fresh(regular,'regular binary (set IMAPLANE_NORMAL_BINARY)')
        cfg,destination,_=lab.config('normalfeatureoff')
        env=os.environ.copy(); env['IMAPLANE_FAULT_POINT']='after_append_reply'
        normal=subprocess.run([str(regular),'migrate','--config',str(cfg),'--json'],env=env,capture_output=True,text=True,timeout=45)
        assert normal.returncode==0,(normal.stdout,normal.stderr)
        lab.check(destination)
        print('PASS regular binary ignores crash-injection environment',flush=True)
        for number,(point,expected_state) in enumerate(POINTS.items()):
            cfg,destination,proxies=lab.config('crash'+str(number))
            run(cfg,expected=-signal.SIGKILL,point=point)
            journal=root/('crash'+str(number))/'journal.sqlite3'
            with sqlite3.connect(journal) as db:
                assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
                states=db.execute('select state from transfers order by uid').fetchall()
                if expected_state=='none': assert not states
                elif expected_state in ['planned','accepted','confirmed']:
                    if states: assert states[0][0]==expected_state
                    else:
                        assert expected_state=='planned'
                        assert not any(v=='APPEND' for v,_ in proxies[1].commands), 'no pre-send record is legal only before any APPEND'
                        # Combined preparation rolled back before its FULL commit.
                else:
                    assert states[0][0]=='uncertain'
                    phase=db.execute('select phase from append_attempts').fetchone()[0]
                    assert phase==('prepared' if expected_state=='prepared' else 'literal_authorized')
            if expected_state=='prepared':
                # An empty search alone is never enough: the durable fence is required.
                restored=run(cfg,'recover',2,extra=['--folder','INBOX','--uid','1'])
                assert restored['entries'][0]['result']=='retry_authorized'
                with sqlite3.connect(journal) as db:
                    assert db.execute('select count(*) from recovery_events').fetchone()[0]==1
            elif expected_state.startswith('ambiguous'):
                resumed=run(cfg,expected=2)
                unresolved=next(e for e in resumed['entries'] if e['result']=='uncertain')
                run(cfg,'recover',1,extra=['--folder','INBOX','--uid','1'])
                if expected_state=='ambiguous-empty':
                    assert not unresolved['candidate_uids']
                    # Repeated resume must never resend even though the fixture
                    # knows the process died before the body write.
                    appends=sum(v=='APPEND' for v,_ in proxies[1].commands)
                    run(cfg,expected=2)
                    assert sum(v=='APPEND' for v,_ in proxies[1].commands)==appends
                    # Two APPENDs above are for the other source UIDs only.
                    print('PASS',point,'remains manual with no candidate',flush=True)
                    continue
                assert len(unresolved['candidate_uids'])==1
                run(cfg,'resolve',2,extra=['--folder','INBOX','--uid','1','--destination-uid',str(unresolved['candidate_uids'][0])])
            assert run(cfg)['complete']
            run(cfg,'verify'); run(cfg)
            lab.check(destination)
            assert not any(v in ['STORE','APPEND','SELECT','EXPUNGE','DELETE','CREATE'] for v,_ in proxies[0].commands)
            assert not any(proxy.errors for proxy in proxies)
            print('PASS',point,expected_state,'exact content, metadata and multiplicity',flush=True)
        for point in ['recovery_before_commit','after_recovery']:
            name=point.replace('_','')
            cfg,destination,_=lab.config(name)
            run(cfg,expected=-signal.SIGKILL,point='after_append_continuation')
            run(cfg,'recover',-signal.SIGKILL,point=point,extra=['--folder','INBOX','--uid','1'])
            with sqlite3.connect(root/name/'journal.sqlite3') as db:
                state=db.execute('select state from transfers').fetchone()[0]
                assert state==('uncertain' if point=='recovery_before_commit' else 'planned')
            if point=='recovery_before_commit': run(cfg,'recover',2,extra=['--folder','INBOX','--uid','1'])
            assert run(cfg)['complete']; lab.check(destination)
            print('PASS',point,'atomic recovery and duplicate-free resume',flush=True)
        for point in ['resolution_before_commit','after_resolution']:
            name=point.replace('_','')
            cfg,destination,_=lab.config(name,proxy_options={'drop_append':True})
            run(cfg,expected=2)
            run(cfg,'resolve',-signal.SIGKILL,point=point,extra=['--folder','INBOX','--uid','1','--destination-uid','1'])
            if point=='resolution_before_commit': run(cfg,'resolve',2,extra=['--folder','INBOX','--uid','1','--destination-uid','1'])
            assert run(cfg)['complete']; lab.check(destination)
            print('PASS',point,'atomic manual attribution and duplicate-free resume',flush=True)
        for point in ['rejection_before_commit','after_rejection']:
            server=ProtocolServer(str(lab.cert),str(lab.key),'rev1')
            try:
                server.rejection_script=[b'OVERQUOTA']
                cfg,_,proxies=lab.config(point.replace('_',''))
                text=cfg.read_text()
                for proxy in proxies: text=text.replace(f'port = {proxy.port}',f'port = {server.port}')
                text=text.replace('username = "'+point.replace('_','')+'"','username = "destination"').replace('source = "INBOX"','source = "台北/📬"').replace('destination = "INBOX"','destination = "台北/📬"'); cfg.write_text(text)
                run(cfg,expected=-signal.SIGKILL,point=point)
                if point=='rejection_before_commit': run(cfg,'recover',2,extra=['--folder','台北/📬','--uid','1'])
                assert run(cfg)['complete']; assert server.messages['source']==server.messages['destination']
                assert not server.errors
            finally: server.close()
            print('PASS',point,'atomic rejection evidence and safe resume',flush=True)
        # Legacy v2 uncertainty must never acquire fabricated pre-send proof.
        cfg,_,_=lab.config('legacy',proxy_options={'drop_append':True})
        run(cfg,expected=2)
        with sqlite3.connect(root/'legacy'/'journal.sqlite3') as db:
            db.execute('DROP TABLE append_attempts'); db.execute('DROP TABLE recovery_events'); db.execute('PRAGMA user_version=2')
        run(cfg,'recover',1,extra=['--folder','INBOX','--uid','1'])
        print('PASS legacy uncertainty remains manual after additive upgrade',flush=True)
        # Empty literal: authorization precedes the command itself.
        server=ProtocolServer(str(lab.cert),str(lab.key),'rev1')
        try:
            server.messages['source']=[b'']
            cfg,_,proxies=lab.config('empty-literal')
            text=cfg.read_text()
            for proxy in proxies: text=text.replace(f'port = {proxy.port}',f'port = {server.port}')
            text=text.replace('username = "empty-literal"','username = "destination"').replace('source = "INBOX"','source = "台北/📬"').replace('destination = "INBOX"','destination = "台北/📬"'); cfg.write_text(text)
            run(cfg,expected=-signal.SIGKILL,point='after_append_continuation')
            run(cfg,'recover',1,extra=['--folder','台北/📬','--uid','1'])
            assert not server.messages['destination']
        finally: server.close()
        print('PASS zero-length APPEND cannot use pre-literal recovery',flush=True)
