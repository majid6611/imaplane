#!/usr/bin/env python3
"""Later-message/folder/reconnect/verify/upgrade crash gates for H5. Run old matrix too."""
import json, os, signal, sqlite3, subprocess, sys, tempfile
from pathlib import Path
from harness import DovecotLab
from e2e import ROOT, snapshot, ProtocolServer
BINARY=Path(sys.argv[1] if len(sys.argv)>1 else ROOT/'target/fault-tests/debug/imaplane').resolve()
from freshness import require_fresh
require_fresh(BINARY, 'fault-injection binary')

def run(cfg,action='migrate',point=None,nth=1,code=0,extra=()):
    env=os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT',None); env.pop('IMAPLANE_FAULT_NTH',None)
    if point: env.update(IMAPLANE_FAULT_POINT=point,IMAPLANE_FAULT_NTH=str(nth))
    p=subprocess.run([str(BINARY),action,'--config',str(cfg),'--json',*extra],env=env,capture_output=True,text=True,timeout=90)
    assert p.returncode==(-signal.SIGKILL if point else code),(point,nth,p.returncode,p.stdout,p.stderr)
    return json.loads(p.stdout) if p.stdout else None

def repair(cfg,lab,folder,uid):
    result=run(cfg,code=2)
    unresolved=[e for e in result['entries'] if e['result']=='uncertain']
    assert len(unresolved)==1
    entry=unresolved[0]
    if entry['candidate_uids']:
        assert len(entry['candidate_uids'])==1
        run(cfg,'resolve',code=2,extra=['--folder',folder,'--uid',str(uid),'--destination-uid',str(entry['candidate_uids'][0])])
    else:
        run(cfg,'recover',code=2,extra=['--folder',folder,'--uid',str(uid)])
    assert run(cfg)['complete']

with tempfile.TemporaryDirectory(prefix='imaplane-h5-crashes-') as tmp:
    root=Path(tmp)
    with DovecotLab(root) as lab:
        bodies=[b'Subject: duplicate\r\n\r\nsame\r\n']*2+[b'Subject: last\r\n\r\n'+b'x'*65536+b'\r\n']
        lab.seed(bodies); lab.seed(bodies,'Travail')
        points=['after_plan','after_metadata','after_baseline','begin_append_before_commit','after_begin_append','after_append_continuation','authorize_literal_before_commit','after_append_reply','acknowledge_before_commit','after_acknowledge','before_verification_fetch','after_verification_fetch','before_confirm','after_confirm']
        for index,point in enumerate(points):
            for nth in [2,4]:
                name=f'late{index}n{nth}'; cfg,dst,proxies=lab.config(name)
                run(cfg,point=point,nth=nth)
                folder='INBOX' if nth==2 else 'Travail'; uid=2 if nth==2 else 1
                with sqlite3.connect(root/name/'journal.sqlite3') as db:
                    assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
                    assert db.execute("select count(*) from transfers where state='confirmed'").fetchone()[0]==(nth if point=='after_confirm' else nth-1)
                    row=db.execute('select state from transfers where folder=? and uid=?',(folder,uid)).fetchone()
                    state=row[0] if row else None
                    if row is None:
                        assert point in ['after_plan','after_metadata','after_baseline','begin_append_before_commit']
                        assert sum(v=='APPEND' for v,_ in proxies[1].commands)==nth-1
                if state=='uncertain': repair(cfg,lab,folder,uid)
                else: assert run(cfg)['complete']
                lab.check(dst)
                for session in proxies[1].sessions:
                    for i,verb in enumerate(session):
                        if verb=='APPEND': assert 'SELECT' in session[:i],session
                assert all(not p.errors for p in proxies)
                print('PASS',point,'nth',nth,'earlier confirmations, folders, exact copies',flush=True)
        for point in ['before_invalidate','after_invalidate','before_verification_fetch','after_verification_fetch','before_confirm','after_confirm']:
            cfg,dst,_=lab.config('verify'+point.replace('_',''))
            run(cfg)
            if 'invalidate' in point:
                for folder in lab.folders:
                    dst.select(folder); assert dst.uid('STORE','1','+FLAGS.SILENT','(\\Flagged)')[0]=='OK'
            fault_nth=2 if 'invalidate' in point else 4
            run(cfg,'verify',point=point,nth=fault_nth)
            if 'invalidate' in point:
                with sqlite3.connect(root/('verify'+point.replace('_',''))/'journal.sqlite3') as db:
                    expected=1 if point=='before_invalidate' else 2
                    assert db.execute("select count(*) from transfers where state='accepted'").fetchone()[0]==expected
                for folder in lab.folders:
                    dst.select(folder); assert dst.uid('STORE','1','-FLAGS.SILENT','(\\Flagged)')[0]=='OK'
            assert run(cfg,'verify')['complete']; lab.check(dst)
            print('PASS verify',point,'nth',fault_nth,flush=True)
        cfg,dst,proxies=lab.config('observedmismatch')
        run(cfg)
        appends=sum(v=='APPEND' for v,_ in proxies[1].commands)
        dst.select('INBOX'); assert dst.uid('STORE','1','+FLAGS.SILENT','(\\Flagged)')[0]=='OK'
        mismatch=run(cfg,'verify',code=2)
        assert any(e['result']=='mismatch' for e in mismatch['entries'])
        with sqlite3.connect(root/'observedmismatch'/'journal.sqlite3') as db:
            assert db.execute("select count(*) from transfers where state='accepted'").fetchone()[0]==1
            assert db.execute("select count(*) from transfers where state='confirmed'").fetchone()[0]==5
        assert dst.uid('STORE','1','-FLAGS.SILENT','(\\Flagged)')[0]=='OK'
        assert run(cfg,'verify')['complete']; lab.check(dst)
        assert sum(v=='APPEND' for v,_ in proxies[1].commands)==appends
        print('PASS observed mismatch durably downgrades history; restoration re-verifies without APPEND',flush=True)
        for role,point in [(0,'after_source_reconnect'),(1,'after_destination_reconnect')]:
            cfg,dst,proxies=lab.config('reconnect'+str(role)); proxies[role].drop_body_nth=2
            run(cfg,point=point)
            journal=root/('reconnect'+str(role))/'journal.sqlite3'
            with sqlite3.connect(journal) as db:
                assert db.execute("select count(*) from transfers where state='confirmed'").fetchone()[0]==1
            assert run(cfg)['complete']; lab.check(dst)
            for session in proxies[1].sessions:
                for i,verb in enumerate(session):
                    if verb=='APPEND': assert 'SELECT' in session[:i],session
            print('PASS reconnect crash after previous confirmation',role,flush=True)
        # Reconnect without a crash must re-establish writable SELECT before another APPEND.
        cfg,dst,proxies=lab.config('reconnectcontinue'); proxies[1].drop_body_nth=2
        assert run(cfg)['complete']; lab.check(dst)
        for session in proxies[1].sessions:
            for i,verb in enumerate(session):
                if verb=='APPEND': assert 'SELECT' in session[:i],session
        print('PASS reconnect then writable SELECT before next APPEND',flush=True)
        cfg,dst,proxies=lab.config('midbody',proxy_options={'mid_body_nth':2})
        p=subprocess.Popen([str(BINARY),'migrate','--config',str(cfg),'--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert proxies[1].partial_received.wait(30)
        p.kill(); p.communicate(timeout=10); proxies[1].release_partial.set()
        report=run(cfg,code=2); unknown=[e for e in report['entries'] if e['result']=='uncertain']
        assert len(unknown)==1 and not unknown[0]['candidate_uids']
        run(cfg,'recover',code=1,extra=['--folder','INBOX','--uid','2'])
        appends=sum(v=='APPEND' for v,_ in proxies[1].commands); run(cfg,code=2)
        assert sum(v=='APPEND' for v,_ in proxies[1].commands)==appends
        assert snapshot(lab.source,lab.folders)==lab.before
        print('PASS mid-body kill after earlier success remains manual without candidate',flush=True)
        for point in ['after_upgrade_backup','schema_upgrade_before_commit','after_schema_upgrade']:
            cfg,dst,_=lab.config('upgrade'+point.replace('_','')); run(cfg)
            journal=root/('upgrade'+point.replace('_',''))/'journal.sqlite3'
            with sqlite3.connect(journal) as db:
                db.execute('DROP TABLE append_attempts'); db.execute('DROP TABLE recovery_events'); db.execute('PRAGMA user_version=2')
            run(cfg,point=point)
            backups=list(journal.parent.glob('journal.sqlite3.v2.bak*')); assert backups
            with sqlite3.connect(backups[0]) as db:
                assert db.execute('PRAGMA user_version').fetchone()[0]==2
                assert db.execute("select count(*) from transfers where state='confirmed'").fetchone()[0]==6
            assert run(cfg)['complete']; lab.check(dst)
            print('PASS backup and atomic schema-upgrade crash',point,flush=True)
        # Candidate search cap must explicitly report incompleteness, never silently attribute.
        cfg,dst,_=lab.config('candidatecap',proxy_options={'drop_append':True}); run(cfg,code=2)
        for _ in range(1001): assert dst.append('INBOX',None,None,b'Subject: unrelated\r\n\r\nnew\r\n')[0]=='OK'
        report=run(cfg,code=2); e=next(e for e in report['entries'] if e['result']=='uncertain')
        assert 'incomplete' in e['detail'] and not e['candidate_uids']
        run(cfg,'recover',code=1,extra=['--folder','INBOX','--uid','1'])
        print('PASS candidate overflow remains explicitly incomplete and manual',flush=True)
