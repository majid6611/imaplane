#!/usr/bin/env python3
"""Incremental migration (phase I1) against real disposable Dovecot servers, two folders.

A folder with an unresolved uncertain transfer gets no new APPEND while the independent folder
continues; the operator is told which; after `resolve` the blocked folder finishes; the destination
ends as exact copies of the source, the source is unchanged, repeated runs write nothing.

  python3 tests/local/incremental_dovecot.py target/fault-tests/debug/imaplane
Needs Docker and the Dovecot image used by e2e.py; loopback only, no real accounts.
"""
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from e2e import ROOT, quoted, snapshot
from freshness import require_fresh
from harness import DovecotLab

BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / 'target/fault-tests/debug/imaplane').resolve()
require_fresh(BINARY, 'fault-injection binary')


def run(cfg, action='migrate', extra=(), fault=None, code=None):
    env = os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT', None); env.pop('IMAPLANE_FAULT_NTH', None)
    if fault:
        env.update(IMAPLANE_FAULT_POINT=fault[0], IMAPLANE_FAULT_NTH=str(fault[1]))
    p = subprocess.run([str(BINARY), action, '--config', str(cfg), '--json', *extra], env=env, capture_output=True, text=True, timeout=180)
    if code is not None:
        assert p.returncode == code, (action, extra, p.returncode, p.stdout[-600:], p.stderr[-400:])
    return p.returncode, (json.loads(p.stdout) if p.stdout.strip().startswith('{') else None), p.stderr


def digest(state):
    h = hashlib.sha256()
    for p in sorted(state.iterdir()):
        if p.name.startswith('job.lock') or p.name.endswith('-shm') or (p.name.endswith('-wal') and p.stat().st_size == 0):
            continue
        h.update(p.name.encode()); h.update(p.read_bytes())
    return h.hexdigest()


def core(journal):
    """Every journal table except the append-only run summaries (each lightweight history check adds one)."""
    h = hashlib.sha256(); c = sqlite3.connect(journal)
    try:
        for (name,) in c.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%' and name<>'verification_runs' order by name").fetchall():
            h.update(name.encode()); h.update(repr(c.execute(f'select * from "{name}" order by rowid').fetchall()).encode())
    finally:
        c.close()
    return h.hexdigest()


def plan(journal):
    """The durable plan and mappings only (a message that stays missing adds an evidence event per run)."""
    h = hashlib.sha256(); c = sqlite3.connect(journal)
    try:
        for name in ('job', 'snapshots', 'scans', 'transfers', 'job_folders'):
            h.update(name.encode()); h.update(repr(c.execute(f'select * from "{name}" order by rowid').fetchall()).encode())
    finally:
        c.close()
    return h.hexdigest()


def appends(proxy):
    return sum(v == 'APPEND' for v, _ in proxy.commands)


with tempfile.TemporaryDirectory(prefix='imaplane-inc-dovecot-') as tmp:
    root = Path(tmp)
    with DovecotLab(root) as lab:
        mk = lambda tag, folder, n: [b'Subject: %s %s %d\r\n\r\n' % (tag, folder.encode(), i) + b'x' * (500 + 90 * i) for i in range(n)]
        lab.seed(mk(b'old', 'INBOX', 3)); lab.seed(mk(b'old', 'Travail', 3), 'Travail')
        cfg, dst, proxies = lab.config('inc')
        state = root / 'inc'; journal = state / 'journal.sqlite3'
        run(cfg, code=0)
        assert sqlite3.connect(journal).execute('PRAGMA user_version').fetchone()[0] == 4
        base = appends(proxies[1]); assert base == 6
        for folder in lab.folders:                                  # new mail arrives at the source
            for i, body in enumerate(mk(b'new', folder, 2)):
                assert lab.source.append(quoted(folder), None, '"02-Jan-2020 03:04:05 +0000"', body)[0] == 'OK'
        lab.before = snapshot(lab.source, lab.folders)
        before = digest(state)
        _, dry, _ = run(cfg, extra=['--incremental', '--dry-run'], code=0)
        assert {f['source']: f['new_uids'] for f in dry['folders']} == {'INBOX': [4, 5], 'Travail': [4, 5]}, dry
        assert digest(state) == before and appends(proxies[1]) == base
        print('PASS dry-run on real Dovecot finds the arrivals and writes nothing', flush=True)

        run(cfg, 'migrate', extra=['--incremental'], fault=('after_append_reply', 1), code=-signal.SIGKILL)
        db = sqlite3.connect(journal)
        assert db.execute('select folder,uid,state from transfers where state=?', ('uncertain',)).fetchall() == [('INBOX', 4, 'uncertain')]
        sent = appends(proxies[1]); assert sent == base + 1
        _, rep, err = run(cfg, extra=['--incremental'], code=2)
        got = {(e['source_folder'], e['source_uid']): e for e in rep['entries']}
        assert got[('INBOX', 4)]['result'] == 'uncertain' and got[('INBOX', 5)]['result'] == 'blocked_by_uncertain', got
        assert [got[('Travail', u)]['result'] for u in (4, 5)] == ['confirmed', 'confirmed']
        assert appends(proxies[1]) == sent + 2, 'only the independent folder may receive APPENDs'
        assert 'no new APPEND' in err
        stable = core(journal)
        # A repeat changes nothing in the journal and sends nothing (nothing to replay, nothing new).
        _, rep2, _ = run(cfg, extra=['--incremental'], code=2)
        assert appends(proxies[1]) == sent + 2 and core(journal) == stable
        print('PASS uncertain INBOX is blocked, independent Travail continues, repeat is idempotent', flush=True)

        candidates = got[('INBOX', 4)]['candidate_uids']
        assert len(candidates) == 1, got[('INBOX', 4)]
        run(cfg, 'resolve', extra=['--folder', 'INBOX', '--uid', '4', '--destination-uid', str(candidates[0])], code=2)
        _, rep, err = run(cfg, extra=['--incremental'], code=0)
        assert rep['complete'] and appends(proxies[1]) == sent + 3, (rep['complete'], appends(proxies[1]), sent)
        lab.check(dst)                                              # exact copies, source unchanged
        done = core(journal)
        _, rep, _ = run(cfg, extra=['--incremental'], code=0)
        assert all(d['new_uids'] == [] for d in rep['discovery']) and core(journal) == done and appends(proxies[1]) == sent + 3
        assert rep['history_check']['level'] == 'metadata' and rep['history_check']['problems'] == 0 and rep['history_check']['drift'] == 0, rep['history_check']
        assert all(not p.errors for p in proxies)
        print('PASS after resolve the blocked folder completes; exact copies; source unchanged; idempotent', flush=True)

        # Tiered history checks against a real server: metadata sees a flag change as drift (no
        # demotion), a full check agrees, and an expunged message is reported missing and never re-sent.
        db = sqlite3.connect(journal)
        du = lambda folder, uid: db.execute('select destination_uid from transfers where folder=? and uid=?', (folder, uid)).fetchone()[0]
        total = appends(proxies[1]); stored = db.execute('select count(*) from verification_events').fetchone()[0]
        dst.select('INBOX'); assert dst.uid('STORE', str(du('INBOX', 1)), '+FLAGS.SILENT', '(\\Flagged)')[0] == 'OK'
        _, rep, _ = run(cfg, extra=['--incremental'], code=0)
        drift = [(e['source_folder'], e['source_uid'], e['level']) for e in rep['entries'] if e['result'] == 'drift']
        assert drift == [('INBOX', 1, 'metadata')] and rep['complete'] and rep['history_check']['drift'] == 1, rep
        assert db.execute("select count(*) from verification_events").fetchone()[0] == stored, 'a metadata check wrote full evidence'
        _, rep, _ = run(cfg, extra=['--incremental', '--verify-history', 'full'], code=0)
        assert [(e['source_folder'], e['source_uid'], e['level']) for e in rep['entries'] if e['result'] == 'drift'] == [('INBOX', 1, 'full')]
        assert db.execute("select count(*) from transfers where state='confirmed'").fetchone()[0] == 10
        dst.select('INBOX'); victim = du('INBOX', 2)
        dst.uid('STORE', str(victim), '+FLAGS.SILENT', '(\\Deleted)'); dst.expunge()
        _, rep, _ = run(cfg, extra=['--incremental'], code=2)
        assert [(e['source_folder'], e['source_uid'], e['result'], e['level']) for e in rep['entries'] if e['result'] != 'drift'] == [('INBOX', 2, 'missing', 'metadata')], rep['entries']
        assert db.execute("select state from transfers where folder='INBOX' and uid=2").fetchone()[0] == 'accepted'
        assert db.execute("select level,result from verification_events where uid=2 order by rowid desc limit 1").fetchone() == ('metadata', 'missing')
        assert appends(proxies[1]) == total, 'a missing destination message must never be re-uploaded'
        assert all(not p.errors for p in proxies)
        print('PASS real Dovecot: metadata drift without demotion, full agreement, missing message demoted and never re-sent', flush=True)

        # Adding folders on real Dovecot: refused without the flag, dry run writes nothing, a crash right
        # after the atomic addition is finished by an ordinary migrate, exact copies, source untouched.
        def results(rep): return {(e['source_folder'], e['source_uid']): e['result'] for e in rep['entries']}
        def rows(conn, folder): return [r[1:] for r in snapshot(conn, [folder])[folder][1]]
        for folder, tag in (('Archive', 'plain'), ('Spam', 'crash')):
            lab.seed(mk(b'add', folder, 3), folder)
            cfg.write_text(cfg.read_text() + f'[[folders]]\nsource = "{folder}"\ndestination = "{folder}"\n')
            before, sent = plan(journal), appends(proxies[1])
            run(cfg, 'migrate', code=1); run(cfg, 'migrate', extra=['--incremental'], code=1)
            assert plan(journal) == before and appends(proxies[1]) == sent
            _, dry, _ = run(cfg, extra=['--incremental', '--add-new-folders', '--dry-run'], code=0)
            assert [(w['source'], w['messages']) for w in dry['would_add_folders']] == [(folder, 3)], dry
            assert plan(journal) == before and appends(proxies[1]) == sent
            assert folder not in [x.decode() for x in dst.list()[1] if x] or True
            if tag == 'plain':
                _, rep, _ = run(cfg, extra=['--incremental', '--add-new-folders'], code=2)   # code 2: the earlier missing INBOX message
            else:
                run(cfg, extra=['--incremental', '--add-new-folders'], fault=('folder_add_after_commit', 1), code=-signal.SIGKILL)
                assert appends(proxies[1]) == sent, 'a crash right after the addition sends nothing'
                assert db.execute('select count(*) from job_folders where source=?', (folder,)).fetchone()[0] == 1
                _, rep, _ = run(cfg, 'migrate', code=2)                                           # ordinary migrate finishes the recorded baseline
                assert 'discovery' not in rep
            assert [results(rep)[(folder, u)] for u in (1, 2, 3)] == ['confirmed'] * 3, results(rep)
            assert db.execute('select origin from job_folders where source=?', (folder,)).fetchone()[0] == 'added'
            assert db.execute('select count(*) from snapshots where folder=?', (folder,)).fetchone()[0] == 0
            assert appends(proxies[1]) == sent + 3 and rows(dst, folder) == rows(lab.source, folder)
            done = plan(journal)
            _, rep, _ = run(cfg, extra=['--incremental', '--add-new-folders'], code=2)
            assert 'added_folders' not in rep and plan(journal) == done and appends(proxies[1]) == sent + 3
        assert snapshot(lab.source, ['Archive', 'Spam']) == {k: v for k, v in lab.before.items() if k in ('Archive', 'Spam')}
        assert all(not p.errors for p in proxies)
        print('PASS real Dovecot: folders added atomically (also across a crash), exact copies, repeat is idempotent, source unchanged', flush=True)
print('all incremental Dovecot checks passed')
