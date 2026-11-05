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
        if p.name.startswith('job.lock') or p.name.endswith('-shm'):
            continue
        h.update(p.name.encode()); h.update(p.read_bytes())
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
        stable = digest(state)
        # A repeat changes nothing in the journal and sends nothing (nothing to replay, nothing new).
        _, rep2, _ = run(cfg, extra=['--incremental'], code=2)
        assert appends(proxies[1]) == sent + 2 and digest(state) == stable
        print('PASS uncertain INBOX is blocked, independent Travail continues, repeat is idempotent', flush=True)

        candidates = got[('INBOX', 4)]['candidate_uids']
        assert len(candidates) == 1, got[('INBOX', 4)]
        run(cfg, 'resolve', extra=['--folder', 'INBOX', '--uid', '4', '--destination-uid', str(candidates[0])], code=2)
        _, rep, err = run(cfg, extra=['--incremental'], code=0)
        assert rep['complete'] and appends(proxies[1]) == sent + 3, (rep['complete'], appends(proxies[1]), sent)
        lab.check(dst)                                              # exact copies, source unchanged
        done = digest(state)
        _, rep, _ = run(cfg, extra=['--incremental'], code=0)
        assert all(d['new_uids'] == [] for d in rep['discovery']) and digest(state) == done and appends(proxies[1]) == sent + 3
        assert all(not p.errors for p in proxies)
        print('PASS after resolve the blocked folder completes; exact copies; source unchanged; idempotent', flush=True)
print('all incremental Dovecot checks passed')
