#!/usr/bin/env python3
"""Incremental migration (phase I1) against the scripted loopback IMAP fixture.

Covers: ordinary migrate unchanged; dry-run writes nothing; schema 4 to 5 only on a real
--incremental run; complete-listing discovery against every journal-known UID; idempotent repeats;
crash points around the atomic scan commit; arrivals and expunges during the UID listing; source and
destination UIDVALIDITY refusals; altered or extra folder mappings; a folder with an uncertain
transfer gets no new APPEND; history states (planned, accepted, confirmed) are never rediscovered.

  python3 tests/local/incremental.py target/fault-tests/debug/imaplane
Run it twice, plain and with IMAPLANE_TEST_STREAM_THRESHOLD=0 (forced spool). Loopback only, no Docker.
"""
import hashlib
import json
import os
import random
import signal
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from e2e import PASSWORD, STREAM_EXTRA, ProtocolServer, command
from freshness import require_fresh
from stream_stress import FOLDER, check_invariants

binary = Path(sys.argv[1]).resolve()
require_fresh(binary, 'fault-injection binary')
FAILED = []
NEW_TABLES = {'scans', 'job_folders', 'verification_events', 'verification_runs'}


def check(name):
    def wrap(fn):
        if os.environ.get('ONLY') and os.environ['ONLY'] not in name:
            return fn
        try:
            fn(); print('PASS', name, flush=True)
        except BaseException as exc:
            import traceback
            where = [f for f in traceback.extract_tb(exc.__traceback__) if f.filename.endswith('incremental.py')][-1]
            FAILED.append(name); print('FAIL', name, f'(line {where.lineno}: {where.line})', '->', repr(exc)[:500], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-inc-') as tmp:
    root = Path(tmp); os.chmod(root, 0o700)
    cert, key = root / 'tls.crt', root / 'tls.key'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
    password = root / 'password'; password.write_text(PASSWORD); password.chmod(0o600)

    class Env:
        def __init__(self, name, count, attempts=2):
            self.name = name
            self.rng = random.Random(name)
            self.ever = []
            self.server = ProtocolServer(str(cert), str(key), 'rev1')
            self.server.messages['source'] = []
            self.arrive(count)
            self.state = root / name
            self.journal = self.state / 'journal.sqlite3'
            self.cfg = root / f'{name}.toml'
            text = f'state_dir = "{self.state}"\ntimeout_seconds = 10\nmax_message_bytes = 4194304\nread_attempts = {attempts}\n{STREAM_EXTRA}'
            for role in ('source', 'destination'):
                text += f'[{role}]\nhost = "localhost"\nport = {self.server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
            self.base = text
            self.folders = f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
            self.cfg.write_text(text + self.folders)

        def arrive(self, n=1):
            for _ in range(n):
                body = b'Subject: inc %d\r\n\r\n' % len(self.ever) + self.rng.randbytes(1500 + 300 * len(self.ever))
                self.ever.append(body); self.server.messages['source'].append(body)

        def expunge(self, uid):
            self.server.messages['source'][uid - 1] = None

        def run(self, action='migrate', extra=(), fault=None, cfg=None):
            env = os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT', None); env.pop('IMAPLANE_FAULT_NTH', None)
            if fault:
                env.update(IMAPLANE_FAULT_POINT=fault[0], IMAPLANE_FAULT_NTH=str(fault[1]))
            p = subprocess.run([str(binary), action, '--config', str(cfg or self.cfg), '--json', *extra], env=env, capture_output=True, text=True, timeout=180)
            self.server.errors.clear()
            assert 'panicked' not in p.stderr, p.stderr[-400:]
            return p.returncode, (json.loads(p.stdout) if p.stdout.strip().startswith('{') else None), p.stderr

        def inc(self, *extra, **kw):
            return self.run('migrate', extra=('--incremental', *extra), **kw)

        def sql(self, query, *args):
            c = sqlite3.connect(self.journal)
            try:
                return c.execute(query, args).fetchall()
            finally:
                c.close()

        def version(self): return self.sql('PRAGMA user_version')[0][0]
        def tables(self): return {r[0] for r in self.sql("select name from sqlite_master where type='table'")}
        def states(self): return [r[0] for r in self.sql('select state from transfers order by uid')]
        def scans(self): return [(r[0], json.loads(r[1])) for r in self.sql('select generation,uids from scans order by generation')]
        def appends(self): return sum(v == b'APPEND' for _, v, _ in self.server.events)
        def backups(self): return sorted(p.name for p in self.state.iterdir() if '.bak' in p.name)

        def digest(self):
            h = hashlib.sha256()
            for p in sorted(self.state.iterdir()):
                if p.name.startswith('job.lock') or p.name.endswith('-shm'):
                    continue
                h.update(p.name.encode()); h.update(p.read_bytes())
            return h.hexdigest()

        def check(self, recovers=0):
            """Stress-harness invariants; fixture-side expunges are restored for the source comparison."""
            live = [m if m is not None else self.ever[i] for i, m in enumerate(self.server.messages['source'])]
            view = SimpleNamespace(messages={'source': live, 'destination': self.server.messages['destination']}, events=self.server.events)
            check_invariants(view, self.ever, self.journal, self.state, recovers)

        def hook(self, action_on_nth):
            """Install a listing hook counting from now; returns a list that records every firing."""
            fired = []
            base = self.server.list_count
            def run(n):
                if n - base == action_on_nth[0]:
                    fired.append(n); action_on_nth[1]()
            self.server.list_hook = run
            return fired

        def close(self): self.server.close()

    def with_env(name, count, attempts=2):
        def deco(fn):
            def run():
                e = Env(name, count, attempts)
                try:
                    fn(e)
                finally:
                    e.close()
            return run
        return deco

    def migrate_ok(e):
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'], (code, rep, err[-300:])

    @check('ordinary migrate ignores new arrivals, keeps schema 4 and writes no schema-5 tables')
    @with_env('ordinary', 3)
    def _(e):
        migrate_ok(e); assert e.version() == 4
        e.arrive(2)
        code, rep, _ = e.run('migrate')
        assert code == 0 and rep['complete'] and 'discovery' not in rep, rep
        assert e.appends() == 3 and e.version() == 4 and not (e.tables() & NEW_TABLES) and e.backups() == []
        e.check()

    @check('dry-run (plain and incremental) writes nothing, upgrades nothing and sends nothing; real run upgrades once and transfers')
    @with_env('basic', 3)
    def _(e):
        migrate_ok(e); e.arrive(2)
        before = e.digest()
        code, dry, err = e.inc('--dry-run')
        assert code == 0 and dry['would_upgrade_to_schema_5'] is True and dry['folders'][0]['new_uids'] == [4, 5], (code, dry, err[-300:])
        assert dry['folders'][0]['listed'] == 5 and dry['folders'][0]['known'] == 3
        assert e.digest() == before and e.version() == 4 and e.backups() == [] and e.appends() == 3
        code, rep, err = e.inc()
        assert code == 0 and rep['complete'], (code, rep, err[-300:])
        d = rep['discovery'][0]
        assert (d['new_uids'], d['scan_generation'], d['listed'], d['known']) == ([4, 5], 1, 5, 3), d
        assert e.version() == 5 and e.backups() == ['journal.sqlite3.v4.bak']
        assert e.appends() == 5 and e.server.messages['destination'] == e.ever
        assert e.scans() == [(1, [4, 5])] and json.loads(e.sql('select uids from snapshots')[0][0]) == [1, 2, 3]
        assert e.sql('select count(*) from job_folders')[0][0] == 1
        e.check()
        # Repeated runs with nothing new change nothing in the journal and send nothing.
        done = e.digest()
        for _ in range(2):
            code, rep, _ = e.inc()
            assert code == 0 and rep['complete'] and rep['discovery'][0]['new_uids'] == [] and rep['discovery'][0]['scan_generation'] is None, rep
            assert e.digest() == done and e.appends() == 5
        code, dry, _ = e.inc('--dry-run')
        assert code == 0 and dry['would_upgrade_to_schema_5'] is False and dry['folders'][0]['new_uids'] == []
        assert e.digest() == done
        # A later arrival becomes generation 2; the first scan and the snapshot are untouched.
        e.arrive(1)
        code, rep, _ = e.inc()
        assert code == 0 and rep['complete'] and rep['discovery'][0]['scan_generation'] == 2
        assert e.scans() == [(1, [4, 5]), (2, [6])] and e.appends() == 6 and e.backups() == ['journal.sqlite3.v4.bak']
        assert json.loads(e.sql('select uids from snapshots')[0][0]) == [1, 2, 3]
        # Ordinary commands keep working on the extended job and do nothing more.
        for action in ('migrate', 'verify'):
            code, rep, _ = e.run(action)
            assert code == 0 and rep['complete'], (action, rep)
        assert e.appends() == 6
        p = subprocess.run([str(binary), 'status', '--state', str(e.journal), '--json'], capture_output=True, text=True)
        assert p.returncode in (0, 2) and json.loads(p.stdout)['confirmed'] == 6
        e.check()

    @check('incremental refuses to create a job')
    @with_env('nojob', 2)
    def _(e):
        for extra in ((), ('--dry-run',)):
            code, rep, err = e.inc(*extra)
            assert code == 1 and not e.state.exists() and e.appends() == 0, (code, err[-300:])

    POINTS = [('scan_listed', 4, 0), ('before_v5_backup', 4, 0), ('after_v5_backup', 4, 0), ('before_v5_upgrade', 4, 0),
              ('v5_upgrade_before_commit', 4, 0), ('after_v5_upgrade', 5, 0), ('scan_before_commit', 5, 0), ('scan_after_commit', 5, 1)]
    for point, version, scans in POINTS:
        for finisher in ('incremental', 'ordinary') if point == 'scan_after_commit' else ('incremental',):
            @check(f'SIGKILL at {point}: no message skipped or duplicated; finished by an {finisher} run')
            @with_env(f'crash-{point}-{finisher}', 3)
            def _(e, point=point, version=version, scans=scans, finisher=finisher):
                migrate_ok(e); e.arrive(2)
                code, _, _ = e.inc(fault=(point, 1))
                assert code == -signal.SIGKILL, code
                assert e.sql('PRAGMA integrity_check')[0][0] == 'ok'
                assert e.version() == version, (e.version(), version)
                assert len(e.scans() if 'scans' in e.tables() else []) == scans
                assert e.states() == ['confirmed'] * 3 and e.appends() == 3, 'a crash during discovery must not transfer or plan anything'
                if finisher == 'ordinary':
                    code, rep, err = e.run('migrate')          # ordinary migrate finishes a committed scan
                    assert 'discovery' not in rep
                else:
                    code, rep, err = e.inc()
                assert code == 0 and rep['complete'], (code, rep, err[-300:])
                assert e.states() == ['confirmed'] * 5 and e.appends() == 5 and e.server.messages['destination'] == e.ever
                assert e.scans() == [(1, [4, 5])], 'exactly one scan, never duplicated or lost'
                assert e.version() == 5
                done = e.digest()
                code, rep, _ = e.inc()
                assert code == 0 and e.digest() == done and e.appends() == 5
                e.check()

    for point in ('after_plan', 'after_acknowledge', 'after_confirm'):
        @check(f'history state left by a kill at {point} is never rediscovered; new arrival is found once')
        @with_env(f'hist-{point}', 4)
        def _(e, point=point):
            code, _, _ = e.run('migrate', fault=(point, 2))
            assert code == -signal.SIGKILL
            e.arrive(1)
            code, rep, err = e.inc()
            assert code == 0 and rep['complete'], (code, rep, err[-300:])
            assert rep['discovery'][0]['new_uids'] == [5] and e.scans() == [(1, [5])]
            assert e.states() == ['confirmed'] * 5 and e.appends() == 5 and e.server.messages['destination'] == e.ever
            e.check()

    @check('uncertain transfer: that folder gets no new APPEND, nothing is replayed, and the operator is told clearly')
    @with_env('blocked', 4)
    def _(e):
        code, _, _ = e.run('migrate', fault=('after_append_reply', 2))
        assert code == -signal.SIGKILL and e.states() == ['confirmed', 'uncertain']
        e.arrive(1)
        reports = []
        for run_number in range(2):                           # repeating must change nothing
            code, rep, err = e.inc()
            reports.append(rep)
            assert code == 2 and not rep['complete'], (code, rep)
            assert rep['discovery'][0]['new_uids'] == ([5] if run_number == 0 else [])
            results = {x['source_uid']: x['result'] for x in rep['entries']}
            assert results == {1: 'confirmed', 2: 'uncertain', 3: 'blocked_by_uncertain', 4: 'blocked_by_uncertain', 5: 'blocked_by_uncertain'}, results
            blocked = [x for x in rep['entries'] if x['result'] == 'blocked_by_uncertain']
            assert all('NOT transferred' in x['detail'] and '[2]' in x['detail'] for x in blocked)
            assert 'no new APPEND' in err and e.appends() == 2 and len(e.server.messages['destination']) == 2
        assert e.states() == ['confirmed', 'uncertain']
        candidate = next(x for x in reports[0]['entries'] if x['source_uid'] == 2)['candidate_uids']
        assert candidate == [2], candidate
        code, _, _ = e.run('resolve', extra=['--folder', FOLDER, '--uid', '2', '--destination-uid', '2'])
        assert code in (0, 2)
        code, rep, err = e.inc()
        assert code == 0 and rep['complete'], (code, rep, err[-300:])
        assert e.appends() == 5 and e.server.messages['destination'] == e.ever and e.states() == ['confirmed'] * 5
        e.check()

    @check('arrival during the UID listing is not recorded half-seen and is found by the next run')
    @with_env('arrival', 3)
    def _(e):
        migrate_ok(e); e.arrive(1)
        fired = e.hook((1, lambda: e.arrive(1)))
        code, rep, err = e.inc()
        assert fired == [e.server.list_count - 0] or len(fired) == 1, fired
        assert code == 0 and rep['complete'] and rep['discovery'][0]['new_uids'] == [4], (rep, err[-200:])
        assert e.appends() == 4 and len(e.ever) == 5
        e.server.list_hook = None
        code, rep, _ = e.inc()
        assert code == 0 and rep['complete'] and rep['discovery'][0]['new_uids'] == [5]
        assert e.scans() == [(1, [4]), (2, [5])] and e.appends() == 5 and e.server.messages['destination'] == e.ever
        e.check()

    @check('expunge during the UID listing: the inconsistent listing is retried, never recorded')
    @with_env('expunge-known', 3)
    def _(e):
        migrate_ok(e); e.arrive(2)
        fired = e.hook((1, lambda: e.expunge(2)))
        code, rep, err = e.inc()
        assert len(fired) == 1, 'the expunge hook never fired'
        if os.environ.get('DEBUG_EVENTS'):
            print([ (u, v, a[:1]) for u, v, a in e.server.events if u == 'source' or v in (b'EXAMINE',)][-14:])
        assert code == 0 and rep['complete'] and rep['discovery'][0]['new_uids'] == [4, 5], (code, rep, err[-300:])
        assert e.server.list_count - (fired[0] - 1) == 2, 'the first listing must have been rejected and repeated'
        assert e.appends() == 5
        e.check()

    @check('a new message expunged during the listing is simply not discovered')
    @with_env('expunge-new', 3)
    def _(e):
        migrate_ok(e); e.arrive(2)
        fired = e.hook((1, lambda: e.expunge(5)))
        code, rep, err = e.inc()
        assert len(fired) == 1, 'the expunge hook never fired'
        assert code == 0 and rep['complete'] and rep['discovery'][0]['new_uids'] == [4], (code, rep, err[-300:])
        assert e.scans() == [(1, [4])] and e.appends() == 4
        e.server.list_hook = None
        code, rep, _ = e.inc()
        assert code == 0 and rep['discovery'][0]['new_uids'] == [] and e.appends() == 4
        e.check()

    @check('permanently inconsistent listings fail closed: no upgrade, no scan, no transfer')
    @with_env('churn', 3)
    def _(e):
        migrate_ok(e); e.arrive(2)
        base = e.server.list_count
        calls = []
        def churn(n):
            calls.append(n); e.expunge(len(calls))
        e.server.list_hook = churn
        before = e.digest()
        code, rep, err = e.inc()
        assert len(calls) == 2, calls
        assert code == 1 and e.digest() == before and e.version() == 4 and e.appends() == 3, (code, err[-300:])

    @check('message expunged after its scan was recorded: reported source_changed, never counted as migrated, never replayed')
    @with_env('gone', 3)
    def _(e):
        migrate_ok(e); e.arrive(2)
        code, _, _ = e.inc(fault=('scan_after_commit', 1))
        assert code == -signal.SIGKILL
        e.expunge(4)
        for _ in range(2):
            code, rep, err = e.inc()
            assert rep is not None, (code, err[-500:])
            results = {x['source_uid']: x['result'] for x in rep['entries']}
            assert code == 2 and not rep['complete'] and results[4] == 'source_changed' and results[5] == 'confirmed', (code, results)
        assert e.appends() == 4 and e.states() == ['confirmed'] * 4
        e.check()

    @check('source UIDVALIDITY change is refused before any write, on schema 4 and on schema 5 (also dry-run)')
    @with_env('src-validity', 3)
    def _(e):
        migrate_ok(e); e.arrive(1)
        for upgraded in (False, True):
            if upgraded:
                code, rep, _ = e.inc(); assert code == 0 and e.version() == 5; e.arrive(1)
            e.server.source_validity += 1
            before, appends, version = e.digest(), e.appends(), e.version()
            for extra in ((), ('--dry-run',)):
                code, rep, err = e.inc(*extra)
                assert code == 1 and 'source UIDVALIDITY' in err and e.digest() == before and e.appends() == appends and e.version() == version, (code, err[-300:])
            e.server.source_validity -= 1

    @check('destination UIDVALIDITY change is refused before any write (also dry-run)')
    @with_env('dst-validity', 3)
    def _(e):
        migrate_ok(e); e.arrive(1)
        e.server.destination_validity = 99
        before, appends = e.digest(), e.appends()
        for extra in ((), ('--dry-run',)):
            code, rep, err = e.inc(*extra)
            assert code == 1 and 'destination UIDVALIDITY' in err and e.digest() == before and e.appends() == appends and e.version() == 4, (code, err[-300:])

    @check('altered, remapped or extra folder mappings are refused on schema 4 and 5; nothing changes')
    @with_env('mappings', 3)
    def _(e):
        migrate_ok(e); e.arrive(1)
        variants = {
            'extra': e.base + e.folders + '[[folders]]\nsource = "X"\ndestination = "Y"\n',
            'remapped': e.base + f'[[folders]]\nsource = "{FOLDER}"\ndestination = "ELSEWHERE"\n',
        }
        for upgraded in (False, True):
            if upgraded:
                code, rep, _ = e.inc(); assert code == 0 and e.version() == 5; e.arrive(1)
            for label, text in variants.items():
                alt = root / f'mappings-{label}.toml'; alt.write_text(text)
                before, appends = e.digest(), e.appends()
                for extra in ((), ('--dry-run',)):
                    code, rep, err = e.inc(*extra, cfg=alt)
                    assert code == 1 and e.digest() == before and e.appends() == appends, (label, upgraded, code, err[-300:])
                    assert 'different migration' in err or 'folder mappings' in err, err[-300:]

print('FAILED: ' + str(FAILED) if FAILED else 'all incremental checks passed')
sys.exit(1 if FAILED else 0)
