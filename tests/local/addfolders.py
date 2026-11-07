#!/usr/bin/env python3
"""Adding folders to an existing job (phase I3) against the scripted loopback IMAP fixture.

Covers: refusals without --add-new-folders; removal, rename, remap and destination-conflict refusals
(schema 4 and 5, also dry run); dry run writes nothing; one run upgrades, adds and copies; empty folder
baseline; repeated runs and repeated additions are idempotent; crash points around the atomic addition;
ordinary migrate and verify finish and check a job with added folders; arrivals and expunges while the
new folder is listed; source and destination UIDVALIDITY refusals; uncertain-transfer blocking in both
directions; the history check covers added folders.

  python3 tests/local/addfolders.py target/fault-tests/debug/imaplane
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
            where = [f for f in traceback.extract_tb(exc.__traceback__) if f.filename.endswith('addfolders.py')][-1]
            FAILED.append(name); print('FAIL', name, f'(line {where.lineno}: {where.line})', '->', repr(exc)[:500], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-add-') as tmp:
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
                if p.name.startswith('job.lock') or p.name.endswith('-shm') or (p.name.endswith('-wal') and p.stat().st_size == 0):
                    continue
                h.update(p.name.encode()); h.update(p.read_bytes())
            return h.hexdigest()

        def core(self):
            """Digest of every journal table except the append-only run summaries: a repeated
            incremental run adds one summary row per folder it re-checked and nothing else."""
            h = hashlib.sha256()
            c = sqlite3.connect(self.journal)
            try:
                h.update(repr(c.execute('PRAGMA user_version').fetchall()).encode())
                for (name,) in c.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%' and name<>'verification_runs' order by name").fetchall():
                    h.update(name.encode()); h.update(repr(c.execute(f'select * from "{name}" order by rowid').fetchall()).encode())
            finally:
                c.close()
            return h.hexdigest()

        def runs(self): return self.sql('select level,checked,drift,problems from verification_runs order by run_id') if 'verification_runs' in self.tables() else []
        def events(self): return self.sql('select uid,level,result,size from verification_events order by rowid') if 'verification_events' in self.tables() else []

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

    EX = 'Extra'
    WRITE_VERBS = {b'APPEND', b'STORE', b'EXPUNGE', b'CREATE', b'DELETE', b'RENAME', b'COPY', b'SELECT'}

    class Ext(Env):
        """Env with extra folders: sources are created by the test, destinations by the product."""
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.bodies = {}

        def add_source(self, name, n):
            self.server.extra['source'][name] = []
            self.bodies[name] = []
            self.arrive_extra(name, n)

        def arrive_extra(self, name, n=1):
            for _ in range(n):
                body = b'Subject: %s %d\r\n\r\n' % (name.encode(), len(self.bodies[name])) + self.rng.randbytes(900 + 200 * len(self.bodies[name]))
                self.bodies[name].append(body); self.server.extra['source'][name].append(body)

        def expunge_extra(self, name, uid): self.server.extra['source'][name][uid - 1] = None
        def dest_extra(self, name): return self.server.extra['destination'].get(name)

        def cfg_for(self, *pairs, default=True, tag=None):
            text = self.base + (self.folders if default else '')
            for s, d in pairs:
                text += f'[[folders]]\nsource = "{s}"\ndestination = "{d}"\n'
            path = root / f'{self.name}-{tag or "-".join(s + d for s, d in pairs) or "plain"}-{int(default)}.toml'
            path.write_text(text); return path

        def plan(self):
            """Digest of the durable plan and every mapping: nothing a refusal may touch."""
            h = hashlib.sha256(); c = sqlite3.connect(self.journal)
            try:
                h.update(repr(c.execute('PRAGMA user_version').fetchall()).encode())
                for name in ('job', 'snapshots', 'scans', 'transfers', 'job_folders'):
                    if c.execute("select count(*) from sqlite_master where name=?", (name,)).fetchone()[0]:
                        h.update(name.encode()); h.update(repr(c.execute(f'select * from "{name}" order by rowid').fetchall()).encode())
            finally:
                c.close()
            return h.hexdigest()

        def mappings(self): return self.sql('select source,destination,origin from job_folders order by rowid') if 'job_folders' in self.tables() else []
        def scans_of(self, folder): return [(g, json.loads(u)) for g, u in self.sql('select generation,uids from scans where folder=? order by generation', folder)] if 'scans' in self.tables() else []
        def state_of(self, folder): return [r[0] for r in self.sql('select state from transfers where folder=? order by uid', folder)]

    def with_ext(name, count, attempts=2):
        def deco(fn):
            def run():
                e = Ext(name, count, attempts)
                try:
                    fn(e)
                finally:
                    e.close()
            return run
        return deco

    def migrate_ok(e):
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'], (code, rep, err[-300:])

    def results(rep): return {(x['source_folder'], x['source_uid']): x['result'] for x in rep['entries']}
    def no_source_writes(e):
        bad = [(v, a) for u, v, a in e.server.events if u == 'source' and v in WRITE_VERBS]
        assert not bad, bad

    def added(e, extra_msgs=2, default=3):
        """A schema-4 job over the default folder, plus an extra source folder, then the addition."""
        migrate_ok(e); e.add_source(EX, extra_msgs)
        cfg = e.cfg_for((EX, EX))
        code, rep, err = e.inc('--add-new-folders', cfg=cfg)
        assert code == 0 and rep['complete'], (code, rep, err[-300:])
        return cfg, rep

    @check('a configured folder the job does not record is refused by every command unless --add-new-folders is given with --incremental')
    @with_ext('noflag', 3)
    def _(e):
        migrate_ok(e); e.add_source(EX, 2); cfg = e.cfg_for((EX, EX))
        before, apps = e.digest(), e.appends()
        for action, extra in (('migrate', ()), ('verify', ()), ('migrate', ('--incremental',)), ('migrate', ('--incremental', '--dry-run'))):
            code, rep, err = e.run(action, extra=extra, cfg=cfg)
            assert code == 1 and 'add-new-folders' in err, (action, extra, code, err[-300:])
            assert e.digest() == before and e.appends() == apps and e.version() == 4 and EX not in e.server.extra['destination']
        code, _, err = e.run('migrate', extra=('--add-new-folders',), cfg=cfg)
        assert code == 2 and e.digest() == before, (code, err[-200:])     # clap: the flag requires --incremental

    @check('dry run lists what would be added and writes, upgrades and sends nothing; one real run upgrades, adds, copies; repeats are idempotent')
    @with_ext('basic', 3)
    def _(e):
        migrate_ok(e); e.add_source(EX, 2); cfg = e.cfg_for((EX, EX))
        before, apps = e.digest(), e.appends()
        code, dry, err = e.inc('--add-new-folders', '--dry-run', cfg=cfg)
        w = dry['would_add_folders']
        assert code == 0 and dry['would_upgrade_to_schema_5'] and len(w) == 1, (code, dry, err[-300:])
        assert (w[0]['source'], w[0]['messages'], w[0]['new_uids'], w[0]['destination_exists']) == (EX, 2, [1, 2], False)
        assert e.digest() == before and e.version() == 4 and e.backups() == [] and e.appends() == apps and EX not in e.server.extra['destination']
        code, rep, err = e.inc('--add-new-folders', cfg=cfg)
        assert code == 0 and rep['complete'], (code, rep, err[-300:])
        a = rep['added_folders']
        assert [(x['source'], x['destination'], x['messages'], x['uid_validity'], x['destination_exists']) for x in a] == [(EX, EX, 2, 77, False)], a
        assert e.version() == 5 and e.backups() == ['journal.sqlite3.v4.bak']
        assert e.mappings() == [(FOLDER, FOLDER, 'binding'), (EX, EX, 'added')]
        assert e.scans_of(EX) == [(1, [1, 2])] and e.sql('select folder from snapshots') == [(FOLDER,)], 'no snapshot is ever created for an added folder'
        assert e.state_of(EX) == ['confirmed'] * 2 and e.appends() == apps + 2
        assert e.dest_extra(EX) == e.bodies[EX] and results(rep)[(EX, 1)] == 'confirmed'
        assert e.server.messages['destination'] == e.ever, 'the original folder is untouched'
        no_source_writes(e)
        # Repeats (with or without the flag) add nothing and write nothing to the plan.
        done, apps = e.plan(), e.appends()
        for extra in (('--add-new-folders',), ()):
            code, rep, _ = e.inc(*extra, cfg=cfg)
            assert code == 0 and rep['complete'] and 'added_folders' not in rep, rep
            assert e.plan() == done and e.appends() == apps and e.mappings()[1] == (EX, EX, 'added')
        # Later arrivals in the added folder are ordinary discoveries.
        e.arrive_extra(EX, 1)
        code, rep, _ = e.inc(cfg=cfg)
        assert code == 0 and e.scans_of(EX) == [(1, [1, 2]), (2, [3])] and e.appends() == apps + 1 and e.dest_extra(EX) == e.bodies[EX]
        # Ordinary migrate and verify read and finish the extended job and change no plan.
        done, apps = e.plan(), e.appends()
        for action in ('migrate', 'verify'):
            code, rep, err = e.run(action, cfg=cfg)
            assert code == 0 and rep['complete'] and 'discovery' not in rep, (action, code, rep, err[-300:])
            assert e.plan() == done and e.appends() == apps
        p = subprocess.run([str(binary), 'status', '--state', str(e.journal), '--json'], capture_output=True, text=True)
        assert p.returncode in (0, 2) and json.loads(p.stdout)['confirmed'] == 6
        no_source_writes(e)

    @check('an empty folder is added with a baseline that fixes its UIDVALIDITY; later mail is a generation-2 discovery')
    @with_ext('empty', 2)
    def _(e):
        migrate_ok(e); e.add_source(EX, 0); cfg = e.cfg_for((EX, EX))
        code, rep, err = e.inc('--add-new-folders', cfg=cfg)
        assert code == 0 and rep['complete'] and rep['added_folders'][0]['messages'] == 0, (code, rep, err[-300:])
        assert e.scans_of(EX) == [(1, [])] and e.dest_extra(EX) == [] and e.appends() == 2
        e.arrive_extra(EX, 2)
        code, rep, _ = e.inc(cfg=cfg)
        assert code == 0 and e.scans_of(EX) == [(1, []), (2, [1, 2])] and e.dest_extra(EX) == e.bodies[EX]

    @check('an existing destination folder is reported; mail in it is warned about, left alone, and copies are appended after it')
    @with_ext('destexists', 2)
    def _(e):
        migrate_ok(e); e.add_source(EX, 2); pre = [b'Subject: already here\r\n\r\nx\r\n', b'Subject: and here\r\n\r\ny\r\n']
        e.server.extra['destination'][EX] = list(pre)
        cfg = e.cfg_for((EX, EX)); before = e.digest()
        code, dry, err = e.inc('--add-new-folders', '--dry-run', cfg=cfg)
        w = dry['would_add_folders'][0]
        assert code == 0 and w['destination_existing_messages'] == 2 and '2 message(s)' in w['warning'] and e.digest() == before, (code, dry)
        code, rep, err = e.inc('--add-new-folders', cfg=cfg)
        a = rep['added_folders'][0]
        assert code == 0 and a['destination_exists'] is True and a['destination_existing_messages'] == 2, (code, rep, err[-300:])
        assert len(rep['warnings']) == 1 and '2 message(s)' in rep['warnings'][0] and 'cannot attribute' in rep['warnings'][0] and 'WARNING' in err
        assert e.dest_extra(EX) == pre + e.bodies[EX], 'pre-existing mail untouched, copies appended after it'
        assert e.state_of(EX) == ['confirmed'] * 2
        # the warning is printed in the text report too
        e.server.errors.clear(); e.arrive_extra(EX, 0)
        text = subprocess.run([str(binary), 'migrate', '--incremental', '--add-new-folders', '--config', str(cfg)], capture_output=True, text=True, timeout=120)
        assert text.returncode == 0 and 'Verification this run:' in text.stdout
        # an existing but EMPTY destination folder is reported as existing, without a warning
        e.add_source('Quiet', 1); e.server.extra['destination']['Quiet'] = []
        code, rep, _ = e.inc('--add-new-folders', cfg=e.cfg_for((EX, EX), ('Quiet', 'Quiet'), tag='q'))
        q = [a for a in rep['added_folders'] if a['source'] == 'Quiet'][0]
        assert code == 0 and q['destination_exists'] is True and q['destination_existing_messages'] == 0 and 'warnings' not in rep

    @check('removal, renaming, remapping and conflicting or duplicate mappings are refused on schema 4 and 5, also in dry run, changing nothing')
    @with_ext('refuse', 3)
    def _(e):
        migrate_ok(e); e.add_source(EX, 2); e.add_source('Other', 1)
        def variants():
            return {
                'remove default': e.cfg_for((EX, EX), default=False, tag='r1'),
                'rename default': e.cfg_for(('Renamed', 'Renamed'), default=False, tag='r2'),
                'remap default': e.cfg_for((FOLDER, 'Other'), default=False, tag='r3'),
                'new source onto a recorded destination': e.cfg_for(('Other', FOLDER), default=False, tag='r4'),
                'duplicate destination': e.cfg_for((EX, EX), ('Other', EX), tag='r5'),
                'duplicate source': e.cfg_for((EX, EX), (EX, 'Other'), tag='r6'),
            }
        added_cfg = None
        for upgraded in (False, True):
            if upgraded:
                added_cfg, _ = added(e) if False else (e.cfg_for((EX, EX)), None)
                code, rep, err = e.inc('--add-new-folders', cfg=added_cfg); assert code == 0 and e.version() == 5
            for label, path in variants().items():
                before, apps = e.plan(), e.appends()
                for action, extra in (('migrate', ('--incremental', '--add-new-folders')), ('migrate', ('--incremental', '--add-new-folders', '--dry-run')), ('migrate', ()), ('verify', ())):
                    code, rep, err = e.run(action, extra=extra, cfg=path)
                    assert code == 1 and e.plan() == before and e.appends() == apps, (label, upgraded, action, code, err[-300:])
                    if 'duplicate' not in label:
                        assert 'folder mapping' in err or 'different migration' in err or 'not record' in err, (label, err[-300:])
        # the extra recorded folder cannot be dropped later either
        code, _, err = e.inc(cfg=e.cfg_for(default=True, tag='plain'))
        assert code == 1 and 'missing from the configuration' in err, err[-300:]

    CRASH = [('scan_listed', 4), ('v5_upgrade_before_commit', 4), ('folder_add_before_commit', 5), ('folder_add_after_commit', 5)]
    for point, version in CRASH:
        for finisher in (('incremental', 'incremental-no-flag', 'ordinary') if point == 'folder_add_after_commit' else ('incremental',)):
            @check(f'SIGKILL at {point}: the folder is added once or not at all, nothing is sent or duplicated; finished by {finisher}')
            @with_ext(f'crash-{point}-{finisher}', 3)
            def _(e, point=point, version=version, finisher=finisher):
                migrate_ok(e); e.add_source(EX, 2); cfg = e.cfg_for((EX, EX)); apps = e.appends()
                code, _, _ = e.inc('--add-new-folders', cfg=cfg, fault=(point, 1))
                assert code == -signal.SIGKILL, code
                assert e.sql('PRAGMA integrity_check')[0][0] == 'ok' and e.version() == version
                assert e.appends() == apps and e.dest_extra(EX) is None, 'a crash during the addition must not copy or create anything'
                durable = point == 'folder_add_after_commit'
                assert e.mappings() == ([(FOLDER, FOLDER, 'binding'), (EX, EX, 'added')] if durable else ([(FOLDER, FOLDER, 'binding')] if version == 5 else []))
                assert e.scans_of(EX) == ([(1, [1, 2])] if durable else [])
                assert e.states() == ['confirmed'] * 3 and e.state_of(EX) == []
                if finisher == 'ordinary':
                    code, rep, err = e.run('migrate', cfg=cfg)        # finishes the recorded baseline, never discovers
                    assert 'discovery' not in rep
                elif finisher == 'incremental-no-flag':
                    code, rep, err = e.inc(cfg=cfg)
                else:
                    code, rep, err = e.inc('--add-new-folders', cfg=cfg)
                assert code == 0 and rep['complete'], (code, rep, err[-300:])
                assert e.mappings() == [(FOLDER, FOLDER, 'binding'), (EX, EX, 'added')], 'added exactly once'
                assert e.scans_of(EX) == [(1, [1, 2])] and e.dest_extra(EX) == e.bodies[EX] and e.appends() == apps + 2
                assert e.server.messages['destination'] == e.ever
                done = e.plan()
                code, rep, _ = e.inc('--add-new-folders', cfg=cfg)
                assert code == 0 and e.plan() == done and e.appends() == apps + 2

    @check('a message expunged after the baseline was recorded is source_changed, never counted as migrated, never replayed')
    @with_ext('gone', 3)
    def _(e):
        migrate_ok(e); e.add_source(EX, 3); cfg = e.cfg_for((EX, EX)); apps = e.appends()
        code, _, _ = e.inc('--add-new-folders', cfg=cfg, fault=('folder_add_after_commit', 1)); assert code == -signal.SIGKILL
        e.expunge_extra(EX, 1)
        for n in (1, 2):
            code, rep, err = e.inc(cfg=cfg)
            r = results(rep)
            assert code == 2 and not rep['complete'] and r[(EX, 1)] == 'source_changed', (code, r, err[-300:])
            assert r.get((EX, 2)) == ('confirmed' if n == 1 else None) and e.appends() == apps + 2
        assert e.dest_extra(EX) == e.bodies[EX][1:]

    @check('mail arriving while the new folder is listed lies beyond the baseline horizon and is found by the next run, once')
    @with_ext('listing-arrive', 3)
    def _(e):
        migrate_ok(e); e.add_source(EX, 2); cfg = e.cfg_for((EX, EX))
        fired = e.hook((2, lambda: e.arrive_extra(EX, 1)))      # listing 1 is the recorded folder, listing 2 the new one
        code, rep, err = e.inc('--add-new-folders', cfg=cfg)
        assert fired and code == 0 and rep['complete'], (code, rep, err[-300:])
        assert e.scans_of(EX) == [(1, [1, 2])] and e.dest_extra(EX) == e.bodies[EX][:2], e.scans_of(EX)
        e.server.list_hook = None
        for _ in range(2):
            code, rep, _ = e.inc(cfg=cfg)
            assert code == 0 and e.scans_of(EX) == [(1, [1, 2]), (2, [3])] and e.dest_extra(EX) == e.bodies[EX]
            assert e.appends() == 6

    @check('mail expunged while the new folder is listed makes the listing inconsistent: it is retried and the baseline omits it')
    @with_ext('listing-expunge', 3)
    def _(e):
        migrate_ok(e); e.add_source(EX, 3); cfg = e.cfg_for((EX, EX))
        fired = e.hook((2, lambda: e.expunge_extra(EX, 1)))
        code, rep, err = e.inc('--add-new-folders', cfg=cfg)
        assert fired and code == 0 and rep['complete'], (code, rep, err[-300:])
        assert e.scans_of(EX) == [(1, [2, 3])] and e.dest_extra(EX) == e.bodies[EX][1:], e.scans_of(EX)
        assert e.appends() == 5

    @check('a new folder that cannot be listed (missing at the source) is refused before any write; the journal is not even upgraded')
    @with_ext('ghost', 2)
    def _(e):
        migrate_ok(e); before, apps = e.digest(), e.appends()
        code, _, err = e.inc('--add-new-folders', cfg=e.cfg_for(('Ghost', 'Ghost')))
        assert code == 1 and e.digest() == before and e.version() == 4 and e.appends() == apps and 'Ghost' not in e.server.extra['destination']

    @check('source or destination UIDVALIDITY changes in an added folder are refused before any write')
    @with_ext('validity', 2)
    def _(e):
        cfg, _ = added(e)
        before, apps = e.plan(), e.appends()
        e.server.folder_validity[('source', EX)] = 99
        for action, extra in (('migrate', ('--incremental',)), ('migrate', ('--incremental', '--dry-run')), ('migrate', ())):
            code, rep, err = e.run(action, extra=extra, cfg=cfg)
            assert code == 1 and 'UIDVALIDITY' in err and e.plan() == before and e.appends() == apps, (action, code, err[-300:])
        del e.server.folder_validity[('source', EX)]
        e.server.folder_validity[('destination', EX)] = 88
        for extra in (('--incremental',), ('--incremental', '--dry-run')):
            code, rep, err = e.run('migrate', extra=extra, cfg=cfg)
            assert code == 1 and 'UIDVALIDITY' in err and e.plan() == before and e.appends() == apps, (extra, code, err[-300:])

    @check('uncertain-transfer blocking: a blocked recorded folder does not stop the new folder; a blocked new folder does not stop the others')
    @with_ext('blocking', 4)
    def _(e):
        code, _, _ = e.run('migrate', fault=('after_append_reply', 2))
        assert code == -signal.SIGKILL and e.states() == ['confirmed', 'uncertain']
        e.add_source(EX, 2); cfg = e.cfg_for((EX, EX)); apps = e.appends()
        code, rep, err = e.inc('--add-new-folders', cfg=cfg)
        r = results(rep)
        assert code == 2 and not rep['complete'], (code, r)
        assert r[(FOLDER, 2)] == 'uncertain' and r[(FOLDER, 3)] == r[(FOLDER, 4)] == 'blocked_by_uncertain', r
        assert r[(EX, 1)] == r[(EX, 2)] == 'confirmed' and e.dest_extra(EX) == e.bodies[EX] and e.appends() == apps + 2
        # now the added folder itself gets an uncertain transfer
        e2 = Ext('blocking2', 2)
        try:
            migrate_ok(e2); e2.add_source(EX, 3); cfg2 = e2.cfg_for((EX, EX))
            code, _, _ = e2.inc('--add-new-folders', cfg=cfg2, fault=('after_append_reply', 2))
            assert code == -signal.SIGKILL and e2.state_of(EX) == ['confirmed', 'uncertain'], e2.state_of(EX)
            e2.arrive_extra(EX, 1); e2.arrive(1); apps = e2.appends()
            code, rep, err = e2.inc(cfg=cfg2)
            r = results(rep)
            assert code == 2 and r[(EX, 2)] == 'uncertain' and r[(EX, 3)] == r[(EX, 4)] == 'blocked_by_uncertain', r
            assert r[(FOLDER, 3)] == 'confirmed' and e2.appends() == apps + 1, 'only the independent folder may receive an APPEND'
        finally:
            e2.close()

    @check('the history check covers added folders: a vanished destination message is demoted, never re-uploaded')
    @with_ext('history', 3)
    def _(e):
        cfg, _ = added(e)
        code, rep, _ = e.inc(cfg=cfg)
        assert code == 0 and rep['history_check']['checked'] == 5, rep['history_check']
        apps = e.appends(); e.server.extra['destination'][EX][0] = None
        code, rep, _ = e.inc(cfg=cfg)
        assert code == 2 and results(rep)[(EX, 1)] == 'missing' and e.state_of(EX) == ['accepted', 'confirmed'] and e.appends() == apps

print('FAILED: ' + str(FAILED) if FAILED else 'all add-folder checks passed')
sys.exit(1 if FAILED else 0)
