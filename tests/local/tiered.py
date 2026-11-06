#!/usr/bin/env python3
"""Tiered verification and flag drift (phase I2) against the scripted loopback IMAP fixture.

Covers: the default incremental run reads no historical message body (counted at the server);
existence, metadata and full levels are distinct and only a full check creates or renews a
confirmation; same-length corruption is invisible to lighter levels and caught by `full` and
`verify`; flag-only differences are drift (never a demotion) in migrate, verify and incremental;
missing messages, INTERNALDATE and known-size mismatches demote without any upload; times that were
never recorded are reported as unknown; evidence is append-only and crash safe.

  python3 tests/local/tiered.py target/fault-tests/debug/imaplane
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
            where = [f for f in traceback.extract_tb(exc.__traceback__) if f.filename.endswith('tiered.py')][-1]
            FAILED.append(name); print('FAIL', name, f'(line {where.lineno}: {where.line})', '->', repr(exc)[:500], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-tier-') as tmp:
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

    def migrate_ok(e):
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'], (code, rep, err[-300:])

    def migrate_ok(e):
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'], (code, rep, err[-300:])

    def results(rep): return {x['source_uid']: x['result'] for x in rep['entries']}
    def dest(e): return e.server.messages['destination']
    def same_length_corruption(body):
        return body[:-1] + bytes([body[-1] ^ 1])

    @check('default incremental run reads no historical body: bodies are read only for new messages; lighter levels read none')
    @with_env('nobody', 30)
    def _(e):
        migrate_ok(e)                                    # 30 copied and fully verified (schema 4)
        e.arrive(2)
        s = e.server
        before = (s.body_fetches['source'], s.body_fetches['destination'], s.meta_fetches['destination'])
        code, rep, err = e.inc()
        assert code == 0 and rep['complete'], (code, rep, err[-300:])
        assert s.body_fetches['source'] - before[0] == 2 and s.body_fetches['destination'] - before[1] == 2, 'only the 2 new messages are read'
        assert s.meta_fetches['destination'] - before[2] == 1, '30 historical messages are checked in one batched metadata FETCH'
        h = rep['history_check']
        assert (h['level'], h['checked'], h['passed'], h['drift'], h['problems'], h['size_unknown']) == ('metadata', 30, 30, 0, 0, 30), h
        assert 'NOT re-read' in h['scope'] and 'no confirmation was created or renewed' in h['scope']
        assert [x['result'] for x in rep['entries']] == ['confirmed', 'confirmed'], 'only the new messages have entries'
        # Nothing new: no body at all, source or destination.
        mark = (s.body_fetches['source'], s.body_fetches['destination'])
        code, rep, _ = e.inc()
        assert code == 0 and rep['complete'] and (s.body_fetches['source'], s.body_fetches['destination']) == mark
        assert rep['history_check']['checked'] == 32 and rep['history_check']['size_unknown'] == 30
        # Existence level: not even a metadata FETCH.
        meta = s.meta_fetches['destination']
        code, rep, _ = e.inc('--verify-history', 'existence')
        assert code == 0 and rep['history_check']['level'] == 'existence' and rep['history_check']['checked'] == 32
        assert s.meta_fetches['destination'] == meta and (s.body_fetches['source'], s.body_fetches['destination']) == mark
        # Full level reads every body once, exactly like `verify`, and renews evidence.
        code, rep, _ = e.inc('--verify-history', 'full')
        assert code == 0 and rep['complete'] and 'history_check' not in rep and len(rep['entries']) == 32
        assert s.body_fetches['destination'] == mark[1] + 32 and s.body_fetches['source'] == mark[0]
        assert len(e.events()) == 2 + 32 and all(v[1:3] == ('full', 'ok') for v in e.events())
        # With sizes now recorded, the metadata level can compare them.
        code, rep, _ = e.inc()
        assert rep['history_check']['size_unknown'] == 0 and len(e.events()) == 34
        e.check()

    @check('same-length corruption is invisible to existence and metadata, which never renew or confirm; verify and full catch it')
    @with_env('samelen', 4)
    def _(e):
        migrate_ok(e)
        code, rep, _ = e.inc(); assert code == 0 and e.version() == 5 and e.events() == []
        original = dest(e)[1]
        dest(e)[1] = same_length_corruption(original)
        for level in ('existence', 'metadata'):
            code, rep, err = e.inc('--verify-history', level)
            assert code == 0 and rep['complete'] and rep['history_check']['level'] == level and rep['entries'] == [], (level, rep, err[-200:])
            assert e.events() == [] and e.states() == ['confirmed'] * 4, 'a lightweight check wrote full evidence or changed a state'
        assert [r[0] for r in e.runs()][-2:] == ['existence', 'metadata'] and all(r[3] == 0 for r in e.runs())
        for action, extra in (('verify', ()), ('migrate', ('--incremental', '--verify-history', 'full'))):
            code, rep, _ = e.run(action, extra=extra)
            assert code == 2 and not rep['complete'] and results(rep)[2] == 'mismatch', (action, results(rep))
            assert e.states() == ['confirmed', 'accepted', 'confirmed', 'confirmed']
            assert (2, 'full', 'mismatch', len(original)) in e.events(), e.events()
            dest(e)[1] = original
            code, rep, _ = e.inc()                         # an unconfirmed record gets a FULL check, and only that confirms
            assert code == 0 and results(rep)[2] == 'confirmed' and e.states() == ['confirmed'] * 4
            assert (2, 'full', 'ok', len(original)) in e.events()[-4:], e.events()
            dest(e)[1] = same_length_corruption(original)
        assert e.appends() == 4

    @check('an accepted (not yet confirmed) message is never confirmed by metadata: same-length corruption stays accepted')
    @with_env('acc', 3)
    def _(e):
        code, _, _ = e.run('migrate', fault=('after_acknowledge', 2))
        assert code == -signal.SIGKILL and e.states() == ['confirmed', 'accepted']
        original = dest(e)[1]
        dest(e)[1] = same_length_corruption(original)
        code, rep, _ = e.inc()
        assert code == 2 and results(rep)[2] == 'mismatch' and e.states()[1] == 'accepted', results(rep)
        dest(e)[1] = original
        code, rep, _ = e.inc()
        assert code == 0 and e.states() == ['confirmed'] * 3
        assert (2, 'full', 'ok', len(original)) in e.events() and e.appends() == 3

    @check('flag-only differences are drift in verify, migrate and incremental (all levels): reported, never demoted')
    @with_env('drift', 3)
    def _(e):
        migrate_ok(e)
        dest(e)                                          # destination uid 2 gets an extra flag
        e.server.dest_flags[2] = b'\\Seen \\Flagged'
        for action in ('verify', 'migrate'):
            code, rep, _ = e.run(action)
            assert code == 0 and rep['complete'], (action, code, results(rep))
            assert results(rep) == {1: 'confirmed', 2: 'drift', 3: 'confirmed'}, results(rep)
            d = [x for x in rep['entries'] if x['result'] == 'drift'][0]
            assert d['level'] == 'full' and 'persistent flags differ' in d['detail'] and 'Flagged' in d['detail'], d
            assert e.states() == ['confirmed'] * 3 and e.version() == 4
        code, rep, _ = e.inc()                           # first incremental run upgrades; metadata level
        assert code == 0 and rep['complete'] and e.version() == 5, (code, rep)
        assert results(rep) == {2: 'drift'} and rep['entries'][0]['level'] == 'metadata'
        assert rep['entries'][0]['last_full_verification'].startswith('unknown'), rep['entries'][0]
        assert rep['history_check']['drift'] == 1 and rep['history_check']['passed'] == 2
        assert e.events() == [] and e.runs()[-1] == ('metadata', 3, 1, 0), 'drift writes a run summary only, no per-message row'
        code, rep, _ = e.inc('--verify-history', 'existence')
        assert code == 0 and rep['entries'] == [], 'existence cannot see flags and must not pretend to'
        code, rep, _ = e.inc('--verify-history', 'full')
        assert code == 0 and rep['complete'] and results(rep) == {1: 'confirmed', 2: 'drift', 3: 'confirmed'}
        assert e.states() == ['confirmed'] * 3 and e.appends() == 3
        assert all(v[2] == 'ok' for v in e.events()) and len(e.events()) == 3

    @check('flags must still match before the FIRST confirmation: an accepted message with different flags stays accepted')
    @with_env('accflags', 3)
    def _(e):
        code, _, _ = e.run('migrate', fault=('after_acknowledge', 2))
        assert code == -signal.SIGKILL and e.states() == ['confirmed', 'accepted']
        e.server.dest_flags[2] = b'\\Seen \\Answered'
        code, rep, _ = e.run('verify')
        assert code == 2 and results(rep)[2] == 'mismatch' and e.states()[1] == 'accepted', results(rep)
        del e.server.dest_flags[2]
        code, rep, _ = e.run('migrate')                   # confirms uid 2 by a full check, then copies the never-sent uid 3
        assert code == 0 and e.states() == ['confirmed'] * 3 and e.appends() == 3

    @check('missing message, INTERNALDATE and known-size mismatches demote with evidence and never upload; the next full check re-judges')
    @with_env('problems', 6)
    def _(e):
        migrate_ok(e)
        code, rep, _ = e.inc('--verify-history', 'full'); assert code == 0 and e.version() == 5 and len(e.events()) == 6
        dest(e)[1] = None                                 # uid 2 missing
        e.server.dest_dates[3] = b'03-Jan-2020 03:04:05 +0000'
        e.server.dest_size_delta[4] = 1
        code, rep, err = e.inc()
        r = results(rep)
        assert code == 2 and not rep['complete'] and (r[2], r[3], r[4]) == ('missing', 'mismatch', 'mismatch'), (code, r, err[-200:])
        assert e.states() == ['confirmed', 'accepted', 'accepted', 'accepted', 'confirmed', 'confirmed'] and e.appends() == 6
        evs = e.events()[6:]
        assert evs == [(2, 'metadata', 'missing', None), (3, 'metadata', 'mismatch', len(e.ever[2])), (4, 'metadata', 'mismatch', len(e.ever[3]) + 1)], evs
        assert 'size differs' in [x for x in rep['entries'] if x['source_uid'] == 4][0]['detail']
        assert all(x['level'] == 'metadata' and x['last_full_verification'][:2] == '20' for x in rep['entries']), rep['entries']
        assert e.runs()[-1] == ('metadata', 6, 0, 3)
        # Next run: unconfirmed records get a full check. Still missing / still wrong date; uid 4's body is intact.
        code, rep, _ = e.inc()
        r = results(rep)
        assert code == 2 and (r[2], r[3], r[4]) == ('missing', 'mismatch', 'confirmed'), r
        assert e.appends() == 6 and e.server.messages['source'] == e.ever

    @check('existence level sees a missing message but not a changed date; both are reported at their own level')
    @with_env('exist', 4)
    def _(e):
        migrate_ok(e); e.inc()
        dest(e)[0] = None; e.server.dest_dates[3] = b'03-Jan-2020 03:04:05 +0000'
        code, rep, _ = e.inc('--verify-history', 'existence')
        assert code == 2 and results(rep) == {1: 'missing'} and rep['entries'][0]['level'] == 'existence', rep['entries']
        assert e.events()[-1] == (1, 'existence', 'missing', None) and e.runs()[-1] == ('existence', 4, 0, 1)
        assert e.appends() == 4

    @check('verification time is unknown for pre-schema-5 records, recorded by full checks, and never invented')
    @with_env('legacy', 3)
    def _(e):
        migrate_ok(e)
        e.server.dest_flags[1] = b'\\Seen \\Flagged'
        code, rep, _ = e.inc()
        assert e.events() == [] and rep['entries'][0]['last_full_verification'].startswith('unknown'), rep['entries']
        for action in ('verify', 'migrate'):               # ordinary full checks on schema 5 write renewal evidence
            code, rep, _ = e.run(action)
            assert code == 0 and e.states() == ['confirmed'] * 3
        assert len(e.events()) == 6 and all(v[1:3] == ('full', 'ok') for v in e.events())
        assert [v[3] for v in e.events()[:3]] == [len(b) for b in e.ever], 'size is backfilled as an event, never as an edit'
        code, rep, _ = e.inc()
        import datetime
        stamp = rep['entries'][0]['last_full_verification']
        when = datetime.datetime.fromisoformat(stamp)
        assert (datetime.datetime.now(datetime.timezone.utc) - when).total_seconds() < 600, stamp
        assert stamp == e.sql("select observed_at from verification_events where uid=1 and level='full' and result='ok' order by rowid desc limit 1")[0][0]
        assert rep['history_check']['size_unknown'] == 0
        # Evidence tables stay append-only through the SQL interface.
        for stmt in ('update verification_events set result="x"', 'delete from verification_events', 'delete from verification_runs'):
            try:
                e.sql(stmt); raise AssertionError(stmt)
            except sqlite3.IntegrityError:
                pass

    @check('--verify-history needs --incremental; the dry run names the level and writes nothing')
    @with_env('flags', 2)
    def _(e):
        migrate_ok(e)
        before = e.digest()
        code, rep, err = e.run('migrate', extra=('--verify-history', 'full'))
        assert code == 2 and e.digest() == before and 'incremental' in err, (code, err[-300:])
        code, dry, _ = e.inc('--dry-run')
        assert code == 0 and dry['history_check_level'] == 'metadata' and e.digest() == before
        code, dry, _ = e.inc('--dry-run', '--verify-history', 'full')
        assert dry['history_check_level'] == 'full' and e.digest() == before

    def text_run(e, *args):
        env = os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT', None)
        p = subprocess.run([str(binary), *args, '--config', str(e.cfg)], env=env, capture_output=True, text=True, timeout=180)
        e.server.errors.clear()
        return p

    @check('reports and status say which level proved what: full read-backs this run, metadata-only checks, drift, oldest full verification')
    @with_env('levels', 5)
    def _(e):
        migrate_ok(e); e.arrive(2)
        code, rep, _ = e.inc()
        v = rep['verification']
        assert (v['fully_verified_this_run'], v['metadata_checked_only'], v['existence_checked_only'], v['flag_drift'], v['uncertain'], v['problems']) == (2, 5, 0, 0, 0, 0), v
        assert 'NOT re-read' in v['statement'] and '2 message(s) proven by a full SHA-256' in v['statement']
        f = v['folders'][0]
        assert (f['confirmed'], f['full_verification_recorded'], f['full_verification_unknown']) == (7, 2, 5), f
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        assert f['oldest_full_verification'] and f['oldest_full_verification'] <= f['newest_full_verification']
        assert datetime.datetime.fromisoformat(f['newest_full_verification']) <= now, 'a recorded time can never lie in the future'
        # a lightweight rerun proves nothing new and says so; the oldest time does not move
        code, rep, _ = e.inc('--verify-history', 'existence')
        v = rep['verification']
        assert (v['fully_verified_this_run'], v['metadata_checked_only'], v['existence_checked_only']) == (0, 0, 7) and v['folders'][0]['oldest_full_verification'] == f['oldest_full_verification'], v
        e.server.dest_flags[1] = b'\\Seen \\Flagged'
        code, rep, _ = e.inc()
        v = rep['verification']
        assert (v['fully_verified_this_run'], v['metadata_checked_only'], v['flag_drift']) == (0, 7, 1), v
        # a full pass proves everything and replaces the unknown times
        code, rep, _ = e.inc('--verify-history', 'full')
        v = rep['verification']
        assert (v['fully_verified_this_run'], v['metadata_checked_only'], v['flag_drift']) == (7, 0, 1), v
        f2 = v['folders'][0]
        assert (f2['full_verification_recorded'], f2['full_verification_unknown']) == (7, 0) and f2['oldest_full_verification'] > f['oldest_full_verification']
        # ordinary verify is a full pass and reports like one
        code, rep, _ = e.run('verify')
        assert rep['verification']['fully_verified_this_run'] == 7 and rep['verification']['metadata_checked_only'] == 0
        # text reports: the statement, the per-folder times; never a bare "verified"
        p = text_run(e, 'migrate', '--incremental')
        assert p.returncode == 0 and 'Verification this run: 0 message(s) proven by a full SHA-256 read-back' in p.stdout, p.stdout
        assert '7 checked by metadata only' in p.stdout and 'content NOT re-read' in p.stdout and 'oldest recorded full verification: 20' in p.stdout, p.stdout
        # status: offline, same distinction, per folder
        s = subprocess.run([str(binary), 'status', '--state', str(e.journal), '--json'], capture_output=True, text=True)
        j = json.loads(s.stdout)
        assert j['confirmed'] == 7 and j['verification']['evidence'] == 'recorded' and j['verification']['folders'][0]['full_verification_unknown'] == 0
        s = subprocess.run([str(binary), 'status', '--state', str(e.journal)], capture_output=True, text=True)
        assert 'does not check anything live' in s.stdout and 'oldest recorded full verification: 20' in s.stdout, s.stdout

    @check('status on a schema-4 job reports every full-verification time as unknown, never an invented one')
    @with_env('statusv4', 3)
    def _(e):
        migrate_ok(e)
        j = json.loads(subprocess.run([str(binary), 'status', '--state', str(e.journal), '--json'], capture_output=True, text=True).stdout)
        f = j['verification']['folders'][0]
        assert j['verification']['evidence'] == 'none' and (f['confirmed'], f['full_verification_unknown'], f['oldest_full_verification'], f['newest_full_verification']) == (3, 3, None, None), j['verification']
        code, rep, _ = e.run('verify')                      # still schema 4: nothing can be recorded
        f = rep['verification']['folders'][0]
        assert rep['verification']['fully_verified_this_run'] == 3 and f['oldest_full_verification'] is None and f['full_verification_unknown'] == 3 and e.version() == 4

    @check('a development-era schema-5 journal is refused up front by every command; status describes it; nothing changes')
    @with_env('devjournal', 3)
    def _(e):
        migrate_ok(e); code, _, _ = e.inc(); assert e.version() == 5
        c = sqlite3.connect(e.journal)
        c.executescript("DROP TABLE verification_events; CREATE TABLE verification_events (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL, level TEXT NOT NULL CHECK(level IN ('full')), result TEXT NOT NULL, size INTEGER, observed_at TEXT NOT NULL, detail TEXT NOT NULL);")
        c.commit(); c.close()
        before, wire, apps = e.digest(), len(e.server.events), e.appends()
        for action, extra in (('verify', ()), ('migrate', ()), ('migrate', ('--incremental',)), ('migrate', ('--incremental', '--dry-run'))):
            code, rep, err = e.run(action, extra=extra)
            assert code == 1 and 'pre-release' in err and 'refused' in err, (action, extra, code, err[-300:])
            assert e.digest() == before and e.appends() == apps and len(e.server.events) == wire, 'refusal must precede any network use or write'
        s = subprocess.run([str(binary), 'status', '--state', str(e.journal), '--json'], capture_output=True, text=True)
        j = json.loads(s.stdout)
        assert s.returncode == 2 and j['confirmed'] == 3 and j['verification']['evidence'] == 'incompatible' and j['verification']['folders'][0]['full_verification_unknown'] == 3
        s = subprocess.run([str(binary), 'status', '--state', str(e.journal)], capture_output=True, text=True)
        assert s.returncode == 2 and 'incompatible' in s.stdout and e.digest() == before

    @check('ordinary migrate keeps its behaviour with an uncertain record in the folder, but now warns; --incremental still blocks')
    @with_env('uncwarn', 4)
    def _(e):
        code, _, _ = e.run('migrate', fault=('after_append_reply', 2))
        assert code == -signal.SIGKILL and e.states() == ['confirmed', 'uncertain']
        code, rep, err = e.run('migrate')
        r = results(rep)
        assert code == 2 and r[2] == 'uncertain' and r[3] == r[4] == 'confirmed', r        # unchanged: later messages are still copied
        assert len(rep['warnings']) == 1 and 'unresolved uncertain' in rep['warnings'][0] and '1000' in rep['warnings'][0] and 'WARNING' in err
        assert rep['verification']['uncertain'] == 1 and rep['verification']['fully_verified_this_run'] == 3
        e2 = Env('uncwarn2', 4)
        try:
            code, _, _ = e2.run('migrate', fault=('after_append_reply', 2)); assert code == -signal.SIGKILL
            code, rep, _ = e2.inc()
            assert results(rep)[3] == results(rep)[4] == 'blocked_by_uncertain' and 'warnings' not in rep, results(rep)
        finally:
            e2.close()

    POINTS = [('before_history_fetch', 'metadata'), ('before_history_demote', 'metadata'), ('before_invalidate', 'metadata'),
              ('after_invalidate', 'metadata'), ('history_run_before_commit', 'metadata'), ('history_run_after_commit', 'metadata'),
              ('evidence_before_commit', 'full'), ('evidence_after_commit', 'full')]
    for point, level in POINTS:
        @check(f'SIGKILL at {point} ({level}): state and evidence stay consistent, nothing is uploaded, a rerun converges')
        @with_env(f'crash-{point}', 4)
        def _(e, point=point, level=level):
            migrate_ok(e); code, _, _ = e.inc(); assert code == 0
            demoting = point in ('before_history_demote', 'before_invalidate', 'after_invalidate')
            if demoting:
                dest(e)[1] = None
            runs, events = len(e.runs()), len(e.events())
            code, _, _ = e.inc('--verify-history', level, fault=(point, 1))
            assert code == -signal.SIGKILL, (point, code)
            assert e.sql('PRAGMA integrity_check')[0][0] == 'ok' and e.appends() == 4
            states, evs = e.states(), e.events()[events:]
            if demoting:
                # The demotion and its evidence are one transaction: both or neither.
                assert (states[1] == 'accepted') == (len(evs) == 1), (states, evs)
                assert (states[1] == 'accepted') == (point == 'after_invalidate')
            else:
                assert states == ['confirmed'] * 4
            if point == 'evidence_before_commit': assert evs == []
            if point == 'evidence_after_commit': assert len(evs) == 4 and all(v[1:3] == ('full', 'ok') for v in evs)
            if point == 'history_run_after_commit': assert len(e.runs()) == runs + 1
            if point in ('before_history_fetch', 'history_run_before_commit'): assert len(e.runs()) == runs
            code, rep, _ = e.inc('--verify-history', level)
            assert code == (2 if demoting else 0) and e.appends() == 4, (code, results(rep))
            if demoting:
                assert e.states()[1] == 'accepted' and results(rep)[2] == 'missing'
            else:
                assert e.states() == ['confirmed'] * 4
            assert e.server.messages['source'] == e.ever

print('FAILED: ' + str(FAILED) if FAILED else 'all tiered-verification checks passed')
sys.exit(1 if FAILED else 0)
