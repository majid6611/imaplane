#!/usr/bin/env python3
"""Repeated-run cost of the history-check levels (phase I2 measurement, not part of CI).

Builds a job of N messages (about 20 KB each), then times repeated no-change runs at every level and
counts what the destination was asked to send. The fixture is a loopback Python server, so absolute
times only compare with each other; the counts (body fetches, bytes, metadata FETCHes) are the result.

  python3 tests/local/tiered_perf.py target/release/imaplane [N ...]
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
SIZES = [int(x) for x in sys.argv[2:]] or [100, 400]
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

    def migrate_ok(e):
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'], (code, rep, err[-300:])


    import time
    def measure(n):
        e = Env(f'perf{n}', 0)
        try:
            e.ever = []; e.server.messages['source'] = []
            for i in range(n):
                body = b'Subject: perf %d\r\n\r\n' % i + e.rng.randbytes(20000)
                e.ever.append(body); e.server.messages['source'].append(body)
            code, rep, _ = e.run('migrate'); assert code == 0 and rep['complete']
            code, rep, _ = e.inc(); assert code == 0
            code, rep, _ = e.inc('--verify-history', 'full'); assert code == 0      # records sizes
            rows = []
            s = e.server
            for label, action, extra in (('incremental --verify-history existence', 'migrate', ('--incremental', '--verify-history', 'existence')),
                                         ('incremental (default: metadata)', 'migrate', ('--incremental',)),
                                         ('incremental --verify-history full', 'migrate', ('--incremental', '--verify-history', 'full')),
                                         ('verify', 'verify', ())):
                b0, m0, sb0 = s.body_fetches['destination'], s.meta_fetches['destination'], s.body_fetches['source']
                events = len(e.events()); runs = len(e.runs()); size = e.journal.stat().st_size
                t = time.monotonic(); code, rep, _ = e.run(action, extra=extra); dt = time.monotonic() - t
                assert code == 0 and rep['complete'], (label, code)
                bodies = s.body_fetches['destination'] - b0
                rows.append((label, dt, bodies, bodies * 20000 / 1e6, s.meta_fetches['destination'] - m0, s.body_fetches['source'] - sb0, len(e.events()) - events, len(e.runs()) - runs))
            print(f'N={n} messages of about 20 KB ({n * 20 / 1000:.1f} MB), no new mail, nothing changed')
            print(f'  {"run":40s} {"seconds":>8s} {"dest bodies":>11s} {"dest MB":>8s} {"meta FETCH":>10s} {"src bodies":>10s} {"new events":>10s} {"new runs":>8s}')
            for r in rows:
                print(f'  {r[0]:40s} {r[1]:8.2f} {r[2]:11d} {r[3]:8.1f} {r[4]:10d} {r[5]:10d} {r[6]:10d} {r[7]:8d}')
            print(flush=True)
        finally:
            e.close()

    for n in SIZES:
        measure(n)
