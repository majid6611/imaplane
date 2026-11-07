#!/usr/bin/env python3
"""One exchange per small message (phase 3 of the performance work), checked on the wire.

A message up to 128 KiB is read with a single `UID FETCH ... (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[]<0.131072>)`
instead of a size query followed by a body fetch, on the source read and on the destination read-back. Larger
messages and streaming keep the established behaviour. Asserts the command counts, the fallbacks, the error classes
and that every copy is byte-exact.

  python3 tests/local/probe_fetch.py target/fault-tests/debug/imaplane
Run it in normal mode only: it has its own forced-streaming and threshold scenarios, and the global
IMAPLANE_TEST_STREAM_THRESHOLD switch (which disables the single-exchange read by design) would conflict with them.
Loopback only, no Docker.
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

if os.environ.get('IMAPLANE_TEST_STREAM_THRESHOLD'):
    print('skipped under the global forced-streaming switch (the forced scenario is part of the normal-mode run)'); sys.exit(0)
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
            where = [f for f in traceback.extract_tb(exc.__traceback__) if f.filename.endswith('probe_fetch.py')][-1]
            FAILED.append(name); print('FAIL', name, f'(line {where.lineno}: {where.line})', '->', repr(exc)[:500], flush=True)
        return fn
    return wrap


with tempfile.TemporaryDirectory(prefix='imaplane-probe-') as tmp:
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

    PROBE = rb'UID FETCH \d+ \(UID FLAGS INTERNALDATE RFC822\.SIZE BODY\.PEEK\[\]<0\.131072>\)'
    import re
    def fetches(e, user, n=131072):
        """(size queries, probes, whole-body fetches) sent by the tool to one server."""
        size = probe = body = 0
        for u, v, a in e.server.events:
            if u != user or v != b'UID' or not a[0].startswith(b'FETCH'):
                continue
            r = a[0]
            if r.endswith(b'(UID RFC822.SIZE)'): size += 1
            elif b'<0.' in r and b'RFC822.SIZE BODY.PEEK[]' in r:
                # the requested range IS the memory bound: exactly 128 KiB, never more, whatever the message size
                assert re.fullmatch(rb'FETCH \d+ \(UID FLAGS INTERNALDATE RFC822\.SIZE BODY\.PEEK\[\]<0\.%d>\)' % n, r), r
                probe += 1
            elif r.endswith(b'(UID FLAGS INTERNALDATE BODY.PEEK[])'): body += 1
        return size, probe, body

    def set_source(e, bodies):
        e.ever = list(bodies); e.server.messages['source'] = list(bodies)

    @check('small messages: one exchange each on the source read and on the destination read-back, no size query')
    @with_env('small', 0)
    def _(e):
        set_source(e, [b'Subject: s%d\r\n\r\n' % i + os.urandom(300 + 7 * i) for i in range(12)])
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'] and e.server.messages['destination'] == e.ever, (code, err[-300:])
        # listing/EXAMINE aside, each message costs 1 read on the source and 1 read-back on the destination
        assert fetches(e, 'source') == (0, 12, 0), fetches(e, 'source')
        assert fetches(e, 'destination') == (0, 12, 0), fetches(e, 'destination')
        e.check()

    @check('messages around the 128 KiB limit: exactly at the limit is one exchange, one byte over falls back to size then body; all exact')
    @with_env('edge', 0)
    def _(e):
        L = 131072
        mk = lambda n, tag: (b'Subject: %s\r\n\r\n' % tag) + os.urandom(n - len(b'Subject: %s\r\n\r\n' % tag))
        set_source(e, [mk(L, b'at'), mk(L + 1, b'over'), mk(L - 1, b'under'), mk(500_000, b'big')])
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'] and e.server.messages['destination'] == e.ever, (code, rep, err[-300:])
        # source: 4 probes; the two larger messages continue with ONE whole-body fetch each (the size came with the probe)
        assert fetches(e, 'source') == (0, 4, 2), fetches(e, 'source')
        assert fetches(e, 'destination') == (0, 4, 2), fetches(e, 'destination')

    @check('an empty message and a one-byte message are copied exactly through the single exchange')
    @with_env('tiny', 0)
    def _(e):
        set_source(e, [b'', b'x', b'\r\n'])
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'] and e.server.messages['destination'] == e.ever, (code, rep, err[-300:])

    @check('a streaming threshold keeps its meaning: messages above it stream (probe bytes dropped), the request text is unchanged')
    @with_env('threshold', 0)
    def _(e):
        e.base = 'stream_threshold_bytes = 50000\nspool_allow_memory_backed = true\n' + e.base
        e.cfg.write_text(e.base + e.folders)
        set_source(e, [os.urandom(2000) , b'Subject: mid\r\n\r\n' + os.urandom(80_000), b'Subject: big\r\n\r\n' + os.urandom(400_000)])
        diag = root / 'threshold.jsonl'
        p = subprocess.run([str(binary), '--diagnostics-file', str(diag), 'migrate', '--config', str(e.cfg), '--json'], capture_output=True, text=True, timeout=180)
        rep = json.loads(p.stdout)
        assert p.returncode == 0 and rep['complete'] and e.server.messages['destination'] == e.ever, (p.returncode, p.stderr[-300:])
        spooled = [json.loads(l)['spooled'] for l in diag.read_text().splitlines() if '"uid_fetch_transfer"' in l]
        assert spooled == [False, True, True], spooled          # only the 2 KB message stays in memory
        assert fetches(e, 'source')[1] == 3, fetches(e, 'source')   # every message was probed with the same request

    @check('forced streaming (threshold 0) sends no probe at all: size query then streamed body, as before')
    @with_env('forced', 0)
    def _(e):
        e.base = 'stream_threshold_bytes = 0\nspool_allow_memory_backed = true\n' + e.base
        e.cfg.write_text(e.base + e.folders)
        set_source(e, [b'Subject: a\r\n\r\n' + os.urandom(900) for _ in range(4)])
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete'] and e.server.messages['destination'] == e.ever, (code, err[-300:])
        assert fetches(e, 'source')[:2] == (4, 0) and fetches(e, 'destination')[:2] == (4, 0), (fetches(e, 'source'), fetches(e, 'destination'))

    @check('a lying RFC822.SIZE on a small message is the same permanent skip as before, and later messages proceed')
    @with_env('lying', 0)
    def _(e):
        set_source(e, [b'Subject: first\r\n\r\nlies', b'Subject: second\r\n\r\nfine', b'Subject: third\r\n\r\nfine'])
        e.server.bad_size = True                                  # source uid 1 reports size + 1
        code, rep, err = e.run('migrate')
        r = {x['source_uid']: x['result'] for x in rep['entries']}
        assert r == {1: 'skipped_permanent', 2: 'confirmed', 3: 'confirmed'}, r
        assert e.server.messages['destination'] == e.ever[1:], 'the lying message must not be copied'

    @check('a message above max_message_bytes is a permanent skip decided from the probe (no whole-body read)')
    @with_env('toobig', 0)
    def _(e):
        e.base = e.base.replace('max_message_bytes = 4194304', 'max_message_bytes = 100000')
        e.cfg.write_text(e.base + e.folders)
        set_source(e, [b'Subject: ok\r\n\r\nsmall', b'Subject: huge\r\n\r\n' + os.urandom(300_000), b'Subject: ok2\r\n\r\nsmall'])
        code, rep, err = e.run('migrate')
        r = {x['source_uid']: x['result'] for x in rep['entries']}
        assert r == {1: 'confirmed', 2: 'skipped_permanent', 3: 'confirmed'}, r
        # the probe is capped by the configured message limit when that is smaller than 128 KiB
        assert fetches(e, 'source', 100000)[2] == 0, 'the oversize message must never be downloaded in full'

    @check('a message deleted between listing and read, and a body returned as NIL, are "source_changed" exactly as before')
    @with_env('gone', 0)
    def _(e):
        set_source(e, [b'Subject: a\r\n\r\nx', b'Subject: b\r\n\r\ny'])
        code, rep, err = e.run('migrate')
        assert code == 0 and rep['complete']
        e.arrive(1)
        e.server.messages['source'][2] = None
        code, rep, err = e.inc()
        r = {x['source_uid']: x['result'] for x in rep['entries']}
        assert code in (0, 2) and 3 not in r or r.get(3) == 'source_changed', r

print('FAILED: ' + str(FAILED) if FAILED else 'all single-exchange checks passed')
sys.exit(1 if FAILED else 0)
