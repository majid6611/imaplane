#!/usr/bin/env python3
"""Randomized SIGKILL stress (phase 5A): invariants must hold after EVERY kill, in every mode.

Each trial migrates a mixed corpus of unique messages while the process is killed at random:
by a fault-injection hook at a random point (random hit count) or by a timed SIGKILL at a random
instant. After every single run the invariants below are checked; between runs the documented
operator procedure is applied to uncertain records (audited `recover` when a prepared-only
attempt proves nothing was sent, `resolve` when exactly one verified candidate exists; anything
else stays manual). A trial ends when every message is confirmed or only manual cases remain.

Invariants (any violation fails the run and prints the seed):
  I1  the journal passes SQLite integrity_check
  I2  no message exists twice in the destination (no duplicate APPEND took effect)
  I3  every destination message is one of the source messages (nothing foreign)
  I4  the source is unchanged and only read verbs were ever sent to it
  I5  every `confirmed` record points at an exact copy of its source message
  I6  states are well formed (confirmed/accepted have a destination UID, others do not)
  I7  APPEND commands received <= messages + audited recover resets (no unaudited replay)
  I8  no spool or temporary file is left in the state directory
The checks live in check_invariants(); tests/local/test_stress_invariants.py proves each one can
fire, so a clean run is evidence rather than silence.

Modes: buffered (default), hybrid (threshold 64 KiB) and spooled (threshold 0).
Needs the fault-injection binary:
  python3 tests/local/stream_stress.py target/fault-tests/debug/imaplane [--trials 12] [--seed N]
Loopback-only scripted TLS server; no Docker, real credentials or real mail.
"""
import argparse
import json
import os
import random
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from e2e import PASSWORD, ProtocolServer, command
from freshness import require_fresh

FOLDER = '台北/📬'
READ_ONLY_VERBS = {'CAPABILITY', 'AUTHENTICATE', 'LIST', 'EXAMINE', 'UID', 'LOGOUT', 'NOOP'}
POINTS = ['before_plan', 'after_plan', 'begin_append_before_commit', 'after_begin_append', 'before_append', 'after_append_continuation',
          'authorize_literal_before_commit', 'after_authorize_literal', 'before_literal_send', 'after_append_reply',
          'acknowledge_before_commit', 'after_acknowledge', 'before_verification_fetch', 'after_verification_fetch',
          'before_confirm', 'after_confirm', 'source_stream_chunk', 'spool_after_fetch', 'spool_sealed',
          'append_stream_chunk', 'verification_stream_chunk', 'candidate_stream_chunk']
STREAM_ONLY = {'source_stream_chunk', 'spool_after_fetch', 'spool_sealed', 'append_stream_chunk', 'verification_stream_chunk', 'candidate_stream_chunk'}
MODES = [('buffered', None), ('hybrid', 65536), ('spooled', 0)]


class Violation(Exception):
    pass


def check_invariants(server, bodies, journal, state, recovers):
    """Raise Violation if any of I1..I8 does not hold. Reads the fixture object and the files."""
    if journal.exists():
        try:
            if sqlite3.connect(journal).execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise Violation('I1 journal integrity')
        except sqlite3.DatabaseError as exc:
            raise Violation(f'I1 journal unreadable: {type(exc).__name__}')
    dest = server.messages['destination']
    if len(set(dest)) != len(dest):
        raise Violation('I2 duplicate message in the destination')
    if not set(dest) <= set(bodies):
        raise Violation('I3 foreign message in the destination')
    if server.messages['source'] != bodies:
        raise Violation('I4 source content changed')
    bad = {v.decode() for u, v, _ in server.events if u == 'source'} - READ_ONLY_VERBS
    if bad:
        raise Violation(f'I4 non-read verbs sent to the source: {bad}')
    rows = sqlite3.connect(journal).execute('select uid,state,destination_uid from transfers order by uid').fetchall() if journal.exists() else []
    for uid, st, du in rows:
        if st == 'confirmed' and not (du and du <= len(dest) and dest[du - 1] == bodies[uid - 1]):
            raise Violation(f'I5 confirmed uid {uid} has no exact copy')
        if (st in ('confirmed', 'accepted')) != (du is not None):
            raise Violation(f'I6 uid {uid} state {st} with destination uid {du}')
    appends = sum(v == b'APPEND' for _, v, _ in server.events)
    if len(dest) > appends:
        raise Violation('harness: more destination messages than APPEND commands (the counter is not counting)')
    if appends > len(bodies) + recovers:
        raise Violation(f'I7 {appends} APPENDs for {len(bodies)} messages and {recovers} audited resets')
    extra = [p.name for p in state.iterdir() if not p.name.startswith(('journal.sqlite3', 'job.lock'))] if state.exists() else []
    if extra:
        raise Violation(f'I8 leftover files {extra}')


def corpus(rng):
    sizes = [30, 2_000, 150_000, 300_000, 700_000, 1_100_000]
    return [b'Subject: stress %d\r\n\r\n' % i + rng.randbytes(sizes[i % len(sizes)] + rng.randrange(50)) for i in range(6)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('--trials', type=int, default=12, help='trials per mode')
    ap.add_argument('--seed', type=int, default=int(time.time()) % 100000)
    ap.add_argument('--max-runs', type=int, default=30)
    args = ap.parse_args()
    binary = Path(args.binary).resolve()
    require_fresh(binary, 'fault-injection binary')
    print(f'seed {args.seed}  trials per mode {args.trials}', flush=True)
    totals = {}
    with tempfile.TemporaryDirectory(prefix='imaplane-stress-') as tmp:
        root = Path(tmp); os.chmod(root, 0o700)
        cert, key = root / 'tls.crt', root / 'tls.key'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        password = root / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
        for mode, threshold in MODES:
            stats = dict(trials=0, runs=0, hook_kills=0, timed_kills=0, clean_runs=0, recovers=0, resolves=0, confirmed=0, messages=0, manual=0, violations=0, checks=0)
            for trial in range(args.trials):
                rng = random.Random(f'{args.seed}-{mode}-{trial}')
                bodies = corpus(rng)
                server = ProtocolServer(str(cert), str(key), 'rev1'); server.messages['source'] = list(bodies)
                state = root / f'{mode}-{trial}'
                cfg = root / f'{mode}-{trial}.toml'
                text = f'state_dir = "{state}"\ntimeout_seconds = 10\nmax_message_bytes = 4194304\nread_attempts = 2\n'
                if threshold is not None:
                    text += f'stream_threshold_bytes = {threshold}\nspool_allow_memory_backed = true\n'
                for role in ('source', 'destination'):
                    text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
                text += f'[[folders]]\nsource = "{FOLDER}"\ndestination = "{FOLDER}"\n'
                cfg.write_text(text)
                recovers = [0]
                journal = state / 'journal.sqlite3'

                def rows():
                    return sqlite3.connect(journal).execute('select uid,state,destination_uid from transfers order by uid').fetchall() if journal.exists() else []

                def check(where):
                    stats['checks'] += 1
                    try:
                        check_invariants(server, bodies, journal, state, recovers[0])
                    except Violation as v:
                        stats['violations'] += 1
                        print(f'  VIOLATION [{mode} trial {trial} after {where}]: {v}  (seed {args.seed})', flush=True)
                        raise

                def run(action='migrate', point=None, nth=1, delay=None, extra=()):
                    env = os.environ.copy(); env.pop('IMAPLANE_FAULT_POINT', None); env.pop('IMAPLANE_FAULT_NTH', None)
                    if point:
                        env.update(IMAPLANE_FAULT_POINT=point, IMAPLANE_FAULT_NTH=str(nth))
                    p = subprocess.Popen([str(binary), action, '--config', str(cfg), '--json', *extra], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    killed = False
                    try:
                        out, err = p.communicate(timeout=delay if delay else 120)
                    except subprocess.TimeoutExpired:
                        p.kill(); out, err = p.communicate(); killed = True
                    stats['runs'] += 1
                    server.errors.clear()
                    return p.returncode, out, killed

                try:
                    for number in range(args.max_runs):
                        kind = rng.random()
                        if kind < 0.55:
                            usable = [p for p in POINTS if threshold is not None or p not in STREAM_ONLY]   # buffered mode never reaches those
                            code, out, _ = run(point=rng.choice(usable), nth=rng.randint(1, 3))
                            stats['hook_kills' if code == -signal.SIGKILL else 'clean_runs'] += 1
                        elif kind < 0.92:
                            code, out, killed = run(delay=rng.uniform(0.05, 1.8))
                            stats['timed_kills' if killed else 'clean_runs'] += 1
                        else:
                            code, out, _ = run(); stats['clean_runs'] += 1
                        check(f'run {number + 1}')
                        # The documented operator procedure for uncertain records.
                        for uid, st, _ in [r for r in rows() if r[1] == 'uncertain']:
                            args_ = ['--folder', FOLDER, '--uid', str(uid)]
                            rc, o, _ = run('recover', extra=args_)
                            if rc == 2:
                                stats['recovers'] += 1; recovers[0] += 1
                            else:
                                rc, o, _ = run()                            # reconcile reports candidates
                                try:
                                    entry = next(e for e in json.loads(o)['entries'] if e['source_uid'] == uid)
                                except (StopIteration, ValueError):
                                    continue
                                if entry['result'] == 'uncertain' and len(entry['candidate_uids']) == 1:
                                    rc, o, _ = run('resolve', extra=args_ + ['--destination-uid', str(entry['candidate_uids'][0])])
                                    if rc in (0, 2):
                                        stats['resolves'] += 1
                            check(f'operator step uid {uid}')
                        states = [r[1] for r in rows()]
                        if states and all(s == 'confirmed' for s in states) and len(states) == len(bodies):
                            break
                        if states and number > 3 and all(s in ('confirmed', 'uncertain') for s in states):
                            # Only manual cases remain; one clean pass proves they stay put.
                            run(); check('final clean pass')
                            if [r[1] for r in rows()].count('uncertain') == states.count('uncertain'):
                                break
                    final = rows()
                    stats['trials'] += 1; stats['messages'] += len(bodies)
                    stats['confirmed'] += sum(1 for r in final if r[1] == 'confirmed')
                    stats['manual'] += sum(1 for r in final if r[1] == 'uncertain')
                except Violation:
                    pass
                finally:
                    server.close()
            totals[mode] = stats
            print(f'{mode:>9}: {stats["trials"]} trials, {stats["runs"]} runs ({stats["hook_kills"]} hook kills, {stats["timed_kills"]} timed kills, {stats["clean_runs"]} unkilled), '
                  f'{stats["checks"]} invariant checks, {stats["recovers"]} audited recovers, {stats["resolves"]} resolves, '
                  f'{stats["confirmed"]}/{stats["messages"]} messages confirmed, {stats["manual"]} left manual, {stats["violations"]} violations', flush=True)
    bad = sum(t['violations'] for t in totals.values())
    print('PASS: no invariant violation' if not bad else f'FAIL: {bad} violation(s)')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
