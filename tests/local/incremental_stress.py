#!/usr/bin/env python3
"""Randomized SIGKILL stress for incremental migration (phase I4): arrivals, expunges, new folders,
interrupted discovery scans and resumptions, with invariants checked after EVERY run.

Each trial drives one job through a random sequence of: mail arriving in existing folders, messages
expunged at the source, new source folders appearing, folders being added to the configuration
(`--add-new-folders`), and runs of `migrate`, `migrate --incremental` (any history level) and
`verify`, each killed at random by a fault-injection hook (transfer, discovery, schema-upgrade,
folder-addition, history and evidence points) or by a timed SIGKILL, or left to finish. Between runs
the documented operator steps are applied to uncertain records (audited `recover`, `resolve` when
exactly one verified candidate exists). A trial ends with clean convergence runs and final checks.

Invariants (any violation fails the run and prints the seed):
  I1  the journal passes SQLite integrity_check
  I2  no message exists twice in any destination folder
  I3  every destination message is a message that ever existed in the matching source folder
  I4  every source folder equals what the harness expects (it only changes what the harness changes)
      and only read verbs were ever sent to the source
  I5  every `confirmed` record points at an exact copy of its source message
  I6  states are well formed (confirmed/accepted have a destination UID, others do not)
  I7  APPEND commands received <= messages that ever existed + audited recover resets
  I8  no spool or temporary file is left in the state directory
  I9  folder mappings only grow: earlier job_folders rows are unchanged and in order
  I10 discovery evidence is append-only: earlier scans, snapshots and transfer keys are all still there
  I11 a folder added after the job began never has an original snapshot
  I12 no source UID appears twice in any folder's durable plan
Final: every destination folder holds exactly the copies of accepted/confirmed records (plus at most
the unresolved uncertain ones), and every live source message is confirmed unless an unresolved
uncertain transfer in its folder legitimately blocks it.

  python3 tests/local/incremental_stress.py target/fault-tests/debug/imaplane [--trials 8] [--seed N]
  python3 tests/local/incremental_stress.py --selftest        # proves each invariant can fire; no binary
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
from types import SimpleNamespace

from e2e import PASSWORD, ProtocolServer, command
from freshness import require_fresh
from stream_stress import FOLDER, Violation

READ_ONLY_VERBS = {'CAPABILITY', 'AUTHENTICATE', 'LIST', 'EXAMINE', 'UID', 'LOGOUT', 'NOOP'}
TRANSFER_POINTS = ['before_plan', 'after_plan', 'begin_append_before_commit', 'after_begin_append', 'before_append', 'after_append_continuation',
                   'authorize_literal_before_commit', 'after_authorize_literal', 'before_literal_send', 'after_append_reply',
                   'acknowledge_before_commit', 'after_acknowledge', 'before_verification_fetch', 'after_verification_fetch',
                   'before_confirm', 'after_confirm']
STREAM_ONLY = ['source_stream_chunk', 'spool_after_fetch', 'spool_sealed', 'append_stream_chunk', 'verification_stream_chunk', 'candidate_stream_chunk']
DISCOVERY_POINTS = ['scan_listed', 'scan_before_commit', 'scan_after_commit', 'folder_add_before_commit', 'folder_add_after_commit',
                    'before_v5_backup', 'after_v5_backup', 'before_v5_upgrade', 'v5_upgrade_before_commit', 'after_v5_upgrade']
HISTORY_POINTS = ['before_history_fetch', 'before_history_demote', 'before_invalidate', 'after_invalidate', 'history_run_before_commit',
                  'history_run_after_commit', 'evidence_before_commit', 'evidence_after_commit']
MODES = [('buffered', None), ('spooled', 0)]


def box(server, role, folder):
    return server.messages[role] if folder == FOLDER else server.extra[role].get(folder)


def check_state(server, ever, live, journal, state, recovers, prev):
    """Raise Violation if any of I1..I12 does not hold. `prev` carries earlier evidence between calls."""
    for folder in ever:
        dest = [d for d in (box(server, 'destination', folder) or []) if d is not None]
        if len(set(dest)) != len(dest):
            raise Violation(f'I2 duplicate message in destination folder {folder!r}')
        if not set(dest) <= set(ever[folder]):
            raise Violation(f'I3 foreign message in destination folder {folder!r}')
        if box(server, 'source', folder) != live[folder]:
            raise Violation(f'I4 source folder {folder!r} changed')
    bad = {v.decode() for u, v, _ in server.events if u == 'source'} - READ_ONLY_VERBS
    if bad:
        raise Violation(f'I4 non-read verbs sent to the source: {bad}')
    appends = sum(v == b'APPEND' for _, v, _ in server.events)
    total = sum(len(v) for v in ever.values())
    if appends > total + recovers:
        raise Violation(f'I7 {appends} APPENDs for {total} messages and {recovers} audited resets')
    extra = [p.name for p in state.iterdir() if not p.name.startswith(('journal.sqlite3', 'job.lock'))] if state.exists() else []
    if extra:
        raise Violation(f'I8 leftover files {extra}')
    if not journal.exists():
        return
    try:
        con = sqlite3.connect(journal)
        if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise Violation('I1 journal integrity')
    except sqlite3.DatabaseError as exc:
        raise Violation(f'I1 journal unreadable: {type(exc).__name__}')
    try:
        tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
        rows = con.execute('select folder,uid_validity,uid,state,destination_uid from transfers').fetchall()
        for folder, _, uid, st, du in rows:
            dest = box(server, 'destination', folder) or []
            if st == 'confirmed' and not (du and du <= len(dest) and dest[du - 1] == ever[folder][uid - 1]):
                raise Violation(f'I5 confirmed {folder!r} uid {uid} has no exact copy')
            if (st in ('confirmed', 'accepted')) != (du is not None):
                raise Violation(f'I6 {folder!r} uid {uid} state {st} with destination uid {du}')
        mappings = con.execute('select source,destination,origin,added_at from job_folders order by rowid').fetchall() if 'job_folders' in tables else []
        scans = con.execute('select folder,validity,generation,observed_uidnext,uids,scanned_at from scans').fetchall() if 'scans' in tables else []
        snaps = con.execute('select folder,validity,uids from snapshots').fetchall()
        keys = {(r[0], r[1], r[2]) for r in rows}
        if mappings[:len(prev.get('mappings', []))] != prev.get('mappings', []):
            raise Violation('I9 a recorded folder mapping changed or disappeared')
        if not set(prev.get('scans', [])) <= set(scans) or not set(prev.get('snaps', [])) <= set(snaps) or not prev.get('keys', set()) <= keys:
            raise Violation('I10 earlier discovery or transfer evidence was altered or lost')
        added = {m[0] for m in mappings if m[2] == 'added'}
        if any(s[0] in added for s in snaps):
            raise Violation('I11 an added folder has an original snapshot')
        plan = {}
        for folder, _, uids in snaps:
            plan.setdefault(folder, []).extend(json.loads(uids))
        for folder, _, _, _, uids, _ in scans:
            plan.setdefault(folder, []).extend(json.loads(uids))
        for folder, uids in plan.items():
            if len(set(uids)) != len(uids):
                raise Violation(f'I12 a UID is planned twice in {folder!r}')
        prev.update(mappings=mappings, scans=scans, snaps=snaps, keys=keys)
    except sqlite3.DatabaseError as exc:
        raise Violation(f'I1 journal unreadable: {type(exc).__name__}')
    finally:
        con.close()


def selftest():
    """Each invariant must be able to fire; otherwise a clean stress run would prove nothing."""
    import shutil
    tmp = Path(tempfile.mkdtemp(prefix='imaplane-istress-selftest-'))
    try:
        def world(**over):
            server = SimpleNamespace(messages={'source': [b'a', b'b'], 'destination': [b'a']}, extra={'source': {'X': [b'x']}, 'destination': {'X': [b'x']}}, events=[(None, b'APPEND', [])])
            return server, {FOLDER: [b'a', b'b'], 'X': [b'x']}, {FOLDER: [b'a', b'b'], 'X': [b'x']}
        state = tmp / 'state'; state.mkdir(); journal = state / 'journal.sqlite3'
        con = sqlite3.connect(journal)
        con.executescript("""create table transfers(folder,uid_validity,uid,state,destination_uid);
            create table snapshots(folder,validity,uids); create table scans(folder,validity,generation,observed_uidnext,uids,scanned_at);
            create table job_folders(source,destination,origin,added_at);
            insert into snapshots values('%s',1,'[1,2]'); insert into job_folders values('%s','%s','binding','t'),('X','X','added','t');
            insert into scans values('X',1,1,2,'[1]','t'); insert into transfers values('%s',1,1,'confirmed',1);""" % (FOLDER, FOLDER, FOLDER, FOLDER))
        con.commit(); con.close()
        server, ever, live = world()
        check_state(server, ever, live, journal, state, 0, {})            # the healthy world passes

        def expect(code, mutate, recovers=0, db=None, prev=None):
            s, e, l = world()
            mutate(s, e, l)
            if db:
                c = sqlite3.connect(journal); c.executescript(db); c.commit(); c.close()
            try:
                check_state(s, e, l, journal, state, recovers, dict(prev or {}))
            except Violation as v:
                assert str(v).startswith(code), (code, str(v))
                return
            finally:
                if db:
                    c = sqlite3.connect(journal)
                    for undo in db_undo.get(db, []):
                        c.executescript(undo)
                    c.commit(); c.close()
            raise AssertionError(f'{code} did not fire')
        db_undo = {}
        expect('I2', lambda s, e, l: s.extra['destination']['X'].append(b'x'))
        expect('I3', lambda s, e, l: s.messages['destination'].append(b'foreign'))
        expect('I4', lambda s, e, l: s.messages['source'].append(b'c'))
        expect('I4', lambda s, e, l: s.events.append(('source', b'STORE', [])))
        expect('I7', lambda s, e, l: s.events.extend([(None, b'APPEND', [])] * 5))
        (state / 'spool.tmp').write_bytes(b'x')
        expect('I8', lambda s, e, l: None)
        (state / 'spool.tmp').unlink()
        expect('I9', lambda s, e, l: None, prev={'mappings': [('X', 'X', 'binding', 't')]})
        expect('I10', lambda s, e, l: None, prev={'scans': [('X', 1, 9, 2, '[1]', 't')]})
        expect('I10', lambda s, e, l: None, prev={'keys': {('gone', 1, 1)}})
        db_undo["update transfers set destination_uid=2;"] = ["update transfers set destination_uid=1;"]
        expect('I5', lambda s, e, l: s.messages['destination'].__setitem__(0, b'a'), db="update transfers set destination_uid=2;")
        db_undo["update transfers set state='planned';"] = ["update transfers set state='confirmed';"]
        expect('I6', lambda s, e, l: None, db="update transfers set state='planned';")
        db_undo["insert into snapshots values('X',1,'[1]');"] = ["delete from snapshots where folder='X';"]
        expect('I11', lambda s, e, l: None, db="insert into snapshots values('X',1,'[1]');")
        db_undo["insert into scans values('X',1,2,3,'[1]','t');"] = ["delete from scans where generation=2;"]
        expect('I12', lambda s, e, l: None, db="insert into scans values('X',1,2,3,'[1]','t');")
        journal.write_bytes(b'not a database' * 100)
        expect('I1', lambda s, e, l: None)
        print('selftest: every invariant I1-I12 fires on a deliberately broken world')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary', nargs='?')
    ap.add_argument('--trials', type=int, default=8, help='trials per mode')
    ap.add_argument('--seed', type=int, default=int(time.time()) % 100000)
    ap.add_argument('--max-steps', type=int, default=20)
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()
    if args.selftest:
        selftest(); return 0
    binary = Path(args.binary).resolve()
    require_fresh(binary, 'fault-injection binary')
    print(f'seed {args.seed}  trials per mode {args.trials}', flush=True)
    totals = {}
    with tempfile.TemporaryDirectory(prefix='imaplane-istress-') as tmp:
        root = Path(tmp); os.chmod(root, 0o700)
        cert, key = root / 'tls.crt', root / 'tls.key'
        command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost')
        password = root / 'password'; password.write_text(PASSWORD); password.chmod(0o600)
        for mode, threshold in MODES:
            stats = dict(trials=0, runs=0, hook_kills=0, timed_kills=0, clean_runs=0, refused=0, recovers=0, resolves=0, additions=0, discoveries=0,
                         messages=0, confirmed=0, manual=0, violations=0, checks=0)
            for trial in range(args.trials):
                rng = random.Random(f'{args.seed}-{mode}-{trial}')
                server = ProtocolServer(str(cert), str(key), 'rev1')
                counter = [0]
                ever, live = {FOLDER: []}, {FOLDER: []}
                def body(folder):
                    counter[0] += 1
                    return b'Subject: %s %d\r\n\r\n' % (folder.encode(), counter[0]) + rng.randbytes(rng.choice([40, 600, 3000, 20000]))
                def arrive(folder, n=1):
                    for _ in range(n):
                        b = body(folder); ever[folder].append(b); live[folder].append(b)
                        box(server, 'source', folder).append(b)
                def expunge(folder, uid):
                    live[folder][uid - 1] = None; box(server, 'source', folder)[uid - 1] = None
                def new_folder(name, n):
                    server.extra['source'][name] = []; ever[name] = []; live[name] = []; arrive(name, n)
                server.messages['source'] = []
                arrive(FOLDER, rng.randint(1, 4))
                state = root / f'{mode}-{trial}'; journal = state / 'journal.sqlite3'
                cfg = root / f'{mode}-{trial}.toml'
                configured = [FOLDER]
                def write_config():
                    text = f'state_dir = "{state}"\ntimeout_seconds = 10\nmax_message_bytes = 4194304\nread_attempts = 2\n'
                    if threshold is not None:
                        text += f'stream_threshold_bytes = {threshold}\nspool_allow_memory_backed = true\n'
                    for role in ('source', 'destination'):
                        text += f'[{role}]\nhost = "localhost"\nport = {server.port}\nusername = "{role}"\npassword_file = "{password}"\nca_file = "{cert}"\n'
                    for f in configured:
                        text += f'[[folders]]\nsource = {json.dumps(f, ensure_ascii=False)}\ndestination = {json.dumps(f, ensure_ascii=False)}\n'
                    cfg.write_text(text)
                write_config()
                recovers = [0]; prev = {}
                pool = ['X1', 'X2', 'X3']
                dirty = {'arrival': False, 'folder': False}   # work a discovery or addition run should find

                def rows():
                    return sqlite3.connect(journal).execute('select folder,uid,state,destination_uid from transfers order by folder,uid').fetchall() if journal.exists() else []

                def check(where):
                    stats['checks'] += 1
                    try:
                        check_state(server, ever, live, journal, state, recovers[0], prev)
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
                    if p.returncode == 1 and os.environ.get('STRESS_DEBUG'):
                        print(f'  refused: {action} {extra} -> {err.strip()[-300:]}', flush=True)
                    server.errors.clear()
                    return p.returncode, out, killed

                def incremental(**kw):
                    level = kw.pop('level', 'metadata')
                    return run('migrate', extra=('--incremental', '--add-new-folders', '--verify-history', level), **kw)

                def operator_steps(where):
                    for folder, uid, st, _ in [r for r in rows() if r[2] == 'uncertain']:
                        a = ['--folder', folder, '--uid', str(uid)]
                        rc, o, _ = run('recover', extra=a)
                        if rc == 2:
                            stats['recovers'] += 1; recovers[0] += 1
                        else:
                            rc, o, _ = incremental()
                            try:
                                entry = next(e for e in json.loads(o)['entries'] if e['source_uid'] == uid and e['source_folder'] == folder)
                            except (StopIteration, ValueError, TypeError):
                                continue
                            if entry['result'] == 'uncertain' and len(entry['candidate_uids']) == 1:
                                rc, o, _ = run('resolve', extra=a + ['--destination-uid', str(entry['candidate_uids'][0])])
                                if rc in (0, 2):
                                    stats['resolves'] += 1
                        check(f'{where}: operator step {folder!r} uid {uid}')

                try:
                    for step in range(args.max_steps):
                        r = rng.random()
                        if step == 0:
                            # Create the job first (ordinary migrate), usually killed part-way.
                            code, out, _ = run(point=rng.choice(TRANSFER_POINTS), nth=rng.randint(1, 3)) if rng.random() < 0.7 else run()
                            stats['hook_kills' if code == -signal.SIGKILL else 'clean_runs'] += 1
                            check('step 1'); operator_steps('step 1'); continue
                        if r < 0.20:
                            dirty['arrival'] = True
                            arrive(rng.choice(list(live)), rng.randint(1, 2))
                        elif r < 0.26:
                            candidates = [(f, i + 1) for f in live for i, m in enumerate(live[f]) if m is not None]
                            if candidates:
                                expunge(*rng.choice(candidates))
                        elif r < 0.34 and pool:
                            new_folder(pool.pop(0), rng.randint(0, 3))
                        elif r < 0.44 and [f for f in live if f not in configured]:
                            configured.append(rng.choice([f for f in live if f not in configured])); write_config(); dirty['folder'] = True
                        else:
                            kind = rng.random()
                            if kind < 0.85 and not (dirty['arrival'] or dirty['folder']) and rng.random() < 0.8:
                                dirty['arrival'] = True; arrive(rng.choice(list(live)), 1)     # give the run something to do
                            if kind < 0.55:
                                usable = TRANSFER_POINTS + HISTORY_POINTS + (STREAM_ONLY if threshold is not None else [])
                                if dirty['folder']:
                                    usable = usable + ['folder_add_before_commit', 'folder_add_after_commit', 'scan_listed'] * 4 + DISCOVERY_POINTS
                                if dirty['arrival']:
                                    usable = usable + ['scan_listed', 'scan_before_commit', 'scan_after_commit'] * 3
                                point = rng.choice(usable)
                                action = rng.choice(['ordinary', 'incremental', 'incremental', 'incremental', 'verify'])
                                nth = rng.choice([1, 1, 1, 2, 3])
                                if action == 'ordinary': code, out, _ = run(point=point, nth=nth)
                                elif action == 'verify': code, out, _ = run('verify', point=point, nth=nth)
                                else: code, out, _ = incremental(point=point, nth=nth, level=rng.choice(['existence', 'metadata', 'full']))
                                stats['hook_kills' if code == -signal.SIGKILL else 'clean_runs'] += 1
                            elif kind < 0.85:
                                delay = rng.uniform(0.05, 1.8)
                                action = rng.choice(['ordinary', 'incremental', 'incremental'])
                                code, out, killed = run(delay=delay) if action == 'ordinary' else incremental(delay=delay, level=rng.choice(['metadata', 'full']))
                                stats['timed_kills' if killed else 'clean_runs'] += 1
                            else:
                                code, out, _ = rng.choice([lambda: run(), lambda: incremental(), lambda: run('verify')])()
                                stats['clean_runs'] += 1
                            if code in (0, 2):
                                if action in ('incremental',) or kind >= 0.85:
                                    dirty['arrival'] = dirty['folder'] = False
                            if code == 1:
                                stats['refused'] += 1          # e.g. incremental before a job exists, or a config the job refuses
                        check(f'step {step + 1}')
                        operator_steps(f'step {step + 1}')
                    # Convergence: clean incremental runs until nothing is left to do or only manual cases remain.
                    for folder in list(live):
                        if folder not in configured:
                            configured.append(folder)
                    write_config()
                    if not journal.exists():
                        code, out, _ = run(); check('first migrate')
                    quiet = 0
                    for number in range(10):
                        before = rows()
                        code, out, _ = incremental(); check(f'convergence run {number + 1}')
                        operator_steps(f'convergence {number + 1}')
                        quiet = quiet + 1 if rows() == before else 0
                        if quiet >= 2:
                            break
                    # Final checks.
                    final = rows(); by = {(f, u): (st, du) for f, u, st, du in final}
                    uncertain_folders = {f for f, _, st, _ in final if st == 'uncertain'}
                    for folder in ever:
                        dest = [d for d in (box(server, 'destination', folder) or []) if d is not None]
                        want = {ever[folder][u - 1] for f, u, st, _ in final if f == folder and st in ('accepted', 'confirmed')}
                        maybe = {ever[folder][u - 1] for f, u, st, _ in final if f == folder and st == 'uncertain'}
                        if not (want <= set(dest) <= want | maybe):
                            raise Violation(f'FINAL destination folder {folder!r} differs from its accepted/confirmed records')
                        for i, m in enumerate(live[folder]):
                            if m is None:
                                continue
                            st = by.get((folder, i + 1), (None, None))[0]
                            if st != 'confirmed' and folder not in uncertain_folders:
                                raise Violation(f'FINAL live message {folder!r} uid {i + 1} is {st} without an unresolved uncertain transfer to blame')
                    stats['trials'] += 1
                    stats['messages'] += sum(1 for f in live for m in live[f] if m is not None)
                    stats['confirmed'] += sum(1 for r in final if r[2] == 'confirmed' and live[r[0]][r[1] - 1] is not None)
                    stats['manual'] += sum(1 for f in live for i, m in enumerate(live[f]) if m is not None and by.get((f, i + 1), (None,))[0] != 'confirmed')
                    stats['additions'] += len(configured) - 1
                except Violation as v:
                    if not str(v).startswith(('I',)):
                        stats['violations'] += 1; print(f'  VIOLATION [{mode} trial {trial}]: {v}  (seed {args.seed})', flush=True)
                finally:
                    server.close()
            totals[mode] = stats
            print(f'{mode:>9}: {stats["trials"]} trials, {stats["runs"]} runs ({stats["hook_kills"]} hook kills, {stats["timed_kills"]} timed kills, {stats["clean_runs"]} unkilled, {stats["refused"]} refused), '
                  f'{stats["checks"]} invariant checks, {stats["additions"]} folders added, {stats["recovers"]} audited recovers, {stats["resolves"]} resolves, '
                  f'{stats["confirmed"]}/{stats["messages"]} live messages confirmed, {stats["manual"]} left manual, {stats["violations"]} violations', flush=True)
    bad = sum(t['violations'] for t in totals.values())
    print('PASS: no invariant violation' if not bad else f'FAIL: {bad} violation(s)')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
