#!/usr/bin/env python3
"""IMAPLANE vs imapsync benchmark orchestrator. See README.md for the method and the exact commands.

  python3 bench.py env                                    # record the environment
  python3 bench.py golden mixed                           # generate + seed the source mailbox once
  python3 bench.py run --profile mixed --reps 3 --seed 1  # fresh / rerun / new-mail chains, interleaved
  python3 bench.py kill --profile mixed --kills 4         # SIGKILL during transfer, resume, verify
  python3 bench.py report results/<dir>                   # medians + tables

Everything that is measured is measured inside the tool's own container by measure.py, or on the
Dovecot servers (its own exported command events), or by the independent verifier; this script only orchestrates.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path

import dataset
import common
from common import HERE, SRC_USER, DST_USER, sh, utf7

WORK = Path(os.environ.get('BENCH_WORK', Path.home() / 'imaplane-bench-work'))
IMAPLANE_BIN = Path(os.environ.get('IMAPLANE_BIN', '/tmp/claude-1000/-home-majid-Desktop-imaplane/7cf405e2-bd5d-4301-a605-fe5d60682523/scratchpad/cargo-target/release/imaplane'))
# Configs named imaplane-wal* run the Phase 1 (write-ahead-log journal) binary; imaplane / imaplane-stream run IMAPLANE_BIN
# (the original a6ec32f build). Both are release builds of committed sources; their hashes are recorded in env.json.
IMAPLANE_WAL_BIN = Path(os.environ['IMAPLANE_WAL_BIN']) if 'IMAPLANE_WAL_BIN' in os.environ else None
# imaplane-fd*: Phase 2 build (WAL + fdatasync); imaplane-rt*: Phase 3 build (adds the one-round-trip small-message read)
IMAPLANE_FD_BIN = Path(os.environ['IMAPLANE_FD_BIN']) if 'IMAPLANE_FD_BIN' in os.environ else None
IMAPLANE_RT_BIN = Path(os.environ['IMAPLANE_RT_BIN']) if 'IMAPLANE_RT_BIN' in os.environ else None


def binary_for(cfg):
    for prefix, binary in (('imaplane-rt', IMAPLANE_RT_BIN), ('imaplane-fd', IMAPLANE_FD_BIN), ('imaplane-wal', IMAPLANE_WAL_BIN)):
        if cfg.startswith(prefix):
            if binary is None:
                sys.exit(f'{prefix}* needs its binary (environment variable not set)')
            return binary
    return IMAPLANE_BIN
TOOL_LIMITS = ['--cpus', '2', '--memory', '2g']
# LATENCY_MS=N adds N ms to every round trip of the TOOL (tc netem on its own interface; the servers are untouched).
# The tool still runs as the unprivileged user: the container starts as root only to configure the interface.
LATENCY_MS = int(os.environ.get('LATENCY_MS', '0'))
CONFIGS = ['imapsync', 'imapsync-tuned', 'imaplane', 'imaplane-stream']
NEWMAIL = 200


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


LOCK_FILE = WORK / 'bench.lock'


class BenchLock:
    """One benchmark command at a time, machine-wide. The lock is held for the whole command (a stage that
    runs several steps takes it once), so two launches can never share datasets, containers or state."""

    def __enter__(self):
        WORK.mkdir(parents=True, exist_ok=True)
        self.f = open(LOCK_FILE, 'a+')
        try:
            fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.f.seek(0)
            sys.exit(f'REFUSED: another benchmark command holds {LOCK_FILE}: {self.f.read().strip()!r}. Overlapping runs are not allowed.')
        self.f.seek(0); self.f.truncate()
        self.f.write(f'pid {os.getpid()} started {time.strftime("%F %T")} args {" ".join(sys.argv[1:])}\n'); self.f.flush()
        return self

    def __exit__(self, *_):
        fcntl.flock(self.f, fcntl.LOCK_UN); self.f.close()


def stale():
    """Everything a previous (possibly crashed) command could have left behind."""
    found = []
    names = sh('docker', 'ps', '-a', '--format', '{{.Names}}').stdout.split()
    found += [f'container {n}' for n in names if n.startswith('bench-')]
    nets = sh('docker', 'network', 'ls', '--format', '{{.Name}}').stdout.split()
    found += [f'network {n}' for n in nets if n.startswith('bench-net')]
    runs = WORK / 'runs'
    if runs.exists():
        found += [f'run directory {d.name}' for d in runs.iterdir()]
    procs = sh('ps', '-eo', 'pid,args').stdout.splitlines()
    found += [f'process {l.strip()[:90]}' for l in procs if 'python3 /bench/measure.py' in l and 'bash -c' not in l and 'ps -eo' not in l]
    return found


def preflight():
    left = stale()
    if left:
        sys.exit('REFUSED: stale benchmark state from an earlier command; run `bench.py clean` after checking it:\n  ' + '\n  '.join(left))
    log('preflight: no stale containers, networks, run directories or measuring processes')


def clean():
    for n in sh('docker', 'ps', '-a', '--format', '{{.Names}}').stdout.split():
        if n.startswith('bench-'):
            sh('docker', 'rm', '-f', n, check=False); log('removed container', n)
    for n in sh('docker', 'network', 'ls', '--format', '{{.Name}}').stdout.split():
        if n.startswith('bench-net'):
            common.remove_network(n); log('removed network', n)
    shutil.rmtree(WORK / 'runs', ignore_errors=True)


def folders_for(profile):
    return dataset.profile(profile)[1]


class Run:
    """One isolated environment: a restored source mailbox, an empty destination, two Dovecots, their own
    Docker network and a uniquely named directory. Nothing is shared with any other run except the
    read-only golden dataset, whose hash is checked before and after."""

    def __init__(self, profile, tag):
        self.profile, self.tag = profile, tag
        self.rid = f'{tag}-{uuid.uuid4().hex[:6]}'
        self.net = f'bench-net-{self.rid}'
        self.dir = WORK / 'runs' / self.rid
        self.cert, self.key = common.ensure_cert(WORK)
        self.folders = folders_for(profile)
        self.golden = WORK / 'golden' / profile
        self.info = json.load(open(self.golden / 'info.json'))
        if common.tree_hash(self.golden / 'mail') != self.info['tree_sha256']:
            sys.exit(f'REFUSED: golden dataset {profile} no longer matches its recorded hash')
        (self.dir / 'out').mkdir(parents=True); (self.dir / 'state').mkdir(mode=0o700)
        os.chmod(self.dir / 'state', 0o700); os.chmod(self.dir / 'out', 0o777)
        (self.dir / 'state' / 'imapsync-tmp').mkdir()
        sh('cp', '-a', str(self.golden / 'mail'), str(self.dir / 'src-mail'))
        sh('chmod', '-R', 'u+w', str(self.dir / 'src-mail'))
        if common.tree_hash(self.dir / 'src-mail') != self.info['tree_sha256']:
            sys.exit('REFUSED: the restored source mailbox differs from the golden dataset')
        common.create_network(self.net)
        self.src = common.Dovecot(f'bench-src-{self.rid}', self.dir / 'src-mail', self.cert, self.key, SRC_USER, self.net, 'bench-src')
        self.dst = common.Dovecot(f'bench-dst-{self.rid}', self.dir / 'dst-mail', self.cert, self.key, DST_USER, self.net, 'bench-dst')
        self.src.start(); self.dst.start()
        self.src_before = None
        self.tool_name = f'bench-tool-{self.rid}'
        self.extra_env, self.binary, self.global_args, self.cmd_prefix = {}, None, [], []
        self.cfg_binary = None

    def close(self):
        self.src.stop(); self.dst.stop()
        sh('docker', 'rm', '-f', self.tool_name, check=False)
        common.remove_network(self.net)
        shutil.rmtree(self.dir, ignore_errors=True)
        if common.tree_hash(self.golden / 'mail') != self.info['tree_sha256']:
            raise RuntimeError(f'golden dataset {self.profile} was modified during run {self.rid}')

    # ---- tool command lines -------------------------------------------------------------------
    def write_imaplane_config(self, stream):
        t = ['state_dir = "/state"', 'timeout_seconds = 60']
        if stream:
            t += ['stream_threshold_bytes = 0']
        for role, host, user in (('source', 'bench-src', SRC_USER), ('destination', 'bench-dst', DST_USER)):
            t += [f'[{role}]', f'host = "{host}"', 'port = 993', f'username = "{user}"', 'password_file = "/work/password"', 'ca_file = "/work/tls.crt"']
        for f in self.folders:
            t += ['[[folders]]', f'source = "{f}"', f'destination = "{f}"']
        (self.dir / 'imaplane.toml').write_text('\n'.join(t) + '\n')

    def command(self, cfg, step):
        """(command line, extra docker args) for a tool config and a step."""
        if cfg.startswith('imapsync'):
            c = ['imapsync', '--host1', 'bench-src', '--port1', '993', '--ssl1', '--user1', SRC_USER, '--passfile1', '/work/password',
                 '--host2', 'bench-dst', '--port2', '993', '--ssl2', '--user2', DST_USER, '--passfile2', '/work/password',
                 '--syncinternaldates', '--logdir', '/tmp/imapsync-log']
            if cfg == 'imapsync-tuned':
                # --useuid keeps its UID cache under --tmpdir. The tool container is throwaway, so the cache
                # must live on the persistent per-chain state volume, or every rerun re-copies everything.
                c += ['--nofoldersizes', '--nofoldersizesatend', '--useuid', '--tmpdir', '/state/imapsync-tmp']
            for f in self.folders:
                c += ['--folder', utf7(f)]
            return c
        self.write_imaplane_config(cfg.endswith('stream'))
        base = ['imaplane'] + self.global_args
        if step in ('fresh', 'resume', 'ordinary'):
            return base + ['migrate', '--config', '/work/imaplane.toml', '--json']
        if step == 'verify':
            return base + ['verify', '--config', '/work/imaplane.toml', '--json']
        level = {'inc-metadata': 'metadata', 'inc-existence': 'existence', 'inc-full': 'full', 'incremental': 'metadata'}[step]
        return base + ['migrate', '--config', '/work/imaplane.toml', '--json', '--incremental', '--verify-history', level]

    def docker_args(self, name, outname, detach=False):
        env = [x for k, v in self.extra_env.items() for x in ('-e', f'{k}={v}')]
        user, image = (f'{common.UID}:{common.UID}', common.RUNNER_IMAGE) if not LATENCY_MS else ('0:0', 'imaplane-bench-runner:2')
        caps = ['--cap-add', 'NET_ADMIN'] if LATENCY_MS else []
        return (['docker', 'run'] + (['-d'] if detach else []) + ['--rm', '--name', name, '--network', self.net] + TOOL_LIMITS + caps + ['--user', user, '-e', 'HOME=/tmp'] + env + [
                '-v', f'{self.dir}/imaplane.toml:/work/imaplane.toml:ro', '-v', f'{WORK}/tls.crt:/work/tls.crt:ro', '-v', f'{WORK}/password:/work/password:ro',
                '-v', f'{self.dir}/state:/state', '-v', f'{self.dir}/out:/out', '-v', f'{HERE}:/bench:ro', '-v', f'{self.binary or self.cfg_binary or IMAPLANE_BIN}:/usr/local/bin/imaplane:ro', image,
                'python3', '/bench/measure.py', '/out', outname, '--'])

    # ---- measured execution -------------------------------------------------------------------
    def measure(self, cfg, step, label, timeout=14400):
        self.cfg_binary = binary_for(cfg) if cfg.startswith('imaplane') else None
        cmd = self.cmd_prefix + self.command(cfg, step)
        if LATENCY_MS:
            cmd = ['sh', '-c', f'tc qdisc add dev eth0 root netem delay {LATENCY_MS}ms && exec setpriv --reuid={common.UID} --regid={common.UID} --clear-groups "$@"', 'sh'] + cmd
        t = time.time()
        sh(*self.docker_args(self.tool_name, label), *cmd, check=False, timeout=timeout)
        t_end = time.time() + 0.3
        res = json.load(open(self.dir / 'out' / f'{label}.json'))
        res['dovecot_src'] = self.src.events(t - 0.2, t_end)
        res['dovecot_dst'] = self.dst.events(t - 0.2, t_end)
        res['imap_commands'] = res['dovecot_src']['commands'] + res['dovecot_dst']['commands']
        res['imap_sessions'] = res['dovecot_src']['sessions'] + res['dovecot_dst']['sessions']
        res['app_bytes'] = sum(res[k][f] for k in ('dovecot_src', 'dovecot_dst') for f in ('app_bytes_client_to_server', 'app_bytes_server_to_client'))
        out = (self.dir / 'out' / f'{label}.stdout').read_text(errors='replace')
        res['tool_report'] = summarize_report(cfg, out)
        res['wall_clock_total_s'] = time.time() - t
        return res

    def snapshots(self):
        names = [utf7(f) for f in self.folders]
        return common.snapshot(self.src, names), common.snapshot(self.dst, names)

    def check(self, note=''):
        """Independent verification: destination vs the live source; source unchanged since the start."""
        s, d = self.snapshots()
        v = common.verify(s, d)
        if self.src_before is not None:
            v['source_unchanged'] = {k: sorted(v_) for k, v_ in s.items() if v_ is not None} == {k: sorted(v_) for k, v_ in self.src_before.items() if v_ is not None}
        self.src_before = s
        return v


def summarize_report(cfg, out):
    if cfg.startswith('imapsync'):
        keep = {}
        for line in out.splitlines():
            for key in ('Transfer total time', 'Messages transferred', 'Messages skipped', 'Messages found in host1 not in host2', 'Detected', 'Exiting with return value'):
                if line.strip().startswith(key) or key in line and key != 'Detected':
                    keep[key] = line.strip()[:200]
        return keep
    try:
        r = json.loads(out)
        res = {}
        for e in r.get('entries', []):
            res[e['result']] = res.get(e['result'], 0) + 1
        return {'complete': r.get('complete'), 'results': res, 'verification': (r.get('verification') or {}) and {k: v for k, v in r['verification'].items() if k != 'folders'}, 'warnings': r.get('warnings', [])}
    except ValueError:
        return {'unparsed': out[-200:]}


def env_info():
    info = {'date': dt.datetime.now(dt.timezone.utc).isoformat(), 'host': platform.platform(), 'cpu': next((l.split(':', 1)[1].strip() for l in open('/proc/cpuinfo') if l.startswith('model name')), '?'),
            'cores': os.cpu_count(), 'mem_gib': round(int(next(l.split()[1] for l in open('/proc/meminfo') if l.startswith('MemTotal'))) / 1048576, 1)}
    info['docker'] = sh('docker', 'version', '--format', '{{.Server.Version}}').stdout.strip()
    info['storage'] = sh('df', '-T', str(WORK.parent)).stdout.splitlines()[-1]
    info['images'] = {n: sh('docker', 'image', 'inspect', n, '--format', '{{.Id}} {{.Created}}').stdout.strip() for n in (common.DOVECOT_IMAGE, common.RUNNER_IMAGE)}
    info['dovecot'] = sh('docker', 'run', '--rm', common.DOVECOT_IMAGE, 'dovecot', '--version').stdout.strip()
    info['imapsync'] = sh('docker', 'run', '--rm', common.RUNNER_IMAGE, 'sh', '-c', 'imapsync --version; cat /usr/local/share/imapsync.sha256; perl -v | sed -n 2p').stdout.strip()
    info['imaplane_binary_sha256'] = hashlib.sha256(IMAPLANE_BIN.read_bytes()).hexdigest()
    info['imaplane_version'] = sh(str(IMAPLANE_BIN), '--version').stdout.strip()
    if IMAPLANE_WAL_BIN:
        info['imaplane_wal_binary_sha256'] = hashlib.sha256(IMAPLANE_WAL_BIN.read_bytes()).hexdigest()
        info['imaplane_wal_binary_path'] = str(IMAPLANE_WAL_BIN)
    for name, b in (('fd', IMAPLANE_FD_BIN), ('rt', IMAPLANE_RT_BIN)):
        if b:
            info[f'imaplane_{name}_binary_sha256'] = hashlib.sha256(b.read_bytes()).hexdigest()
            info[f'imaplane_{name}_binary_path'] = str(b)
    info['imaplane_baseline_binary_path'] = str(IMAPLANE_BIN)
    info['imaplane_commit'] = sh('git', '-C', str(HERE.parents[1]), 'rev-parse', 'HEAD').stdout.strip()
    info['imaplane_tree_clean'] = not sh('git', '-C', str(HERE.parents[1]), 'status', '--porcelain', '--', 'src', 'Cargo.toml', 'Cargo.lock').stdout.strip()
    info['injected_latency_ms'] = LATENCY_MS
    info['limits'] = {'tool_container': TOOL_LIMITS, 'dovecot_containers': '--cpus 2 --memory 2g each'}
    info['scripts_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(HERE.glob('*.py')) + [HERE / 'dovecot-bench.conf', HERE / 'Dockerfile.runner']}
    return info


def cmd_golden(args):
    WORK.mkdir(parents=True, exist_ok=True)
    cert, key = common.ensure_cert(WORK)
    records, folders = dataset.profile(args.profile)
    gdir = WORK / 'golden' / args.profile
    if gdir.exists():
        sh('chmod', '-R', 'u+w', str(gdir)); shutil.rmtree(gdir)
    (gdir / 'mail').mkdir(parents=True); os.chmod(gdir / 'mail', 0o777)
    rid = uuid.uuid4().hex[:6]; net = f'bench-net-golden-{rid}'
    common.create_network(net)
    d = common.Dovecot(f'bench-src-golden-{rid}', gdir / 'mail', cert, key, SRC_USER, net, 'bench-src').start()
    t = time.time()
    common.seed(d, records, folders, batch_log=log)
    log(f'seeded {len(records)} messages in {time.time() - t:.0f}s')
    snap = common.snapshot(d, [utf7(f) for f in folders])
    want = sorted(dataset.manifest(records))
    got = sorted((f, h, tuple(fl), dt_) for f in folders if snap[utf7(f)] is not None for h, _, fl, dt_ in snap[utf7(f)])
    # the server must hold exactly what was generated: content, flags (as sets) and INTERNALDATE (as instants)
    mism = len(set(want) ^ set(got)) + abs(len(want) - len(got))
    d.stop(); common.remove_network(net)
    total_bytes = sum(len(r['body']) for r in records)
    tree = common.tree_hash(gdir / 'mail')
    json.dump({'profile': args.profile, 'messages': len(records), 'bytes': total_bytes, 'folders': folders, 'manifest_sha256': hashlib.sha256(json.dumps(want).encode()).hexdigest(), 'seed_mismatch': mism, 'server_count': len(got),
               'tree_sha256': tree}, open(gdir / 'info.json', 'w'), indent=1)
    if mism:
        sys.exit(f'golden {args.profile}: server content differs from the generated dataset ({mism} differences)')
    sh('chmod', '-R', 'a-w', str(gdir / 'mail'))      # the golden copy is read-only from now on
    log(f'golden {args.profile}: {len(records)} messages, {total_bytes / 1e6:.0f} MB, {len(got)} on the server, mismatches {mism}')


def outdir(args):
    d = HERE / 'results' / (args.out or f'{args.profile}-{time.strftime("%Y%m%d-%H%M%S")}')
    if (d / 'runs.jsonl').exists():
        sys.exit(f'REFUSED: {d} already holds results; results are never mixed or overwritten (choose another --out)')
    (d / 'raw').mkdir(parents=True, exist_ok=True)
    return d


def record(out, row):
    with open(out / 'runs.jsonl', 'a') as f:
        f.write(json.dumps(row) + '\n')


def save_raw(run, out, label):
    for ext in ('stdout', 'stderr', 'json'):
        src = run.dir / 'out' / f'{label}.{ext}'
        if src.exists():
            shutil.copy(src, out / 'raw' / f'{label}.{ext}')


def chain(profile, cfg, rep, out, rng, newmail_seed, newmail=True):
    tag = f'{profile}-{cfg}-r{rep}'
    run = Run(profile, tag)
    info = json.load(open(WORK / 'golden' / profile / 'info.json'))
    try:
        run.src_before = None
        def step(name, label_step, verify=True, mutate=None):
            label = f'{tag}-{name}'
            res = run.measure(cfg, label_step, label)
            save_raw(run, out, label)
            row = {'profile': profile, 'cfg': cfg, 'rep': rep, 'step': name, **res}
            if verify:
                row['verify'] = run.check()
            record(out, row)
            log(f'{tag} {name}: wall {res["wall_s"]:.1f}s rc={res["returncode"]} rss={res["peak_rss_kib"] / 1024:.0f}MiB cmds={res["imap_commands"]} '
                f'verify={"ok" if row.get("verify", {}).get("ok") else row.get("verify", {}).get("total")}')
            return row
        step('fresh', 'fresh')
        # no-change reruns
        if cfg.startswith('imapsync'):
            step('rerun', 'fresh', verify=False)
        else:
            order = ['inc-metadata', 'inc-existence', 'inc-full', 'verify', 'ordinary']
            rng.shuffle(order)
            for s in order:
                step(f'rerun-{s}', s, verify=False)
        # incremental with new mail (twice; the second uses the full history level for IMAPLANE)
        for n in ((1, 2) if newmail else ()):
            recs = dataset.new_mail(NEWMAIL, run.folders, newmail_seed + n)
            common.append_records(run.src, recs)
            run.src_before = None
            label_step = 'fresh' if cfg.startswith('imapsync') else ('inc-metadata' if n == 1 else 'inc-full')
            step(f'newmail{n}', label_step)
        run.check()
    finally:
        run.close()


def cmd_run(args):
    out = outdir(args)
    json.dump(env_info(), open(out / 'env.json', 'w'), indent=1)
    json.dump(vars(args), open(out / 'args.json', 'w'), indent=1)
    rng = random.Random(args.seed)
    cfgs = args.configs.split(',')
    for rep in range(1, args.reps + 1):
        order = list(cfgs); rng.shuffle(order)          # interleaved/randomized order within each repetition
        log(f'rep {rep} order {order}')
        for cfg in order:
            chain(args.profile, cfg, rep, out, rng, args.seed * 100 + rep, newmail=not args.no_newmail)
    log('run complete:', out)


def journal_attempts(run):
    """Phase evidence from a COPY of the run's journal (never touches the live state): append_attempts rows and
    uncertain transfers."""
    import sqlite3, shutil, tempfile
    try:
        with tempfile.TemporaryDirectory() as t:
            for n in ('journal.sqlite3', 'journal.sqlite3-wal'):
                if (run.dir / 'state' / n).exists():
                    shutil.copy(run.dir / 'state' / n, t)
            db = sqlite3.connect(f'{t}/journal.sqlite3')
            out = {'attempts': db.execute('select folder,uid,phase from append_attempts').fetchall(), 'uncertain': db.execute("select folder,uid from transfers where state='uncertain'").fetchall()}
            db.close()
            return out
    except Exception as exc:
        return {'error': repr(exc)}


def operator_loop(run, cfg, label, max_rounds=6, decisions=None):
    """The documented operator procedure for uncertain IMAPLANE records: audited recover when nothing was
    sent, resolve when exactly one verified candidate exists. Returns (actions, remaining_uncertain)."""
    actions = 0
    decisions = decisions if decisions is not None else []
    for round_ in range(max_rounds):
        res = run.measure(cfg, 'ordinary', f'{label}-op{round_}')
        try:
            report = json.loads((run.dir / 'out' / f'{label}-op{round_}.stdout').read_text())
        except ValueError:
            return actions, None
        unc = [e for e in report.get('entries', []) if e['result'] == 'uncertain']
        if not unc:
            return actions, 0
        progressed = False
        for e in unc:
            base = ['docker', 'run', '--rm', '--network', run.net, '--user', f'{common.UID}:{common.UID}', '-e', 'HOME=/tmp', '-v', f'{run.dir}/imaplane.toml:/work/imaplane.toml:ro',
                    '-v', f'{WORK}/tls.crt:/work/tls.crt:ro', '-v', f'{WORK}/password:/work/password:ro', '-v', f'{run.dir}/state:/state', '-v', f'{run.cfg_binary or IMAPLANE_BIN}:/usr/local/bin/imaplane:ro', common.RUNNER_IMAGE, 'imaplane']
            a = ['--config', '/work/imaplane.toml', '--folder', e['source_folder'], '--uid', str(e['source_uid'])]
            p = sh(*base, 'recover', *a, '--json', check=False)
            decisions.append({'uid': e['source_uid'], 'folder': e['source_folder'], 'recover_rc': p.returncode, 'recover_out': (p.stdout or '')[-600:], 'recover_err': (p.stderr or '')[-300:],
                              'candidates': len(e.get('candidate_uids', [])), 'journal': journal_attempts(run)})
            if p.returncode == 2:
                actions += 1; progressed = True; continue
            if len(e.get('candidate_uids', [])) == 1:
                p = sh(*base, 'resolve', *a, '--destination-uid', str(e['candidate_uids'][0]), '--json', check=False)
                if p.returncode in (0, 2):
                    actions += 1; progressed = True
        if not progressed:
            return actions, len(unc)
    return actions, None


def cmd_kill(args):
    out = outdir(args)
    json.dump(env_info(), open(out / 'env.json', 'w'), indent=1)
    rng = random.Random(args.seed)
    info = json.load(open(WORK / 'golden' / args.profile / 'info.json'))
    fresh_medians = json.load(open(args.fresh_medians)) if args.fresh_medians else {}
    cfgs = args.configs.split(',')
    for k in range(1, args.kills + 1):
        order = list(cfgs); rng.shuffle(order)
        for cfg in order:
            tag = f'{args.profile}-{cfg}-k{k}'
            run = Run(args.profile, tag)
            try:
                frac = rng.uniform(0.25, 0.75)
                expected = fresh_medians.get(cfg, 60.0)
                delay = max(2.0, frac * expected)
                label = f'{tag}-killed'
                run.cfg_binary = binary_for(cfg) if cfg.startswith('imaplane') else None
                cmd = run.command(cfg, 'fresh')
                name = run.tool_name
                sh(*run.docker_args(name, label, detach=True), *cmd)
                time.sleep(delay)
                sh('docker', 'kill', '-s', 'KILL', name, check=False)
                for _ in range(100):
                    if sh('docker', 'inspect', name, check=False).returncode:
                        break
                    time.sleep(0.1)
                time.sleep(1.0)
                mid = {}
                c = run.dst.connect()
                for f in run.folders:
                    typ, data = c.status(common.quoted(utf7(f)), '(MESSAGES)')
                    mid[f] = int(data[0].split(b'MESSAGES ')[1].split(b')')[0]) if typ == 'OK' else None
                c.logout()
                landed = sum(v or 0 for v in mid.values())
                mid_verify = run.check()
                at_kill_journal = journal_attempts(run)
                # resume with the SAME command; this is the recovery time
                res = run.measure(cfg, 'resume' if cfg.startswith('imaplane') else 'fresh', f'{tag}-resume')
                save_raw(run, out, f'{tag}-resume')
                after_one = run.check()
                actions = remaining = None; decisions = []
                final = after_one
                if cfg.startswith('imaplane') and (res['tool_report'].get('results', {}).get('uncertain') or not res['tool_report'].get('complete')):
                    actions, remaining = operator_loop(run, cfg, tag, decisions=decisions)
                    final = run.check()
                row = {'profile': args.profile, 'cfg': cfg, 'kill': k, 'kill_after_s': delay, 'fraction_of_median_fresh': frac, 'messages_in_destination_at_kill': landed,
                       'at_kill': mid_verify['total'], 'resume': res, 'after_one_rerun': after_one, 'operator_actions': actions, 'uncertain_remaining': remaining, 'journal_at_kill': at_kill_journal, 'operator_decisions': decisions, 'manual_review': bool(remaining), 'final': final}
                record(out, row)
                log(f'{tag}: killed at {delay:.1f}s with {landed} in destination; resume {res["wall_s"]:.1f}s; one-rerun ok={after_one["ok"]} {after_one["total"].get("duplicates")} dup {after_one["total"].get("missing")} missing; final ok={final["ok"]} ops={actions}')
            finally:
                run.close()
    log('kill run complete:', out)


def cmd_stage2(_):
    """1,000- and 5,000-message scaling, then the corrected imapsync-tuned rerun, all under ONE lock.
    The 20,000-message test is deliberately not part of this stage."""
    old = {}
    try:
        old = json.load(open(WORK / 'golden' / 'mixed' / 'info.json'))
    except OSError:
        pass
    cmd_golden(argparse.Namespace(profile='mixed'))          # rebuilt read-only with a recorded tree hash
    new = json.load(open(WORK / 'golden' / 'mixed' / 'info.json'))
    log('mixed dataset identity: manifest', 'UNCHANGED' if old.get('manifest_sha256') == new['manifest_sha256'] else f'differs from the earlier build ({old.get("manifest_sha256")})')
    for n in (1000, 5000):
        cmd_golden(argparse.Namespace(profile=f'scale-{n}'))
        cmd_run(argparse.Namespace(profile=f'scale-{n}', reps=2, seed=3, no_newmail=True, configs='imapsync,imapsync-tuned,imaplane,imaplane-stream', out=f'scale-{n}'))
    cmd_run(argparse.Namespace(profile='mixed', reps=3, seed=11, no_newmail=False, configs='imapsync-tuned', out='main-mixed-tuned-fixed'))
    log('STAGE2 DONE (scale-20000 deferred)')


def cmd_stage_p1(_):
    """Phase 1 (write-ahead-log journal) comparison, all under ONE lock: original binary vs the WAL binary vs tuned
    imapsync, interleaved, on the mixed dataset; SIGKILL tests for the WAL binary; 1k and 5k scaling."""
    if IMAPLANE_WAL_BIN is None:
        sys.exit('set IMAPLANE_WAL_BIN to the Phase 1 release binary')
    cfgs = 'imaplane,imaplane-wal,imaplane-wal-stream,imapsync-tuned'
    cmd_run(argparse.Namespace(profile='mixed', reps=3, seed=21, no_newmail=False, configs=cfgs, out='p1-main-mixed'))
    med = {}
    for l in open(HERE / 'results' / 'p1-main-mixed' / 'runs.jsonl'):
        r = json.loads(l)
        if r['step'] == 'fresh':
            med.setdefault(r['cfg'], []).append(r['wall_s'])
    med = {k: statistics.median(v) for k, v in med.items()}
    json.dump(med, open(HERE / 'results' / 'p1-fresh-medians-mixed.json', 'w'))
    cmd_kill(argparse.Namespace(profile='mixed', kills=4, seed=17, configs='imaplane-wal,imaplane-wal-stream', fresh_medians=str(HERE / 'results' / 'p1-fresh-medians-mixed.json'), out='p1-kill-mixed'))
    for n in (1000, 5000):
        cmd_run(argparse.Namespace(profile=f'scale-{n}', reps=2, seed=23, no_newmail=True, configs='imaplane,imaplane-wal,imapsync-tuned', out=f'p1-scale-{n}'))
    log('PHASE 1 BENCHMARK DONE')


def cmd_stage_p2(_):
    """Phase 2 (WAL + fdatasync) comparison under ONE lock: original, Phase 1, Phase 2 and tuned imapsync interleaved
    on the mixed dataset, SIGKILL tests for the Phase 2 build, and the 1k/5k scaling sets."""
    if IMAPLANE_FD_BIN is None or IMAPLANE_WAL_BIN is None:
        sys.exit('set IMAPLANE_WAL_BIN and IMAPLANE_FD_BIN')
    cfgs = 'imaplane,imaplane-wal,imaplane-fd,imaplane-fd-stream,imapsync-tuned'
    cmd_run(argparse.Namespace(profile='mixed', reps=3, seed=31, no_newmail=False, configs=cfgs, out='p2-main-mixed'))
    med = {}
    for l in open(HERE / 'results' / 'p2-main-mixed' / 'runs.jsonl'):
        r = json.loads(l)
        if r['step'] == 'fresh':
            med.setdefault(r['cfg'], []).append(r['wall_s'])
    json.dump({k: statistics.median(v) for k, v in med.items()}, open(HERE / 'results' / 'p2-fresh-medians-mixed.json', 'w'))
    cmd_kill(argparse.Namespace(profile='mixed', kills=4, seed=19, configs='imaplane-fd,imaplane-fd-stream', fresh_medians=str(HERE / 'results' / 'p2-fresh-medians-mixed.json'), out='p2-kill-mixed'))
    for n in (1000, 5000):
        cmd_run(argparse.Namespace(profile=f'scale-{n}', reps=2, seed=33, no_newmail=True, configs='imaplane,imaplane-wal,imaplane-fd,imapsync-tuned', out=f'p2-scale-{n}'))
    log('PHASE 2 BENCHMARK DONE')


def cmd_stage_p3(_):
    """Phase 3 (one exchange for small messages): the same copy at 0, 20 and 60 ms of added round-trip latency
    (Phase 2 build vs Phase 3 build vs tuned imapsync), then the mixed dataset and SIGKILL tests at 0 ms."""
    global LATENCY_MS
    if IMAPLANE_FD_BIN is None or IMAPLANE_RT_BIN is None:
        sys.exit('set IMAPLANE_FD_BIN and IMAPLANE_RT_BIN')
    for lat in (0, 20, 60):
        LATENCY_MS = lat
        cmd_run(argparse.Namespace(profile='scale-1000', reps=2, seed=41 + lat, no_newmail=True, configs='imaplane-fd,imaplane-rt,imapsync-tuned', out=f'p3-lat{lat}-scale-1000'))
    LATENCY_MS = 0
    cfgs = 'imaplane-fd,imaplane-rt,imaplane-rt-stream,imapsync-tuned'
    cmd_run(argparse.Namespace(profile='mixed', reps=3, seed=51, no_newmail=False, configs=cfgs, out='p3-main-mixed'))
    med = {}
    for l in open(HERE / 'results' / 'p3-main-mixed' / 'runs.jsonl'):
        r = json.loads(l)
        if r['step'] == 'fresh':
            med.setdefault(r['cfg'], []).append(r['wall_s'])
    json.dump({k: statistics.median(v) for k, v in med.items()}, open(HERE / 'results' / 'p3-fresh-medians-mixed.json', 'w'))
    cmd_kill(argparse.Namespace(profile='mixed', kills=4, seed=29, configs='imaplane-rt,imaplane-rt-stream', fresh_medians=str(HERE / 'results' / 'p3-fresh-medians-mixed.json'), out='p3-kill-mixed'))
    for n in (1000, 5000):
        cmd_run(argparse.Namespace(profile=f'scale-{n}', reps=2, seed=53, no_newmail=True, configs='imaplane-fd,imaplane-rt,imapsync-tuned', out=f'p3-scale-{n}'))
    log('PHASE 3 BENCHMARK DONE')


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('env')
    g = sub.add_parser('golden'); g.add_argument('profile')
    r = sub.add_parser('run'); r.add_argument('--profile', default='mixed'); r.add_argument('--reps', type=int, default=3); r.add_argument('--seed', type=int, default=1)
    r.add_argument('--configs', default=','.join(CONFIGS)); r.add_argument('--out'); r.add_argument('--no-newmail', action='store_true')
    k = sub.add_parser('kill'); k.add_argument('--profile', default='mixed'); k.add_argument('--kills', type=int, default=4); k.add_argument('--seed', type=int, default=7)
    k.add_argument('--configs', default='imapsync,imaplane,imaplane-stream'); k.add_argument('--fresh-medians'); k.add_argument('--out')
    sub.add_parser('stage2'); sub.add_parser('clean'); sub.add_parser('stage_p1'); sub.add_parser('stage_p2'); sub.add_parser('stage_p3')
    a = ap.parse_args()
    if a.cmd == 'env':
        print(json.dumps(env_info(), indent=1)); return
    with BenchLock():
        if a.cmd == 'clean':
            clean(); return
        preflight()
        {'golden': cmd_golden, 'run': cmd_run, 'kill': cmd_kill, 'stage2': cmd_stage2, 'stage_p1': cmd_stage_p1, 'stage_p2': cmd_stage_p2, 'stage_p3': cmd_stage_p3}[a.cmd](a)


if __name__ == '__main__':
    main()
