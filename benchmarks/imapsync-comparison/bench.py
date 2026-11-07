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
TOOL_LIMITS = ['--cpus', '2', '--memory', '2g']
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
        self.write_imaplane_config(cfg == 'imaplane-stream')
        base = ['imaplane'] + self.global_args
        if step in ('fresh', 'resume', 'ordinary'):
            return base + ['migrate', '--config', '/work/imaplane.toml', '--json']
        if step == 'verify':
            return base + ['verify', '--config', '/work/imaplane.toml', '--json']
        level = {'inc-metadata': 'metadata', 'inc-existence': 'existence', 'inc-full': 'full', 'incremental': 'metadata'}[step]
        return base + ['migrate', '--config', '/work/imaplane.toml', '--json', '--incremental', '--verify-history', level]

    def docker_args(self, name, outname, detach=False):
        env = [x for k, v in self.extra_env.items() for x in ('-e', f'{k}={v}')]
        return (['docker', 'run'] + (['-d'] if detach else []) + ['--rm', '--name', name, '--network', self.net] + TOOL_LIMITS + ['--user', f'{common.UID}:{common.UID}', '-e', 'HOME=/tmp'] + env + [
                '-v', f'{self.dir}/imaplane.toml:/work/imaplane.toml:ro', '-v', f'{WORK}/tls.crt:/work/tls.crt:ro', '-v', f'{WORK}/password:/work/password:ro',
                '-v', f'{self.dir}/state:/state', '-v', f'{self.dir}/out:/out', '-v', f'{HERE}:/bench:ro', '-v', f'{self.binary or IMAPLANE_BIN}:/usr/local/bin/imaplane:ro', common.RUNNER_IMAGE,
                'python3', '/bench/measure.py', '/out', outname, '--'])

    # ---- measured execution -------------------------------------------------------------------
    def measure(self, cfg, step, label, timeout=14400):
        cmd = self.cmd_prefix + self.command(cfg, step)
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
    info['imaplane_commit'] = sh('git', '-C', str(HERE.parents[1]), 'rev-parse', 'HEAD').stdout.strip()
    info['imaplane_tree_clean'] = not sh('git', '-C', str(HERE.parents[1]), 'status', '--porcelain', '--', 'src', 'Cargo.toml', 'Cargo.lock').stdout.strip()
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


def operator_loop(run, cfg, label, max_rounds=6):
    """The documented operator procedure for uncertain IMAPLANE records: audited recover when nothing was
    sent, resolve when exactly one verified candidate exists. Returns (actions, remaining_uncertain)."""
    actions = 0
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
                    '-v', f'{WORK}/tls.crt:/work/tls.crt:ro', '-v', f'{WORK}/password:/work/password:ro', '-v', f'{run.dir}/state:/state', '-v', f'{IMAPLANE_BIN}:/usr/local/bin/imaplane:ro', common.RUNNER_IMAGE, 'imaplane']
            a = ['--config', '/work/imaplane.toml', '--folder', e['source_folder'], '--uid', str(e['source_uid'])]
            p = sh(*base, 'recover', *a, '--json', check=False)
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
                # resume with the SAME command; this is the recovery time
                res = run.measure(cfg, 'resume' if cfg.startswith('imaplane') else 'fresh', f'{tag}-resume')
                save_raw(run, out, f'{tag}-resume')
                after_one = run.check()
                actions = remaining = None
                final = after_one
                if cfg.startswith('imaplane') and (res['tool_report'].get('results', {}).get('uncertain') or not res['tool_report'].get('complete')):
                    actions, remaining = operator_loop(run, cfg, tag)
                    final = run.check()
                row = {'profile': args.profile, 'cfg': cfg, 'kill': k, 'kill_after_s': delay, 'fraction_of_median_fresh': frac, 'messages_in_destination_at_kill': landed,
                       'at_kill': mid_verify['total'], 'resume': res, 'after_one_rerun': after_one, 'operator_actions': actions, 'uncertain_remaining': remaining, 'final': final}
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


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('env')
    g = sub.add_parser('golden'); g.add_argument('profile')
    r = sub.add_parser('run'); r.add_argument('--profile', default='mixed'); r.add_argument('--reps', type=int, default=3); r.add_argument('--seed', type=int, default=1)
    r.add_argument('--configs', default=','.join(CONFIGS)); r.add_argument('--out'); r.add_argument('--no-newmail', action='store_true')
    k = sub.add_parser('kill'); k.add_argument('--profile', default='mixed'); k.add_argument('--kills', type=int, default=4); k.add_argument('--seed', type=int, default=7)
    k.add_argument('--configs', default='imapsync,imaplane,imaplane-stream'); k.add_argument('--fresh-medians'); k.add_argument('--out')
    sub.add_parser('stage2'); sub.add_parser('clean')
    a = ap.parse_args()
    if a.cmd == 'env':
        print(json.dumps(env_info(), indent=1)); return
    with BenchLock():
        if a.cmd == 'clean':
            clean(); return
        preflight()
        {'golden': cmd_golden, 'run': cmd_run, 'kill': cmd_kill, 'stage2': cmd_stage2}[a.cmd](a)


if __name__ == '__main__':
    main()
