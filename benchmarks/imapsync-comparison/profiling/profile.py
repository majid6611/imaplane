#!/usr/bin/env python3
"""IMAPLANE profiling driver (analysis only; the production engine is never modified).

Each variant restores the same 1,000-message source into a fresh isolated environment, copies it with IMAPLANE
(`migrate`), and records: the usual measurements, Dovecot's per-command accounting (count and server time per
verb), and variant-specific evidence. Variants use either the unmodified release binary (observed from outside by
an LD_PRELOAD shim or IMAPLANE's own --diagnostics-file) or an ISOLATED diagnostic build (timers and experiment
switches; never committed, never part of the product).

  python3 profiling/profile.py base shim diag-file  d-timers d-wal d-sync-normal d-wal-normal d-sync-off d-skip-readback
"""
import json
import os
import sqlite3
import sys
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bench
import common
from bench import Run, BenchLock, preflight, log, HERE

DIAG_BIN = Path(os.environ['DIAG_BIN']) if 'DIAG_BIN' in os.environ else None
PROFILE = os.environ.get('PROFILE_DATASET', 'scale-1000')
SHIM = ['env', 'LD_PRELOAD=/bench/profiling/shim.so', 'SHIM_OUT=/out/shimstats.json']
VARIANTS = {
    'base': dict(),
    'shim': dict(prefix=['env', 'LD_PRELOAD=/bench/profiling/shim.so', 'SHIM_OUT=/out/shimstats.json']),
    'diag-file': dict(global_args=['--diagnostics-file', '/out/diag.jsonl']),
    'd-timers': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json'}),
    'd-timers-shim': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json'}, prefix=SHIM),
    'd-wal': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json', 'DIAG_JOURNAL_MODE': 'WAL'}, prefix=SHIM),
    'd-truncate': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json', 'DIAG_JOURNAL_MODE': 'TRUNCATE'}, prefix=SHIM),
    'd-persist': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json', 'DIAG_JOURNAL_MODE': 'PERSIST'}, prefix=SHIM),
    'f-delete': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json'}, prefix=SHIM),   # run with DIAG_BIN = fdatasync build
    'f-wal': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json', 'DIAG_JOURNAL_MODE': 'WAL'}, prefix=SHIM),
    'd-sync-normal': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json', 'DIAG_SYNC': 'NORMAL'}, prefix=SHIM),
    'd-wal-normal': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json', 'DIAG_JOURNAL_MODE': 'WAL', 'DIAG_SYNC': 'NORMAL'}, prefix=SHIM),
    'd-sync-off': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json', 'DIAG_SYNC': 'OFF'}, prefix=SHIM),
    'd-skip-readback': dict(diag=True, env={'DIAG_TIMING_OUT': '/out/timing.json', 'DIAG_SKIP_READBACK': '1'}, prefix=SHIM),
}


def run_variant(name, out):
    v = VARIANTS[name]
    run = Run(PROFILE, f'prof-{name}')
    try:
        run.extra_env = dict(v.get('env', {}))
        run.global_args = list(v.get('global_args', []))
        run.cmd_prefix = list(v.get('prefix', []))
        if v.get('diag'):
            run.binary = DIAG_BIN
        label = f'{name}'
        res = run.measure('imaplane', 'fresh', label)
        for ext in ('stdout', 'stderr', 'json'):
            src = run.dir / 'out' / f'{label}.{ext}'
            if src.exists():
                shutil.copy(src, out / f'{name}.{ext}')
        for extra in ('shimstats.json', 'timing.json', 'diag.jsonl'):
            f = run.dir / 'out' / extra
            if f.exists():
                shutil.copy(f, out / f'{name}.{extra}')
        j = run.dir / 'state' / 'journal.sqlite3'
        info = {}
        if j.exists():
            c = sqlite3.connect(f'file:{j}?mode=ro', uri=True)
            info['journal_mode'] = c.execute('PRAGMA journal_mode').fetchone()[0]
            info['synchronous_default_note'] = 'synchronous is a per-connection setting; the product sets FULL'
            info['page_size'] = c.execute('PRAGMA page_size').fetchone()[0]
            info['page_count'] = c.execute('PRAGMA page_count').fetchone()[0]
            info['journal_bytes'] = j.stat().st_size
            info['tables'] = {t: c.execute(f'select count(*) from "{t}"').fetchone()[0] for (t,) in c.execute("select name from sqlite_master where type='table'")}
            c.close()
        info['state_dir_files'] = sorted(p.name for p in (run.dir / 'state').iterdir())
        v_ = run.check()
        res['verify_ok'] = v_['ok']
        res['journal_info'] = info
        (out / f'{name}.summary.json').write_text(json.dumps(res, indent=1))
        log(f'{name}: wall {res["wall_s"]:.1f}s cpu {res["cpu_user_s"] + res["cpu_sys_s"]:.1f}s cmds {res["imap_commands"]} verify_ok={v_["ok"]} journal_mode={info.get("journal_mode")}')
    finally:
        run.close()


def main():
    names = sys.argv[1:] or ['base']
    out = HERE / 'results' / ('profile-' + PROFILE)
    out.mkdir(parents=True, exist_ok=True)
    with BenchLock():
        preflight()
        for n in names:
            run_variant(n, out)


if __name__ == '__main__':
    main()
