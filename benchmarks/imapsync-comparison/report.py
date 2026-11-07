#!/usr/bin/env python3
"""Aggregate a results directory (runs.jsonl) into medians and a correctness summary.

  python3 report.py results/main-mixed [--exclude-steps imapsync-tuned:rerun,imapsync-tuned:newmail1,...]
Throughput uses the dataset's message count and byte total (from golden/info.json) for fresh runs, and the
number of messages in the source for reruns. Medians over repetitions; min/max shown.
"""
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

WORK = Path.home() / 'imaplane-bench-work'


def med(xs):
    return statistics.median(xs) if xs else float('nan')


def main():
    d = Path(sys.argv[1])
    skip = set()
    if '--exclude-steps' in sys.argv:
        skip = set(sys.argv[sys.argv.index('--exclude-steps') + 1].split(','))
    # Steps recorded as invalid (harness defects) are excluded automatically and listed, never silently dropped.
    if (d / 'invalid.json').exists():
        invalid = json.load(open(d / 'invalid.json'))
        skip |= set(invalid)
        for k, why in invalid.items():
            print(f'EXCLUDED (invalid): {k}: {why}')
    rows = [json.loads(l) for l in open(d / 'runs.jsonl')]
    profile = rows[0]['profile']
    info = json.load(open(d / 'dataset.json')) if (d / 'dataset.json').exists() else json.load(open(WORK / 'golden' / profile / 'info.json'))
    by = defaultdict(list)
    for r in rows:
        if f"{r['cfg']}:{r['step']}" in skip:
            continue
        by[(r['cfg'], r['step'])].append(r)
    print(f"dataset {profile}: {info['messages']} messages, {info['bytes'] / 1e6:.0f} MB; repetitions per cell shown as n")
    print(f"{'config':16s} {'step':20s} {'n':>2s} {'wall s':>8s} {'(min-max)':>14s} {'msg/s':>7s} {'MiB/s':>7s} {'cpu s':>6s} {'RSS MiB':>8s} {'IMAP cmds':>9s} {'net MB':>7s} {'disk wr MB':>10s} {'exact':>6s}")
    for (cfg, step), rs in sorted(by.items()):
        wall = [r['wall_s'] for r in rs]
        cpu = [r['cpu_user_s'] + r['cpu_sys_s'] for r in rs]
        rss = [r['peak_rss_kib'] / 1024 for r in rs]
        cmds = [r['imap_commands'] for r in rs]
        net = [(r['net_rx_bytes'] + r['net_tx_bytes']) / 1e6 for r in rs]
        wr = [(r.get('cgroup_write_bytes') or 0) / 1e6 for r in rs]
        v = [r['verify']['total'] for r in rs if 'verify' in r]
        exact = '-' if not v else f"{med([t['exact'] for t in v]):.0f}/{med([t['src'] for t in v]):.0f}"
        msgs = info['messages']
        mbs = info['bytes'] / 1048576
        print(f"{cfg:16s} {step:20s} {len(rs):2d} {med(wall):8.1f} {f'({min(wall):.1f}-{max(wall):.1f})':>14s} {msgs / med(wall):7.1f} {mbs / med(wall):7.1f} {med(cpu):6.1f} {med(rss):8.0f} {med(cmds):9.0f} {med(net):7.0f} {med(wr):10.0f} {exact:>6s}")
    print('\nCorrectness (independent verifier, multiset compare of content+flags+INTERNALDATE; per run, worst case):')
    for (cfg, step), rs in sorted(by.items()):
        vs = [r['verify'] for r in rs if 'verify' in r]
        if not vs:
            continue
        agg = defaultdict(int)
        for v in vs:
            for k, x in v['total'].items():
                agg[k] = max(agg[k], x)
        bad = {k: x for k, x in agg.items() if k in ('missing', 'duplicates', 'foreign', 'date_diff', 'flag_diff_other', 'flag_diff_only_deleted') and x}
        unchanged = all(v.get('source_unchanged', True) for v in vs)
        print(f"  {cfg:16s} {step:10s} ok in {sum(v['ok'] for v in vs)}/{len(vs)} runs; worst-case anomalies {bad or 'none'}; source unchanged {unchanged}")


if __name__ == '__main__':
    main()
