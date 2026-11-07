#!/usr/bin/env python3
"""Runs one command inside a tool container and records what the container itself observed.

  measure.py OUTDIR NAME -- command ...

Writes OUTDIR/NAME.json (+ .stdout / .stderr). Everything is measured from inside the container so the
same code measures both tools: wall time, CPU time and peak RSS of the process tree (getrusage),
block I/O (cgroup io.stat when present, else getrusage), and network bytes (eth0 counters, which
include TLS framing). Nothing here depends on, or is known to, either tool.
"""
import json
import os
import resource
import subprocess
import sys
import time


def netdev(name='eth0'):
    try:
        for line in open('/proc/net/dev'):
            if line.strip().startswith(name + ':'):
                f = line.split(':', 1)[1].split()
                return int(f[0]), int(f[8])
    except OSError:
        pass
    return 0, 0


def cgroup_io():
    rb = wb = 0
    try:
        for line in open('/sys/fs/cgroup/io.stat'):
            for part in line.split()[1:]:
                k, _, v = part.partition('=')
                if k == 'rbytes':
                    rb += int(v)
                elif k == 'wbytes':
                    wb += int(v)
        return rb, wb
    except OSError:
        return None


def cgroup_cpu_usec():
    try:
        for line in open('/sys/fs/cgroup/cpu.stat'):
            if line.startswith('usage_usec'):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def main():
    outdir, name = sys.argv[1], sys.argv[2]
    cmd = sys.argv[sys.argv.index('--') + 1:]
    rx0, tx0 = netdev(); io0 = cgroup_io(); cpu0 = cgroup_cpu_usec()
    started = time.time(); t0 = time.perf_counter()
    with open(f'{outdir}/{name}.stdout', 'wb') as out, open(f'{outdir}/{name}.stderr', 'wb') as err:
        rc = subprocess.run(cmd, stdout=out, stderr=err).returncode
    wall = time.perf_counter() - t0
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    rx1, tx1 = netdev(); io1 = cgroup_io(); cpu1 = cgroup_cpu_usec()
    result = {
        'name': name, 'command': cmd[:1] + ['...'], 'returncode': rc, 'started_at': started, 'wall_s': wall,
        'cpu_user_s': ru.ru_utime, 'cpu_sys_s': ru.ru_stime, 'peak_rss_kib': ru.ru_maxrss,
        'rusage_block_in': ru.ru_inblock, 'rusage_block_out': ru.ru_oublock,
        'net_rx_bytes': rx1 - rx0, 'net_tx_bytes': tx1 - tx0,
        'cgroup_read_bytes': (io1[0] - io0[0]) if io0 and io1 else None,
        'cgroup_write_bytes': (io1[1] - io0[1]) if io0 and io1 else None,
        'cgroup_cpu_s': ((cpu1 - cpu0) / 1e6) if cpu0 is not None and cpu1 is not None else None,
    }
    json.dump(result, open(f'{outdir}/{name}.json', 'w'))
    sys.exit(0)


if __name__ == '__main__':
    main()
