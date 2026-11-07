# IMAPLANE vs imapsync benchmark (local, reproducible)

Everything runs in Docker on one machine; no real mail provider is contacted. Nothing here is published.
Results and analysis: [REPORT.md](REPORT.md). Invalid or discarded results: [results/INVALID.md](results/INVALID.md).

## What is compared

* IMAPLANE 0.1.0 at commit `a6ec32f` (release build, unmodified), default mode and `stream_threshold_bytes = 0`.
* imapsync **2.314** (upstream release script, SHA-256 in `results/*/env.json`), default options plus
  `--syncinternaldates`, and a "tuned" variant (`--nofoldersizes --nofoldersizesatend --useuid`, UID cache on a
  persistent volume).
* Source and destination: two identical `dovecot/dovecot:2.3.21` containers (`dovecot-bench.conf`), each limited to
  2 CPUs / 2 GiB, on a private Docker network per run. Tools run in one shared runner image
  (`Dockerfile.runner`) under the same limits and the same measuring wrapper (`measure.py`).

## Measured, and by whom

| Quantity | Measured by |
|---|---|
| wall time, CPU time, peak RSS, block I/O, network bytes | `measure.py` inside the tool container (getrusage, cgroup, eth0 counters) |
| IMAP commands, server time per verb, session bytes | Dovecot's own exported `imap_command_finished` events and `Disconnected` lines |
| correctness | `common.verify`: independent multiset comparison of content (SHA-256), flags and INTERNALDATE, fetched from both servers with `BODY.PEEK[]` |
| source unchanged | the same snapshot before and after |

## Isolation and integrity

`bench.py` takes one machine-wide lock for a whole command, refuses to start if any stale container, network, run
directory or measuring process exists (`bench.py clean`), gives every run its own network, container names and
directory, keeps each dataset in a read-only "golden" copy whose tree hash is checked before and after every run, and
refuses to write into a results directory that already holds results.

## Reproduce

```sh
docker build -f Dockerfile.runner -t imaplane-bench-runner:1 .        # needs network once (apt, imapsync source)
export IMAPLANE_BIN=/path/to/release/imaplane                          # built from the commit above
python3 bench.py env                                                   # records the environment
python3 bench.py golden mixed                                          # dataset.py generates it deterministically
python3 bench.py run --profile mixed --reps 3 --seed 1 --out main-mixed
python3 bench.py kill --profile mixed --kills 4 --seed 7 --fresh-medians results/fresh-medians-mixed.json --out kill-mixed
python3 bench.py stage2                                                # 1k/5k scaling and the corrected tuned rerun
python3 report.py results/main-mixed                                   # medians and the correctness summary
```

Profiling (analysis only; the diagnostic build is a throwaway copy with timers and experiment switches, never part
of the product): `profiling/shim.c` (LD_PRELOAD fsync/write counter; build with
`docker run --rm -v $PWD/profiling:/w -w /w imaplane-dev:1.85.1 gcc -shared -fPIC -O2 -o shim.so shim.c -ldl -lpthread`),
`profiling/profile.py`.
