# H5 safety gates and measurements

The full independent pre-H5 audit was read before changes. Its conditional GO
requires later-hit crash injection and fresh commit-bound measurements. R1 and
pre-upgrade backups are implemented before optimization. No transfers run in
parallel, no MULTIAPPEND is introduced, and uncertain attribution stays manual.

## The 12 invariants

| Invariant | Enforcement and evidence |
| --- | --- |
| 1. Source read-only | Source API, EXAMINE/BODY.PEEK and source proxy wire allowlist; before/after real-Dovecot snapshots. |
| 2. FULL begin/authorize/acknowledge commits in order | Separate durable transactions remain; crash immediately before/after commits, including hits 2 and 4. |
| 3. No body without durable authorization | Fallible literal guard and guard-failure test; zero-body authorization precedes prefix; partial-body kill stays manual. |
| 4. No automatic uncertain replay | Direct APPEND outside safe-read retry; only verified NO/BAD resets planned with its audit row; repeated unknown resume has no extra APPEND. |
| 5. Recover requires prepared evidence | SQL predicate plus atomic recovery/audit; authorized/missing/legacy and candidate overflow are refused. |
| 6. Confirm only after exact content/date/flags at acknowledged UID | Full destination read-back remains on fresh, resume and verify; corruption and missing-message fixtures. |
| 7. Baseline is a pre-send lower bound, epoch checked | Saved UIDNEXT/epoch precedes begin; reconnect epoch check; reject APPENDUID with different epoch or UID below baseline before acknowledgement. |
| 8. One APPEND per destination folder | Single synchronous engine thread; no prefetch, pipelining or concurrency added. |
| 9. One writer/job lock | Job's exclusive lock and existing lock contention regression. |
| 10. Additive transactional upgrades, no fabricated evidence | SQLite-consistent private backup first, no-clobber publication; before-commit/after-commit upgrade kills and legacy evidence tests. |
| 11. Honest complete/results | Current exact verification is required for every confirmed report entry; any uncertain/rejected/skipped/mismatch is incomplete. |
| 12. Default builds have no active fault hook | Feature-gated hook; normal binary ignores both environment variables; separate fault target directory. |

A SIGKILL test does not demonstrate physical power-loss or lying-storage behavior.
The FULL guarantee relies on SQLite, filesystem and storage honoring sync requests.
No live-provider, arm64 or production-readiness claim follows from these tests.

## Prerequisites

`IMAPLANE_FAULT_NTH=k` counts hits of the selected `IMAPLANE_FAULT_POINT` in a
fault-enabled process. Positive k defaults to 1 if omitted. The expanded matrix
uses hits 2 and 4, after previous confirmed messages and into the second folder.
It includes verification/invalidation, reconnect followed by writable SELECT,
partial literals, upgrade crashes, and an explicitly incomplete >1000-UID scan.

R1: TOOBIG and OVERQUOTA are size-dependent message rejections. They stay planned,
are reported rejected, and do not open the server-wide breaker. A full destination
may therefore reject every message; safety does not justify inferring that a
smaller later message cannot fit. UNAVAILABLE/THROTTLED/INUSE/LIMIT use the bounded
interruptible breaker. Unknown rejection categories stop for operator review.
No rejected APPEND is retried in the same invocation.

Before upgrading an existing journal, an SQLite online backup captures committed
content (including WAL pages) into a private temporary file, checks integrity,
syncs it, and publishes journal.sqlite3.vN.bak without overwriting any existing
file or symlink. Existing names receive .1, .2, etc. The directory is synced before
migration starts. Backup errors abort the upgrade. Fresh private initialization
needs no backup. Backups are sensitive, ignored by Git, and never auto-restored;
restoring old evidence after subsequent uploads can duplicate mail.

## Reproducing the controlled baseline

Prerequisites and every measured optimization are local Git commits so frozen
binaries can be tied to exact source commits. No automatic Git push is required.
With a clean tracked tree and Rust/OpenSSL/Docker/strace/GNU time installed:

```sh
python3 scripts/build-benchmark-binary.py
# Use the printed immutable target/baselines/<commit>/imaplane path as A.
python3 tests/local/benchmark.py --binary target/baselines/<commit>/imaplane \
  --mixed --messages 100 --latency-ms 0 --repeats 5 \
  --output /tmp/imaplane-pre-h5-control.json
```

Without --binary-b the A and B labels use the identical frozen binary: this is
an A/A control, not an invented before/after improvement. After a tested optimization
has its own commit/snapshot, pass --binary-b target/baselines/<new-commit>/imaplane.
Runs alternate AB/BA and retain each fresh/resume sample. Mixed input cycles 1KiB,
8KiB, 128KiB and 1MiB attachments in legitimate duplicate pairs across two folders.
Every timed run has exact checks outside timing. Startup/end and per-run fsync
micro-probes report individual wall-latency samples, medians and p95. These are
not correction factors that magically normalize host drift. Deterministic counters
and RSS are primary evidence; traced wall time remains advisory. The latency proxy
models protocol turns, excluding TLS handshakes, bandwidth and packet loss.

## Validation commands

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --release --locked
cargo build --locked --features fault-injection --target-dir target/fault-tests
python3 tests/local/security.py target/release/imaplane
python3 tests/local/e2e.py target/release/imaplane
python3 tests/local/reliability.py target/release/imaplane
python3 tests/local/crash_matrix.py
python3 tests/local/h5_crash_matrix.py
python3 -m unittest discover -s tests/local -p 'test_*.py'
```

Results and optimization gates are appended after each measured/tested increment.


WAL was deliberately excluded after checking the bundled SQLite source (3.51.1)
against [SQLite's WAL-reset advisory](https://www.sqlite.org/wal.html#walresetbug),
which identifies fixes in 3.51.3 and later (or listed backports). This iteration
keeps the existing rollback journal. A future WAL change requires a separately
validated patched dependency and its own read-only/status/recovery tests.
