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
python3 tests/local/c1_u1.py target/release/imaplane
python3 tests/local/skip_crash_matrix.py target/fault-tests/debug/imaplane
python3 tests/local/diagnostics.py target/release/imaplane
python3 tests/local/memory.py target/release/imaplane --profile current --sizes 16 64 256   # dedicated CI job
python3 tests/local/memory.py target/release/imaplane --profile streaming --scenario verify --threshold-bytes 0 --sizes 16 64 256   # dedicated CI job
python3 tests/local/stream_verify.py target/fault-tests/debug/imaplane
# Forced-streaming mode: every generated config sets stream_threshold_bytes = 0. Run these
# again with the variable set (crash_matrix.py also needs IMAPLANE_NORMAL_BINARY=target/release/imaplane):
IMAPLANE_TEST_STREAM_THRESHOLD=0 python3 tests/local/e2e.py target/release/imaplane
IMAPLANE_TEST_STREAM_THRESHOLD=0 python3 tests/local/reliability.py target/release/imaplane
IMAPLANE_TEST_STREAM_THRESHOLD=0 python3 tests/local/crash_matrix.py target/fault-tests/debug/imaplane
IMAPLANE_TEST_STREAM_THRESHOLD=0 python3 tests/local/h5_crash_matrix.py target/fault-tests/debug/imaplane
python3 tests/local/provider_tools_integration.py target/release/imaplane   # needs Docker
python3 -m unittest discover -s tests/local -p 'test_*.py'
```

Results and optimization gates are appended after each measured/tested increment.


WAL was deliberately excluded after checking the bundled SQLite source (3.51.1)
against [SQLite's WAL-reset advisory](https://www.sqlite.org/wal.html#walresetbug),
which identifies fixes in 3.51.3 and later (or listed backports). This iteration
keeps the existing rollback journal. A future WAL change requires a separately
validated patched dependency and its own read-only/status/recovery tests.


## Completed prerequisite control and increment 1

The prerequisites are commit `82b316d`; its frozen normal binary passed 30
original and 42 expanded fault scenarios. The 100-message mixed/two-folder A/A
control has five repetitions per label (20 fresh/resume runs), in
[the complete control artifact](benchmarks/h5-control.json). Counters were
identical across labels/runs: fresh 24.17 syncs and 7.23 exchanges/message;
resume 8.00 syncs and 2.21 exchanges/message. Startup/end fsync probe medians
were 0.63/3.75 ms. Wall-time drift is therefore observed, not corrected away.

Increment 1 is commit `2ddad4b`: preparation is one FULL transaction, followed
by the unchanged separate FULL literal authorization and acknowledgement.
Pre-commit fault points can now leave no new record because preparation rolls
back atomically. Tests allow this only at internal preparation boundaries and
require no APPEND plus all earlier confirmations preserved. Post-commit fence
states, no-retry and exact verification assertions stay strict. The unit,
security, e2e, reliability and both crash suites passed before the next increment.

The [12-message A/B smoke artifact](benchmarks/h5-s1-smoke.json) is a counter
check, not a five-repetition performance claim: fresh syncs fell from 25.42 to
17.42/message (8 fewer), with identical exchanges. Resume counters were unchanged.
Small-run startup costs differ from the 100-message control; do not compare
per-message setup overhead across different dataset sizes.


Increment 2 is commit `80ad8be`: successful current exact read-back retains an
already durable historical confirmation instead of invalidating/reconfirming it.
Observed mismatch/missing/failed checks still durably invalidate history. Fresh
accepted transfers still require a FULL confirmation after exact verification.
The unit, protocol/security/reliability suites and 30+43 fault scenarios passed.
The [counter smoke check](benchmarks/h5-s2-smoke.json) retained identical read
exchanges while healthy resume sync calls fell from 8.00 to 0.00/message.
Zero here means no client fsync/fdatasync calls in that measured process, not
zero server I/O or device activity. A crash during a new check leaves historical
confirmation; offline status never proves current destination integrity.

Increment 3 reuses writable destination selection. Each reconnect restores the
original writable/read-only mode and checks UIDVALIDITY; a writable SELECT is
mandatory before another APPEND. Validated APPENDUID+1 advances a monotone lower
bound, without integer wrap. A fresh selection after reconnect can raise it.
The unit, security/e2e/reliability suites and all 73 fault scenarios passed before
committing this increment. Exact read-back, separate durable authorization/ack,
manual uncertainty, and sequential APPEND remain unchanged. An idle connection
failure first discovered by APPEND can still leave prepared uncertainty requiring
explicit recover. Cached lower bounds can widen the candidate scan under concurrent
deliveries; overflow is explicitly incomplete, never silently attributed.

The mixed-profile harness now validates its memory budget against the actual
attachment sizes rather than the unrelated uniform-size option.


## Final measured result — 2026-11-03

The normal binaries are exact committed snapshots: prerequisite A `82b316d` and
optimized B `83de491`. The [complete 100-message, five-repeat interleaved A/B
artifact](benchmarks/h5-final-comparison.json) has 20 fresh/resume runs, mixed
1KiB/8KiB/128KiB/1MiB attachments and two folders. Its B build-source fingerprint
matches the final production sources. Later report/test-only commits do not
change those build inputs. All exact content/date/flag/multiplicity and source
checks passed; deterministic counters matched within every group.

| Metric | Prerequisite A | Optimized B | Interpretation |
| --- | ---: | ---: | --- |
| Fresh client syncs/message | 24.17 | 16.17 | 8 fewer; 33.1% reduction including setup |
| Healthy resume client syncs/message | 8.00 | 0.00 | No redundant durable transitions |
| Fresh protocol exchanges/message | 7.23 | 6.23 | One fewer per copied message; 13.8% reduction |
| Resume exchanges/message | 2.21 | 2.21 | Exact reads intentionally retained |
| Median fresh peak RSS, KiB | 17512 | 17532 | +20 KiB; no material measured increase |
| Median resume peak RSS, KiB | 18600 | 18556 | -44 KiB; essentially unchanged |
| Median fresh wall seconds | 27.727 | 27.746 | Flat; no wall-time gain claimed |
| Median resume wall seconds | 9.874 | 8.998 | Faster observed, advisory only |

Fsync probe medians rose from 0.54 to 4.46 ms during this comparison. Alternating
AB/BA and five repetitions improve the method but do not eliminate drift. Wall
throughput is not a proven causal speedup; the deterministic I/O reductions are.
The tiny RSS differences are not a memory optimization claim or a worst-case
bound. The final [increment-3 counter smoke artifact](benchmarks/h5-s3-smoke.json)
also exercises 0/10 ms protocol delay; its single repetitions are not statistical
performance evidence.

Each kept production increment passed unit/Clippy checks, security, real-Dovecot
e2e, reliability and both deterministic crash suites before the next increment.
Final coverage: 32 project tests, 82 parser tests (15 upstream doc examples ignored),
138 client tests, 3 offline benchmark tests, 5 offline lab tests, and 30+43 crash
scenarios pass. The last expanded run strengthens invalidation kills to the second
actual mismatch in the second folder, checks prior downgrades and restores/verifies
without APPEND. The normal binary contains neither fault environment variable name.
The Rust 1.85.1 Compose client build and existing 120-message lab verification/resume
passed with 360 attachments, no extra uploads, intact source, preserved preexisting
mail and untrusted-CA rejection. cargo-audit reported no known crate advisories or
warnings; that does not negate the separate upstream SQLite WAL advisory.

## Remaining work and limitations

No WAL on the bundled affected SQLite, no parallel transfers or prefetch, no
MULTIAPPEND, no weaker default verification, and no automatic unique-candidate
attribution. Source size requests and exact destination read-back still consume
round trips and bandwidth. Streaming, chunked size lookups and larger-scale soak
runs remain future work. The measured mixed profile is not a near-cap memory test.
Prepared/authorized/legacy uncertainty stays conservative, and candidate overflow
stays explicit. N3 continuation handling, N4 missing UIDNEXT fallback, real-provider
validation and earlier M-series limitations remain open. No public-beta or
production-readiness claim is made. Git commits were local provenance snapshots;
this work did not publish releases or push changes automatically.
