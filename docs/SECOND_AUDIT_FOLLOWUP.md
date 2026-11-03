# Second independent audit follow-up

Claude's full second report was read before changes. The report confirmed H1,
H2's main triggers, H4 and M1/M2, and identified three prerequisites before H5.
Code inspection independently confirmed N1's immediate continue after rejection,
N2's unstructured/lazy evidence, and the absence of durable evidence distinguishing
a pre-literal crash from a possibly committed APPEND.

| Finding / prerequisite | Change | Evidence and limits |
| --- | --- | --- |
| Deterministic crash injection | Feature-gated kill points around transfer transitions and APPEND, including before critical transaction commits. Separate fault binary; default builds ignore the environment hook. | Main matrix uses real TLS Dovecot. It checks journal integrity, state, exact copies and manual outcomes; additional scripted fixtures cover rejection/empty-message paths. Hardware power loss is not simulated. |
| Reproducible benchmark | Disposable Dovecot + TLS proxy with fixed protocol-exchange latency; deterministic MIME dataset; fresh/resume; strace sync counts; GNU time peak RSS; per-run JSON and medians. | See PERFORMANCE_BASELINE.md. Counts are client/protocol measurements, not device flushes, packet-level RTTs or server RSS. No optimization is included. |
| N1 rejection circuit | Sanitized status/code pair, interruptible 1/2/4… second pauses capped at 120 seconds, and stop after K identical consecutive rejections (default 3). Successful APPEND resets the circuit. | Rejected transfers remain planned and are never replayed in that invocation. Report includes halt_reason. Limit is configurable as append_rejection_limit (1..100); state resets on a new invocation. Different rejection signatures start a new streak. |
| N2 rejection evidence | Schema 3 creates rejection/attempt/recovery tables transactionally; rejection rows retain allowlisted code and NO/BAD status instead of arbitrary server prose. | Unknown codes collapse to UNSPECIFIED. Old evidence and transfer states remain unchanged. The small rejection object now carries and supplies the evidence. |
| H3 residual | A durable attempt fence records prepared atomically with uncertain, then literal_authorized with FULL durability before any body write. Explicit recover can return prepared uncertainty to planned with an audit row. | Zero candidates alone is never sufficient. Authorized, missing-fence, legacy and changed-UIDVALIDITY records are refused. No unique-candidate auto-attribution or operator override was added. |
| N6 source session-wide NO | Only explicitly message-specific TOOBIG remains classified as a permanent NO skip; unknown/authentication NO responses stop safely. Typed size/cap errors remain isolated. | A fixture returns AUTHENTICATIONFAILED and asserts one failed entry and no uploads, rather than thousands of skips. |

## Safe recovery protocol

The journal and adapter form a write permission fence:

1. Commit uncertain and a new prepared attempt in one FULL transaction.
2. Send a synchronizing APPEND prefix and wait for the continuation.
3. Commit literal_authorized with FULL durability. If this fails, send no body.
4. Only then write the literal and command terminator.
5. On valid tagged success/APPENDUID, commit accepted separately, then verify
   exact bytes, date and supported flags before confirming.

For a zero-length message, step 3 occurs before even the APPEND prefix, since
there are no body bytes to withhold. The guard still runs, but does not authorize
a second time. Source messages and destination message content are unchanged.

A new `recover` command requires an uncertain record with a matching destination
UIDVALIDITY, a completed search of at most 1000 post-baseline UIDs with no matching
candidate, and a persisted prepared attempt. It writes the planned transition and
an audit event atomically. It uploads nothing and reports retry_authorized with
exit 2. A later normal migrate invocation re-fetches the source and performs the
full normal APPEND/verification workflow.

```sh
imaplane recover --config migration.toml --folder INBOX --uid 123 --json
imaplane migrate --config migration.toml --json
```

Recovery contacts only the destination. A concurrent identical delivery can make
it refuse the command; manual resolve remains available for candidate attribution.
The zero-candidate check is conservative context, while the **durable never-authorized
fence is the actual proof**. Once authorization committed, even a crash immediately
before the write cannot be distinguished from a committed upload whose message
was later expunged or hidden. Those records remain manual and are never resent.
This is a safe partial resolution of H3, not a universal “not appended” command.

## Compatibility and preserved guarantees

Schema 1/2 journals upgrade additively to 3, without inventing attempt evidence
for old uncertain records. Offline status reads all three versions without
upgrading. Old binaries that support only schema 2 must not be used after upgrade.
Existing configuration values and account/folder bindings remain valid; the new
rejection threshold is optional and does not alter the binding.

The source still exposes only read operations. FULL durability, job locking,
UIDVALIDITY checks, exact verification, independent duplicate multiplicity and
manual uncertain attribution remain in place. There is no APPEND batching,
relaxed confirmation, resume shortcut, SELECT removal, write concurrency or
SQLite durability optimization.

N3 (untagged response before continuation), N4 (missing UIDNEXT), N5 (trickle
connections), N7's proposed automated pristine-upstream diff, earlier provider
compatibility and other deferred audit findings are not claimed fixed. The two
vendored patches remain documented in their patch notes; their regression suites
run in CI. Public beta and production readiness are still not established.

## Validation

The fixed benchmark and crash commands are in
[PERFORMANCE_BASELINE.md](PERFORMANCE_BASELINE.md). Regression commands:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --manifest-path vendor/imap-proto/Cargo.toml --target-dir target/vendor-tests
cargo test --manifest-path vendor/imap/Cargo.toml --lib --target-dir target/vendor-client-tests
cargo build --release --locked
cargo audit
python3 tests/local/security.py target/release/imaplane
python3 tests/local/e2e.py target/release/imaplane
python3 tests/local/reliability.py target/release/imaplane
python3 -m unittest discover -s tests/local -p 'test_*.py'
python3 -m unittest discover -s tests/compose -p 'test_*.py'
# Build and run the isolated fault binary:
cargo build --locked --features fault-injection --target-dir target/fault-tests
python3 tests/local/crash_matrix.py target/fault-tests/debug/imaplane
# Reset deletes/reseeds only this disposable lab's state and mail volumes:
./scripts/lab.sh reset
./scripts/lab.sh test
./scripts/lab.sh recovery
```

Local results:

- 28 project tests, 82 parser tests (15 upstream documentation examples ignored),
  138 client tests, 5 offline lab tests and 2 offline benchmark tests passed.
- Formatting and Clippy with all features/targets passed. cargo-audit reported
  zero known vulnerabilities/warnings at RustSec revision
  `263a4d951a0867d4bddc29dddd6d59427c78f9a7`.
- Release security, Dovecot e2e and reliability suites passed, including quota and
  THROTTLED circuits, successful-APPEND reset, SIGTERM during rejection backoff,
  session-wide source NO, slow uploads, dropped replies and server restarts.
- All 30 deterministic crash/recovery scenarios passed. Before-commit failures
  roll back; exact copies resume without duplication. Authorized-but-empty and
  legacy uncertainty deliberately remain manual. The regular release binary
  ignores the fault environment.
- All 12 instrumented benchmark runs passed exact content, date/flag and
  multiplicity checks with an unchanged source. The [aggregate artifact](benchmarks/linux-amd64-baseline.json)
  records the benchmarked Rust build-source fingerprint. Small-fixture medians and
  interpretation are in the baseline document; these are traced, host-specific
  measurements, not production throughput estimates.
- The Rust 1.85.1 Compose build and existing 120-message journal upgrade/resume
  passed. A fresh 120-message migration/verify/resume and SIGINT recovery passed,
  including all 360 attachments, preserved preexisting destination mail and an
  unchanged source. SIGKILL recovery also completed all 120 transfers without
  duplicate uploads; lost acknowledgement remained uncertain until audited
  attribution.

No live providers, arm64, package installation or release publication were tested
in this iteration. Power-loss guarantees still rely on SQLite/filesystem/storage
honoring FULL durability; no physical power-cut simulation was performed.
No production servers, Git pushes or release publication were involved.
