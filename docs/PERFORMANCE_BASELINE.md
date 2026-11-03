# Current commit-bound H5 benchmark method

Current results, invariant gates and commit IDs are in
[H5 safety and results](H5_SAFETY_AND_RESULTS.md). The older method below is an
archive; use these commands with the current harness:

```sh
# Requires a clean tracked commit. Builds normal release, freezes binary + metadata.
python3 scripts/build-benchmark-binary.py
# Substitute the printed immutable binary paths for A and B:
python3 tests/local/benchmark.py --binary target/baselines/<A-commit>/imaplane \
  --binary-b target/baselines/<B-commit>/imaplane \
  --mixed --messages 100 --latency-ms 0 --repeats 5 \
  --output /tmp/imaplane-h5-comparison.json
```

Omit --binary-b for an explicitly labeled same-binary A/A control. Five repeats
are required except for explicit --smoke harness/counter checks. AB/BA ordering
alternates by repetition; fresh and exact-read-back resume are both measured.
Mixed inputs span four attachment sizes across two folders. Binary SHA-256,
source fingerprint, lockfile and exact build commit are validated from sidecars;
source commits can precede later documentation/artifact-only commits.

The JSON includes individual startup/end and per-run fsync latency samples,
client fsync/fdatasync counts, protocol command/continuation exchanges, CPU time,
kernel-reported peak RSS and every timed sample. Latency injection delays protocol
turns, not TLS handshakes, bandwidth or packet loss. strace changes timing; host
caches, load and filesystem drift are not fully controlled. Fsync probes reveal
drift but do not normalize it away. Treat counters and memory as primary evidence
and wall-time improvements as advisory. Full exact content/date/flag/multiplicity
and source-immutability checks are outside the timed interval.

The 100-message, five-repeat H5 control and final A/B measurements supersede the
20-message early artifact for optimization decisions. The mixed attachment total
has an enforced 128 MiB input budget; reported RSS is the IMAPLANE child process,
not the Python fixture/server memory or a worst-case global memory bound.

---

## Archived early baseline and initial crash method

The remainder records the earlier pre-H5 method/artifact and its original commands.
It is historical evidence, not the current invocation contract.

# Baseline before performance optimization

This iteration adds measurement and safety prerequisites. It does not batch
journal commits, trust confirmed records without read-back, remove SELECT,
change SQLite durability, pipeline requests, or add concurrency.

## Fixed method

Build the regular binary and run from the repository root on Linux:

```sh
cargo build --release --locked
python3 tests/local/benchmark.py \
  --binary target/release/imaplane \
  --messages 100 --attachment-bytes 4096 \
  --latency-ms 0 25 50 --repeats 3 \
  --output /tmp/imaplane-baseline.json
```

Requires Docker, OpenSSL, Python 3, strace, and GNU `/usr/bin/time`. The harness
creates two disposable Dovecot 2.3.21 containers using the pinned test image,
with loopback-only published ports, test credentials, temporary Maildirs, and a
verified test CA. It accepts no server addresses or production configuration.
It removes only containers it created. All fixtures and credentials are deleted
on normal cleanup. An interrupted harness can leave named `imaplane-baseline-*`
containers; inspect them before removing those specific test containers.

The deterministic MIME dataset contains attachments, UTF-8 body text and adjacent
identical messages. Each trial uses a new destination account and state directory,
then measures a fresh migration and a no-op resume. Exact bytes, INTERNALDATE,
flags, multiplicity and source immutability are checked outside the timed region.
Rerunning with the same parameters produces the same dataset fingerprint. Output
files are created exclusively; choose a new filename for another run.

The JSON records every run and group medians:

- Throughput and wall time, including process startup, connection setup, tracing
  overhead, journal creation and current verification behavior.
- Protocol round trips: one exchange for each tagged command, plus one for each
  AUTHENTICATE/APPEND continuation. Source and destination counts and command
  histograms are separate. These are protocol turn counts, not TCP packet counts.
- Injected latency: a fixed delay per counted exchange in the TLS-to-TLS proxy.
  Both TLS hops validate certificates and hostnames. This models sequential IMAP
  round-trip cost, not kernel-level WAN behavior. TLS handshakes, DNS, bandwidth,
  packet loss and network jitter are not delayed by this model.
- Client `fsync` and `fdatasync` syscall counts under `strace -f -c`, with per-message
  totals. Dovecot/server storage flushes and actual device flushes are not counted.
  Trace output is aggregate-only; no commands, credentials or message bytes are
  written into trace logs.
- IMAPLANE peak RSS in KiB and CPU times from GNU time/kernel child accounting.
  This excludes the Python harness, Docker and server memory. It is not a large
  message memory bound or an allocation profile.
- Binary, build-source, lockfile and dataset fingerprints; base Git commit and
  tracked-diff fingerprint; kernel/architecture, Docker and strace versions.

Tracing affects throughput. Compare instrumented runs using the same method,
message count/size, latency, build profile, host and storage conditions. Warm
caches, host load and storage latency are uncontrolled; preserve individual runs
rather than interpreting small wall-time differences as regressions. Setup costs
are amortized differently with different message counts. The current literal
fence intentionally adds a durable commit; its extra syncs belong in this
baseline. No durability cost was hidden to improve benchmark numbers.

## Local results

The initial local baseline uses 20 messages with 4096-byte attachments, latencies
0/10/50 ms, and two repetitions of fresh/resume per latency. This is a harness
baseline, not a scale or provider benchmark. The [aggregate artifact](benchmarks/linux-amd64-baseline.json) contains all 12 runs
and fingerprints. It was captured before the license-only metadata change to
MIT; migration code was unchanged by that change. All exact content/metadata/multiplicity checks passed and the
source remained unchanged. These medians include strace overhead:

| Protocol delay | Phase | Messages/s | Exchanges/message | Syncs/message | Peak RSS KiB |
| --- | --- | ---: | ---: | ---: | ---: |
| 0 ms | fresh | 4.15 | 7.80 | 24.65 | 14486 |
| 0 ms | resume | 7.87 | 2.80 | 8.00 | 14586 |
| 10 ms | fresh | 3.10 | 7.80 | 24.65 | 14518 |
| 10 ms | resume | 6.36 | 2.80 | 8.00 | 14224 |
| 50 ms | fresh | 1.58 | 7.80 | 24.65 | 14652 |
| 50 ms | resume | 3.75 | 2.80 | 8.00 | 14302 |

Reproduce this smaller local run with:

```sh
python3 tests/local/benchmark.py --binary target/release/imaplane \
  --messages 20 --attachment-bytes 4096 --latency-ms 0 10 50 --repeats 2 \
  --output /tmp/imaplane-baseline-small.json
```

The canonical command above uses a larger sample. The new pre-literal fence increases sync cost; throughput is not an
uninstrumented production prediction.

## Deterministic crash tests

Crash hooks compile only with the explicit `fault-injection` feature:

```sh
cargo build --locked --features fault-injection --target-dir target/fault-tests
python3 tests/local/crash_matrix.py target/fault-tests/debug/imaplane
```

Build the regular release binary first; the matrix also verifies that it ignores
`IMAPLANE_FAULT_POINT`. Keep fault binaries in the separate target directory.
Production/package builds use default features and contain no environment-driven
crash hook. Feature-enabled binaries deliberately SIGKILL themselves at the
selected static fault point, without destructors or graceful SQLite shutdown.
Never use one for real migration.

The matrix creates two real disposable TLS Dovecot servers. It kills the client
before/after planning, metadata, baseline, begin-APPEND commit, literal permission,
APPEND reply, acknowledgement and confirmation; it also kills inside transactions
before critical commits. It verifies SQLite integrity, persisted state, recovery
eligibility, source immutability and exact destination multiplicity after resume.
Recovery/attribution transaction boundaries, rejection boundaries, legacy journals
and zero-length messages are covered. A small scripted TLS fixture supplies exact
NO rejection and zero-length cases; real Dovecot supplies the main crash matrix.
Existing reply-loss/SIGKILL proxy tests complement these boundaries. This does not
simulate hardware power loss or every possible crash during a filesystem syscall.

The source adapter remains read-only, `begin_append` and acknowledgement stay
FULL-durable, and confirmation still requires exact destination read-back.
