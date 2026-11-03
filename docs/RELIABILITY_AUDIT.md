# Reliability and security audit — 2026-11-02

Latest follow-up: [second independent audit prerequisites and recovery](SECOND_AUDIT_FOLLOWUP.md).
It supersedes historical schema/rejection/recovery descriptions below; see
[the performance baseline](PERFORMANCE_BASELINE.md) for the fixed measurement method.



## Independent audit follow-up — 2026-11-02

Claude's complete report was read before changes. H1–H4 and M1–M2 were then
independently checked against the adapters, engine, journal and upstream client.
All six findings were confirmed. The table below supersedes historical statements
in the earlier audit about timeouts, inventories and stopping on every failure.

| Finding | Implemented correction and evidence | Remaining limits |
| --- | --- | --- |
| H1 — command-wide deadline | Socket and TLS byte progress renew an idle deadline without renewing the response-size budget. Raw TLS-record progress also counts. Slow FETCH, slow APPEND upload and delayed progressing APPEND replies exceed a 1-second timeout while preserving exact bytes. | Setup retains absolute deadlines; no minimum-throughput or total transfer deadline. |
| H2 — one permanent message blocks the job | Oversize, completed size-mismatch and non-transient per-message NO errors are isolated only after a synchronized response. Reports use skipped_permanent / verification_failed_permanent, remain incomplete, and later messages proceed. Repeated runs do not duplicate already confirmed transfers. | No operator skip list or failure-count switch; unsafe protocol/transport failures still stop. Permanent failures are reconsidered on rerun rather than silently accepted. |
| H3 — definite rejection becomes permanently uncertain | The upstream client discarded pre-literal rejection evidence. A narrow vendored patch now validates the response tag and preserves NO/BAD. A FULL-durability journal transaction records rejection evidence and restores planned state. Before-/after-literal rejection and mismatched-tag regressions cover this path. | Partially resolved: ambiguous APPENDs still require audited operator attribution. No zero-candidate “not appended” command or automatic unique-match attribution was added. |
| H4 — weak retries and reconnect failures escape | Safe-operation retries include connect and re-EXAMINE failures, verify UIDVALIDITY, and use exponential delays, jitter and a retry window. Structured UNAVAILABLE, THROTTLED, INUSE and LIMIT codes are classified separately from arbitrary prose. Tests stop a server during FETCH, refuse reconnects, then restore it; startup refusal also recovers. | Six attempts by default; explicit old read_attempts values remain effective. Unknown TLS/setup errors fail conservatively. This is not a provider-specific throttling policy. |
| M1 — termination/EINTR | ctrlc termination feature handles SIGTERM/SIGHUP. Socket/TLS wrappers retry Interrupted without losing partial state or resetting deadlines. A Linux test targets a blocked recv with SIGUSR1 and SA_RESTART disabled. SIGTERM/HUP/INT during APPEND and SIGTERM/INT during silent TLS setup are tested. A signal during the final message also marks the report interrupted. | Graceful stop waits for the active operation's completion or idle/setup timeout; SIGKILL remains inherently uncertain. Signal tests do not simulate every OpenSSL or kernel path. |
| M2 — live snapshot races | Inventory FETCH is bounded by initial UIDNEXT-1; EXISTS is compared within that horizon and UIDVALIDITY rechecked. Concurrent delivery is excluded; an existing durable snapshot remains unchanged on resume. Inconsistent inventories retry within the read budget. Empty snapshots skip FETCH. | Continuous expunges or nonconforming inventories can exhaust retries safely; snapshots are per-folder rather than globally atomic. |

Returning a rejected APPEND to planned relies on the IMAP server honoring the
required rollback on unsuccessful APPEND. See [RFC 9051 §6.3.12](https://www.rfc-editor.org/rfc/rfc9051.html#section-6.3.12)
and [RFC 3501 §6.3.11](https://www.rfc-editor.org/rfc/rfc3501#section-6.3.11).
A dropped reply supplies no such evidence. A unique content match may be a
concurrent identical delivery; zero candidates may reflect expunge or visibility
changes. Neither is a safe proof for automatic retry or attribution. Existing
uncertain journals are deliberately not rewritten using hindsight.

No source mutation API was added. The source wire allowlist and Dovecot source
snapshot comparisons remain part of the tests. Existing schema versions 1 and 2,
account bindings and explicit configuration values remain supported; rejection
evidence is an additive table, not a transfer-state format change.

H5 and the other M/L findings remain outside this iteration, including performance,
source-deletion acceptance, destination adoption, OAuth refresh, provider testing,
folder subscriptions, release hardening and large-scale memory profiling. Source-side empty
inventory handling (part of M11) was addressed as part of M2; destination
reconciliation still uses the existing inventory path. No production-readiness or
live-provider compatibility claim is made.

### Repeatable validation

Use a Rust toolchain with OpenSSL development libraries, Python 3, OpenSSL, and
Docker/Compose for the real-server tests. All IMAP fixtures use throwaway accounts
and loopback or the private lab network; certificate verification stays enabled.
From the repository root:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo test --manifest-path vendor/imap-proto/Cargo.toml --target-dir target/vendor-tests
cargo test --manifest-path vendor/imap/Cargo.toml --lib --target-dir target/vendor-client-tests
cargo build --release --locked
cargo audit
python3 tests/local/security.py target/release/imaplane
python3 tests/local/e2e.py target/release/imaplane
python3 tests/local/reliability.py target/release/imaplane
python3 -m unittest discover -s tests/compose -p 'test_*.py'
# Deletes/reseeds only the disposable imaplane-lab volumes and test state:
./scripts/lab.sh reset
./scripts/lab.sh test
./scripts/lab.sh recovery
```

Local result: 25 project tests, 82 parser tests (15 documentation examples ignored
upstream), 137 client unit tests, and 5 offline lab tests passed. Formatting and
Clippy passed; cargo-audit found zero known vulnerabilities/warnings using
RustSec database commit 263a4d951a0867d4bddc29dddd6d59427c78f9a7.
All three release-binary TLS suites passed: security, disposable Dovecot e2e,
and reliability faults. The latter covers a throttled 16 MiB APPEND, slow FETCH
and APPEND replies, permanent-message isolation, tagged quota/size rejection
before and after the literal, mismatched tags, retryable NO codes, server restart
during FETCH with failed reconnects, startup refusal, concurrent delivery, empty
folders, and signal handling during APPEND and silent TLS setup. Existing e2e
coverage also passed for dropped APPEND replies and audited uncertain attribution.

The Compose reset/build succeeded with Rust 1.85.1. Its 120-message migration
and verification passed, including 360 attachment instances, duplicate
multiplicity, metadata, three preexisting destination messages, untrusted-CA
rejection and unchanged source snapshots. SIGINT and SIGKILL recovery each
completed all 120 transfers with no duplicate uploads and an unchanged source.
Generated reports remain in ignored tests/compose/.runtime/client/reports/.
These results do not cover hardware power loss, arbitrary disk failures,
100k-message soak runs, external providers or arm64. Package installation and
release workflows were not exercised in this iteration.

## Historical audit record

Scope: current Rust CLI, durable transfer state, source immutability, protocol
adapters, memory/credential handling, new XOAUTH2/STARTTLS paths and package/release
automation. This is a code review plus local automated validation, not a security
certification or a claim of production readiness. No real provider credentials,
mailboxes or GitHub release publishing were used.

## Confirmed findings and fixes

| Finding | Fix and regression evidence |
| --- | --- |
| A source read error could leave a reconnected session with changed UIDVALIDITY and allow the next message to be attempted on it. | Failed source reads now stop the pass. A scripted server truncates a body, changes UIDVALIDITY on reconnect, and asserts no destination APPEND and no attempt at the next UID. |
| Destination verification errors could leave an unsynchronized session available for later uploads. | Failed destination reads stop the pass. Fault fixtures repeatedly break read-back after APPENDUID; the accepted record survives, no second upload occurs in that pass, and a healthy resume verifies it without duplicating it. |
| IMAP parser errors can include raw message literals; NO/BAD responses can echo secrets. | Adapter errors now expose a sanitized category with no underlying raw error source. Fixtures include private body text and echoed tokens and check stdout/stderr. This intentionally sacrifices arbitrary server prose; operation context remains. |
| A successful FETCH without FLAGS was interpreted as an empty flag list. | Typed FETCH validation requires exactly one body, UID, INTERNALDATE and FLAGS for the requested message. Missing/duplicate fields and size discrepancies fail. Unrelated unsolicited responses are not used as message evidence. |
| Missing UID inventory responses could make a nonempty folder appear to be an empty successful snapshot. | The inventory must match the EXAMINE EXISTS count before persisting a snapshot. Concurrent changes now fail safely and ask for retry; a missing-UID fixture asserts zero APPENDs. This favors integrity over accepting an unstable snapshot. |
| Opening a named pipe as a credential file could block before its type was checked. | Credential opens use O_NOFOLLOW, O_NONBLOCK and O_CLOEXEC, then validate type, owner, permissions, size and syntax. FIFO, wrong permissions, control characters and symlink cases are tested. |
| A crash during initial journal creation could publish an empty schema-zero database. | SQLite initializes a private temporary file fully, closes it, publishes without clobbering, and fsyncs the parent directory before the job can upload. Existing targets and symlinks are never replaced. Hardware power-loss behavior still depends on filesystem/storage semantics. |
| Offline status used a read-write connection. | Status uses read-only/no-follow SQLite flags and does not upgrade schemas. Tests compare the database bytes before/after legacy status reads. |
| Holding the source buffer while reading back the destination increased peak memory unnecessarily. | Release source content immediately after APPEND returns successfully, before read-back. A 16 MiB single-line literal is copied and verified at its configured limit; one byte over is rejected before APPEND. This is not a measured global memory bound. |
| Per-socket I/O timeouts alone did not impose a total TLS-handshake deadline against a slow peer. | The handshake transport enforces an absolute deadline. Slow partial TLS record fixtures exercise both implicit TLS and STARTTLS. |

The unchanged design still journals uncertainty **before** sending an APPEND,
requires APPENDUID for acknowledged identity, validates destination bytes/date/flags,
and never auto-retries an uncertain upload. Duplicate source content remains
separate by UID. Operator resolution remains explicit and audited, and a candidate
hash match alone is never promoted automatically.

## Compatibility decisions

- Old endpoint configurations still default to implicit TLS, port 993 and the old
  `auto` authentication policy. New security/auth fields are optional.
- Journal schema stays at version 2. Version 2 account bindings and message keys
  are unchanged by auth/security settings. Port/account/mapping changes still
  refuse reuse because a transport alias cannot prove mailbox identity.
- Version 1 upgrades transactionally and additively. Existing fingerprints and
  transfer states are retained. No date, flags or uncertain attribution are
  fabricated. Status reads version 1 without upgrading. Missing old metadata may
  prevent full verification; this is reported rather than silently re-uploaded.
- XOAUTH2 consumes externally issued access tokens from private files and re-reads
  them at each connection. It handles empty initial challenges and empty replies
  to OAuth error challenges, and never falls back to a password. Interactive
  authorization, refresh grants and provider app registration are external.
- STARTTLS is explicit and mandatory: only CAPABILITY and STARTTLS precede the
  TLS handshake; no credentials are sent before trust/hostname checks. Plaintext
  state is discarded and capabilities are queried inside TLS. Minimum TLS is 1.2.

## Validation and boundaries

Current evidence is summarized in README and the final local validation record.
The automated suites include:

- Rust unit/integration tests for Unicode encodings, raw FETCH completeness,
  journal transitions, abrupt exit, UID identity uniqueness, legacy migration,
  read-only status, credential checks, private files and job binding/locking.
- Two disposable Dovecot 2.3 servers with real TLS, exact attachment bytes,
  metadata, legitimate duplicates, destination preservation, source wire command
  allowlists, resume, deletion/corruption detection, SIGINT, SIGKILL, lost replies,
  accepted-before-verification crashes, and real STARTTLS message migration.
- Scripted TLS fixtures for rev1, rev2-only, dual-mode, ENABLE behavior, UIDVALIDITY
  changes, truncated reads, omitted inventory UIDs, 16 MiB limits, XOAUTH2 challenge
  exchanges, token rotation, certificate/hostname rejection and downgrade refusal.
- Native package-family builds and clean container install/execute/uninstall tests
  where actually executed; see PACKAGING.md for the four CI targets.

Assumptions and remaining validation:

- Live Gmail and Microsoft 365 OAuth/IMAP sessions have not been exercised. Local
  wire compatibility is not provider support certification. Tenant policy, token
  audience/scopes, consent, token acquisition and expiry are external conditions.
- Native arm64 runners and hosted release publication are configured but must
  execute successfully before arm64 binaries or GitHub release behavior are
  claimed as tested here. No signing key or published package repository exists.
- Snapshots are not an atomic cross-folder view. A busy mailbox can fail an
  inventory count check and require retry. Server-reported identities, content
  and metadata must be trustworthy; a malicious server can lie consistently.
- Large-body memory is O(configured message cap), with parser vector spare
  capacity and a content copy. UID snapshots and reports are O(message count).
  No disk spooling, global RSS guarantee or million-message soak test is claimed.
- File fsync/SQLite transactions are tested through process death, not simulated
  controller failure, every power-loss ordering, disk-full boundary or NFS fault.
  Use private local storage; do not copy a live state directory to another writer.
- OAuth token theft by a compromised same-user process/OS is outside this model.
  Borrowed secrets and transient library authentication buffers are not a promise
  of complete memory erasure, although owned file-secret strings use Zeroizing.
- The synchronous IMAP dependency is alpha software with known parser limitations;
  the small rev2 patch and regression tests are retained. Binary literal8 and
  broad provider extensions remain outside the tested core subset.
- Collected dependency and Rust toolchain notices are packaged, but a complete
  SBOM and independent license compatibility review, cryptographic signing, external
  penetration testing and a sustained multi-provider soak remain release gates.


## Completed local validation

- 23 project tests pass with Rust 1.99.1 on the development host and Rust 1.85.1
  in native Debian bookworm and Rocky Linux 9 build containers.
- All 82 vendored parser regression tests pass; 15 upstream documentation examples
  are marked ignored by upstream, not counted as passing executable tests.
- Security fixtures pass against both native package-family release binaries.
  They include true token re-read after a forced reconnect, error challenges,
  STARTTLS no-fallback behavior, TLS trust/hostname checks, slow handshakes,
  credential-file validation and diagnostic sanitization.
- The expanded two-server Dovecot/crash suite passes against the Debian release
  binary, including real STARTTLS message migration, the 16 MiB boundary,
  missing UID inventory, and failures before/after acknowledged APPEND.
- Both amd64 package formats build and pass clean install/execute/uninstall checks;
  user-state sentinels survive uninstall. ARM64 remains CI-configured, unexecuted
  locally. Hosted release creation/upload was not run.
- cargo-audit 0.22.2 reports **0 known vulnerabilities and 0 warnings** across 144
  lockfile dependencies, against 1,402 RustSec advisories at database commit
  `263a4d951a0867d4bddc29dddd6d59427c78f9a7` (2026-11-02). This checks known crate
  advisories, not unknown defects, compiler/OS CVEs or the correctness of this code.
- Clippy with warnings denied, formatting checks, shell/Python syntax checks and
  workflow/package YAML parsing pass. Hosted workflow execution remains untested.
