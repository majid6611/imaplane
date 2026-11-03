# Reliability and security audit — 2026-11-02

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
