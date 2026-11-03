# IMAPLANE technical design

Status: accepted initial design; implementation proceeds in reviewed increments.

## Scope and guarantees

Migrate one account's selected mail folders to another IMAP account. The first
network milestone copies one explicitly selected folder; recursive discovery
follows after its recovery behavior is tested. No source writes, deletion,
expunge, flag updates, subscriptions, or message rewriting. Existing destination
messages are never removed. A migration is an additive copy, not an IMAP MOVE.

The tool can guarantee that it issues no source mutation commands. It cannot
prevent server access logs, server-side bookkeeping, or changes by other clients.
Use a source credential restricted to read-only access where the server permits.

Do not claim universal exactly-once delivery. IMAP APPEND is not idempotent.
An interrupted upload can have succeeded without a received response. Unresolved
ambiguity must remain visible and block another upload of that source record.

## Architecture

One Rust process, one source connection and one destination connection initially.
Separate protocol adapters from the migration state machine and SQLite journal.
The source adapter exposes only capability negotiation, LIST, EXAMINE, bounded UID FETCH,
UID FETCH with BODY.PEEK[], and LOGOUT. Authentication and ENABLE are permitted
session operations. No generic command escape hatch in the migration engine.
Never use SELECT, STORE, COPY, MOVE, CLOSE, EXPUNGE, CREATE or subscription commands
on the source. Close a failed connection rather than attempt a writable cleanup.
Protocol transcript tests must assert these rules, including reconnects.

Use an established IMAP parser/client after evaluating literal handling, rev2
ENABLE, APPENDUID visibility, unsolicited responses and response limits. The
initial candidate async-imap has an APPEND convenience method returning (), so
its lower-level response path must be evaluated before adoption. Do not build a
new ad-hoc line-oriented IMAP parser. TLS uses certificate and hostname validation;
implicit TLS first. STARTTLS, if introduced, is mandatory with no plaintext fallback.
Secrets enter through terminal prompts or protected files; never CLI password
arguments, journal contents or logs. OAuth is a later adapter.

SQLite transactions provide durable state. Use synchronous=FULL and rollback
journaling initially. Hold one exclusive job lock throughout network migration;
database transaction boundaries alone do not prevent two uploading processes.
Refuse unsupported schema versions and mismatched account/folder bindings.
Create private state directories/files on Unix. Journal metadata is sensitive
even without message bodies. Store no credentials or raw messages in it.

## Identity and source snapshot

Each job binds non-secret source/destination identities and explicit folder
mapping. Each source record is keyed by folder, UIDVALIDITY and UID; never by
sequence number or Message-ID. Capture the UID set and UIDVALIDITY at the start
of each folder pass. New mail belongs to a subsequent pass. Missing source UIDs
are reported as source changes, not successful copies. If UIDVALIDITY changes,
stop and require explicit re-planning rather than treating new UIDs as old mail.
Concurrent client changes mean this is not an atomic cross-folder snapshot.

Transfer original RFC822 bytes, INTERNALDATE and supported persistent flags.
Never MIME-decode and reconstruct mail. Read with BODY.PEEK[] in EXAMINE mode.
Exclude session-only \\Recent; report unsupported keywords and flags. Treat
\\Deleted specially: omit by default and report the omission, because external
expunges at the destination could otherwise remove freshly copied messages.
Do not modify destination flags before or after an uncertain APPEND.
Use bounded message spooling with private temporary files and a configurable
size/disk limit; never unbounded FETCH batches. Clean spools on normal exit and
recover orphaned files safely. SHA-256 fingerprints describe exact fetched bytes.

## Protocol and Unicode

Support IMAP4rev1 (RFC 3501) and IMAP4rev2 (RFC 9051) through explicit capability
negotiation. A rev2-only session uses UTF-8 folder names. For a server advertising
both versions, retain rev1 behavior until ENABLE IMAP4rev2 succeeds. On rev1,
use UTF-8 only after successful ENABLE UTF8=ACCEPT; otherwise use modified UTF-7.
UTF8=ONLY requires successful UTF8=ACCEPT enablement. RFC 9755 supersedes RFC 6855.
Reconnects repeat negotiation; never reuse the previous connection's mode.

Keep decoded Unicode folder names plus original source identifiers. Do not apply
Unicode normalization, arbitrary case folding, or split paths on a guessed '/'.
Respect each LIST hierarchy delimiter and namespace. Only INBOX is specially
case-insensitive. Detect destination name collisions and nonrepresentable folder
mappings before writes. A folder name is protocol data and must be safely encoded
by the protocol library, never interpolated into a command.

## Transfer state and recovery

1. Persist a planned source message and exact content fingerprint after fetching.
2. Commit `uncertain` BEFORE invoking APPEND. A crash after this commit may mean
   no upload occurred; conservative ambiguity is intentional.
3. On tagged success with valid APPENDUID, persist `accepted` and the destination
   UIDVALIDITY/UID. Tagged success without UID evidence remains `uncertain` until
   reconciliation. Never interpret connection loss as definite failure.
4. Read back the exact destination UID using PEEK. Compare content hash plus
   expected INTERNALDATE and supported flags. Mark `confirmed` only with matching
   evidence. Retain metadata deviations separately from content confirmation.
5. On resume, skip confirmed records only while destination UIDVALIDITY and the
   evidence remain valid. Revalidate destination evidence in `verify`. Journal
   confirmation records historical evidence, not a promise mail still exists.

For uncertain records, compare against a saved pre-append destination baseline
and enumerate new UID candidates. Hash candidate bodies, check metadata, and
account for multiplicity. Byte-identical legitimate messages must stay distinct.
Concurrent identical deliveries can make attribution impossible. A unique hash
match alone does not prove which upload created a message. Never auto-retry an
ambiguous record. A future explicit operator resolution command must preserve an
audit trail; no silent conversion from uncertain to confirmed.

Transient safe reads and connection setup retry with exponential backoff and jitter;
failed reconnects consume the same attempt budget and restored selections must
retain UIDVALIDITY. Established I/O uses progress-aware idle timeouts; TLS setup
retains an absolute deadline. Permanent synchronized per-message errors are
reported incomplete while later messages proceed. A matching tagged APPEND NO/BAD
is recorded as rejection evidence and returns to planned for a future invocation.
Ambiguous APPENDs are never automatically replayed. SIGINT/SIGTERM/SIGHUP request
a stop; an active APPEND may complete and verify, or retain uncertainty on failure.

## Verification and reporting

Report planned, uncertain, accepted and confirmed separately. `accepted` means
the server acknowledged APPEND and returned a destination identity; it does not
mean read-back verification passed. `confirmed` requires read-back evidence.
Display flag/date deviations and source changes separately. Folder counts and
byte totals are useful checks, never proof of individual transfers. JSON reports
are versioned and include the verification scope and observation time. Exit 0
only for a completed run with every required check passing; exit 2 for unresolved
or incomplete work; exit 1 for invocation/storage/operational errors.

The initial status command reports journal evidence only and says so explicitly.
It is not a live destination verification command.

## Implementation increments and release gates

1. Foundation: CLI, strict folder encoding/negotiation model, durable journal,
   state transition and restart tests. No real-server migration exposed yet.
2. Transport spike: evaluate client APIs; TLS authentication, capabilities,
   Unicode LIST/EXAMINE and source-only wire transcript tests.
3. Single-folder copy: snapshot, bounded fetch/spool, APPENDUID, read-back and
   reports. Validate against local Dovecot fixtures before real credentials.
4. Recovery: fault-injection proxy, kill/restart at journal/APPEND boundaries,
   lost confirmations, duplicate multiplicity and concurrent destination writes.
5. Account folder mapping, documentation, reproducible release builds, Debian
   package and clean install/uninstall checks. RPM and other packaging follow.

Required tests cover rev1/rev2 negotiation, modified UTF-7 examples and malformed
input, Unicode round trips and collisions, unchanged source flags and content,
quota/size failures, UIDVALIDITY changes, unsupported flags, large literals,
certificate rejection, credential redaction, database corruption/schema mismatch,
destination deletions and verification discrepancies. No production-ready claim
until end-to-end and recovery gates pass. Keep dependencies locked and inspect
licenses/security advisories before release. No upstream imapcopy code is copied.

## Primary references

- https://www.rfc-editor.org/rfc/rfc3501.html
- https://www.rfc-editor.org/rfc/rfc9051.html
- https://www.rfc-editor.org/rfc/rfc4315.html
- https://www.rfc-editor.org/rfc/rfc9755.html
- https://docs.rs/async-imap/latest/async_imap/struct.Session.html

## Implemented core workflow (2026-11-02)

The foundation is now followed by a functional network CLI: inspect, migrate
(including dry-run/resume), verify, status and audited resolve. See README for
operator commands and the exact current limitations. Schema version 2 stores
source folder UID snapshots, frozen message metadata, pre-append UIDNEXT baselines
and attribution audit records. Jobs hold an exclusive filesystem lock.

Implementation decisions refining the initial plan:

- Use synchronous `imap` 3.0.0-alpha.15 behind private source/destination adapters.
  Its APPEND result exposes APPENDUID. Native TLS validates system/custom trust
  and hostnames, with TLS 1.2 minimum and no insecure fallback. LOGIN/SASL PLAIN
  use private files or terminal prompts. Debug protocol logging stays disabled.
- A small vendored imap-proto patch accepts rev2-only CAPABILITY responses; the
  upstream version demands IMAP4rev1. Adapter regression tests correct quoted
  LIST escapes without unescaping literal folder data. Snapshot inventories use
  UID FETCH 1:(UIDNEXT-1) (UID), avoiding SEARCH/ESEARCH differences and
  excluding deliveries after the initial EXAMINE. Empty inventories skip FETCH;
  inconsistent counts retry safely and UIDVALIDITY is checked again.
- The source adapter issues only authentication, capability/ENABLE, LIST, EXAMINE
  and UID FETCH operations. Disconnects close sockets, never CLOSE/EXPUNGE.
- The synchronous APPEND API accepts a byte slice. The current implementation
  uses bounded per-message memory instead of disk spooling, enforcing a configured
  size limit plus wire-response budgets. Streaming/spooling remains a later memory
  optimization. Raw messages do not persist on disk in this implementation.
- All configured source folders are snapshotted before any destination creation
  or upload. Explicit one-to-one mappings avoid guessed namespace/delimiter rules.
  New arrivals require a separate future incremental-pass design, not an implicit
  extension of an existing job.
- Successful APPEND replies become accepted; exact destination read-back and
  timestamp/flag comparisons establish confirmed results. A live verification
  first invalidates historical confirmation, then restores it only on success.
- Uncertain transfers never auto-promote from matching candidates. Explicit
  `resolve` verifies a candidate, enforces UID identity uniqueness, then records
  the operator's attribution transactionally. There is no force-retry path.
- Ctrl-C requests stopping between operations. SIGKILL around APPEND leaves a
  durable uncertain record. Read-only reconnects re-negotiate and re-EXAMINE the
  selected folder, refusing changed UIDVALIDITY. Writes are never auto-retried.

The local harness runs two disposable TLS-enabled Dovecot servers and TLS fault
proxies; fixture tests cover rev1, dual-mode, rev2-only and UTF8=ONLY sessions.
Production release gates remain: broader real-provider/rev2 interoperability,
large-scale and storage-failure testing, dependency/security review, and Linux
package build/install validation. The core is functional, not production-certified.

## Audit and authentication/packaging update (2026-11-02)

See RELIABILITY_AUDIT.md for confirmed defects and regression coverage. The
transfer state machine is retained; passes now fail closed after session-invalidating
read errors. Typed FETCH completeness and source EXISTS/inventory checks guard
against false confirmation or empty-success results on incomplete responses.
Journal creation is atomic and version 1 upgrades additively to version 2; version
2 identity and evidence are unchanged. Status is read-only.

Endpoints optionally select mandatory STARTTLS and XOAUTH2. Plaintext negotiation
is bounded and parsed with the existing typed parser; authenticated capability
state is always obtained after TLS. Access tokens come only from protected files
and are re-read at each connection. No token grant client or password fallback is
introduced. Live provider validation remains outstanding.

Native Debian/Rocky build containers, checksum-pinned nFPM and a four-target
GitHub Actions package/release workflow are included. ELF architecture checks and
clean install/uninstall tests gate publication. See PACKAGING.md for distro
boundaries and the distinction between configured and actually tested targets.


## Pre-optimization safety prerequisites

See [SECOND_AUDIT_FOLLOWUP.md](SECOND_AUDIT_FOLLOWUP.md) for the schema-3
pre-literal durable fence, safe explicit recovery, rejection circuit and
compatibility details. [PERFORMANCE_BASELINE.md](PERFORMANCE_BASELINE.md)
defines the deterministic crash matrix and instrumented fresh/resume benchmark.
These changes preserve FULL durability and exact verification. They do not
implement H5 optimizations.
