# IMAPLANE

A Rust command-line tool for additive IMAP-to-IMAP mailbox migration on Linux.
The core workflow is functional and tested with disposable local Dovecot servers
and TLS protocol fixtures. **This is development software, not a production-ready
release.** Start with a small test folder and verify the results.

IMAPLANE reads the source using `EXAMINE` and `UID FETCH ... BODY.PEEK[]`. Its
source adapter exposes no write, flag-update, delete, expunge or subscription
operations. It copies original message bytes to a separate destination account;
attachments are part of those bytes. It never uses IMAP MOVE. Server access logs
and server-side bookkeeping are outside the client's control.

Implemented:

- Implicit TLS or mandatory STARTTLS with certificate/hostname validation and
  TLS 1.2 minimum. System trust plus an optional custom CA; no insecure fallback.
- SASL PLAIN, LOGIN and XOAUTH2 inside TLS. Passwords use protected files or
  terminal prompts; bearer access tokens use protected files. No inline secrets.
- IMAP4rev1 modified UTF-7, negotiated UTF-8, dual-mode rev2 enablement and
  rev2-only session handling. Unicode names are not normalized or case-folded.
- Folder discovery, explicit one-to-one folder mappings, and destination folder
  creation. Existing destination mail is retained.
- Durable source UID snapshots, SHA-256 fingerprints, INTERNALDATE and supported
  persistent flags; one exclusive job lock and private SQLite state.
- Sequential copying with per-message size limits, bounded wire responses,
  network timeouts, reconnect/retry for transient reads, and resumable transfers.
- Live destination verification of exact content, date and flags, with separate
  confirmed, uncertain, missing, changed, failed and mismatch results.
- Safe handling of Ctrl-C, process termination and lost APPEND confirmations.
  Uncertain uploads are not automatically repeated. Candidate discovery and
  explicit, audited operator attribution are available.

## Build and checks

Install stable Rust (1.85 or newer) and the platform build prerequisites. On
Debian/Ubuntu these include `build-essential`, `pkg-config` and `libssl-dev`.
SQLite is bundled; OpenSSL is linked through `native-tls`.

```sh
cargo build --release --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
./target/release/imaplane --help
```

To install the executable for your user:

```sh
cargo install --path . --locked
```

DEB and RPM build/install scripts and a gated GitHub Actions release workflow
are included; see [packaging instructions](docs/PACKAGING.md). No GitHub release
has been published by this local session. Keep the `vendor/` directory:
its documented parser and APPEND literal-guard patches are required.
See [third-party notes](vendor/README.md).

## Test a real migration

Use two distinct accounts. Aliases that authenticate to the same underlying
mail store must not be used as opposite endpoints. IMAP cannot reliably prove
that two differently named login identities are different physical accounts.
A read-only source credential provides an additional server-enforced safeguard.

1. Copy [examples/migration.toml](examples/migration.toml) to a private working
   directory. Set the server names and account names. Start with just INBOX or a
   small explicit source folder mapped to a new destination test folder.
2. Omit `password_file` to receive terminal prompts, or create separate UTF-8
   password files using a text editor. They must be regular files owned by your
   user, without symlinks or any group/other permissions. Use mode `0600` or
   `0400`. One trailing newline is removed.
   Never put real credentials in this repository.
3. Discover names, review the mapping, and run a read-only preflight:

```sh
imaplane inspect --config /path/to/migration.toml
imaplane migrate --config /path/to/migration.toml --dry-run
```

`inspect` prints JSON folder names, hierarchy delimiters and selectability for
both servers. Use these exact Unicode names in `[[folders]]`. No automatic
namespace or hierarchy translation is attempted. Dry-run creates no state,
folders or messages, and does not establish that destination writes will succeed.

4. Copy, then verify against the saved evidence:

```sh
imaplane migrate --config /path/to/migration.toml
imaplane verify --config /path/to/migration.toml
```

`state_dir` is created with mode `0700`; its files contain sensitive mailbox
metadata and fingerprints, but no passwords or raw messages. Keep this directory
through every retry. Its account identities and folder mappings are fixed: a
changed mapping requires a separate job. Never run the same job using a copied
state directory concurrently. Use local storage with working SQLite locking
and durability semantics; network filesystems have not been validated.

Progress goes to stderr. Add `--json` to migrate/verify for a versioned JSON
report on stdout. To retain a private report:

```sh
umask 077
imaplane migrate --config /path/to/migration.toml --json > migration-report.json
imaplane verify --config /path/to/migration.toml --json > verification-report.json
```

Exit codes: `0` means the recorded snapshot passed all required destination
checks (or a read-only inspect/dry-run completed), `2` means incomplete,
interrupted, uncertain or mismatching work, and `1` means an invocation,
configuration, storage, authentication, transport or other operational error.
Argument parsing/help use Clap's standard exit conventions. Fatal operational
errors can prevent a final JSON report; journal evidence still survives.

The first run saves each configured folder's UID set. New arrivals are outside
that job's snapshot, even after resume. This is not continuous synchronization.
A new state directory starts an independent copy and can duplicate mail already
copied by another job. Do not discard state to resolve an uncertain transfer.

## Recovery and verification

Rerun the same `migrate` command after interruption. Confirmed and acknowledged
messages are still read back exactly; they are not uploaded again. A healthy
historical confirmation is retained without redundant journal writes. Observed
verification failures durably downgrade it; offline status remains historical
evidence, especially if a new verification was interrupted. Planned records may
continue copying. Source UIDVALIDITY changes stop migration. Destination
UIDVALIDITY changes, missing messages, changed bytes, dates or flags are reported;
IMAPLANE does not overwrite or automatically recreate those destination messages.

Each upload is committed as **uncertain before any APPEND bytes are sent**. A
successful reply with APPENDUID is **accepted**. It becomes **confirmed** only
after the exact destination UID passes content, INTERNALDATE and flag checks.
A crash between these steps is recoverable without guessing. Metadata comparison
uses the original timestamp as an instant (not its timezone spelling) and
case-insensitive flag matching.

A lost confirmation can leave an upload uncertain even if the message exists.
Resuming inspects up to 1,000 destination UIDs at/after the saved UIDNEXT baseline
and lists candidates matching content, date and flags. Neither Message-ID nor a
unique hash match proves attribution when identical deliveries can coexist.
IMAPLANE therefore leaves these candidates **uncertain** and never blindly retries.

When you have independently identified the destination UID belonging to this
transfer, explicitly attribute it:

```sh
imaplane resolve --config /path/to/migration.toml \
  --folder INBOX --uid 123 --destination-uid 456
imaplane verify --config /path/to/migration.toml
imaplane migrate --config /path/to/migration.toml
```

`resolve` verifies exact content, date, flags and destination UIDVALIDITY, rejects
UIDs before the saved baseline and UIDs already assigned to another source
record, and writes an attribution audit entry. It never uploads. It exits `2`
because resolving one message does not establish whole-job completion; run
`verify`/`migrate` afterward. The operator is responsible for attribution among
otherwise identical candidates. If there is no identifiable candidate, the job
remains uncertain; there is deliberately no unsafe force-retry command.

For offline historical evidence only:

```sh
imaplane status --state /path/to/migration-state/journal.sqlite3 --json
```

`status` does not contact either server, cannot establish current completeness,
and always exits `2` when it successfully reports a journal. Its confirmed count
is historical content evidence; use `verify` for live content and metadata checks.
`verify` uses the saved source evidence and contacts only the destination, so it
cannot report later source changes or prove an atomic cross-server snapshot.


For an uncertain transfer with no matching destination candidate, the new
`recover` command can authorize a future attempt **only** if schema-3 attempt
evidence proves literal sending was never authorized:

```sh
imaplane recover --config examples/migration.toml --folder INBOX --uid 123 --json
imaplane migrate --config examples/migration.toml --json
```

Recovery performs no upload and exits 2 with `retry_authorized`. It refuses
legacy/missing evidence, already authorized literals, changed UIDVALIDITY,
matching candidates and an incomplete/over-limit candidate search. An empty
search alone is never enough. Genuinely ambiguous transfers still require manual
review; there is no force-retry switch. See the [second audit follow-up](docs/SECOND_AUDIT_FOLLOWUP.md)
for the durable fence, zero-length handling and remaining H3 limitations.

### Rejected messages: classification and the operator skip

A tagged `NO` to APPEND is classified by what it implies for the *next* message,
not matched against a retry list. Only the first two rows let later messages
proceed; nothing is ever replayed in the same invocation.

| Scope | Examples | Behavior |
| --- | --- | --- |
| message | `TOOBIG`, `CONTENTREJECTED` | rejected, stays planned, later messages continue |
| size-dependent | `OVERQUOTA` | same; a smaller message may fit |
| transient | `UNAVAILABLE`, `THROTTLED`, `INUSE`, `LIMIT` | bounded, interruptible breaker |
| mailbox | `NOPERM`, `NONEXISTENT`, `TRYCREATE` | stop, name the mailbox scope |
| account | `AUTHENTICATIONFAILED`, `AUTHORIZATIONFAILED`, `EXPIRED`, `PRIVACYREQUIRED` | stop, name the account scope |
| ambiguous | `CANNOT`, `SERVERBUG`, code-less, unknown or provider-specific text, any `BAD` | stop for operator review |

Only a fixed allowlist of code names is ever stored; other server text is reduced
to `UNSPECIFIED`. If a message can never be migrated (for example a provider keeps
refusing it), an operator can record that decision. This contacts no server:

```sh
imaplane skip   --config migration.toml --folder INBOX --uid 123 --reason "ticket 42: provider refuses this message" --json
imaplane unskip --config migration.toml --folder INBOX --uid 123 --reason "provider fixed" --json
```

`skip` works only on a planned, never-attributed message that already has a
durable tagged rejection. It requires a reason (at most 500 characters, no control
characters), appends to an audit log and changes no transfer state. A skipped
message is reported as `skipped_by_operator`, is **not** counted as migrated, and
keeps `complete` false and the exit code at 2 for as long as the skip stands.
`unskip` returns the message to the normal path. `status` shows the skipped count.

Before an APPEND is prepared, a destination connection that has been idle for
2 seconds or more (for example during a slow source read) is probed with `NOOP`
and replaced if dead, then re-selected with the UIDVALIDITY check. A successful
probe cannot promise the connection survives the APPEND itself; a failure during
APPEND is still uncertain and never replayed.

## Preservation policy and limitations

- `\Recent` is session-only and never copied. `\Deleted` is intentionally omitted
  and reported to avoid making migrated mail vulnerable to an external expunge.
  Unsupported or unsafe keywords/flags are also omitted and reported. A confirmed
  result means all **supported, planned** flags match; review `omitted_flags` for
  fidelity limitations even when the job completes.
- Destination UIDPLUS or IMAP4rev2 support, stable UIDVALIDITY and UIDNEXT are
  required. UIDPLUS advertised but missing APPENDUID yields an uncertain record.
- Messages are fetched individually into bounded memory rather than disk-spooled.
  The default cap is 64 MiB per message; peak memory includes the parser buffer
  and a content copy (vector capacity may exceed content length). The source
  message buffer is released before destination verification. This is not a total
  process RSS limit: UID snapshots and JSON/text report entries consume memory
  proportional to the number of messages. `max_message_bytes` is configurable up to 1 GiB. LIST and
  UID-inventory responses are capped at 16 MiB; other metadata at 1 MiB. Very
  large inventories or messages fail clearly rather than bypass limits.
- No built-in OAuth browser/device authorization or token-refresh grant client,
  Gmail label deduplication, provider-specific transformations,
  batch accounts, subscriptions, quota preflight, ongoing synchronization or
  automatic incremental passes. Treat Gmail virtual/label folders carefully:
  different source folder instances are copied independently.
- Arbitrary folder control characters, noncanonical modified UTF-7, special-use
  attribute migration, binary literal8 extensions and unusual server responses
  are not fully supported. Explicit mappings do not detect every server's hidden
  case-insensitivity or shared namespace aliases; review exact destination names.
- Established IMAP connections use progress-aware idle timeouts. Positive socket
  or TLS I/O renews the idle deadline; TLS handshakes and STARTTLS negotiation
  retain absolute setup deadlines. There is no minimum-throughput requirement.
- Safe reads and connection establishment retry up to `read_attempts` (default 6,
  existing explicit values respected), with 1-second exponential backoff, a
  120-second base-delay cap, up to 249 ms jitter, and a 600-second retry window per
  operation. A healthy progressing command is never cut off by that retry window.
  Failed reconnects and session restoration consume attempts. Authentication
  rejection, certificate errors, malformed responses and changed UIDVALIDITY
  fail conservatively. Structured NO codes UNAVAILABLE, THROTTLED, INUSE and
  LIMIT are retryable on safe operations; arbitrary server prose is ignored.
- Oversized messages, completed reads with an RFC822.SIZE mismatch, and permanent
  message-specific TOOBIG rejections are isolated where the session remains synchronized.
  `skipped_permanent` and `verification_failed_permanent` keep the report incomplete
  (exit 2), while later messages continue. They are checked again on rerun.
  Broken/ambiguous protocol sessions still stop the pass. There is no manual
  skip list or general per-message failure limit; the destination rejection
  circuit below is separate.
- APPEND is never automatically replayed. A matching tagged NO/BAD rejection is
  recorded durably and returns the transfer to `planned`, for a future run after
  the operator addresses the failure. Other messages can continue. Dropped replies,
  malformed/mismatched tags and missing APPENDUID remain `uncertain`.
  Neither zero candidates nor one content match proves an ambiguous APPEND's
  outcome; manual audited attribution remains necessary.
- Ctrl-C, SIGTERM and SIGHUP request a graceful stop. Interrupted socket calls
  retry without resetting setup deadlines. An in-flight APPEND can finish and
  be verified before stopping; a silent operation may wait for its timeout.
  Forced termination can still leave durable uncertainty.
- Source snapshots use the initial UIDNEXT as a fixed horizon, excluding later
  deliveries. A second EXAMINE checks UIDVALIDITY. Inventory/count discrepancies
  (including concurrent expunges) retry boundedly and never publish a partial
  successful snapshot. Empty folders do not issue an inventory FETCH.
- Existing schema 1/2/3 journals upgrade additively to schema 4 (an empty
  operator-skip audit log), after a private pre-upgrade backup. Transfer states,
  bindings, fingerprints and legacy evidence are preserved. Old uncertain records
  acquire no fabricated pre-send evidence. Offline status reads versions 1-4
  without writing or upgrading; older binaries cannot open schema-4 journals.
- Repeated identical destination APPEND rejections back off 1, 2, 4… seconds
  (maximum 120 seconds per pause) and open a run-wide circuit after
  `append_rejection_limit` consecutive status/code pairs (default 3, range 1..100).
  A successful APPEND resets the count; a different pair starts a new streak.
  JSON `halt_reason` explains the stop. Rejected records remain planned, later
  messages remain unattempted, and no APPEND is replayed in that run. After fixing
  destination limits, rerun with the same state directory. SIGTERM/Ctrl-C can stop
  during the pauses. Unknown server codes are reported as UNSPECIFIED.
- Testing covers local Dovecot 2.3 plus rev1/rev2 scripted TLS fixtures. Large-scale,
  multi-provider, sustained performance, full RFC9051 interoperability, quotas,
  malicious-server fuzzing and all crash/power-loss/storage failures have not been
  exhaustively tested. No production-readiness claim is made.

## Persistent isolated Docker Compose lab

For a ready-to-use local environment with two Dovecot servers, 120 synthetic
emails, attachments, Unicode folders, verified test TLS, and deterministic
interruption/resume checks:

```sh
./scripts/lab.sh up
./scripts/lab.sh cli migrate --dry-run
./scripts/lab.sh cli migrate
./scripts/lab.sh cli verify
./scripts/lab.sh test
./scripts/lab.sh recovery
```

The CLI runs inside an internal-only network with fixed test endpoints, no
published IMAP ports, test-only credentials and separate mail volumes. No real
configuration is loaded. `./scripts/lab.sh reset` recreates only this lab;
`./scripts/lab.sh down` stops it while preserving its mail and journals.
See [the Compose lab instructions](tests/compose/README.md) for exact repeatable
commands, configuration paths, reports, reset behavior and isolation limits.

## Local end-to-end tests

With Docker, Python 3 and OpenSSL installed:

```sh
cargo build --locked
python3 tests/local/security.py
python3 tests/local/e2e.py
# Or pass a release binary:
python3 tests/local/e2e.py target/release/imaplane
python3 tests/local/reliability.py target/release/imaplane
```

The suite starts two disposable Dovecot containers from a pinned image, uses
random loopback-only ports, generates a temporary TLS certificate, seeds only
synthetic mail, and removes its containers in cleanup. The image download needs
network access. It does not use your configuration or real mail credentials.

It checks Unicode/escaped folder discovery and creation; exact attachment bytes,
flags and dates; identical legitimate messages; preservation of source and
existing destination mail; no duplicate uploads on resume; newly arriving mail
outside the snapshot; TLS rejection; password authentication methods; read reconnects;
job locking; size limits; verification discrepancies; lost APPEND replies;
Ctrl-C; SIGKILL; and audited resolution. Separate security fixtures test XOAUTH2, strict STARTTLS, rotating tokens on
reconnect and refusal paths. Scripted TLS fixtures exercise rev1,
rev2-only, dual-mode ENABLE, UTF8=ONLY and unsuccessful enablement. See
[technical design](docs/TECHNICAL_DESIGN.md) for architecture and remaining gates.

Licensed under the [MIT License](LICENSE). Vendored dependencies retain their
upstream licenses, including MIT/Apache-2.0. No imapcopy source code is included.


## XOAUTH2 and mandatory STARTTLS

Existing configurations keep implicit TLS, port 993, and their previous auth
behavior. New settings belong inside an endpoint section:

```toml
[source]
host = "imap.example.com"
port = 143
security = "starttls"
username = "mailbox@example.com"
auth = "xoauth2"
access_token_file = "./source.access-token"
# ca_file = "./private-ca.pem"
```

Omit `password_file` when using XOAUTH2. The token file contains only a bearer
**access token**, not a refresh token or a JSON response. It uses the same owner,
permissions, symlink and size checks as password files. The token is re-read on
every connection, including reconnects; atomically replace the file using a
trusted external token manager before expiration. IMAPLANE never runs an arbitrary
credential command or falls back to a password after XOAUTH2 failure. OAuth
consent, token acquisition and refresh are managed outside this tool.

For implicit TLS, retain `security = "tls"` (the default) and port 993. For
STARTTLS, explicitly configure `security = "starttls"` and port 143 (or your server's
configured upgrade port). The server must advertise STARTTLS and complete the
upgrade; credentials are sent only after certificate validation. Pre-TLS
capabilities are discarded and queried again inside TLS. DNS lookup time still
depends on the operating system; handshake and protocol I/O have deadlines.
Changing auth or security on the same host/port/user does not change journal
identity. Changing a bound account, port or mapping still correctly refuses resume.

**Provider status:** the XOAUTH2 wire format is implemented and tested using
local TLS fixtures, including Google's error challenge exchange. Gmail and
Microsoft 365 have **not** been tested with live accounts in this environment.
The implementation is intended to interoperate with their documented XOAUTH2
mechanisms, not certified for either provider. A valid token alone does not
ensure that IMAP is enabled or that tenant/consent policies permit access.

- For Gmail, follow [Google's IMAP XOAUTH2 documentation](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol),
  including the documented `https://mail.google.com/` scope and account policy.
- For Microsoft 365, follow [Microsoft's IMAP OAuth documentation](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth/).
  Delegated IMAP access uses `https://outlook.office.com/IMAP.AccessAsUser.All`;
  application permissions require additional Exchange service-principal and
  mailbox authorization. Do not substitute a Microsoft Graph token for an
  Exchange IMAP token.

## Reliability audit and evidence

See [the audit record](docs/RELIABILITY_AUDIT.md) for confirmed findings, fixes,
test coverage and remaining assumptions. Tests exercise synthetic mail only;
passing them does not establish production readiness or live-provider support.
Malformed protocol responses are sanitized to avoid leaking message literals or
server-echoed credentials through error output. A failed read that leaves session
state uncertain stops the pass rather than continuing uploads on that session.


Latest validation (2026-11-03): **32 project tests, 82 parser tests,
138 vendored client tests, 5 offline lab tests and 3 benchmark harness tests pass**.
The H5 changes passed 73 deterministic crash scenarios for the final optimizations
(the initial preparation increment passed 72). Final 100-message, five-repeat interleaved
A/B measurements reduced fresh client syncs from 24.17 to 16.17/message and
exchanges from 7.23 to 6.23/message. Healthy resume performs zero client syncs
while still reading and checking every message exactly. Peak RSS was essentially
unchanged; fresh wall time was flat and wall-time comparisons remain advisory.
See [H5 results and limits](docs/H5_SAFETY_AND_RESULTS.md). Formatting and Clippy
pass. All three release TLS suites pass, including slow uploads, quota rejection,
failed reconnects and termination. The Compose 120-message migration, verification,
SIGINT and SIGKILL recovery pass with unchanged source mail and no duplicate
uploads. See the audit record for repeatable commands and detailed limits. cargo-audit reports zero known vulnerabilities or warnings
at database revision `263a4d951a0867d4bddc29dddd6d59427c78f9a7`.
Package installation checks from the earlier audit were not repeated in this
iteration. Live Gmail/Microsoft 365, other server implementations, arm64 and
production-scale operation remain unvalidated. This is a technical preview.


## Baseline and crash testing before optimization

See [the fixed benchmark method](docs/PERFORMANCE_BASELINE.md) and
[second audit follow-up](docs/SECOND_AUDIT_FOLLOWUP.md). The current H5 increments and safety gates are documented in
[H5 safety and results](docs/H5_SAFETY_AND_RESULTS.md). Preparation writes are
combined under FULL durability, healthy resume avoids redundant writes, and
destination selections are reused with reconnect/UIDVALIDITY guards. Exact
read-back remains mandatory. Default/package builds contain
no active crash-injection hook.

```sh
cargo build --release --locked
cargo build --locked --features fault-injection --target-dir target/fault-tests
python3 tests/local/crash_matrix.py target/fault-tests/debug/imaplane
python3 -m unittest discover -s tests/local -p 'test_*.py'
python3 scripts/build-benchmark-binary.py
python3 tests/local/benchmark.py --binary target/release/imaplane \
  --mixed --messages 100 --latency-ms 0 --repeats 5 \
  --output /tmp/imaplane-baseline.json
```

Fault binaries deliberately SIGKILL themselves at test points. Use the regular
release binary for real migrations. All harness endpoints are disposable local
Dovecot servers with test-only credentials and verified TLS.
