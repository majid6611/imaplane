# Gmail and Microsoft 365 compatibility testing guide

Status: **plan only. No real account has been contacted.** IMAPLANE has been tested
against Dovecot and scripted servers, never a live provider. Everything in the
"Provider facts to verify" table is an expectation from public documentation or
general experience, not an observation, and must be confirmed during testing.

Goal: find out whether IMAPLANE's safety guarantees hold against real Gmail and
Microsoft 365 IMAP servers, in **both directions**, using small disposable
accounts. This is a compatibility exercise, not a production migration.

## 1. Hard rules

1. Disposable accounts only: created for this test, holding only synthetic mail
   you generated, deletable afterwards. Never a personal, work or customer mailbox.
2. Do not start until the project owner has said so explicitly (the current
   approval is: **not yet**).
3. Credentials, tokens, configs, journals and `*.bak` backups live **outside the
   repository** in a private directory (`chmod 700`), and are destroyed afterwards.
   Journals and backups contain message metadata and are sensitive.
4. Nothing from a provider run is committed or pushed without review. Raw server
   transcripts can contain mailbox names and addresses.
5. Stop at the first unexplained result. A surprising tool result is a finding, not
   something to retry until it passes. Never use `resolve`, `recover` or `skip` to
   make a run look green; use them only as the documented procedure under test.
6. Never weaken verification (exact content, INTERNALDATE, supported flags) to get
   a provider to pass. If a provider cannot satisfy it, that is the result to report.
7. One IMAPLANE process per job; no other mail client connected to either test
   mailbox during a run.

## 2. Provider facts to verify

| # | Expectation (unconfirmed) | Why it matters | How to check |
| --- | --- | --- | --- |
| P1 | Gmail: `imap.gmail.com:993`, implicit TLS. Plain account passwords are not accepted; use an app password (2-Step Verification) or OAuth2/XOAUTH2 with scope `https://mail.google.com/`. | Auth mode choice | Stage 0 |
| P2 | Microsoft 365: `outlook.office365.com:993`. Basic auth is disabled or being retired; use OAuth2/XOAUTH2 (delegated `IMAP.AccessAsUser.All`, or app-only `IMAP.AccessAsApp` with the mailbox granted to the service principal). IMAP must be enabled for the mailbox. | Auth mode, tenant setup | Stage 0 |
| P3 | Both advertise `UIDPLUS` and return a single `APPENDUID`. | IMAPLANE **requires** it. Without a usable APPENDUID every APPEND ends uncertain. | CAPABILITY, Stage 1 |
| P4 | Gmail exposes labels as folders; one message can appear in several. `[Gmail]/All Mail` holds everything. APPEND to a label folder adds that label. | Duplicates across folders; folder mapping | Stage 2 |
| P5 | Gmail may de-duplicate an APPENDed message that matches an existing Message-ID. | Could break IMAPLANE's exact duplicate multiplicity and APPENDUID/read-back expectations | Stage 2 (D1) |
| P6 | Exchange rebuilds MIME on FETCH, so `BODY[]` may not be byte-identical to what was appended or stored. | Exact read-back (invariant 6) could report `mismatch` after a correct upload | Stage 2 (X1) |
| P7 | Supported system flags only (`\Seen \Answered \Flagged \Draft \Deleted`); few or no custom keywords. | Flags are intentionally omitted and reported; confirm via PERMANENTFLAGS | Stage 2 (F1) |
| P8 | Per-message size limits (commonly ~25 MB, tenant-configurable on Microsoft 365). | `TOOBIG`-style rejections, or opaque `NO` | Stage 3 (R1) |
| P9 | Daily IMAP bandwidth and connection-count limits (Gmail documents per-day upload/download caps and a small simultaneous-connection cap). | Throttling shape, `[ALERT]`/`BYE` rather than `[THROTTLED]` | Stage 3 (R2) |
| P10 | Idle connections are dropped by the server after some minutes. | U1 probe behaviour | Stage 3 (U1) |
| P11 | OAuth access tokens expire (about an hour). IMAPLANE re-reads `access_token_file` at every connect, so an external refresher can rotate it. | Long runs | Stage 3 (T1) |

Re-check current provider documentation immediately before testing; limits and
authentication rules change.

## 3. Prerequisites

- IMAPLANE built from a clean, committed tree; record `git rev-parse HEAD` and the
  binary's SHA-256. Run the full local suites first (`cargo test`, clippy, and the
  `tests/local` scripts, including `c1_u1.py` and `skip_crash_matrix.py`).
- Two accounts per direction: a **source** holding only synthetic mail, and an
  **empty destination** of the other provider. Different provider per side.
- Auth ready for each: an app password file, or an access-token file refreshed by an
  external tool, both mode `0600`. Tokens are IMAP-scoped and short-lived.
- IMAP enabled on both mailboxes.
- An **independent, read-only before/after snapshot** of the source (UIDVALIDITY,
  UID list, size and SHA-256 per message) taken with a separate client. This does
  not exist yet; building it is a prerequisite and needs the owner's approval to
  handle credentials.
- A way to see raw tagged responses. IMAPLANE deliberately discards server text and
  records only an allowlisted code and scope, so a new code or message text is
  invisible to it. This is a tooling gap (see section 9).

## 4. Configuration skeletons

Copy outside the repository. Placeholders only; never paste real values into a file
under version control. Run `imaplane inspect` first and use the **exact** folder names
and delimiter it prints; names such as `[Gmail]/Sent Mail` and `Sent Items` can be
localized.

Direction A, Gmail to Microsoft 365:

```toml
state_dir = "/private/dir/state-A"
timeout_seconds = 60
max_message_bytes = 26214400        # stay near the provider limit while probing

[source]
host = "imap.gmail.com"
port = 993
username = "<gmail test address>"
password_file = "/private/dir/gmail.app-password"      # or auth = "xoauth2" + access_token_file

[destination]
host = "outlook.office365.com"
port = 993
username = "<m365 test address>"
auth = "xoauth2"
access_token_file = "/private/dir/m365.access-token"

[[folders]]
source = "INBOX"
destination = "INBOX"
```

Direction B swaps the roles: `[source]` is Microsoft 365, `[destination]` is Gmail.
Map a small set of folders; do **not** map both a Gmail label and `[Gmail]/All Mail`
unless duplication is the thing being tested.

## 5. Synthetic corpus

Generate deterministically (fixed seed), keep the generator and the manifest of
SHA-256 values outside the repo. Cover: tiny text; no Message-ID; non-ASCII headers
and UTF-8 body; bare LF and very long lines; 8-bit content; nested `message/rfc822`;
inline image; ~1 MiB, ~10 MiB, just-under-limit and just-over-limit attachments; a
legitimate **duplicate pair** (identical bytes and Message-ID); old (1999) and
mid-timezone INTERNALDATE values; flag combinations (`\Seen`, `\Flagged`,
`\Answered`, `\Draft`, a custom keyword, `\Deleted`); a Unicode-named and a nested
folder; an empty folder.

## 6. Staged plan

Each stage has a gate. Do not advance on a failed or unexplained gate.

**Stage 0, no mail moved.** `inspect`, `migrate --dry-run`, and CAPABILITY for both
sides (pre-auth CAPABILITY needs no credentials). Gate: both authenticate, both list
the expected folders, destination advertises UIDPLUS (P3), TLS verifies with the
system trust store.

**Stage 1, one message.** One small message, one folder. Gate: `complete` true, exit
0; `verify` complete; destination message matches; source snapshot unchanged;
journal shows one confirmed APPENDUID. Then rerun `migrate`: **zero** APPEND.

**Stage 2, corpus fidelity (about 25 messages).**

| ID | Check | Pass criterion |
| --- | --- | --- |
| D1 | Duplicate pair | Both copies present with distinct UIDs, or a clearly explained provider behaviour; never a silent merge reported as success |
| X1 | Exact bytes | Read-back equals source for every message, or each difference is catalogued |
| F1 | Flags | Supported flags equal; unsupported ones appear in `omitted_flags`, not silently dropped |
| T1 | INTERNALDATE | Equal after timezone normalization |
| U0 | Unicode folders | Created and matched by exact name |
| M1 | Rerun / `verify` | Zero APPEND on rerun; `verify` complete; source unchanged |

**Stage 3, behaviour under stress (still small).**

| ID | Scenario | Look for |
| --- | --- | --- |
| R1 | A message over the size limit | The exact code/scope recorded; run continues for message-scope, stops otherwise; no replay |
| R2 | Deliberate throttling (many small APPENDs, or repeated runs) | Whether it shows as a code IMAPLANE classifies, or as `[ALERT]`/`BYE` (currently ambiguous and stops) |
| U1 | Destination idle during a slow source read | NOOP probe fires and reconnects; no uncertain record |
| T1 | Token expiry mid-run | Reconnect with rotated token, or a clean stop; never a duplicate |
| K1 | `SIGTERM` mid-run, then resume | No duplicate, no uncertain record that was not already ambiguous |
| S1 | `skip` / `unskip` of a message the provider really rejected | Audit rows written; message reported not migrated; run incomplete |

**Stage 4, repeat both directions** with the full corpus once Stage 3 is clean.

## 7. Evidence to record per run

Provider, direction, date, IMAPLANE commit and binary hash; the JSON report; journal
summary (`status`); counts of APPEND commands and reconnects; any `uncertain`,
`rejected` or `skipped_by_operator` entries with their recorded code and scope;
before/after source snapshot comparison; elapsed time. Remove addresses and mailbox
names before anything leaves the private directory.

## 8. Stop and clean-up

Stop immediately on: any `uncertain` entry that is not explained, any source change,
any credential or token appearing in output, an unexpected duplicate, or a provider
lockout/abuse warning. Then: do not rerun; preserve the journal and report; record
what was observed. Clean-up: revoke app passwords and tokens, delete the test
mailboxes or accounts, securely delete configs, journals and `*.bak` backups.

## 9. Known gaps before live testing

1. **Raw response visibility.** To learn the exact code and text a provider returns
   for oversize, throttle or permission errors, a separate read-only capture method
   is needed. Options: a manual `openssl s_client` session for CAPABILITY only; a
   small standalone probe script. Adding an opt-in diagnostic to IMAPLANE would
   conflict with the rule that server text is never stored, so it is not proposed.
2. **Independent source snapshot tool** (section 3).
3. **Ambiguous by design.** Provider-specific rejections, including bandwidth
   `[ALERT]` replies, are treated as ambiguous and stop the run. That is
   deliberately conservative; Stage 3 decides whether any provider needs a narrower,
   evidence-based classification.
4. **Fixed 2-second idle probe threshold** is untested against real idle timeouts.
5. No arm64, no IMAP4rev2-only server, and no parallel transfers are in scope.

## 10. Decisions for the project owner

- Which auth mode for each provider (app password vs OAuth2), and who creates the
  disposable accounts and the Microsoft 365 app registration.
- Whether to build the source-snapshot and response-capture helpers (section 9).
- The explicit go-ahead to begin Stage 0.
