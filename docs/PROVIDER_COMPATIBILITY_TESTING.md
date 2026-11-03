# Gmail and Microsoft 365 compatibility testing guide

Status: **Stage 0 (preparation) is complete; no real provider has been contacted.**
IMAPLANE has been tested against Dovecot and scripted servers, never a live
provider. Everything in "Provider facts to verify" is an expectation from public
documentation or general experience, not an observation, and must be confirmed.

Goal: find out whether IMAPLANE's safety guarantees hold against real Gmail and
Microsoft 365 IMAP servers, using small disposable accounts. Every test pairs **one
provider with one local Dovecot**, in this order of priority:

1. Gmail to Dovecot
2. Dovecot to Gmail
3. Microsoft 365 to Dovecot
4. Dovecot to Microsoft 365

A local Dovecot is a controlled counterpart: any surprise is attributable to the
provider. Gmail-to-Microsoft-365 directly is deliberately out of scope.

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

## 3. Tooling (built and tested in Stage 0)

| Tool | Purpose |
| --- | --- |
| `scripts/provider_lab.py` | `up`/`down`/`status` for loopback-only disposable Dovecot containers; `seed` loads the synthetic corpus into a Dovecot **source**; `config` writes a path-only IMAPLANE config for any of the four directions. Refuses to seed anything it did not create. |
| `scripts/imap_snapshot.py` | Independent, read-only (EXAMINE, BODY.PEEK, command allowlist) snapshot of any mailbox, plus `same` (source unchanged?) and `copy` (destination equals source: content hash, multiplicity, INTERNALDATE, flags). Shares no code with IMAPLANE. |
| `scripts/oauth_token.py` | Loopback + PKCE consent flow, then keeps an access-token file fresh. Tokens only in 0600 files, never printed. Google design is exercised against a fake endpoint only; the Microsoft preset is **untested**. |
| `imaplane --diagnostics-file PATH` | Opt-in sanitized protocol log (see section 7). Off by default. |

Other prerequisites:

- IMAPLANE built from a clean, committed tree; record `git rev-parse HEAD` and the
  binary's SHA-256. Run the local suites first (`cargo test`, clippy, the `tests/local`
  scripts including `c1_u1.py`, `diagnostics.py`, `skip_crash_matrix.py` and
  `provider_tools_integration.py`).
- A disposable provider account with OAuth2 set up. Google: see
  [GOOGLE_OAUTH_SETUP.md](GOOGLE_OAUTH_SETUP.md). Microsoft 365: not written yet.
- OAuth2/XOAUTH2 is the preferred authentication method for both providers.

## 4. Configuration

Do not hand-write configs. Generate them (paths only, no secrets, mode 0600):

```sh
python3 scripts/provider_lab.py up --dir lab --roles destination        # provider is the SOURCE
python3 scripts/provider_lab.py up --dir lab --roles source             # provider is the DESTINATION
python3 scripts/provider_lab.py config --dir lab --direction gmail-to-dovecot \
    --provider-user DISPOSABLE@gmail.com --token-file access.token --state-dir state --out run.toml
```

`--direction` is one of `gmail-to-dovecot`, `dovecot-to-gmail`, `m365-to-dovecot`,
`dovecot-to-m365`. Run `imap_snapshot.py list` first and map folders using the exact
names it prints (modified UTF-7 for non-ASCII). Do **not** map both a Gmail label and
`[Gmail]/All Mail` unless duplication is the thing being tested.

## 5. Synthetic corpus

`provider_lab.py seed` loads a deterministic corpus into a Dovecot **source** and
writes `corpus-manifest.json` (SHA-256, size, flags, date per message). It covers: tiny
text; no Message-ID; non-ASCII headers and UTF-8 body; bare LF and a very long line;
8-bit content; nested `message/rfc822`; an inline image; a 1 MiB attachment; a
legitimate **duplicate pair** (identical bytes and Message-ID); a 1999 INTERNALDATE and
a negative-offset timezone; flag combinations including a custom keyword; and a
Unicode-named nested folder. `--include-large` adds 10 MiB and `--oversize-bytes N`
adds one message of that size, to probe provider limits. Everything is synthetic.

For the Dovecot-to-provider directions this corpus is the source. For the
provider-to-Dovecot directions the provider mailbox holds a few hand-made messages
first (Stage 1b); afterwards the corpus that Dovecot-to-Gmail placed in the provider
can be migrated back to a fresh Dovecot and compared with the manifest.

## 6. Staged plan

Each stage has a gate. Do not advance on a failed or unexplained gate.

**Stage 0, preparation (done).** Tooling built and rehearsed end to end against two
local Dovecot containers; no provider contacted.

**Stage 1a, first contact, no mail moved.** OAuth authorization, `imap_snapshot.py list`,
`inspect` and `migrate --dry-run` with diagnostics on. Gate: authenticates, lists the
expected folders, the destination advertises UIDPLUS (P3), TLS verifies with the system
trust store, the diagnostics file looks as expected.

**Stage 1b, a handful of messages.** 3 to 5 hand-made messages, one folder (Gmail to Dovecot first; the full corpus reaches Gmail via Dovecot to Gmail, which also allows a corpus round trip compared against `corpus-manifest.json`). Gate: `complete` true, exit
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
summary (`status`); the diagnostics file; the before/after snapshot comparisons; counts
of APPEND commands and reconnects; any `uncertain`, `rejected` or `skipped_by_operator`
entries with their code and scope; elapsed time. Remove addresses and mailbox names
before anything leaves the private directory.

### What the diagnostics file contains

One JSON line per event. **Recorded:** role (source/destination); operation class
(`list`, `examine`, `select`, `uid_search`, `uid_fetch`, `append`, `create`, `noop`);
tagged status (`OK`, `NO`, `BAD`, `BYE`, `IO`); the response-code name when IMAPLANE
knows it; for any other code, the validated atom (at most 32 characters of
`A-Z 0-9 -`, e.g. `ALERT`) in `unlisted_code`; the failure scope IMAPLANE assigned;
elapsed milliseconds; counts and byte sizes; whether APPENDUID was present; writable or
read-only; the system flags a mailbox advertises; capability names from a fixed list
(including `X-GM-EXT-1`), a count of the other capabilities, and `APPENDLIMIT` if
advertised.

**Never recorded:** passwords, tokens, usernames, folder names, message content or
headers, UIDs, or any free-form server text. A failure whose code has no usable atom
shows as `UNSPECIFIED`, which is itself informative.

## 8. Stop and clean-up

Stop immediately on: any `uncertain` entry that is not explained, any source change,
any credential or token appearing in output, an unexpected duplicate, or a provider
lockout/abuse warning. Then: do not rerun; preserve the journal and report; record
what was observed. Clean-up: revoke app passwords and tokens, delete the test
mailboxes or accounts, securely delete configs, journals and `*.bak` backups.

## 9. Remaining gaps and risks

1. **Raw server text stays invisible by design.** Diagnostics reveal status and code,
   not the wording. If a provider returns a `NO` with no code, only `UNSPECIFIED` is
   recorded; a manual `openssl s_client` session (CAPABILITY only) is the fallback.
2. **Ambiguous by design.** Provider-specific rejections, including bandwidth `[ALERT]`
   replies, are ambiguous and stop the run. Stage 3 decides whether a provider needs a
   narrower, evidence-based classification.
3. **Fixed 2-second idle probe threshold** is untested against real idle timeouts.
4. **Microsoft 365** OAuth setup guidance and the Microsoft token preset are untested.
5. **Gmail bandwidth and connection limits** are expectations (P9); a large corpus may
   hit them. Keep early runs tiny.
6. No arm64, no IMAP4rev2-only server, and no parallel transfers are in scope.

## 10. What needs the project owner

- The disposable accounts and OAuth clients (Google steps are in GOOGLE_OAUTH_SETUP.md).
- Explicit go-ahead for Stage 1a (first live contact) and again for each later stage.
