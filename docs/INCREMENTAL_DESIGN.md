# Incremental migration: architecture proposal

Status: **revision 2: approach A approved with conditions (section 4); phases in section 9 await approval. Nothing here is implemented.**
"Verified" = read in this repository at commit `a237dd1`. "Proposed" = new behaviour.

## 1. Goal

A later `migrate` run on an existing job finds source messages that arrived since the job was
planned and transfers only those, without a new job and without losing journal evidence, while
keeping: source immutability, exact verification, journal durability and recovery rules,
duplicate prevention, and compatibility with existing journals.

## 2. How it works today (verified)

| Fact | Where |
|---|---|
| The UID set of a folder is frozen once in `snapshots(folder PK, validity, uids JSON)`. Later runs reuse it; the code comment says "new arrivals need a new job". | `Journal::snapshot` |
| `transfers` is keyed `(folder, uid_validity, uid)`, with `UNIQUE(folder, destination_validity, destination_uid)`. | schema |
| Job identity (`binding`) is source and destination host/port/user **plus the whole folder mapping list**. Any change refuses the job. | `Config::binding`, `check_binding` |
| A changed source UIDVALIDITY is a hard error, before any write. | `Journal::snapshot`, `migrate` |
| A planned UID that no longer exists is reported `source_changed`, never counted as migrated. | `migrate` |
| **Every run reads back every previously transferred message** (`verify_record`) and compares hash, INTERNALDATE **and flags**. Any difference, or a missing UID, demotes `confirmed` to `accepted` and reports a failure. It never re-uploads, because the record keeps its destination identity. | `verify_record`, `matches_digest`, `invalidate` |
| `UIDNEXT` is required of the source and bounds the snapshot. It is **not stored**. | `SourceReader::snapshot` |

Two consequences drive the design:

1. Cost: a re-run costs a full destination read of everything ever migrated. Fine for resume, wrong for "run nightly".
2. Flags: once a person starts reading mail at the destination, `\Seen` and friends diverge from the journal. Today that is reported as a mismatch and the record is demoted. For a migration that is
   meant to be re-run while users are already switching over, this would make every incremental run fail loudly.

3. Size: the journal stores the SHA-256 of each body but **not its size** (`transfers` has no size column), so a cheap size check is impossible for existing records without new evidence (section 5.3).

## 3. Approaches compared

### A. Append-only discovery scans (approved)

Keep `snapshots` as the immutable "generation 0". Later discoveries are appended as scan rows. The
work list for a folder is `snapshots.uids ∪ every scans.uids`. Nothing existing is rewritten.

```
-- schema 5: additive tables only (CREATE TABLE IF NOT EXISTS); no ALTER, no existing row touched
scans(folder, validity, generation, observed_uidnext, uids JSON, scanned_at,
      PRIMARY KEY(folder, validity, generation))
job_folders(source PRIMARY KEY, destination, origin /*'binding'|'added'*/, added_at)
verification_events(folder, validity, uid, level /*'full'*/, result, size, observed_at, detail)
verification_runs(run_id, level, started_at, finished_at, checked, drift, problems)
```

**Discovery of one folder (source session, EXAMINE only).** Revised from revision 1: the boundary is
a consistent full UID inventory, not a range derived from `UIDNEXT`.

1. EXAMINE; require `UIDVALIDITY == V` (the value recorded in `snapshots`/`scans`/`transfers`).
2. Fetch the complete UID list with the existing `snapshot_uids` and check it with the existing
   `check_inventory` (`EXISTS` equals the list length), then EXAMINE again and require the same
   validity. A mismatch (a message arrived or was expunged mid-listing) is the existing
   `SnapshotChanged` retry, never a partial result. This is the same mechanism that already protects
   generation 0.
3. `new = listed − known`, where `known` is every UID in `snapshots`, `scans` and `transfers` for
   this folder and validity. Every UID in `new` must be below the `UIDNEXT` observed in step 1;
   otherwise refuse (anomaly).
4. `observed_uidnext` must be at least the highest earlier observed value (fail closed if it moved
   backwards). It is a sanity check, **not** the discovery boundary.
5. If `new` is empty: write nothing (the run is idempotent at the journal level).
6. Else one SQLite transaction (FULL sync) inserts the scan row (UIDs and `observed_uidnext` together).

Why not a `UIDNEXT` range (revision 1): if a server over-reports `UIDNEXT`, or makes a UID with a
lower number visible late, a watermark advanced past it would skip that message permanently. A
full listing diffed against durable known UIDs cannot skip anything that exists. The cost is one
UID-only listing per folder per run (about 1.5 MB per 100,000 messages, no bodies), which is
comparable to the destination existence check and acceptable for v0.1. A ranged fast path is a
later optimisation that would have to keep a periodic full diff.

Crash behaviour: before step 6 commits, nothing exists and the scan repeats. After it, the scan is
durable and the unchanged per-message sequence (plan, prepare, fence, append, acknowledge, verify)
takes over. `append_attempts`, uncertain handling, `recover`, `resolve`, `skip`, `unskip` are untouched.

Risks: relies on UIDs being unique and increasing inside one UIDVALIDITY (the same assumption the
existing journal key uses). A reused UID with different content is caught when it is planned
(`plan` already refuses a changed fingerprint for an existing key); for an already-confirmed UID the
source body is not re-read in incremental mode, so reuse there is undetected, which RFC 3501 forbids.

### B. Mutate the snapshot row in place

`UPDATE snapshots SET uids = uids ∪ new`. No new table.

- Pros: smallest diff.
- Cons: destroys the property that the plan is immutable evidence; no record of when or against which `UIDNEXT` a UID was discovered; a bug in the update silently changes history; harder to prove a crash cannot lose or duplicate UIDs; larger and larger JSON rewritten each run. Does not store `UIDNEXT`, so it still needs the `max+1` fallback forever.
- Verdict: rejected. The saving is a few lines; the loss is auditability.

### C. Stateless diff (no snapshot; list the source and subtract `transfers`)

Each run lists all source UIDs and processes those with no `transfers` row.

- Pros: no new tables, trivially "incremental".
- Cons: cannot distinguish "deleted before transfer" from "never seen"; cannot detect UIDNEXT regression; makes the plan depend on a moving source with no durable boundary, which contradicts the snapshot-before-any-write rule; a whole-folder listing every run; a UIDVALIDITY change would look like thousands of new messages (a mass duplicate risk).
- Verdict: rejected. It trades the safety boundary for convenience.

### D. Chain a new job to the old one

A new journal that references the old one.

- Cons: duplicate prevention would span two databases with no shared unique constraint, two locks, and split `uncertain` evidence. The existing `UNIQUE(folder, destination_validity, destination_uid)` and `PRIMARY KEY` guarantees are lost.
- Verdict: rejected; this is exactly the duplicate-prevention loss we must avoid.

**Recommendation: A.**


## 4. Approved decisions (your conditions, restated as requirements)

1. **Verification** is tiered; existence is never presented as content integrity; historical evidence
   and timestamps are preserved; flag differences are drift, not demotion; destination UIDVALIDITY
   change and UID reuse cannot create a false confirmation.
2. **Folders** can be added to a job; existing mappings and job identity stay immutable.
3. **Scan correctness**: atomic recording, no permanent skip after a crash, safe under concurrent
   arrival and expunge, UIDVALIDITY change fails closed, old evidence never rewritten, idempotent.
4. **Recovery** stays conservative: no automatic repair of missing destination messages, no replay
   of uncertain transfers, all existing crash and duplicate guarantees kept.
5. **CLI**: explicit `--incremental`; ordinary `migrate` behaves exactly as today.

## 5. Verification model

### 5.1 Three levels, named and reported separately

| Level | What it reads | What it proves | What it does **not** prove |
|---|---|---|---|
| **L0 existence** | destination UID list, plus destination UIDVALIDITY | the UID exists in the same UIDVALIDITY epoch the journal recorded | anything about content, size, date or flags |
| **L1 metadata** | `UID FETCH (RFC822.SIZE INTERNALDATE FLAGS)`, no body | size (when known) and INTERNALDATE equal the journal; flags compared as drift | the content hash |
| **L2 full** | body streamed through SHA-256 (existing `digest`) | hash, INTERNALDATE, and (at confirmation time) flags | nothing about later changes |

Rules that make a false confirmation impossible:

- **Only L2 can create or renew `confirmed`.** L0 and L1 never write `confirmed`; they write events and, on a real problem, demote. Code review rule plus a mutation test (section 8).
- Every check first selects the destination folder and requires its UIDVALIDITY to equal the
  `destination_validity` stored in the record. A UID is only meaningful together with its validity;
  inside one validity a UID is never reused, and `UNIQUE(folder, destination_validity, destination_uid)` already forbids two records claiming one destination message.
- Reports never say "verified" without the level: `existence_checked`, `metadata_checked`, `fully_verified`, each with the time of the last such check.

### 5.2 What each run does (default `--incremental`)

| Records | Check |
|---|---|
| new messages | transfer with the full existing sequence, ending in L2, exactly as today |
| `accepted` or demoted (never or no longer confirmed) | L2 (they are unfinished, few) |
| `uncertain` | existing `reconcile`, unchanged |
| `confirmed` | L0, then L1 (default `--verify-history metadata`); `existence` or `full` selectable |

`verify` (the existing command, L2 over everything) stays the way to prove content; its default does not change. `--verify-history full` makes an incremental run do L2 on history too.

### 5.3 Evidence and timestamps (append-only)

- The journal has no size or verification time for existing records. **None is invented.** A legacy
  `confirmed` record is reported as "confirmed, no recorded verification time (before schema 5)".
- At schema 5, an L2 pass (transfer confirmation, `verify`, or `--verify-history full`) appends a
  `verification_events` row holding `observed_at`, the observed size and the result. That is also how
  size becomes known for old records: the first L2 pass backfills it as an event, never as an edit.
- L1 compares size only when a prior event recorded one; otherwise it compares INTERNALDATE only and
  says "size unknown". It never claims more than it checked.
- L0/L1 results are summarised in `verification_runs` (counts and times) and written per message only
  when something is wrong, so a nightly run does not add one row per message per night.
- The write that adds the size event for a new transfer happens inside the existing confirm
  transaction (no extra fsync); crash tests cover it.

### 5.4 Outcomes: drift versus demotion

| Observation | Outcome |
|---|---|
| flags differ from the journal (L1 or L2, record already `confirmed`) | **drift**: counted and listed in the report, no state change, no event per message |
| hash mismatch (L2) | real integrity problem: demote `confirmed` to `accepted`, event, exit 2 |
| INTERNALDATE mismatch, or size mismatch when size is known | same |
| destination UID missing | real problem: demote to `accepted`, event, exit 2, **no upload** |
| destination UIDVALIDITY differs from the record | identity unknown: **fail closed before any write**; no per-record demotion, because no per-record claim can be made; event |
| flags differ on a record that is not yet `confirmed` | must match before confirmation, as today |

Demotion never deletes anything: the event table keeps what was true and when. A demoted record
stays visible every run (L2 each time) until an operator acts; automatic repair is out of scope (section 7).

## 6. Folders

- **Immutability.** `job_folders` is seeded at the schema-5 upgrade from the stored binding (origin `binding`) and is the authority afterwards. A mapping (source to destination) can never change or be deleted. The endpoint part of the binding (hosts, ports, users) is still checked exactly; the historical `binding` row is never rewritten.
- **Config must contain every recorded mapping, identically.** A config that drops a recorded folder, or remaps one, is refused (this resolves a contradiction in revision 1, which allowed removal). A deliberate remap needs a new job in v0.1.
- **Adding.** Under `--incremental`, a config folder unknown to the job is refused with its name unless `--add-new-folders` is also given. This stops a typo from becoming a permanent mapping, and `--dry-run --incremental --add-new-folders` shows what would be added.
- **How a new folder joins the durable plan.** One transaction inserts the `job_folders` row (origin `added`, time) and the folder's first scan (generation 1, full listing, same checks as section 3A). Crash before commit: nothing; after: durable and resumable. From then on it is planned like any folder.
- **Ordinary `migrate`** requires the config folder set to equal `job_folders` exactly (today's behaviour), finishes already-committed scans (so a crash after a scan can be resumed by either command) and never discovers.
- Destination folders stay one-to-one with sources, checked against the stored set including the new entry.

## 7. Recovery

- No new transfer state. No automatic repair or replay; no change to the fence or `append_attempts`.
- **New rule, only under `--incremental`:** a folder with an unresolved `uncertain` record gets no new transfers (`blocked_by_uncertain`, exit 2); other folders proceed. Reason: each additional append lands above the uncertain record's baseline and adds reconciliation candidates (cap 1000), so repeated nightly runs could turn a resolvable case into an unresolvable one. Ordinary `migrate` keeps today's behaviour. (Decision D2.)
- A destination message found missing or changed is reported and demoted, never re-uploaded, because deletion by a user, a move and loss cannot be told apart and a re-upload could duplicate.
- Concurrent processes are excluded by the existing `job.lock`.
- Source deleted after transfer: ignored. Source deleted before transfer: `source_changed`, not counted as migrated.
- Source UIDVALIDITY change: all folders' validity is checked **before any scan or write**; any change refuses the whole run, naming the folder, with no remap and no discarded evidence. v0.1 procedure: a new job into a fresh destination folder.

## 8. Contradictions found and how they are resolved

| # | Contradiction or gap | Resolution |
|---|---|---|
| C1 | Revision 1 allowed removing a folder from the config; that conflicts with immutable mappings and with a well-defined "complete". | Removal refused in v0.1; config must contain every recorded mapping. |
| C2 | Revision 1 compared sizes, but the journal has no size. | Size becomes known only through append-only L2 events; L1 says "size unknown" otherwise. |
| C3 | Revision 1's `UIDNEXT` watermark could skip messages if a server over-reports it or exposes a lower UID late. | Boundary is a consistent full inventory diffed against durable known UIDs; `UIDNEXT` is a regression check only. |
| C4 | "Never demote on drift" versus today's `verify`/`migrate`, which fail on any flag difference. | Drift rule applies to already-confirmed records in incremental mode. Decision D1 asks whether ordinary `verify`/`migrate` should adopt it too. |
| C5 | A destination UIDVALIDITY change used to demote record by record. | Incremental fails closed before writes without demoting; evidence is kept. |
| C6 | Ordinary `migrate` on a schema-5 job with committed scans. | It resumes them, never discovers; a crash between a scan and the first transfer is resumable by either command. |
| C7 | Auto-upgrade to schema 5 would change journals of users who never use `--incremental`. | Upgrade (with the existing pre-upgrade backup) happens only on the first `--incremental` run; schema 4 jobs are untouched otherwise. |
| C8 | Repeated runs and the 1000-candidate cap with an outstanding uncertain record. | `blocked_by_uncertain` (D2). |
| C9 | Typos creating permanent mappings. | `--add-new-folders` plus dry-run preview. |
| C10 | `status`, `verify`, report and tests assume one snapshot row per folder. | All read the unified work list `snapshots ∪ scans`; report version bumped additively. |
| C11 | A source UID reused inside one validity with a confirmed record is undetectable without re-reading the source. | Accepted and documented (protocol violation); planning of any unconfirmed UID still checks its fingerprint. |

No contradiction remains with the 12 safety invariants as I read them; D1 and D2 are policy
choices, not conflicts.

## 9. Implementation phases (each ends with a report and waits for your approval)

**Phase I0: schema 5 groundwork, no behaviour change.**
Add the four tables; upgrade only on first `--incremental`; seed `job_folders`; unified work-list reader; ordinary commands read it.
Tests: schema 4 to 5 upgrade with backup, interrupted upgrade (the existing 3 to 4 crash pattern), old-binary refusal, `status` on 4 and 5, unchanged behaviour of the full existing suites and both crash matrices in normal and forced-spool modes, byte-for-byte schema-4 journal untouched by ordinary runs.

**Phase I1: discovery scan and transfer of new messages (existing verification semantics).**
`--incremental` for existing folders, with the scan of section 3A and the all-folders-first validity check; history verified exactly as today (slow but identical), so this phase changes only discovery.
Tests: scan crash matrix (new fault points before/after the scan commit, SIGKILL in each folder), idempotence (second run writes nothing), `UIDNEXT` regression, out-of-range and unsorted lists, UID reuse, arrival and expunge during the listing (fixture hooks), late-visible lower UID, validity change fail closed, dry-run writes nothing, source only receives read verbs, streaming and forced-spool variants.

**Phase I2: tiered verification and drift.**
L0/L1 fetches, `verification_events`/`verification_runs`, size backfill, drift reporting, destination validity guard, outcome table 5.4, `--verify-history`.
Tests: one fixture per row of 5.4; property test that no L0/L1 path can write `confirmed` plus a mutation check that fails when one does; destination UIDVALIDITY change and UID-reuse fixtures; legacy record with unknown size; crash in the event write; benchmark proving no body is read on the default path and cost scales with count.

**Phase I3: adding folders.**
`--add-new-folders`, `job_folders` authority, remap/removal refusals, atomic add plus first scan, ordinary-migrate exact-match rule.
Tests: add, typo refusal, remap refused, removal refused, crash at the addition, ordinary migrate resumes an added folder, destination collisions.

**Phase I4: uncertain interplay, reports, docs, soak.**
`blocked_by_uncertain`, report and `status` fields, README/CHANGELOG/operator guide entries, randomized SIGKILL stress extended with arrivals between runs in all three modes (the Phase 5A harness and its eight invariants plus "no UID skipped, none planned twice"), full regression and crash matrices in normal and forced-spool modes.

Every phase: small commits, new tests first and shown to fail without the change, full relevant regression before the report, nothing pushed, no provider contact, streaming default unchanged.

## 10. Decisions still open

- **D1.** Should ordinary `verify` and `migrate` also treat flag-only differences on already-confirmed records as drift? Recommended yes, in Phase I2, with a CHANGELOG entry, so one record is never judged two ways. Default if you do not decide: ordinary commands unchanged.
- **D2.** Approve `blocked_by_uncertain` for incremental runs (recommended).
- **D3.** Approve the full UID listing per folder per run (about 1.5 MB per 100,000 messages) instead of a ranged fast path for v0.1 (recommended).

## 11. Phase I0 status (implemented, awaiting approval to start I1)

Implemented: `Journal::upgrade_to_v5` (explicit, one transaction, backup first, seeds `job_folders` from
the binding, refuses unsound bindings and foreign evidence before touching anything), the four schema-5
tables with append-only/immutable triggers, `work_list()` (snapshot plus scans, used by `migrate` and
`verify`), schema 5 accepted by every ordinary open, and the schema-5 mapping check in `check_binding`.
Ordinary opens never upgrade to schema 5, and nothing in the CLI calls the upgrade yet (I1 will, on the
first `--incremental` run); `tests/support/upgrade_v5.rs` is a test-only helper. Obligation carried into
I1/I3: `Journal::snapshot` must not create a generation-0 snapshot for a folder that exists only as scans.
`docs/benchmarks/phase-i0-stress-raw.txt` is the unedited stress output of the final I0 regression.

## 12. Phase I1 status (implemented and approved)

Implemented: `migrate --incremental` (and `--incremental --dry-run`). Order of a real run: open the
existing job (never creates one, binding/mappings checked) then a read-only plan for every folder (complete,
inventory-checked UID listing; source UIDVALIDITY compared with the recorded plan; `UIDNEXT` sanity;
destination UIDVALIDITY compared with every recorded transfer epoch), then upgrade to schema 5 if needed,
then one atomic scan per folder with new UIDs, then the unchanged transfer sequence over the extended
plan. A refusal at any earlier step has written nothing. Folders with an unresolved `uncertain` transfer get
`blocked_by_uncertain` entries and no APPEND; other folders continue. `Journal::snapshot` refuses to create
an original snapshot for a folder that has scans. Fault points: `scan_listed`, `scan_before_commit`,
`scan_after_commit` (plus the I0 upgrade points). History is still verified exactly as before (I2 changes that).
Known limits carried forward: adding folders (I3); verification tiers and flag drift (I2); the
UID-reuse case for already-confirmed UIDs (C11).


## 13. Phase I2 status (implemented and approved)

Implemented as designed in sections 5.1-5.4, with these precise choices.

**Levels and defaults.** `migrate --incremental [--verify-history existence|metadata|full]`, default
`metadata`; the flag is refused without `--incremental`. `verify` and ordinary `migrate` stay full (L2)
over everything and have no lighter mode, so an explicit full request is never substituted. In an
incremental run: new messages use the unchanged transfer sequence ending in L2; records that are not
`confirmed` (accepted, or demoted earlier) get L2; `uncertain` uses the unchanged `reconcile`; `confirmed`
records get L0 or L1 in a pre-pass per folder, then the transfer loop skips them. `full` sends them through
the same L2 path as `verify`.

**What L0 and L1 read.** L0: one UID listing of the destination folder. L1: `UID FETCH <set> (UID FLAGS
INTERNALDATE RFC822.SIZE)` in batches of 500 UIDs; no body is read. An unreturned UID is absent (missing); a
UID returned only partially (for example an unsolicited flag update) is an error, never "missing".

**Evidence (append-only, schema 5).**
- `verification_events` rows: every successful confirmation (`full`/`ok`, with the observed size, written in the
  same transaction as the state change), every renewal by a full check of an already-confirmed record
  (`full`/`ok`, buffered and written in batches of 256 and on exit; losing them in a crash loses evidence only),
  and every problem at any level (written in the same transaction as the demotion). The table's level CHECK
  now allows `existence`, `metadata`, `full` (the I0 DDL allowed only `full`; schema 5 is unreleased, and a
  journal made by a pre-release build is refused with a clear message rather than treated as evidence-free).
- `verification_runs`: one row per folder per lightweight pass (level, times, checked, drift, problems).
- Drift writes no per-message row. A metadata or existence pass never writes a `full` event, never writes
  `confirmed`, and only ever demotes. `Journal::confirm_verified` is the single place that sets `confirmed`.
- Size is known only from a prior full check. L1 compares it only when known and otherwise reports
  `size_unknown` in the summary. Times: a message with no recorded full verification reports
  `last_full_verification: "unknown (no recorded full verification before schema 5)"`.

**Outcomes (table 5.4 as built).** Flag-only difference on a `confirmed` record: `drift` entry, no state
change (L1 and L2, and now also ordinary `verify` and `migrate`: decision D1 applied everywhere). Flag
difference on a record that is not yet confirmed: `mismatch`, no confirmation. Hash, INTERNALDATE or known-size
mismatch, or missing destination UID: record demoted to `accepted`, event, exit 2, never re-uploaded; the next
run re-judges it with a full check (so a lightweight false alarm heals itself, a real problem repeats).
Destination UIDVALIDITY change: incremental runs refuse before any write (I1); `verify` and ordinary
`migrate` keep their existing `destination_changed` demotion. `drift` does not make a run `complete=false`;
every other non-`confirmed` entry does.

**Behavioural differences to know about.**
1. `verify`/`migrate` used to demote a confirmed record on a flag change and exit 2; they now report drift and
   exit 0. This is the D1 decision.
2. A repeat incremental run is no longer byte-identical in the journal: it appends one `verification_runs` row
   per folder. Transfers, scans, snapshots, mappings and events are unchanged.
3. Incremental reports no longer list one `confirmed` entry per historical message; they carry a
   `history_check` summary. Reports of ordinary commands are unchanged except for the `drift` result.
4. `existence` and `metadata` cannot detect same-length content corruption; only `full` and `verify` can.

**Ordinary migrate versus incremental with an uncertain folder (item 12; no recovery rule changed).**

| | ordinary `migrate` | `migrate --incremental` |
|---|---|---|
| the uncertain record | `reconcile` reports candidates; never replayed | identical |
| other planned messages in the same folder | still appended | `blocked_by_uncertain`, no APPEND (D2) |
| other folders | continue | continue |
| a new uncertain transfer mid-run | run ends | run ends |

Ordinary `migrate` is deliberately unchanged because changing it would change recovery behaviour that this
phase was told not to touch; the asymmetry is documented in the README. Whether ordinary `migrate` should also
block is a separate decision for you.

Fault points added: `before_history_fetch`, `before_history_demote`, `history_run_before_commit`,
`history_run_after_commit`, `evidence_before_commit`, `evidence_after_commit` (and the existing
`before_invalidate`/`after_invalidate`, now around the atomic demotion).


## 14. Phase I3 status (implemented, awaiting approval to start I4)

Implemented as designed in section 6, with these precise choices and two refinements to the approved design.

**Command.** `migrate --incremental --add-new-folders [--dry-run]`; clap refuses the flag without
`--incremental`. Every command (ordinary migrate and verify included) refuses a configuration that lists a
folder the job does not record, naming it and the flag, before touching anything.

**Binding check (`Journal::check_binding_mode`).** The account part of the binding is compared exactly.
Every recorded mapping (schema 5: `job_folders`; schema 4: the binding) must appear in the configuration with
the same source and destination, compared exactly (no INBOX alias spelling): a missing or renamed folder is a
removal, a different destination is a remap, a new source that reuses a recorded destination is a conflict;
all are refused whatever the flag. Unrecorded configured folders are refused without the flag and returned
with it. A schema-4 journal checked without the flag is still compared byte for byte (an additional hint is
given if only folders were added). Order of folders in the configuration no longer matters on schema 5.

**Order of a real run.** open the job (never creates) -> read-only planning of existing folders (unchanged)
-> read-only planning of each new folder (a consistent, inventory-checked source listing, retried on
inconsistency; destination folder existence) -> upgrade to schema 5 if needed -> `add_folder` per new folder
-> scans of existing folders -> the unchanged transfer loop. A failure before the upgrade has written nothing.

**Atomic addition (`Journal::add_folder`).** One transaction inserts the `job_folders` row (origin `added`) and
the folder's first scan (generation 1 = the baseline: UIDVALIDITY, UIDNEXT, the listed UIDs, possibly none).
Refused, changing nothing, if the source or destination is already recorded (INBOX aliases included), if any
snapshot, scan or transfer evidence exists for the folder, or if the baseline is malformed.

**Refinement 1 (baseline is a scan, not a snapshot).** Section 6 says the folder's "first scan" is its baseline.
Built that way: an added folder never has an original snapshot (`snapshot()` still refuses to create one),
`work_list` already extends snapshots with scans, and `record_scan` now accepts a folder whose plan begins
with its generation-1 scan. An empty baseline is allowed only here, so an empty folder still fixes its UIDVALIDITY.

**Refinement 2 (ordinary migrate).** Ordinary `migrate` skips the snapshot step for scan-only folders
(`is_scan_only`), so it finishes an addition that crashed before the transfers but never discovers or re-plans
anything. `verify` needed no change (it reads `work_list`).

**Safety carried over.** UIDVALIDITY: the baseline records the source epoch; every later run compares it
(`plan_discovery`) and the destination epochs of recorded transfers, refusing before any write. A new folder has
no destination epoch until its first APPENDUID, which must equal the epoch selected for that APPEND (existing
guard). Uncertain blocking is per folder and unchanged. Dry run opens the journal read-only. Fault points:
`folder_add_before_commit`, `folder_add_after_commit` (plus `scan_listed` and the upgrade points).

**Not changed / limits.** No removal, renaming or remapping in v0.1 (new job instead). An existing destination
folder is allowed (reported), because ordinary migrate already allows it; its pre-existing mail is never
attributed. A folder added while another folder has an uncertain transfer is added and copied; the uncertain
folder stays blocked.

## 15. Follow-up concerns recorded for Phase I4 (from the I2 review)

1. **Reports must distinguish metadata from full verification everywhere.** The incremental JSON has
   `history_check` (level, counts, scope text), per-entry `level` and `last_full_verification`, and the text
   output prints the level. Still to do in I4: make the text report and `status` say plainly, in one line, which
   level the run used and how many messages were proven by a full read-back in this run (versus only checked);
   consider an explicit `fully_verified_this_run` count and a `complete` wording that cannot be read as "all
   content was re-verified"; show the oldest `last_full_verification` per folder in `status`; document the
   fields in a reference page.
2. **Compatibility with schema-5 journals made by earlier development builds.** I0 and I1 builds created
   `verification_events` with `level IN ('full')`. Today such a journal is refused (clear error) the first time
   evidence is needed. I4 must decide: (a) keep refusing (schema 5 is unreleased, no such journals outside
   development), (b) a one-time, backed-up, transactional rebuild of the table copying its rows, or (c) a
   schema 6. Recommendation: (a) for v0.1 and say so in the changelog, unless a real journal exists. Also test
   `status`, `verify`, ordinary `migrate` and the dry run against such a file (they must not crash).
3. **Consistent uncertain-folder behaviour across ordinary and incremental migration.** Ordinary `migrate`
   keeps appending a folder's other planned messages after reporting an uncertain one; `--incremental` blocks
   them (decision D2). Evaluate for I4 whether ordinary `migrate` should also block (same candidate-growth
   reason), the effect on a user resuming an interrupted first copy, and whether the block should become the
   default with an explicit override. This changes recovery behaviour, so it needs your approval first.
