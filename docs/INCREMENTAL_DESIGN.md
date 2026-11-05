# Incremental migration: architecture proposal

Status: **proposal for approval. Nothing here is implemented.**
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

## 3. Approaches compared

### A. Append-only discovery scans (recommended)

Keep `snapshots` as the immutable "generation 0". Add a table of later scans. The work list for a
folder is `snapshots.uids ∪ every scan.uids`. Each scan records the `UIDNEXT` it covered, which
becomes the next lower bound.

```
-- schema 5, additive only (CREATE TABLE IF NOT EXISTS; no existing row is rewritten)
scans(folder TEXT, validity INTEGER, generation INTEGER, from_uid INTEGER, uidnext INTEGER,
      uids TEXT /*JSON*/, scanned_at TEXT, PRIMARY KEY(folder, validity, generation))
job_folders(source TEXT PRIMARY KEY, destination TEXT NOT NULL, added_at TEXT)   -- see section 5
```

Discovery for one folder, in one source session (EXAMINE only):

1. `H` = lower bound = highest `scans.uidnext` for the folder, else `max(snapshot uids) + 1` (1 if the snapshot is empty). The fallback is safe for legacy jobs: UIDs are strictly increasing inside one UIDVALIDITY, and the original snapshot covered everything below its `UIDNEXT`, so no unseen message can have a UID at or below the snapshot maximum.
2. EXAMINE: require `UIDVALIDITY == V` and `UIDNEXT >= H`. A smaller `UIDNEXT` is a protocol violation: refuse, change nothing.
3. If `UIDNEXT == H`: nothing new.
4. `UID FETCH H:UIDNEXT-1 (UID)`. Require every UID inside the range and strictly increasing (the full-folder `EXISTS` equality used for the first snapshot cannot be used on a range).
5. EXAMINE again: same validity, `UIDNEXT` not smaller.
6. One SQLite transaction (FULL sync): insert the scan row. Skip any UID already present in `transfers`; if the server reused one, that is reported as an anomaly instead of being replanned.

Crash behaviour: before step 6 commits nothing exists, so the scan simply repeats. After it commits, the scan is durable and the existing per-message sequence (prepare, fence, append, acknowledge, verify) takes over unchanged. The fence, `append_attempts`, uncertain handling, `recover`, `resolve`, `skip` and `unskip` are untouched.

- Schema: two new tables, upgrade follows the existing pattern (backup first, additive, `user_version` 5). Old binaries refuse schema 5 cleanly; a schema-4 journal is never modified until the first incremental run.
- Cost: one extra `UID FETCH` of the new range per folder. Cheap.
- Risks: the `UIDNEXT` contract (mitigated by the checks in steps 2, 4, 5); servers that return a non-monotonic `UIDNEXT` are refused rather than tolerated.

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

## 4. Re-verification policy (needs your decision)

This is the main semantic question, and it applies to every approach.

Proposed: separate what is *immutable* from what is *mutable by users*.

| Property | At transfer time | On a later incremental run |
|---|---|---|
| Content SHA-256, size | exact, mandatory (unchanged) | checked by `verify` and `migrate --reverify` |
| INTERNALDATE | exact, mandatory (unchanged) | same as content |
| Flags | exact, mandatory (unchanged) | **informational drift**, not failure |
| Destination UID still present | n/a | checked by default (one `UID FETCH 1:* (UID)` per folder, cheap) |

Concretely:

- Default incremental run: discover new messages, transfer them (full exactness), and for old records do only the cheap presence check plus destination UIDVALIDITY check. It does **not** re-read every body.
- `migrate --reverify` and the existing `verify` command: full read-back of everything. Hash or date difference demotes to `accepted` exactly as today. A flags-only difference is reported as `flags_drifted` and does **not** demote.
- Whether this changes the meaning of `confirmed`: it stays "exact at the time of confirmation". The report states the time of the last full read-back.

The alternative (keep the current behaviour: full read-back and flag-exactness on every run) is
safest but makes a large mailbox slow to re-run and makes flag changes at the destination look like
corruption. I recommend the split above but will not change it without your approval.

## 5. Specific situations

**New source messages.** Section 3A. Planned in arrival (UID) order after the existing ones.

**Deleted source messages.**
- Before transfer: unchanged, reported `source_changed`, never counted as migrated.
- After transfer: ignored. IMAPLANE does not delete or sync deletions (out of scope). Optionally later, `source_gone` could be derived from the same cheap UID listing; not v0.1.

**UIDVALIDITY change.** Still refused, for the whole run, before any write; no automatic remap. The
error names the folder. The documented operator procedure for v0.1 is a new job into a fresh
destination folder. A later `rebase-validity` command could match the new UIDs to old records by
content fingerprint, but that requires reading source bodies and a design of its own; not proposed
now. Per-folder isolation (other folders continue) is a possible follow-up; it is not needed for
safety, so v0.1 keeps the simpler, stricter behaviour.

**New folders.** Today any change to the folder list changes the binding and refuses the job.
Proposed: `binding` keeps only the endpoints identity; the folder set lives in `job_folders`.
- Adding a new `[[folders]]` entry: allowed, recorded with a timestamp, planned by a generation-0
  style scan on first use (or as a scan with `from_uid = 1`).
- Changing the destination of an existing source folder: refused.
- Removing a folder from the config: allowed; its records are kept; the run reports it as not
  processed this time, never as complete. The job is `complete` only when every recorded folder is
  accounted for.
- Compatibility: for an old journal the stored `binding` JSON is parsed; endpoints must equal, and
  the old folder list must be a subset of the new one with identical mappings. `job_folders` is
  seeded from it at the schema-5 upgrade.

**Metadata (flags).** Frozen when the message is first prepared (already tested:
`combined_preparation_freezes_metadata_and_never_resets_uncertainty`). Source flag changes after
transfer are not propagated and not reported. Destination flag changes are drift (section 4). No
flag synchronisation in either direction in v0.1.

**Destination message missing or changed.** Never repaired automatically.
- Missing UID or destination UIDVALIDITY changed: report `missing` / `destination_changed`, demote to
  `accepted`, no upload. We cannot tell a user's deletion or a move from loss, and re-uploading
  could create the duplicate we promise to prevent.
- Content or date mismatch: report `mismatch`, same treatment.
- Recovery is explicit and operator-driven, with a new audited command if you want one
  (`reset-missing`, requiring a reason and the record's evidence). Not proposed for the first
  increment.

## 6. Recovery and compatibility semantics

- All existing states and transitions are unchanged; incremental adds one place where rows appear
  (the scan) and no new transfer state.
- `status` on schema 4 stays read-only and keeps working; schema 5 is created only by a run that
  needs it, after the existing pre-upgrade backup.
- A schema-4 job that never runs incrementally is byte-for-byte unchanged in behaviour.
- A scan is atomic; a killed scan repeats. A killed transfer follows the existing matrices.
- The run report gains: new messages discovered per folder, scan generation, last full read-back
  time, drift counts. Report version bump, additive.
- New CLI surface (one choice, your call): a flag `migrate --incremental`, or make it the default
  once a job is complete. Proposed: **explicit `--incremental`** for v0.1 so existing scripts keep
  today's exact behaviour.

## 7. Test plan (before enabling)

1. Scan crash matrix: SIGKILL before and after the scan commit, in each folder, with new messages
   arriving between runs. Invariants: no duplicate, no missed UID, no change to existing rows.
2. Randomised stress (the Phase 5A harness) extended with arrivals between runs, in all three modes.
3. Server-misbehaviour fixtures: `UIDNEXT` decreasing, UID reuse, out-of-range or unsorted UID
   list, validity change between scan and transfer, expunge during scan.
4. Schema upgrade 4 to 5 with backup, old-binary refusal, and legacy-job fallback bound.
5. Re-verification policy: flags-only drift does not demote; hash or date mismatch does; missing UID
   does; presence check scales (benchmark with 10^5 messages, no body reads).
6. Folder-set changes: add, remove, remap refused, complete-only-when-all-accounted.
7. Source immutability: only read verbs ever reach the source (existing harness check).

## 8. Decisions requested

1. Approve approach A (append-only scans) over B, C and D.
2. Approve the re-verification split in section 4 (flags drift is informational; presence check by
   default; full read-back on request).
3. Approve additive folders via `job_folders` and an endpoint-only binding.
4. Keep UIDVALIDITY changes a whole-run refusal for v0.1.
5. Keep destination repair out of the first increment.
6. Explicit `--incremental` flag rather than a changed default.
