# Gmail duplicate merging: revised design (for review, nothing implemented)

> **Updated 2026-11-07 after experiments E0-E7 (sections 10-12).** The experiments disproved the assumption in sections 1-3 that
> Gmail merges on Message-ID alone, and changed the recommended policy. Where sections 1-8 conflict with 10-12, 10-12 win.

Status: **design only.** No production code changed, nothing written to Gmail for this document. It replaces the
first proposal (a new "held" state). Written for the project owner, who decides what gets built.

## 1. Evidence and hypotheses

Everything below is labelled **CONFIRMED** (observed on the live Gmail test account, 2026-11-07, read-only diagnostics),
**HYPOTHESIS** (plausible, not observed) or **UNKNOWN**.

### The one confirmed behavior (case 1 below)
Two source messages with byte-identical content (so the same Message-ID), appended to the same label one after the
other, gave:

* one message in All Mail (one X-GM-MSGID, one All Mail UID; the second APPEND created no new All Mail entry);
* in the label: the first copy's UID vanished without notice, the second APPEND got a new UID, **the flags became those
  of the second APPEND** (the first copy's `\Answered \Seen` were lost), **INTERNALDATE stayed the first copy's**,
  the message's modseq was bumped;
* both APPENDs returned a normal `APPENDUID` (different UIDs), so the response does not reveal the merge.

### Not confirmed
| # | Question | Status |
| --- | --- | --- |
| H1 | Same Message-ID, **different** bodies, same label: is the second body kept, discarded, or stored as a separate message? | UNKNOWN. A silently discarded body would be the worst outcome. |
| H2 | Is the key the Message-ID alone, or more (headers, size, date, sender)? | UNKNOWN |
| H3 | Same message appended to a **different** label: does Gmail add the label to the existing message (the Gmail model) and reset its flags? | HYPOTHESIS (consistent with "flags are per message, not per label") |
| H4 | Is a message found in Trash or Spam also merged with a new APPEND? Does an All Mail search see it? | UNKNOWN |
| H5 | Message-ID normalization (case, angle brackets, whitespace), and what happens with a missing Message-ID | UNKNOWN |
| H6 | Does `X-GM-RAW "rfc822msgid:..."` find a message immediately after the APPEND that created it? | HYPOTHESIS (it worked minutes later) |
| H7 | Does the key survive the original being deleted? | UNKNOWN |

Design rule: **anything not CONFIRMED is treated as risky and held**, never assumed harmless; the policy relaxes only
after a documented experiment confirms a behavior.

## 2. The three cases

1. **Byte-identical source messages** (same bytes, same Message-ID). Confirmed to merge. Exact copies are impossible on
   Gmail: the destination can hold one message. What must not happen is the *silent* damage: losing the first copy's
   flags and UID. Goal: copy one, do **not** touch it again, report the rest explicitly.
2. **Different bodies, same Message-ID.** Unknown (H1, H2). Treated as risky: a later APPEND could discard its body or
   change an existing message. Goal: never APPEND into a known collision; report it.
3. **Duplicates across labels** (the same message in two source folders, or a source message that already exists in
   the Gmail account, for example in Inbox or Sent from earlier mail). Hypothesis H3: Gmail would add a label to the one
   existing message and overwrite its flags. For a pre-existing Gmail message this means *modifying existing mail*, which
   conflicts with "existing destination mail is retained". Goal: detect before APPEND; hold.

## 3. Detection before APPEND (read-only, Gmail destinations only)

Applies only when the destination advertises `X-GM-EXT-1` (seen before and after login). Other servers: no change.

Where it runs: **after the body is read and before the `prepare` commit**, on the message about to be appended. It
only reads (journal and destination). It adds **no durable commit, does not move the pre-literal fence, and does not
change the four commit boundaries.**

Inputs and checks, in order of cost:

1. **Journal (free).** Another transfer to the same destination account with the same content fingerprint (SHA-256, already
   stored) in state `accepted`, `confirmed` or `uncertain`. This catches case 1 inside a job, including across labels,
   with no network.
2. **Destination search (one read per message, batched later).** Parse the Message-ID from the body in hand (first
   `Message-ID` header, unfolded, angle-addr). Search the destination account with `X-GM-RAW "rfc822msgid:<id>"` in `[Gmail]/All Mail`
   (identified by the `\All` special-use, not by name, to survive localization), and also in Trash and Spam
   (`\Trash`, `\Junk`) because All Mail excludes them (H4). A hit means an APPEND would merge into an existing message:
   pre-existing mail, a message from an earlier job, or one in another label (cases 2 and 3 as well as case 1).
   For each hit read X-GM-MSGID, X-GM-LABELS, RFC822.SIZE and, when within the size cap, a SHA-256 of the body
   (`BODY.PEEK` only), to say *identical content* versus *different content*.
3. **No Message-ID, or a search that fails or is unavailable:** the message cannot be proven safe. Policy for the first
   release: **hold** (conservative), with a clear reason; revisited after experiment E5.

Outcomes:

| Finding | Class | Action |
| --- | --- | --- |
| No hit in the journal or the destination | clear | APPEND as today |
| Identical content, already delivered by this job (case 1) | `provider_duplicate_same_content` | do not APPEND |
| Identical content already in the account but not from this job, any label (cases 3) | `provider_existing_same_content` | do not APPEND |
| Same Message-ID, different content (case 2) | `provider_message_id_collision` | do not APPEND |
| Search impossible or no Message-ID | `provider_dedup_unverifiable` | do not APPEND |

"Do not APPEND" means the message stays `planned` and is reported with a result and reason. It is **not** counted as
migrated, and completeness stays false (exit 2), exactly like today's rejected messages.

## 4. Representing a hold without a new journal state

* **No new transfer state.** A held message stays `planned` with no destination attribution, as a message rejected
  by the server does today.
* **Evidence**: one row in the existing `append_rejections` table, written in a single transaction (new journal
  function; **no schema change**), with an evidence string that says plainly it is a client-side check, e.g.
  `client-side pre-APPEND check [PROVIDER_DUPLICATE_SAME_CONTENT] scope=message; sibling source UID 3; destination labels ...`.
  It must never claim a server response. (Today the evidence reads "matching tagged NO ...".) Folder and label names
  already appear in the journal and are equally sensitive; no message text is stored.
* **Report**: result `rejected` (existing vocabulary, so consumers and exit codes are unchanged) plus an additive
  field `rejection_code` / `classification`, and a counter in the `verification` block. Rerun re-evaluates the hold,
  as it already re-evaluates rejected messages.
* **Why not a new state or a prepare-then-reject cycle:** prepare would put the message in `uncertain` with an
  `append_attempts` row for something never sent, adding operator work (`recover`) after a crash. A hold needs neither.
  A crash before the evidence commit leaves nothing; after it, only the evidence row.

## 5. Operator decisions, incomplete jobs, recovery

* **Skip.** `skip` already requires a planned, unattributed transfer with a durable rejection row; it records the reason
  and the evidence in `operator_skip_events`. A hold qualifies unchanged, so **`skip` needs no code change**, and `unskip`
  returns the message to the normal path (where the check will hold it again if the risk is still there). The job then
  reports `skipped_by_operator`, `complete` stays false while the skip stands: same as every skip today. A mailbox with
  Gmail duplicates therefore never reports plain "complete"; it reports "complete except N operator-skipped duplicates",
  which is honest.
* **There is no force-append for a hold.** Consistent with "no force-retry". If experiments later show a case is
  harmless, the policy changes in code (and docs), not through an override flag.
* **Crash in the middle of an APPEND (existing behavior).** Unchanged: the message is `uncertain`; `recover` or `resolve`
  as today. Two interactions to note: a later duplicate whose sibling is `uncertain` is held ("sibling uncertain"),
  because the destination state is unknown; and `resolve` cannot attribute one destination UID to two sources in
  the same folder because the journal enforces `UNIQUE(folder, destination_validity, destination_uid)`.
* **Incremental runs and `--verify-history`.** New arrivals go through the same pre-APPEND check. Tiered verification on
  Gmail can report flag drift for a duplicate whose surviving message has the other copy's flags; the classifier below
  explains it.
* **Resume after a held message:** later messages continue (per-message scope), so one duplicate never blocks a folder.

## 6. Classifying merges afterward (verification and older jobs)

For jobs copied before this check existed, or when a race slipped past it, `verify` and the read-back need an explanation, not
a verdict change. Keep today's results (`missing`, `mismatch`) and exit codes, and add an additive `classification` field
plus a `provider_merges` counter.

* **Confirmed merge** (all must hold): destination advertises `X-GM-EXT-1`; two or more journal transfers share a content
  fingerprint; the destination holds identical bytes for at least one of them; there are fewer destination copies than source
  copies; and the symptoms fit (a sibling's UID gone, date retained or flags replaced). Message: "Gmail merged source UIDs 3
  and 10 (identical content) into one message; the destination keeps the first copy's date and the last copy's flags."
* **Suspected merge**: only a Message-ID match or a partial fit; reported as suspected, with what was and was not checked.
* The classifier reads and compares only; it never changes a transfer state. Exactness is never weakened: a merged
  message is still not "confirmed", the multiset still differs, and the report says so.

## 7. Experiments needed to turn hypotheses into facts (each needs your approval; Gmail writes)

All in the `IMAPLANE-Test` label or a second test label of the test account, tiny synthetic messages, at most ~12
APPENDs in total, none deleted afterwards, guard proxy with a hard APPEND cap, nothing outside those labels touched.

* E1: identical bytes, different flags, **different label** (H3, flag overwrite across labels).
* E2: same Message-ID, **different body**, same label (H1, H2).
* E3: same Message-ID, different body, different label.
* E4: Message-ID differences: case, no angle brackets, whitespace, missing header (H5).
* E5: search latency: `X-GM-RAW rfc822msgid` immediately after an APPEND, and the `in:anywhere` / Trash / Spam scope (H4, H6).
* E6 (optional, needs deletion rights): merge with a message in Trash (H4, H7). Skip unless you want it.

## 8. Risks and costs

* **Cost:** one or three extra read round trips per message on Gmail destinations. Gmail copies are latency-bound (about 3 messages/s in the
  1,000-message test), so expect roughly +30% time unless searches are batched; batching with `OR` is itself a hypothesis to test.
* **False holds:** an unusual but legitimate Message-ID reuse would be held. Fails safe; resolved by operator `skip`.
* **Pre-existing destination mail:** the check will hold messages that already exist in the Gmail account. This is
  desirable (no mutation of existing mail), but changes the first-run experience for people migrating into a used account.
* **Localization and label names** are handled through special-use attributes; unverified for non-English accounts.
* **Not covered:** other providers' dedup behavior (Microsoft 365 is untested).

## 9. Decisions requested

1. Approve the principle: **hold, never force**, anything not confirmed safe (section 1).
2. Approve reusing `append_rejections` with a client-side evidence string (no schema change) versus adding an evidence table.
3. Approve experiments E1 to E5 (and say whether you want E6), before any code.
4. Decide whether holds are on by default for Gmail destinations (recommended) or opt-in.

Nothing will be implemented until these are answered.


## 10. Experimental results (live Gmail test account, 2026-11-07; labels `IMAPLANE-Exp-A` and `IMAPLANE-Exp-B`)

12 synthetic APPENDs in total (hard cap enforced by the guard proxy; 11 in the main run, 1 follow-up). Nothing existing was
touched, nothing deleted, no flags changed by us. Raw per-step snapshots (UID, UIDVALIDITY, UIDNEXT, X-GM-MSGID, flags, INTERNALDATE,
labels, SHA-256, counts, before and after every step) are in `~/.config/imaplane/gmail-dest/exp/steps.jsonl` (outside the repository).
Message-IDs are `<exp-N@example.invalid>`; everything is synthetic.

### Observed behavior (CONFIRMED)
| # | What was appended | What Gmail did |
| --- | --- | --- |
| E0 | one message into A | stored; A UID 1; All Mail +1. Control. |
| E1a/b | **identical bytes** into A, then into B (other flags, other date) | **One message.** Same X-GM-MSGID in both labels; All Mail count unchanged; B got UID 1 and the message now carries both labels. INTERNALDATE stayed the first copy's. **The first copy's `\Seen` was cleared** (flags changed from `\Flagged \Seen` to `\Flagged`); `\Answered` appears on the B view only. |
| E2a/b | **same Message-ID, different body**, same label | **Two separate messages** (two X-GM-MSGIDs, All Mail +2), both bodies kept intact, each with its own flags and date. **No merge.** |
| E3a/b | same Message-ID, different body, **different labels** | **Two separate messages**, no merge. |
| E4b | Message-ID in upper case, different body | separate message |
| E4c | Message-ID without angle brackets, different body | separate message |
| E4d | **no Message-ID header** | stored; Gmail added no Message-ID to the fetched bytes; separate message |
| E7 | **same Message-ID, same body, one extra header**, into A (the label that already had it) | **Merged into the existing message, and the new bytes were discarded**: A's count and All Mail did not change; the existing message got a new UID in A (UID 2 vanished, UID 10 now); the stored bytes are still the **original** (SHA-256 unchanged, no `X-Dup-Test` header); the flags did **not** take the APPEND's `\Seen`; INTERNALDATE unchanged. APPEND reported success with `APPENDUID 14 10`. |
| E5 | search latency | `X-GM-RAW "rfc822msgid:..."` found a just-appended message only **2.0 to 5.0 s** later (never immediately). |

Earlier test (first account, `IMAPLANE-Test`): identical bytes, same label: merged, the first copy's UID vanished, flags replaced by the
second APPEND's, date retained. Consistent with E1.

### What this means
* **Case 2 (different bodies, same Message-ID) does NOT merge** (E2, E3). The first design's "Message-ID collision" hold would have
  held messages that Gmail stores correctly. The hold on case 2 should be dropped.
* **What merges is a message whose Message-ID and body match an existing one** (E1, E7), **even when a header differs, and then the new
  bytes are silently lost** (E7). This is the dangerous case: the APPEND succeeds, `APPENDUID` points at a message that is not what
  was sent. Only the read-back (content SHA-256) reveals it; the old UID may vanish.
* **Cross-label duplicates (case 3) are one message with several labels** (E1b), with the other copy's flags altered. This is Gmail's model,
  not a failure, but it breaks per-folder exactness (shared flags and date).
* **A pre-APPEND search cannot be the only defence**: it cannot see a sibling appended in the last 2 to 5 s, and Gmail copies run at about
  3 messages/s, so a sibling in the same run is usually not yet visible.

### Still UNKNOWN (not tested; the 12-APPEND budget is spent)
* Whether the key is Message-ID plus the body, the body alone, or something wider. E7 used the same Message-ID and body; a **different**
  Message-ID with the **same** body was not tested, nor changed Subject/Date headers, nor Message-ID case or bracket differences with
  identical bodies (E4b and E4c changed the body too, so they say nothing about normalization).
* Why `\Seen` clears on a re-APPEND (E1b) but the APPEND's `\Seen` is not applied (E7). Flag results after a merge are not predictable;
  treat them as unreliable.
* Two identical messages with **no** Message-ID.
* Trash and Spam (not touched, by decision).

## 11. The two design risks, reassessed

1. **A missing Message-ID, or an unavailable search, must not become a permanent rejection.** Agreed. Policy, to be confirmed in review:
   * A missing or malformed Message-ID is **not a hold**. The Message-ID search is skipped for it; the in-run and journal checks on identical
     content still apply, and post-APPEND verification decides. E4d shows Gmail stores such messages separately.
   * A search that fails or times out is a **transient condition**: bounded retries with backoff, **no durable evidence written**. If it
     still fails, that message is not appended in this run (fail-closed for the run), the report says why, and the next run tries again.
     Only a positive finding of a risky duplicate produces a durable hold.
2. **A clean search cannot guarantee that Gmail will not merge, so post-APPEND verification stays mandatory and unchanged.** The experiments
   support this: E7 was invisible to the APPEND response and would be caught only by the read-back. Every merge class seen here (E1, E7, the
   earlier test) is caught by the existing read-back (content, INTERNALDATE, flags) or by `verify` (vanished UID). No relaxation is proposed.

## 12. Recommended minimal implementation (for review; nothing built)

Applies only when the destination advertises `X-GM-EXT-1`. Default on. No change to the four commit boundaries, the pre-literal fence,
read-back, or recovery.

**Before APPEND (read-only):**
1. **In-run index**: keep, in memory per run, `(Message-ID, SHA-256 of the body part)` and the full-content fingerprint of every message appended or
   in doubt. A candidate with the same pair, or the same fingerprint, is a risky duplicate. This closes the 2 to 5 s search blind spot.
2. **Journal fingerprint** (free): another transfer to the same destination account with the same full-content fingerprint in
   `accepted`, `confirmed` or `uncertain` (covers earlier runs of the job).
3. **Destination search** for pre-existing mail and earlier jobs: `X-GM-RAW "rfc822msgid:<id>"` in All Mail; for each hit compare the **body
   part** (read via `BODY.PEEK`, size-capped) with the candidate's body. **Same body means risky; a different body is safe** (E2, E3).
   Messages without a Message-ID skip this step.

**Hold only a positive finding**, never a missing signal. A hold does not APPEND, keeps the message `planned`, and is reported. Differences from
the first design: the Message-ID-collision-with-different-body class is **removed**; "unverifiable" is **removed** (see section 11).

**Open design question for the hold's evidence (decision 2, not finalized).** Reusing `append_rejections` works for `skip` (it needs a
planned, unattributed transfer plus one evidence row), but the engine's rejection handling was built for server answers: consecutive
identical rejections trip a run-stopping breaker (`append_rejection_limit`, default 3), and the report text says "APPEND ... rejection".
A run with several duplicates in a row would stop. So either (a) write the same table through a **separate code path** that bypasses the
breaker and says "client-side check", or (b) add a small **additive evidence table** (`client_precheck_events`, schema bump with the usual
verified backup) and let `skip` accept either source. Option (a) avoids a schema change but couples two meanings in one table, and each rerun
appends another row; (b) is cleaner for audit. To be decided in the design review, after the report/`status`/`skip` interactions are checked.

**Performance, honest estimate:** the in-run and journal checks are free. The destination search adds one round trip per message with a
Message-ID, plus a fetch only when it finds a hit. On Gmail, whose copies run at about 3 messages/s (latency-bound), that is roughly +30% for a
destination that holds nothing. Batching several Message-IDs in one `X-GM-RAW` search with `OR` is untested and may cut this; it needs its own
experiment.

**Safety trade-offs:** (+) every merge we observed is either prevented before the APPEND (in-run, journal, search), or caught afterward by
the unchanged read-back. (-) a duplicate that differs in a way we have not tested (different Message-ID, same body) could still merge and is
caught only afterward. (-) a hold needs an operator `skip` to finish a job, so a mailbox with many true duplicates ends "complete except N
operator-skipped". (-) the search relies on an undocumented-in-our-tests Gmail extension; if Gmail changes, the check fails closed for the run.

**What I would test next if you approve more Gmail writes** (small, one new label): different Message-ID with the same body; same
Message-ID and body with changed Subject or Date; Message-ID case and bracket variants with identical bodies; two identical messages with no
Message-ID; a batched `OR` search; and the same checks with an old (days-old) sibling to confirm the search sees it.
