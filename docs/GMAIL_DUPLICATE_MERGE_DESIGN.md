# Gmail duplicate merging: revised design (for review, nothing implemented)

> **Updated 2026-11-07 after experiments E0-E7 and a read-only search-cost measurement (sections 10-13).** The experiments disproved the assumption in sections 1-3 that
> Gmail merges on Message-ID alone, and changed the recommended policy. Where sections 1-8 conflict with 10-13, 10-13 win. Section 13 is the final design for review.

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

## 11. Measured cost of destination searches (read-only, 2026-11-07)

Measured against the live Gmail test account through the guard proxy, with zero writes (about 40 single searches and 10 batched ones):

| Operation | Time |
| --- | --- |
| `NOOP` round trip | about 100 ms |
| One `X-GM-RAW "rfc822msgid:<id>"` search, id absent | **about 407 ms** (p90 413 ms); present: 612 ms |
| One batched search, `rfc822msgid:a OR rfc822msgid:b OR ...`, 10 / 50 / 100 / 200 / 400 ids | 204 / 394 / 246 / 411 / **615 ms** |
| Batched search, brace syntax `{a b c}` | returned **no hits** for ids that exist: unusable |

* The batched `OR` form **returned the correct hits** (9 expected, 9 found, including the upper-case and bracket-less variants of one id,
  so it is a case- and bracket-insensitive superset, which is the safe direction). It scales to about 1.5 ms per id.
* **A per-message search would add about 407 ms to every message.** The 1,000-message Gmail copy took 302 s, so that is **about +135%.** My
  earlier "+30%" estimate was wrong. A per-message search is therefore rejected as the design.
* **Batching by 100 ids** costs about 250 to 400 ms per 100 messages, so about 3 to 5 s per 1,000 messages (under 2%).
* Not measured, so still hypotheses: behavior beyond 400 ids per search, correctness at scale, any Gmail quota that counts searches.

## 12. Confirmed patterns and untested cases

| Pattern | Gmail behavior | Status |
| --- | --- | --- |
| Identical bytes, same label | merged; first copy's UID vanishes; flags/date effects as in section 10 | CONFIRMED (twice) |
| Identical bytes, different label | one message, two labels; other view's flags altered | CONFIRMED |
| Same Message-ID **and** body, any header differs (E7) | merged; **appended bytes silently discarded**, APPEND reports success | CONFIRMED (once) |
| Same Message-ID, different body | separate messages | CONFIRMED (same label and different label) |
| No Message-ID | stored separately; no Message-ID added | CONFIRMED (one message only) |
| Same body, **different** Message-ID | separate messages (X1) | CONFIRMED (once) |
| Same Message-ID and body, **Subject** changed / **Date** header changed | separate messages, nothing discarded (X2b, X3) | CONFIRMED (once each) |
| Message-ID upper-case variant, identical body | separate messages (X4); the search still finds both (superset) | CONFIRMED (once); bracket-less variant UNTESTED with identical body |
| Two identical messages with no Message-ID | merged like any identical bytes; first UID vanished (X5) | CONFIRMED (once) |
| Sibling in Trash or Spam | unknown; All Mail search does not see it | UNTESTED, out of scope by decision |
| Sibling appended less than about 5 s ago | not visible to search | CONFIRMED (E5) |
| Messages added to the account by another client during the run | not covered | UNTESTED |

**Consequence (your point 2): the key is not known.** The check below is a *risk reducer built on observed patterns*, not a predictor. It
is deliberately broader than the proven pattern where that is cheap (same Message-ID and same body, whatever the headers), and it never replaces
the SHA-256 read-back, which stays mandatory and unchanged. An unknown merge pattern is caught afterward, not prevented.

### 12.1 Follow-up experiments X1-X5 (live, 2026-11-07, label `IMAPLANE-Exp-C`, 9 APPENDs, proxy cap 10)

New label created by the harness; no existing label, message, Trash or Spam was touched; the proxy forwarded 9 APPENDs and refused nothing
(no STORE/EXPUNGE/MOVE/DELETE ever attempted). Raw per-step records: `~/.config/imaplane/gmail-dest/exp/steps2.jsonl`.

| Step | Result |
| --- | --- |
| X1 same body, different Message-ID | 2 messages (UIDs 1,2; distinct X-GM-MSGID) |
| X2 same Message-ID and body, **Subject** changed | 3rd and 4th message stay separate (no merge, nothing discarded) |
| X3 same Message-ID and body, **Date header** changed | separate (5 messages after X3) |
| X4 same body, Message-ID upper-cased | separate; Message-ID search returns both (superset, as measured earlier) |
| X5 two byte-identical messages without Message-ID | merged: one message, UID 8 vanished, UID 9 holds it (same X-GM-MSGID) |

**Interpretation, stated carefully.** Together with E7 (an *extra* header was ignored and the bytes were discarded) these results show
the merge key is **narrower than "Message-ID plus body"**: changing Subject or the Date header prevented the merge, adding an unrelated
header did not. The key plausibly includes the principal headers; it is *not* known. Consequences for the design: (1) the `SAME_ID_AND_BODY_EXISTING`
hold remains a deliberate **over-approximation** (it may hold a message Gmail would have stored separately; the operator then decides with
`skip`, never a silent loss); (2) it is still **never complete**: an unknown merge rule is caught only by the mandatory read-back;
(3) the exact-content hold (`SAME_CONTENT_*`, covering X5 and E1) is the only rule confirmed to match Gmail exactly.

## 13. Final design (for review; nothing implemented)

### 13.1 Scope and defaults
Applies only when the destination advertises `X-GM-EXT-1` (seen before and after login). **Default on** for those destinations; every other
server behaves exactly as today. No change to: the four commit boundaries, the pre-literal fence, SHA-256 read-back, `recover`, `resolve`,
`skip` semantics, the rejection circuit breaker, or the transfer states (`planned`, `uncertain`, `accepted`, `confirmed`).

### 13.2 Detection: three sources, ordered by cost
1. **In-run index (memory, free).** `(Message-ID, SHA-256 of the body part)` and the full-content fingerprint of every message this run appended or
   left in doubt. It covers the 2 to 5 s window in which a just-appended sibling is invisible to search.
2. **Journal (free).** Another transfer to the same destination account with the same full-content fingerprint in `accepted`, `confirmed` or
   `uncertain` (earlier runs of the job). An `uncertain` sibling holds the later copy ("sibling uncertain"), because the destination state is unknown.
3. **Destination prescan, batched (bounded cost).** For existing Gmail mail.
   * **When:** per folder, in windows of at most 1,000 planned messages, before transferring the window.
   * **Source side:** read each planned message's `Message-ID` header with batched `BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]` (source stays read-only).
   * **Destination side:** a **second, read-only destination connection** (`EXAMINE` of the `\All` mailbox once, not by name, so localization does not
     matter; Gmail allows many connections). One `UID SEARCH X-GM-RAW "rfc822msgid:a OR rfc822msgid:b ..."` per **at most 100 ids** (command length bounded).
   * **Hits only:** for each hit, `BODY.PEEK` fetch of the Message-ID header and the body part (size-capped by `max_message_bytes`), keyed into an index of
     `(Message-ID, body hash) -> X-GM-MSGID, labels, size`. Different body means no risk (E2, E3); same body means risk (E1, E7).
   * **A message without a Message-ID skips this source;** the in-run and journal checks still apply. Not a hold (E4d: Gmail stores it).
   * **Cost:** about 3 to 5 s per 1,000 messages for searches plus a source header pass; per hit about two round trips. Memory is bounded by the window
     and by the number of hits.
   * **Retries:** at most 2 retries per batch with 1 s and 2 s backoff and one reconnect (existing destination reconnect), then failure (13.6).

A message is **held** only on a **positive** finding: same full-content fingerprint, or same Message-ID and same body, in the in-run index, in the journal
or among the prescan hits, or an uncertain sibling. An unknown or unverifiable situation is never a hold (see 13.6).

### 13.3 Evidence table (separate, additive, append-only)
```sql
CREATE TABLE IF NOT EXISTS client_hold_events (
  folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL,
  observed_at TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('hold','release')),
  reason TEXT NOT NULL CHECK(reason IN ('SAME_CONTENT_THIS_JOB','SAME_CONTENT_EXISTING','SAME_ID_AND_BODY_EXISTING','SIBLING_UNCERTAIN','RELEASED')),
  fingerprint TEXT NOT NULL,          -- full-content SHA-256 of the held message (already in the journal)
  detail TEXT NOT NULL                -- bounded text: sibling source UID, existing X-GM-MSGID, label names, body-hash prefix; no message text
);
-- plus no-update / no-delete triggers, like the other evidence tables
```
* **Not a state:** a hold is evidence next to a `planned` transfer. No transfer state is added, no existing row or column changes.
* **No schema version change.** The table is created with `CREATE TABLE IF NOT EXISTS` inside the first hold's own transaction, so it appears only
  in journals that need it, atomically, for both schema 4 and schema 5 journals; `user_version` and the supported-schema list stay as they are.
  Cost: an older binary ignores the table and has none of this protection, so **do not mix versions on one job** (to be documented). An explicit
  schema bump with a verified backup is the alternative; it adds an upgrade step for little gain, and I do not recommend it.
* **No growth per rerun:** a row is added only when the latest event for the message differs in `(kind, reason, detail)`.
* **Independent of the rejection machinery:** it never touches `append_rejections`, the rejection circuit, `append_rejection_limit` or the
  rejection scope table. Test: any number of consecutive holds must not stop a run.

### 13.4 Transitions (all before `prepare_append`; nothing is ever sent for a held message)
Where it runs: after the source body is read and the flags computed, **immediately before `prepare_append`** (the first durable commit). It reads only.

| From | Event | To | Durable effect |
| --- | --- | --- | --- |
| `planned`, no hold | check finds a positive risk | `planned` + hold | one `client_hold_events` row (one commit) |
| `planned` + hold | rerun, same risk | unchanged | none (deduplicated) |
| `planned` + hold | rerun, risk changed | `planned` + hold | new row with the new reason/detail |
| `planned` + hold | rerun, risk gone (for example the existing message was removed by its owner) | normal path | one `release` row, then `prepare_append` as usual |
| `planned` + hold | `skip --reason` | `planned`, skipped | existing `operator_skip_events` row (see 13.7) |
| skipped | `unskip` | normal path, re-checked | existing `unskip` row; a fresh check follows |
| `uncertain` | existing recovery | unchanged | none; held messages are never `uncertain`, so `recover` has nothing to do for them |

A held message **never** enters `uncertain`, never gets an `append_attempts` row (no fence is needed because no literal is ever authorized), and
never becomes `confirmed`.

### 13.5 Crash recovery
* Crash before the hold commit: nothing was written; the next run re-checks.
* Crash after the hold commit: evidence only; the next run re-evaluates before `prepare_append` anyway, so the hold lasts only while the risk does.
* Crash between a `release` row and `prepare_append`: the row is audit only; the next run re-checks and proceeds or holds again.
* Crash during an APPEND (existing behavior): unchanged. While such a sibling is `uncertain`, later duplicates are held (`SIBLING_UNCERTAIN`).
* `resolve` cannot attribute one destination UID to two sources in the same folder (`UNIQUE(folder, destination_validity, destination_uid)`).
* Fault points to add for tests: `hold_before_commit`, `after_hold`, `release_before_commit`, `after_release`.

### 13.6 Failures of the check itself (your risk 1)
* **Missing or malformed Message-ID:** no prescan lookup, no hold, no rejection. In-run and journal checks and the read-back apply.
* **Search or fetch failure** (timeout, dropped connection, `NO`/`BAD`, capability disappears): bounded retries, then **fail closed for this run
  and fail open for the journal**: the message is **not** appended, **nothing durable is written**, the report entry is `failed` with
  "duplicate check unavailable; nothing was sent", the run stops (it would fail the same way for the rest), exit code 2. The next run tries again.
  A transient condition is never recorded as a hold, a rejection or a skip.
* **Capability absent or not Gmail:** feature off; no change in behavior.

### 13.7 Operator decisions: `skip` and `unskip`
`skip` today requires a planned, unattributed transfer with a durable rejection row. Change (small): accept a **hold event** as well, copying its text
into `operator_skip_events.rejection_evidence`. All other checks and the audit log stay the same. Reason required. `unskip` is unchanged.
A skipped message is reported `skipped_by_operator`, is **not** counted as migrated, and keeps `complete` false (existing rule).
There is **no force-append** for a held message.

### 13.8 Reporting: held messages can never count as migrated or disappear
* **Run report:** entry result `held` (additive value) with the reason and the sibling, in every run for as long as the hold stands; counters
  `results.held` and a `warnings` line "N message(s) held; see entries". `complete` is false; exit code 2.
* **Status (offline):** "Held (client-side duplicate checks): N", derived from the journal (latest event per message is a `hold`, not skipped).
* **`confirmed` counts** only verified-delivered messages. A held message is never confirmed, so it cannot inflate any success count.
* **Accounting invariant** (tested): every message in the job is exactly one of `confirmed`, `accepted`, `uncertain`, `held`, `skipped`, `rejected`,
  `planned` (not yet attempted). The report totals equal the journal totals.
* **Human output** ends with a held/skipped line, so it cannot scroll past unnoticed.

### 13.9 Existing messages in the Gmail destination (your point 8)
IMAPLANE never changes destination mail: it uses only `EXAMINE`, searches and `BODY.PEEK` reads on existing messages, and no `STORE`, `EXPUNGE`,
`COPY` or `MOVE`.
* Same Message-ID **and** same body already present: **held**, never appended (an APPEND would reset its UID and flags, E1 and E7).
* Same Message-ID, **different** body: appended normally; Gmail stores it separately and leaves the existing one untouched (E2, E3).
* **Residual risk, documented, not removable:** a merge pattern we have not seen (section 12), a sibling in Trash or Spam, or mail added by another
  client during the run can still alter an existing message before the read-back sees it. Recommendation in the docs: migrate into a fresh account
  where possible.

### 13.10 What stays exactly as it is (your point 7)
`prepare_append` (commit 1), `authorize_literal` and the pre-literal fence (commit 2), `acknowledge` (commit 3), `confirm` (commit 4),
exact SHA-256 read-back of content, INTERNALDATE and supported flags, the rejection circuit breaker, `recover`/`resolve`, the single job lock,
WAL with `synchronous=FULL` and `fdatasync`, source read-only. After a merge that slips through, the read-back or `verify` still reports
`mismatch` or `missing` as today; an additive `classification` (section 6) explains it ("appended bytes were discarded by the provider",
"UID vanished after a duplicate APPEND").

## 14. Implementation plan

Small commits, each green before the next, none touching the commit sequence.

| Step | Content | Tests |
| --- | --- | --- |
| P0 | Pure module: `Message-ID` and body-part extraction (first header, unfolding, comments, angle-addr, case, absence, malformed, multiple headers) and body hash | unit and property tests; fuzz for panics; fixtures from E1-E7 messages |
| P1 | Journal: lazy `client_hold_events`, `record_hold`, `latest_hold`, `record_release`, summary and `status` counts, `skip` precondition extension | unit tests; schema 4 and 5 journals; WAL and rollback modes; append-only triggers; deduplication; crash matrix with the four new fault points; a journal without the table is unaffected |
| P2 | Transport (read-only): capability detection, `\All` discovery, second read-only destination connection, batched OR search (<=100 ids, command length bound), hit resolution with caps, retry and reconnect | scripted-server tests for responses, `NO`/`BAD`, truncation, huge hit lists, case/bracket-insensitive hits, brace-syntax absence; no write verb ever sent (asserted) |
| P3 | Engine: per-window prescan, in-run index, journal check, hold path before `prepare_append`, fail-closed search failure, report, human summary | scripted **Gmail-like** server that reproduces E1, E2, E7 (merge, discard bytes, reissue UID); Dovecot regressions unchanged (feature off); forced-spool mode; all existing suites and crash matrices; randomized SIGKILL stress with duplicates; mutation checks |
| P4 | Post-hoc `classification` for read-back mismatch and `verify` | scripted merge scenarios; no change to results or exit codes |
| P5 | Documentation (README provider note, operator guide, version-mixing warning), changelog | doc review |
| P6 | Live acceptance (**needs your approval and Gmail writes**) on a fresh test label | see acceptance below |

Mutation checks to include: remove the in-run index (a duplicate pair gets through), count a hold as confirmed (accounting test fails), let a hold
reach `prepare_append`, write a hold on a search failure, let holds trip the rejection breaker, skip the dedupe (row growth), drop the `skip`
extension (skip is refused).

## 15. Acceptance criteria

1. **No bytes for a held message:** with a Gmail-like server that merges, a duplicate pair yields exactly one APPEND; the first copy's UID, flags and date are
   unchanged; the second is `held`; zero APPENDs reach the server for it (asserted at the wire).
2. **Never counted, never lost:** held messages are never `confirmed`; `complete` is false; the accounting invariant holds in every run, after every crash
   point, and after resume; the report and `status` agree.
3. **Skip and unskip:** `skip` works on a hold with a reason, is audited, keeps `complete` false; `unskip` re-checks and holds again if the risk remains.
4. **Crash safety:** SIGKILL at each new fault point and at random points of a duplicate-heavy job ends duplicate-free, with no message both held and
   delivered, and no state other than the four existing ones.
5. **No breaker coupling:** 50 consecutive holds do not stop a run; `append_rejection_limit` is untouched.
6. **Failures fail closed and leave no trace:** search timeouts, drops and `NO`/`BAD` produce no evidence rows, no append, exit 2; the next run succeeds.
7. **Different bodies are not held** (E2, E3 pattern), and a missing Message-ID is not held.
8. **Read-back unchanged:** a scripted E7-style merge that slips past the check is reported by the existing read-back as a mismatch, and `verify`
   reports a vanished UID, exactly as today, plus the additive classification.
9. **Existing destination messages untouched:** the destination script log shows no `STORE`, `EXPUNGE`, `COPY` or `MOVE` and no APPEND for a message
   whose Message-ID and body already exist.
10. **Performance:** on a 1,000-message Gmail-like run with latency injected like the measured values (about 100 ms round trip, 250 to 400 ms per 100-id search), the
    check adds **at most 3% of wall time** (about 5 s), and at most one extra connection; peak RSS stays within the existing ceilings.
11. **Non-Gmail unchanged:** every existing suite, crash matrix and the benchmark behave identically (byte-identical protocol conversation for Dovecot).
12. **Live (P6, approved separately):** IMAPLANE copies a duplicate pair into a fresh label as one message plus one held entry, leaves the first copy
    untouched, reruns idempotently, and reports a skip correctly.

## 16. Open items before implementation
* Confirm **13.3 (lazy additive table, no schema bump)** versus a schema bump.
* Confirm that a **search failure stops the run** (fail closed) rather than deferring just that message.
* Approve the **live untested-pattern experiments** (section 12) before or after implementation; they do not block P0-P3.
* The batched search was verified only up to 400 ids and on a small account; P2 keeps a 100-id bound and the live acceptance run checks it on more data.

## 17. Implementation status and deviations from this design (2026-11-07)

Implemented in separate local commits P0-P5 (not pushed). Decisions taken after review: **explicit schema 6** instead of the lazy
table (section 13.3); **fail closed** on a failed check (13.6); live experiments X1-X5 done (12.1) and P6 live acceptance still to be approved.

Deviations and clarifications, so the document matches the code:

* **Schema 6, explicit.** `Journal::upgrade_to_v6` (4 -> 5 -> 6, each step one transaction with a verified backup `*.v4.bak`, `*.v5.bak`); the
  engine performs it at the start of a protected run, before any transfer. Older binaries refuse schema 6 (tested with the previous release binary).
  A journal is never upgraded when `gmail_duplicate_protection = "off"` or the destination is not Gmail-like.
* **A hold creates the planned row.** `record_hold` inserts the `planned` transfer row (if missing) in the same transaction as the event,
  so `skip` and the status counts work; no attempt row, no fence, no other state.
* **Where the check runs:** after the source message was read and its INTERNALDATE check, immediately before the destination liveness probe and
  `prepare_append`; it writes nothing except the hold/release evidence.
* **Comparison is deliberately broader than Gmail's merging (X2-X4):** Message-ID compared lowercase and with or without angle brackets; same
  Message-ID and body counts whatever the other headers (Gmail kept messages with a changed Subject or Date separate). More holds, never fewer.
* **Source header pass** reads at most the first 64 KiB of each header with `BODY.PEEK[HEADER]<0.65536>`; a Message-ID beyond that is found by a
  single-id search at check time. Ids that cannot be placed safely in a quoted search (non-ASCII, quotes) are not searched (never a hold).
* **Existing hits** are compared by fetching the whole message (BODY.PEEK) with the existing size cap; a hit larger than `max_message_bytes` stops the
  run (fail closed) rather than guessing.
* **Spooled messages** (large, streaming on) are keyed by streaming the spool (`keys_from_reader`), never held whole in memory.
* **Not implemented / out of scope:** P4 post-hoc `classification` of a read-back mismatch (the read-back result itself is unchanged and still
  reported as before); Trash and Spam siblings; mail added by other clients during a run; the live acceptance P6.
