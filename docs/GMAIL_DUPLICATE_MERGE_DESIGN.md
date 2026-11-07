# Gmail duplicate merging: revised design (for review, nothing implemented)

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
