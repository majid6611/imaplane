# Streaming large messages: assessment and implementation plan

Status: **proposal only. No code has been changed.** Numbers marked *measured* come
from the current release binary against a loopback TLS test server (GNU time peak RSS,
one message per run, exact destination content checked); everything else is analysis
that the plan's tests must confirm.

## 1. Problem

IMAPLANE holds each message fully in RAM, more than once. Measured on the current
build:

| Message | Peak RSS | Multiple of message |
| ---: | ---: | ---: |
| 1 MiB | 16.3 MiB | baseline |
| 4 MiB | 22.6 MiB | |
| 16 MiB | 46.6 MiB | 2.9x |
| 64 MiB (default cap) | 142.6 MiB | 2.2x |
| 128 MiB | 270.5 MiB | 2.1x |

Fitted: **peak RSS ≈ 14.6 MiB + 2.0 × N**. At the configurable maximum
(`max_message_bytes` up to 1 GiB) that extrapolates to about **2.0 GiB**. This is the
single biggest limit on running IMAPLANE on small hosts or containers, and on Gmail or
Microsoft 365 mailboxes with large attachments.

### Where the 2x comes from (code review)

| Phase | Mechanism | Copies of N |
| --- | --- | --- |
| Source FETCH | `Session::run` reads the entire response into one `Vec<u8>` (`read_response_onto`, growing by doubling); `decode_message` then does `bodies[0].to_vec()` | response vec + body copy = 2N (transient), then N retained in `Message` |
| Journal hash | `prepare_append` hashes `&message.body` (whole slice) | N |
| APPEND | `AppendCmd` holds `&[u8]` and `write_all`s it; guarded literal already patched | N (no extra copy) |
| Read-back | destination `message()` repeats the FETCH path, then `matches_record` hashes the body | 2N transient |

The source copy is released before read-back (an earlier fix), so the peaks are
sequential, not additive. Two further whole-message readers exist: `reconcile` and
`recover` read up to 1000 destination candidates one at a time, and `resolve` reads
one; all at 2N each.

## 2. Does the IMAP client library support streaming?

The client is a vendored fork of `imap` 3.0.0-alpha.15 with `imap-proto` as the parser.

- **FETCH: no.** There is no incremental API. `run`/`run_command_and_read_response`
  return a `Vec<u8>`; `Fetches::parse` and `imap_proto::parser::parse_response` need the
  literal fully in a contiguous buffer. Nothing in the public surface exposes a literal
  as a reader.
- **APPEND: partly.** The body is written straight from a borrowed slice with no
  copy, which is memory-neutral but still requires the whole message in RAM.
  Our existing patch (`finish_with_literal_guard`) already sits at exactly the right
  spot, after the `+` continuation and before the first body byte.
- **Transport is ready.** `BoundedTls` already enforces a per-command byte budget and
  an idle-progress deadline that renews on every successful read or write, so a
  chunked copy loop inherits the H1/M1 timeout, size-limit and EINTR behaviour.

**Conclusion: true streaming requires modifying the vendored client, but only two
additions, both in `vendor/imap/src/client.rs`, where the fork is already patched.**
`imap-proto` stays untouched, and no replacement library is needed. Switching to a
sans-IO or async IMAP library was considered and not recommended: it would touch
every protocol path (and invalidate the audited ones) to solve a problem confined to
two literals. I have not evaluated those libraries in depth.

## 3. Constraints that shape the design

1. The pre-literal fence requires the journal to hold the message **fingerprint**
   (SHA-256 of the whole body) before the first body byte reaches the destination.
2. Source access stays read-only (`BODY.PEEK`, source wire allowlist).
3. Verification stays exact (content hash, INTERNALDATE, supported flags).
4. Journal transitions and their order are unchanged; no schema bump is wanted.
5. An interrupted APPEND stays uncertain and manual; nothing is replayed.

Constraint 1 is the crux. A pure pass-through (source straight into the destination,
hash computed on the way) cannot know the fingerprint until the end, which is after the
bytes have already left. Deferring the fingerprint would weaken the source-change
detection and the attribution evidence that recovery relies on, so it is rejected.

## 4. Options considered

| Option | Memory | Disk | Source reads | Verdict |
| --- | --- | --- | --- | --- |
| 0. Keep in-memory; remove the extra copy and parse in place | about 1.0 x N | none | 1 | Cheap, safe interim (halves the numbers above) but still O(N). Not a solution. |
| A. Two source passes: pass 1 hashes and records per-block digests; pass 2 streams to the destination, verifying each block before sending it | O(block) | none | **2** | No disk, but doubles source download (Gmail is expected to cap daily downloads), and relies on the server returning identical bytes twice. Exchange is suspected to rebuild MIME on FETCH (unconfirmed). A divergence found mid-literal leaves an uncertain record. |
| B. **Spool to an anonymous temporary file**, then stream from it | O(chunk) | **up to N, transient** | 1 | **Recommended.** Deterministic; the fingerprint is known before any journal write; any source-side parse problem aborts with nothing durable and nothing sent. |
| C. Pass-through with the fingerprint recorded afterwards | O(chunk) | none | 1 | Rejected: breaks constraint 1. |

### Recommendation: B, as a hybrid

- **Small messages keep the current in-memory path unchanged** (default threshold
  8 MiB, new optional `stream_threshold_bytes`). The audited path, its tests and
  throughput for typical mail do not change, and no temporary file is created per
  message for large mailboxes of small mail.
- **Messages above the threshold use the streaming path.**
- **All destination reads become digest reads** (hash while reading, keep nothing):
  verification, candidate reconciliation, `recover` and `resolve`. This is phased in
  (section 8) and needs no disk.

## 5. Detailed design

### 5.1 Vendored client additions

1. **`Session::uid_fetch_body_stream(uid, expected_len, sink)`**
   - Sends `UID FETCH <uid> (UID FLAGS INTERNALDATE BODY.PEEK[])` (the same command as today).
   - Reads line by line. When a line ends in `BODY[] {N}` and no body literal has been
     seen, it checks `N == expected_len`, then copies exactly N bytes through a fixed
     buffer into `sink` and records `{0}\r\n` in a small **skeleton** buffer instead.
     Everything else (all other lines, the text after the literal, unsolicited
     responses) accumulates in the skeleton.
   - Any other literal is read into the skeleton only if it is small (1 MiB, the
     existing OVERHEAD); otherwise the fetch fails.
   - The tagged line is checked exactly as `read_response_onto` does (tag match,
     OK/NO/BAD/BYE).
   - The skeleton is then handed to the **existing** `decode_message` logic, with the
     body length supplied by the streamer. This keeps every current check (UID matching,
     ambiguity, one INTERNALDATE, one FLAGS) instead of writing a second parser. It also
     handles servers that send `BODY[]` before or after `UID`/`FLAGS`.
   - Wire budget stays `expected + OVERHEAD` through `Control::reset`; the idle deadline
     renews per chunk, so H1 semantics are preserved.
2. **`AppendCmd::finish_streaming(len, reader, guard)`**
   - Identical to `finish_with_literal_guard` up to and including `guard()`, so the durable
     authorization still runs after the continuation and before any body byte.
   - Then copies exactly `len` bytes from `reader` in chunks, then CRLF, then reads the
     tagged response. A short read or reader error returns a distinct error; the
     connection is out of sync and is discarded (the engine already stops the run on an
     unresolved APPEND error).
   - Both additions are documented in `vendor/imap/IMAPLANE_PATCH.md` and covered by
     vendored unit tests with a recording mock stream.

### 5.2 Spool

- Anonymous file created with `O_TMPFILE` in `state_dir` (or optional `spool_dir`):
  mode 0600, **no directory entry**, reclaimed by the kernel on close or SIGKILL. A
  crash therefore leaves nothing behind. (The `tempfile` crate already in use creates
  files this way where supported and otherwise falls back to create-then-unlink, which
  has a short leak window; the implementation should use the O_TMPFILE form directly
  and fail closed otherwise, to be confirmed in code.)
- If the filesystem cannot provide it, or the write fails (`ENOSPC`), the message is
  reported as failed with a clear detail. **No journal write has happened yet**, so
  nothing is uncertain.
- Sequential model preserved: one spool at a time.

### 5.3 Streamed transfer order

1. Source: RFC822.SIZE query (existing). If size ≤ threshold, use the current path.
2. Stream FETCH into the spool while computing SHA-256 and counting bytes. Require
   count == RFC822.SIZE. Take date and flags from the skeleton. The source is not
   touched again.
3. Re-read the spool and recompute the hash; require it to equal the streamed hash
   (**nothing leaves the machine unless it matches the journaled fingerprint**).
   Cost: one local read.
4. Destination liveness probe and writable selection (existing, including the U1 probe,
   which matters more here because step 2 can take minutes).
5. Journal: the existing single FULL `prepare_append` commit, using the precomputed
   fingerprint. Then, after the `+` continuation, the existing FULL `literal_authorized`
   commit inside the guard. **Order and durability unchanged.**
6. `finish_streaming` from the spool, re-hashing on the way out and comparing at the end
   (detects a read error between steps 3 and 6).
7. On APPENDUID: existing acknowledge commit. Close the spool (frees disk) before
   read-back.
8. Read-back as a **digest read** (section 5.4); `confirm_content` with the digest.

A source-side anomaly in step 2 (truncated literal, size mismatch, ambiguous response,
connection loss) aborts before any journal write or destination byte. The source read
retry already wraps this call, and the retry must truncate and restart the spool.

### 5.4 Digest reads (destination)

`Destination::message_digest(uid) -> Option<{sha256, len, date, flags}>` uses the same
streaming FETCH with a hashing sink and no spool. `matches_record`, `verify_record`,
`reconcile`, `recover` and `resolve` compare a digest instead of a body. Memory is
O(chunk) regardless of N, and the 1000-candidate scan stops holding a message per step.

### 5.5 Journal and configuration compatibility

- **No schema change.** The stored fingerprint is the same SHA-256 hex of the same
  bytes. `plan`, `prepare_append` and `confirm_content` gain variants that take a
  precomputed fingerprint, and the existing slice-taking functions become thin wrappers.
  Existing journals open and resume unchanged, and a message first confirmed by the
  in-memory path can be re-verified by the streaming path (a required test).
- New optional config keys `stream_threshold_bytes` and `spool_dir`; defaults preserve
  current behavior; unknown-field rejection is unaffected because they are declared.
  Neither alters the job binding (like `append_rejection_limit`).
- `max_message_bytes` semantics are unchanged (still a per-message cap, still checked
  before any transfer).

## 6. Memory, disk and performance targets

| Metric | Today (measured) | Target for N above the threshold |
| --- | --- | --- |
| Peak RSS | 14.6 MiB + 2.0 N | **at most baseline + 16 MiB**, independent of N |
| 256 MiB message | about 527 MiB (projected) | **at most 40 MiB** |
| 1 GiB message | about 2.0 GiB (projected) | **at most 48 MiB** |
| RSS slope vs N | 2.0 | **at most 0.02** |
| Transient disk | none | at most N, one message at a time, zero residue after exit or SIGKILL |

Budget for the targets: two 1 MiB chunk buffers, SHA-256 state, skeleton (at most 1 MiB),
TLS records. Page cache from the spool is not RSS but counts toward container memory
limits; the implementation should advise the kernel to drop spool pages
(`posix_fadvise(DONTNEED)`) as it goes, and the soak test should watch cgroup memory.

Performance expectations (to be measured, not promised):

- Network exchanges per message are unchanged (the SIZE query is kept for parity).
- Large messages become store-and-forward: time ≈ download + upload, as today, with
  no overlap (sequential APPEND is invariant 8 and stays).
- Local I/O is about 3N (write, verify read, send read), normally far below network speed.
- The streaming reader avoids vector growth, the extra copy and the repeated
  parse-attempt loop, so large-message CPU time should fall; this needs a benchmark.
- Small messages: identical path, so the existing 100-message benchmark must not
  regress beyond noise.

## 7. Limitations and risks

- **Plaintext at rest, briefly.** The spool holds message content on disk. It is
  anonymous and private, but disk encryption is the operator's responsibility. A
  `spool_dir` on tmpfs silently turns the spool back into RAM; the implementation
  should warn on tmpfs.
- **Needs free disk** up to the largest message, and a filesystem with `O_TMPFILE`
  (common local Linux filesystems; not all network or FUSE mounts). Failure is clean
  and fail-closed; `spool_dir` is the escape hatch.
- **Larger uncertain window.** A kill during a multi-hundred-megabyte literal stays
  uncertain and manual, as the H5 matrix already asserts for partial bodies, but the
  window is longer in wall time. No recovery rule changes.
- **Servers disagree on FETCH attribute order and SIZE.** Handled by the skeleton
  approach and the existing size check, but real Gmail and Exchange behavior is
  unconfirmed; provider testing (see PROVIDER_COMPATIBILITY_TESTING.md) should include a
  large message.
- **Vendored-patch maintenance** grows slightly; mitigated by vendored unit tests.
- RFC822.SIZE is parsed as 32-bit, which is fine under the 1 GiB cap.
- Linux only (`O_TMPFILE`), consistent with current packaging.

## 8. Phases

Each phase is a local commit that passes the full regression set before the next.

1. **Baseline and harness.** Commit the memory measurement script and the target
   assertions as `tests/local/memory.py` (failing or xfail until the feature lands).
2. **Vendored streaming FETCH + digest type + unit tests.** Not used by the engine yet.
3. **Digest reads for the destination** (verification, reconcile, recover, resolve) above
   the threshold. Ships first because it needs no disk and removes half of the peak.
4. **Spool, streamed source read, `finish_streaming`, engine integration**, behind a
   default threshold equal to the cap (feature effectively off).
5. **Validation soak**, then lower the default to 8 MiB; documentation (remove "no disk
   spooling" statements, add the at-rest note).

Optional interim: Option 0 (drop the extra copy) as its own small commit if a quick win
is wanted before phase 4.

## 9. Tests required

**Vendored client (mock stream, recording writes)**
- Streaming FETCH with the literal before, between and after other attributes.
- Randomized fragmentation (chunk sizes 1, 7, 4096, random) produces results identical
  to the non-streaming reader.
- Literal length differs from RFC822.SIZE; EOF mid-literal; budget exceeded; second
  `BODY[]` literal; oversized non-body literal; empty literal; bytes in the body that
  look like `{N}` or a tagged line; interleaved unsolicited responses; tag mismatch;
  tagged NO/BAD/BYE.
- Streaming APPEND: guard failure writes **zero** body bytes; success writes exactly
  `len` bytes plus CRLF; short reader and reader error poison the connection; server NO
  before the continuation is preserved with its tag check.
- Fuzz the skeleton reader: no panic, no over-read, no acceptance of a length mismatch.

**Rust**
- Streaming hash equals the in-memory fingerprint for random sizes, including 0, 1,
  chunk boundaries and threshold ± 1.
- Spool lifecycle: private mode, no directory entry, nothing left after SIGKILL,
  `ENOSPC` handled with zero journal change (force with a file-size limit or a small
  filesystem), unsupported-filesystem error.
- Journal: a message confirmed through the in-memory path re-verifies through the
  streaming path with the same fingerprint; old journals open unchanged.

**End to end (scripted server and real Dovecot)**
- Sizes 0, 1, threshold ± 1, 16 MiB, 64 MiB, 256 MiB, with exact byte equality;
  source snapshot unchanged and only allowlisted source verbs seen.
- Server orderings (`BODY[]` first, last, middle), lying RFC822.SIZE (smaller and
  larger), source dropped mid-literal (spool restarts, no partial reuse), destination
  dropped mid-literal after authorization (uncertain, no replay, resume reconciles by
  digest), slow throttled upload (per-chunk timeouts).
- **Force-streaming regression mode:** run the entire existing suite (security,
  reliability, e2e, `c1_u1`, and the 30 + 43 + 8 crash scenarios) with
  `stream_threshold_bytes = 0` so every message takes the new path, in addition to the
  default run. This is the strongest check that the new path honors every invariant.

**Crash matrix additions** (new fault points after the spool is verified, mid-literal
after k chunks, and mid read-back): kill before `prepare_append` leaves no record and
no residue; kill after authorization mid-literal is uncertain and manual; kill during
read-back keeps the accepted state; no duplicates after resume in any case.

**Memory and performance**
- Peak RSS at 16, 64 and 256 MiB in CI-sized runs, and 1 GiB as a manual soak,
  asserting the section 6 targets and the slope.
- A/B benchmark (existing harness) with large messages for throughput, CPU and
  exchange counters, plus a no-regression run of the 100-message mixed benchmark.

**Security**
- Diagnostics and reports never contain spool paths or content; spool never appears
  in `state_dir` listings; file mode asserted.

## 10. Approved decisions and added requirements

Approved by the project owner:

1. Hybrid memory/disk-spooling architecture.
2. Default `stream_threshold_bytes` of 8 MiB, configurable.
3. `O_TMPFILE` when supported. A secure fallback is evaluated below. **Never a silent
   fallback to unbounded RAM.**
4. Disk spooling is acceptable if plaintext exposure, permissions, free space, quotas
   and cleanup are handled carefully.
5. The "remove the extra copy" quick win is **not** shipped separately.
6. A 256 MiB memory regression test runs in a dedicated CI job. A roughly 1 GiB
   (1000 MiB, because the configured cap is 1 GiB including headers) soak is manual.

Added requirements, each of which needs a test before streaming is enabled by default:

- Journal durability and the pre-literal authorization order are unchanged.
- Disk full, including a failure part-way through a spool write, fails the message
  safely with no journal change and no authorized APPEND.
- A truncated or interrupted FETCH can never lead to an authorized APPEND. Nothing is
  journaled or sent until the spool is complete, size-checked and hash-verified.
- The in-memory path for small messages is unchanged.
- SIGKILL is tested during source streaming, during the destination APPEND and during
  destination verification.
- An uncertain APPEND stays conservative and is never retried automatically.
- Memory is verified with real peak-RSS measurements, not estimates.
- **Documentation must state plainly that `O_TMPFILE` does not encrypt:** spooled mail is
  plaintext on the underlying disk until the kernel reclaims it, and protecting it
  (disk or volume encryption, quotas, a private `spool_dir`) is the operator's job.
- Existing journals and configurations keep working.
- A failed, partial or unverified transfer is never marked verified: `confirmed` is
  reachable only through the existing exact read-back.

### Evaluation of a fallback when `O_TMPFILE` is unavailable

| Option | Behavior | Assessment |
| --- | --- | --- |
| F0. Fail closed | Large message is reported failed with a clear reason; operator sets `spool_dir` to a supporting filesystem | Safest; always available; may block some network or FUSE mounts |
| F1. Named file in a private directory, unlinked immediately | `state_dir/spool/` mode 0700, create with `O_CREAT\|O_EXCL\|O_NOFOLLOW`, mode 0600, random name, unlink straight after open; sweep leftovers at startup (safe under the exclusive job lock) | Residual risk: a SIGKILL or power loss in the instant between create and unlink leaves plaintext that survives until the next run's sweep. Small, bounded and auditable, but real |
| F2. RAM | Never | Rejected by the owner |

Proposed position, to be settled in phase 4 with tests: `O_TMPFILE` first; if it is
unsupported, use **F1 only when it is enabled explicitly or accepted after a visible
warning that is also recorded in the report and diagnostics**, otherwise **F0**. Every
path also checks free space and quota before the transfer (`statvfs` for the needed
bytes plus a margin) and handles `ENOSPC` and `EDQUOT` as clean per-message failures.
The startup sweep and the leftover-after-SIGKILL test are mandatory if F1 ships.

## 11. Phase 1 harness and CI

`tests/local/memory.py` measures real peak RSS (GNU time) of the IMAPLANE process for one
message per run against a loopback TLS test server, checks exact content, and applies a
profile:

- `current`: a regression ceiling for today's in-memory behavior (the measured fit with
  margin). Used by the dedicated CI job now so memory cannot silently get worse.
- `streaming`: the section 6 targets (absolute RSS and slope). Expected to fail until
  the streaming path exists, and becomes the CI profile when streaming is enabled.

### Phase 1 baseline (measured on the commit before any streaming change)

Release binary, loopback TLS scripted server, one message per run, GNU time peak RSS of
the IMAPLANE process only, exact destination bytes checked every run.

| Message | Peak RSS | x message | Seconds |
| ---: | ---: | ---: | ---: |
| 1 MiB (baseline) | 16.4 MiB | | |
| 16 MiB | 46.8 MiB | 2.92 | 1.4 |
| 64 MiB | 142.5 MiB | 2.23 | 3.0 |
| 256 MiB | 526.4 MiB | 2.06 | 5.7 |

Slope between 64 and 256 MiB: 1.999 MiB of RSS per MiB of message. Run-to-run spread was
about 0.2 MiB. The `streaming` profile fails on all sizes and on the slope today, as
intended; the `current` profile passes and is the dedicated CI job's check.

### Phase 3 results: streaming destination verification and candidate scanning

Commits 3a to 3e. Streaming is **off by default** (`stream_threshold_bytes` unset). The
migration engine does not use streaming APPEND or disk spooling; the source read and the
APPEND still hold a whole message (phase 4).

Measured peak RSS of the IMAPLANE process (GNU time, one message per run, exact destination
bytes checked). `verify` never contacts the source, so it isolates the destination read:

| Scenario | Message | Buffered (default) | Streaming (threshold 0) |
| --- | ---: | ---: | ---: |
| `verify` | 16 MiB | 46.2 MiB | 14.0 MiB |
| `verify` | 64 MiB | 141.9 MiB | 14.1 MiB |
| `verify` | 256 MiB | 525.7 MiB | **13.8 MiB** |
| `resume` (second `migrate`) | 256 MiB | 526.5 MiB | **14.7 MiB** |
| fresh `migrate` (source still buffered) | 256 MiB | 526.6 MiB | unchanged, by design |

Slope of RSS against message size: 2.0 MiB per MiB buffered, about 0 streaming. A fresh
transfer is unchanged because its peak is the source read, which phase 4 addresses.

Both paths are exercised by the whole suite: it was run with the threshold unset and again
with `IMAPLANE_TEST_STREAM_THRESHOLD=0` (every generated config sets the key). Streaming and
buffered paths are compared directly by a differential test (18 scripted responses at four
fragmentation sizes) and by `stream_verify.py`, which requires identical observable results
in both modes, including a 1 MiB message altered only in its final byte.

Deliberate difference: if a streamed body could belong to another UID (another message's
response also carries a body and the requested UID has one too), the streaming path fails
closed where the buffered path would ignore the foreign body. Without a body for the
requested UID both report "absent".

