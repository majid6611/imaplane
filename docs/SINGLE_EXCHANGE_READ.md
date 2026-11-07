# One exchange for small messages (Phase 3 of the performance work)

## What changed

Reading a message used to take two IMAP exchanges on each side: `UID FETCH n (UID RFC822.SIZE)` to learn the size
(needed to enforce `max_message_bytes` and to choose between a buffered and a streamed read), then
`UID FETCH n (UID FLAGS INTERNALDATE BODY.PEEK[])` for the content. That applied to the source read and to the
destination read-back that confirms every message (four exchanges per message, plus the APPEND).

A message up to 128 KiB is now read with one exchange:

    UID FETCH n (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[]<0.131072>)

The reply carries the size, the flags, the date and up to 131,072 bytes of the body. If the reported size fits, the body is
the whole message and nothing more is fetched. `BODY.PEEK` never changes flags, so the source stays untouched.

## What does not change

* **The memory bound.** The read is capped at 128 KiB plus the fixed overhead; a lying server cannot make it read more.
  Larger messages use the established path (buffered up to the configured cap, or streamed to a verified spool above the
  streaming threshold), now with the size the same reply already carried, so they still take two exchanges, as before.
* **The size limit and error classes.** A size above `max_message_bytes` is the same permanent skip, decided from the first
  reply (at most 128 KiB is read of it, never the message). A body whose length differs from `RFC822.SIZE` is the same permanent
  mismatch. A missing size or a NIL body means "no longer available", as before. Two sizes for one UID, or missing/duplicate
  date or flags, fail rather than guess.
* **Exact verification.** The destination read-back still reads the whole message and hashes it; only the number of
  exchanges changed. Confirmation, the four durable commits and the pre-literal fence are untouched.
* **Streaming semantics.** The request text does not depend on the streaming threshold. A message that arrives whole in
  the probe but is above the threshold is treated by its size alone (its probe bytes, at most 128 KiB, are dropped) and
  streamed exactly as before. With the threshold at 0 (stream everything) no probe is sent at all.

## Why it matters

Locally the round trip costs almost nothing, so the gain is small (see the benchmark). Over a real network every message used
to wait for four sequential round trips for reads plus the APPEND; this removes two of them. The latency benchmark
(`LATENCY_MS`, `tc netem` on the tool container's interface) quantifies it at 0, 20 and 60 ms.

## Tests

`src/transport.rs` unit tests (equivalence with the body fetch, boundary at the limit, empty message, lying sizes in both
directions, over the cap, NIL body, no size, other UIDs, ambiguity, missing date/flags, the limit and threshold rules);
`tests/local/probe_fetch.py` (command counts on the wire, the 128 KiB boundary, empty and tiny messages, streaming threshold
and forced streaming, lying size, oversize skip, deleted message); the existing suites (forced-spool mode exercises the
unchanged path). The scripted IMAP fixtures (`e2e.py`, `lean_server.py`) learned the partial fetch.
