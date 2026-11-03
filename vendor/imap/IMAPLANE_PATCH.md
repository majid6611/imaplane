Upstream: imap 3.0.0-alpha.15, dual MIT/Apache-2.0.

Functional changes are confined to AppendCmd in src/client.rs:
- Preserve and tag-check pre-literal NO/BAD via read_response_onto.
- Add finish_with_literal_guard: after a synchronizing continuation and before
  any body byte, invoke a fallible caller-provided durable authorization guard.
  Existing finish delegates to it with a no-op, retaining the upstream API.

Guard failure sends no body. The IMAPLANE adapter uses a FULL SQLite commit in
this guard. Empty literals are authorized before even the APPEND prefix.
No automatic APPEND retries. Added focused client tests cover rejection tags
and guard failure. All other upstream modules are unchanged.

## Streaming additions (phase 2 of docs/STREAMING_DESIGN.md)

Purely additive; no existing API or behavior changes. New code is in
`src/client/streaming.rs`, plus: `Error::Stream(StreamError)` (fixed variants, never
carries server data), a `desynced` flag on `Connection` checked in `write_line`, and the
re-exports in `client.rs`.

- `Session::uid_fetch_body_stream(uid, expected_len, sink)`: sends
  `UID FETCH <uid> (UID FLAGS INTERNALDATE BODY.PEEK[])` (PEEK is fixed, so it cannot set
  `\Seen`), copies the `BODY[]` literal through one 128 KiB buffer into `sink`, and returns
  a "skeleton" (the response with the body replaced by `{0}`, capped at 1 MiB) for the usual
  parser. The announced length must equal `expected_len`, checked before any body byte is
  read. Lines are bounded at 64 KiB. A bare-LF or overflowing literal marker, a second
  oversized literal, truncation, a sink error or a wrong tag all fail.
- `Session::append_stream(mailbox)` -> `StreamAppendCmd::finish_streaming(len, reader,
  guard)`: same order as `finish_with_literal_guard` (command, `+` continuation, **guard**,
  then body), copying exactly `len` bytes from `reader` through one 128 KiB buffer. It
  returns `StreamedAppend { phase, body_bytes_sent, result }`. `AppendPhase` is
  `NotAuthorized < Authorized < BodyStarted < BodyComplete < Responded`: the first two prove
  no body byte reached the connection; `BodyStarted` is set BEFORE the first body write
  because a failed write may still have delivered bytes. `body_bytes_sent` is informational
  only; safety decisions must use `phase`.
- Any streaming failure other than a fully consumed tagged NO/BAD leaves the stream at an
  unknown position, so the connection is marked desynced and every later command is
  refused (`is_desynced()`); the caller must drop it. A tagged NO/BAD keeps the connection
  in sync.
- Tests: 21 new unit tests in `streaming.rs` (randomized read/write fragmentation,
  zero-length literals, length mismatch, truncation, malformed markers and completions,
  guard-before-body, short reader/writer, disconnects, a 400-case randomized fence and
  phase invariant check, command-line parity with `finish_with_literal_guard`), and
  `tests/streaming_client.rs` in the IMAPLANE crate (real loopback sockets, 24 MiB, with a
  per-thread tracking allocator: peak client allocation 128 KiB).

