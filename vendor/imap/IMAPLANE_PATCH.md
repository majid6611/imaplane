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
