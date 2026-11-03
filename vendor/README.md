# Third-party source

`imap-proto` 0.16.7 is from https://crates.io/crates/imap-proto/0.16.7
(upstream: https://github.com/djc/tokio-imap), MIT OR Apache-2.0.

Local patch: accept CAPABILITY responses containing IMAP4rev2 without
IMAP4rev1. The upstream parser incorrectly requires rev1, preventing rev2-only
servers from connecting. No wire substitution is performed. The core still
uses upstream's literal-aware parser and Rust imap client.

IMAPLANE also compensates for upstream LIST quoted escapes in its adapter,
and uses UID FETCH for snapshots so it does not depend on legacy SEARCH
responses in rev2 sessions. TLS protocol fixture tests cover rev1, dual-mode,
rev2-only, UTF8=ONLY and ENABLE not acknowledged scenarios.

The adapter also parses selection responses through the typed protocol parser
instead of the client's convenience mailbox parser, which can panic on untagged
NO responses. UIDNOTSTICKY, unsuccessful selections and a source EXAMINE returning
read-write mode are rejected explicitly.

Upstream copyright/license texts are retained as LICENSE-MIT and LICENSE-APACHE
(retrieved from the upstream repository; the crates.io archive omitted them).


The parser also retains structured UNAVAILABLE, THROTTLED, INUSE, LIMIT,
OVERQUOTA and TOOBIG response codes. This supports sanitized retry/rejection
classification without examining or retaining arbitrary server prose.

`imap` 3.0.0-alpha.15 is also vendored (MIT OR Apache-2.0). Its narrow APPEND
patch preserves tag-checked pre-literal rejections and adds a fallible durable
literal guard; see [its patch notes](imap/IMAPLANE_PATCH.md). Upstream license
texts are retained in that directory. Functional changes remain in client.rs;
upstream client/parser regression suites run separately in CI. Keep both patched
crates when building IMAPLANE.
