# Contributing

Thanks for helping. IMAPLANE's first priority is data integrity: a change must never
weaken durability, the source-is-read-only rule, duplicate prevention or crash recovery.

## Before you start
- For anything beyond a small fix, open an issue first.
- Read `docs/TECHNICAL_DESIGN.md`, `docs/RELIABILITY_AUDIT.md` and `docs/WAL_JOURNAL.md`.
- Never use real mail accounts or credentials in tests, issues or logs. Tests use
  disposable Dovecot servers and scripted TLS fixtures only.

## Checks that must pass
```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --features fault-injection --target-dir target/fault-tests
python3 tests/local/security.py
python3 tests/local/e2e.py
python3 tests/local/crash_matrix.py
```
`.github/workflows/ci.yml` lists the complete set (crash matrices, incremental, WAL,
streaming). Changes to the journal, the engine or the transport need a test that fails
without the change; killing the process at the relevant point must stay duplicate-free.

## Rules of thumb
- Small, focused commits; explain *why* in the message.
- Do not relax `synchronous=FULL`, merge or remove a durable commit, skip read-back
  verification or change recovery semantics without a written design and review.
- The `vendor/` patches are required; see `vendor/README.md`.
- Licensed MIT; by contributing you agree your work is under the same license.
