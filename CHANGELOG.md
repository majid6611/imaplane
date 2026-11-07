# Changelog

All notable changes are listed here. This project follows semantic versioning; while
the version is 0.x, command-line options, report formats and journal schema versions
may change (journal upgrades keep a verified backup and never discard evidence).

## [0.1.0] - unreleased (technical preview)

### Added
- Additive, resumable IMAP-to-IMAP migration with read-only source access, strict
  TLS/STARTTLS, PLAIN/LOGIN/XOAUTH2, Unicode folder names, flags and INTERNALDATE.
- Durable SQLite journal with four commit boundaries per message and a pre-literal
  authorization fence; `uncertain` handling with `recover`, `resolve`, `skip`, `unskip`.
- `verify` with exact content, date and flag checks; `status` for offline inspection.
- Incremental migration (`migrate --incremental`, `--add-new-folders`,
  `--verify-history`), tiered verification (existence, metadata, full SHA-256) and
  flag-drift reporting (journal schema 5, explicit upgrade).
- Optional bounded-memory disk spool for very large messages (off by default).
- DEB and RPM packages (amd64; arm64 build scripts), third-party license notices,
  and the `oauth_token.py` helper for XOAUTH2 access tokens.

### Performance (no change to durability guarantees)
- Write-ahead-log journal with `synchronous=FULL` (one sync per durable commit),
  `fdatasync` instead of `fsync`, and one IMAP round trip for messages up to 128 KiB.
  On the benchmark set a full copy went from 245 s to about 105 s; tuned imapsync
  took about 66 s. See `benchmarks/imapsync-comparison/REPORT.md`.

### Security
- Credential and token files must be private, owned by you and not symlinks;
  the state directory must be 0700; the journal and its `-wal`/`-shm` files are 0600.
- Bundled SQLite 3.51.3 (fixes the WAL-reset bug present in 3.7.0–3.51.2); the program
  refuses to use WAL with an older SQLite.

### Known limitations
- Tested only against Dovecot and scripted protocol fixtures. Gmail and Microsoft 365
  are untested with live accounts.
- arm64 packages are built by the workflow but have no runtime test evidence.
- An uncertain message whose literal was authorized and that has no destination
  candidate needs manual review by design; there is no force-retry.
