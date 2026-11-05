# v0.1 roadmap for the offline blockers

Status: **plan only; nothing here is implemented.** Decisions recorded: ship the existing Python OAuth helper after a security review; `SECURITY.md` points to GitHub Private Vulnerability Reporting (no personal email); `CODE_OF_CONDUCT.md` optional; release dry runs happen locally first and no test branch is pushed without separate approval; streaming stays off by default pending live-provider validation. Complements `docs/V0_1_GAP_LIST.md`
(blockers 2, 5, 6, 7). Incremental migration is in `docs/INCREMENTAL_DESIGN.md`. Phase 5B (live
providers) stays on hold, and streaming stays off by default. Nothing is pushed or published.

Order: A (hygiene files) and D (docs) are independent and cheap; B (OAuth helper) needs one decision;
C (release dry run) should come last so it exercises the final package contents.

## A. SECURITY.md, CONTRIBUTING.md, CHANGELOG.md (about half a day)

| File | Content | Notes |
|---|---|---|
| `SECURITY.md` | Supported versions (0.x: latest only); how to report privately (GitHub private vulnerability reporting, or an address you choose); what is in scope (journal integrity, source mutation, credential handling, spool exposure); response targets stated as intentions, not promises; the plaintext-spool and secret-file caveats. | Uses GitHub Private Vulnerability Reporting (decided). **Needs from you later:** enabling it in the repository settings; it cannot be checked offline. No email address is published. |
| `CONTRIBUTING.md` | Build and test commands exactly as CI runs them (Docker-based, nothing installed on the host); the 12 safety invariants as a review checklist; rule that a safety-relevant change needs a test that fails without it; the fault-injection and stale-binary guard; commit style; how to run offline suites. | Mostly assembled from `docs/H5_SAFETY_AND_RESULTS.md` and CI. |
| `CHANGELOG.md` | Keep a Changelog format; an `[Unreleased]` section and a `0.1.0` draft built from the commit history: streaming transfer (off by default), skip and unskip, diagnostics, schema 4. States compatibility (journal schema, report version). | One entry per user-visible change; checked in review. |

Also decide on `CODE_OF_CONDUCT.md` (optional) and whether `Cargo.toml` `publish = false` stays. It
should: distribution for 0.1 is GitHub Releases plus `.deb` and `.rpm`.

Check: a CI step that fails if `CHANGELOG.md` lacks a heading for the manifest version on a tag build.

## B. Packaging the OAuth helper securely (about 1 to 2 days, one decision)

Today `scripts/oauth_token.py` (278 lines, standard library only) is not in the packages, and the
tool has no built-in OAuth client (README), so Gmail and Microsoft 365 users cannot authenticate
from an installed package.

**Decided:** (1) ship the existing helper as an installed script (not an `imaplane auth` subcommand): smallest change, no new dependency in
the migration binary, and the migration process never handles refresh tokens.

Plan for option (1):

1. Install as `/usr/bin/imaplane-oauth` (python3 declared as a package dependency), plus
   `/usr/share/doc/imaplane/GOOGLE_OAUTH_SETUP.md`. Add a Microsoft guide only after it is tested
   (untested today; it must be labelled so).
2. Security review of the helper before shipping: loopback redirect only (127.0.0.1, random port),
   PKCE and `state` verified (check), token files created `0600` in a `0700` directory via
   `O_EXCL`/atomic rename (check), tokens and client secrets never printed or logged, refusal to run
   if the target path is inside a Git work tree, no use of `HTTP_PROXY`-style env that could leak
   the code, TLS verification on for the token endpoint, timeouts, no shell invocation.
3. Offline tests (no network): the existing `provider_tools` suite plus new ones against a local
   fake token endpoint: state mismatch rejected, permissions of output files, secret-leak scan of
   stdout and stderr, refresh path, error body never echoed.
4. Package test (`scripts/test-package.sh`): file present, executable, `--help` works in a clean
   container, no secrets in the package (scan).
5. Document how a long-running migration obtains a fresh access token (the access-token file is
   re-read; refresh is the helper's job). State the real limit: access tokens expire in about an
   hour, so a long run needs the helper's refresh loop or a re-run. Check how the engine reacts to an
   expired token mid-run before documenting it.

Not in scope: storing secrets in a keyring, a GUI, bundling client credentials.

## C. Testing the release workflow without publishing (about 1 day)

Verified: `.github/workflows/release.yml` already builds and tests on `pull_request` and
`workflow_dispatch`, and the `publish` job only runs on a pushed `v*` tag. So a build dry run does
not publish. Gaps and plan:

1. **Local rehearsal, no GitHub:** run `scripts/build-packages.sh deb amd64` and `rpm amd64`, then
   `scripts/test-package.sh` on both (Docker only). arm64 cannot run locally (no emulation here).
2. **Remote dry run:** with your approval to push a throwaway branch (this is a push, so it needs
   it), trigger `workflow_dispatch`; check all four matrix cells, including the two arm64 cells,
   which have never run. This is also the first native arm64 test of the spool and security suites.
3. **Make the tag path testable without a tag:** add a `dry_run` input to `workflow_dispatch`; when
   set, the `publish` job runs its checksum and notes steps but replaces the final release call with
   a listing, so the publish logic itself is exercised. Guard: the real call requires
   `github.ref_type == 'tag'` and `dry_run != true`.
4. **Pin and review the actions:** pin third-party actions by commit SHA (they use floating major
   tags now) and keep `permissions` minimal (already `contents: read`; `write` only on publish).
5. **Artifact checks:** installed file list matches an expected manifest; `--version` equals the
   manifest and tag; SHA256SUMS verified from the downloaded artifacts; reproducibility note (two
   builds, compare, or state it is not reproducible).
6. **Rollback plan** written in `docs/PACKAGING.md`: how to yank a bad release.

Exit criterion: one green dry run on all four cells, install tests on clean amd64 and arm64 hosts,
and a documented list of exactly what a tag push will do.

## D. Installation and user documentation (about 2 to 3 days)

The README is 499 lines of design and guarantees without a path from install to first migration.

1. **Split the README.** Short README: what it is, the safety promise in five lines, install,
   five-minute quick start, link out. Move the design and guarantee text to `docs/` (largely
   already there).
2. **Install guide:** `.deb`, `.rpm`, build from source (Rust 1.85, OpenSSL), checking the checksum,
   uninstall. Only methods that were tested are listed.
3. **Quick start** against a local Dovecot (Docker), copy-pasteable, ending with a successful
   `verify`. This doubles as an end-to-end docs test run in CI.
4. **Reference pages:** every config key with default and unit (generated or checked against
   `config.rs` so they cannot drift); an exit-code table (0 complete, 1 error, 2 incomplete or
   needs attention); report and journal format versions and the 0.x stability promise.
5. **Operator guide for the unhappy paths:** `uncertain`, `recover`, `resolve`, `skip`, `unskip`,
   rejection scopes, and what to do after a crash or a full disk. One worked example each, using
   real output from the test fixtures.
6. **Server compatibility matrix:** tested (Dovecot, scripted fixtures), untested (Gmail, Microsoft
   365, others), requirements (UIDPLUS, TLS), limits (1 GiB message). Today this is split over
   three documents.
7. **Man page and shell completions** generated from clap at build time and shipped in the packages.
8. **Streaming section:** off by default, how to turn it on, the plaintext-spool warning, spool
   sizing, shutdown timing for huge messages. Written to the facts in `docs/STREAMING_DESIGN.md`.
9. **Docs check in CI:** link check, config-key coverage test, quick-start run.

## Suggested sequence and gates

1. A and D in parallel; B after the helper decision; C last.
2. Gate for starting incremental migration: your approval of `docs/INCREMENTAL_DESIGN.md`.
3. Gate for any push, any dry run on GitHub, and any provider contact: your explicit approval.

## What I need from you

1. A security-reporting channel for `SECURITY.md`.
2. OAuth: ship the helper (recommended) or build `imaplane auth`.
3. Whether I may push a throwaway branch for the CI dry run, when we get there.
4. Whether a `CODE_OF_CONDUCT.md` is wanted.
