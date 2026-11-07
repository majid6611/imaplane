# Technical gap list for a public v0.1 Linux CLI

> **Status update (release readiness audit, commit 6f4662d + hygiene commits).** The original
> list below was written before the incremental, performance and WAL work. Current state:
> incremental migration (schema 5, tiered verification, `--add-new-folders`), the WAL journal,
> `fdatasync` and the single-exchange read are implemented and covered by the regression, crash
> and stress suites; `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, a quick start and an
> exit-code table now exist; the OAuth helper ships in the packages. **Still open:** live-provider
> validation (Gmail / Microsoft 365, blocker 1), a tagged release dry run and arm64 runtime
> evidence (blocker 6, SHOULD 10), the streaming-default decision (blocker 4; streaming stays
> off by default), an independent review (15), and the parts of 8/9/11/12 not named above.
> The text below is kept as the historical plan; where it says "nothing implemented" it is stale.

Scope: a reliable, usable **v0.1 preview of the Linux command-line tool**, not enterprise features.
This is a plan, not work done; nothing here has been implemented. Items are tagged
**BLOCKER** (do not tag v0.1 without it), **SHOULD** (strongly recommended) or **LATER**.
"Verified" means checked in this repository; "assumed" means not yet evidenced.

## State today (verified)

- CLI: `inspect`, `migrate` (`--dry-run`), `verify`, `resolve`, `recover`, `skip`, `unskip`, `status`,
  plus opt-in `--diagnostics-file`. Journal schema 4; report format versioned.
- (Historical snapshot; see the status update above.)
- Safety design and tests: durable journal, pre-literal authorization fence, exact read-back, source
  read-only, conservative uncertain handling, crash matrices, randomized kill stress, disk-full tests.
- Optional bounded-memory transfer (disk spool), off by default: peak RSS about 15 MiB up to the
  1 GiB message maximum.
- CI (fmt, clippy, unit, Dovecot e2e, reliability, crash matrices, memory job) and a release workflow
  that builds `.deb` and `.rpm` for amd64 and arm64 and installs them in clean containers.
- MIT licensed, third-party licenses collected, `rust-version = "1.85"`.

## BLOCKERS

1. **No live-provider validation.** Everything was proven against Dovecot and scripted servers.
   Gmail and Microsoft 365 behaviour (UIDPLUS/APPENDUID, byte-exact read-back, de-duplication,
   throttling, size limits, OAuth) is unverified. Phase 5B, awaiting your approval and disposable
   accounts. A v0.1 should state exactly which servers were tested.
2. **OAuth is not usable from the package.** Gmail and Microsoft 365 need XOAUTH2. The token helper
   (`scripts/oauth_token.py`) is not shipped in the packages, the README says there is no built-in
   OAuth client, and the Google setup is a long manual document. Decide: ship and document the helper
   (smallest change), or add an `imaplane auth` command. Microsoft's flow is untested.
3. **No incremental run.** A job is a fixed UID snapshot; mail that arrives later needs a new job.
   Users will expect "run again to catch up". Either document the supported procedure clearly
   (new job, or a re-plan command) or implement the minimal safe re-plan. This is the next priority
   you named; it needs a design that preserves duplicate prevention across jobs.
   Approach approved with conditions; revised design and phases awaiting approval: `docs/INCREMENTAL_DESIGN.md`. Plans for blockers 2, 5, 6, 7: `docs/V0_1_ROADMAP.md`.
4. **Streaming default and Phase 5 sign-off.** Decide and document the default and the explicit
   buffered fallback after Phase 5A risks are reviewed (see the Phase 5A report).
5. **Release hygiene files are missing:** `SECURITY.md` (how to report), `CONTRIBUTING.md`,
   `CHANGELOG.md` (and a `CODE_OF_CONDUCT.md` if you want one). `Cargo.toml` has `publish = false`;
   decide the distribution channel (GitHub Releases plus packages is enough for v0.1).
6. **Release workflow never exercised on a tag.** Verified: it exists and matches the tag to the
   manifest. Assumed: it works end to end, including arm64. Do a tagged dry run on a private branch
   and install the artifacts on a clean amd64 and a clean arm64 host.
7. **User documentation is not v0.1-grade.** The README is 499 lines of design and guarantees with no
   quick start, no exit-code table, and no operator guide for the `uncertain`, `recover`, `resolve`
   and `skip` workflow. A new user cannot get from install to first successful migration quickly.

## SHOULD

8. **Supply-chain checks in CI.** No `cargo audit` or `cargo deny` runs in CI (it was run by hand
   earlier). Add it, and a policy for the two patched vendored crates (track upstream, plan to
   upstream or fork).
9. **Packaging contents.** Packages omit the newer design and validation documents; add man page and
   shell completions (clap can generate them); decide whether the examples directory and helper
   scripts ship.
10. **ARM64 runtime evidence.** Spool and streaming code compile-checks for aarch64 only. Run the
    spool, streaming and crash suites natively on an arm64 runner before claiming arm64.
11. **Documented compatibility matrix.** Which servers, which authentication modes, UIDPLUS required,
    maximum message size (1 GiB), folder-name handling, flags kept or omitted. Today this is spread
    across the README and the provider guide.
12. **Stable, documented output contract.** Exit codes (0, 1, 2) in one table; report and journal
    format versions; what is guaranteed not to change in 0.x.
13. **Operational guardrails around the spool:** warn when `spool_dir` shares a filesystem with the
    journal on a nearly full disk; a one-line startup note when streaming is enabled; document disk
    encryption responsibility.
14. **CI time and flakiness budget.** The Docker suites are long; split required checks from the
    nightly soak, stress, cgroup and filesystem suites and keep the new Phase 5A suites out of the
    required path except the offline ones.
15. **Independent review.** Audits so far were by the same assistant family; an external reviewer
    pass on the journal, the authorization fence and the vendored client patches would add real
    assurance before a public announcement.

## LATER (explicitly not v0.1)

- Parallel transfers, bandwidth throttling, progress/ETA, subscription and Gmail-label mapping,
  flag/delete synchronisation, automatic folder mapping, daemon or scheduler, web dashboard,
  multi-account orchestration, Windows and macOS.
- Size prefilter for candidate scans (schema 5), if benchmarks justify it.
- An imapsync comparison harness (planned once streaming passes final validation).

## Suggested order

Phase 5A report review, then 5B (needs your accounts), then blockers 2, 3, 5, 6, 7 in parallel, then the
SHOULD items, then a release candidate on a private branch with the dry-run artifacts tested on clean
hosts.
