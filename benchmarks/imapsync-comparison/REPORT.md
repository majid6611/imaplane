# IMAPLANE vs imapsync: benchmark and profiling report

Status: **local, unpublished, for review.** Nothing was pushed. No real provider was contacted. IMAPLANE was
benchmarked **unmodified** at commit `a6ec32f` (release build); optimization experiments used an isolated diagnostic
copy of the source that is not part of the repository.

## 1. Setup in one paragraph

One laptop (AMD Ryzen 3 5300U, 8 threads, 7.1 GiB RAM, NVMe ext4, Docker 29.6.1, kernel 6.14). Two identical
Dovecot 2.3.21 containers (source, destination; 2 CPUs / 2 GiB each) on a private Docker network per run. Both tools
run in the same runner image under the same limits (2 CPUs / 2 GiB) and the same measuring wrapper. imapsync 2.314
(upstream script, SHA-256 `89faed96...`). Dataset "mixed": 3,280 messages / 395 MB in 9 folders (4 levels of nesting,
a Unicode folder, an empty folder), messages from 228 B to 7.3 MB, base64 attachments, 8-bit and long-line bodies,
messages without Message-ID, empty bodies, the common flags plus keywords, dates 2015-2024 in eight time zones, and
**four kinds of duplicate-looking mail** (byte-identical pairs, same Message-ID with different bodies, same body with
different dates and flags, the same message in two folders). Correctness is checked by an independent verifier that
fetches both servers and compares **multisets** of (SHA-256, flags, INTERNALDATE), so a doubled message can never be
counted as a copy and a dropped one cannot hide behind a duplicate. Full method, commands and isolation rules:
[README.md](README.md). Repetitions: 3 for the main comparison, 2 for the scaling tests, 4 kills per tool; order
randomized (interleaved) within each repetition. Run-to-run spread was small (min-max within 1-3% for every cell).

## 2. Verification levels are not equivalent (read this first)

| | what it proves about a message after the run |
|---|---|
| **IMAPLANE `migrate` (fresh)** | every copied message was read back from the destination and compared by **SHA-256**, INTERNALDATE and flags before it is called confirmed |
| IMAPLANE `--incremental` default rerun | existence + size/INTERNALDATE/flags **metadata** only. Content is **not** re-read; same-length corruption is not noticed |
| IMAPLANE `verify` / `--verify-history full` | full SHA-256 read-back of every message |
| imapsync (default and tuned) | a message is considered present if its **header-derived identifier** matches; content is not compared, there is no read-back. A rerun compares headers/ids only |

So IMAPLANE's fresh copy does more work than imapsync's (an extra read of every message). Where numbers are compared
below, that difference is stated. imapsync's own "tuned" variant (`--nofoldersizes --nofoldersizesatend --useuid`
with its UID cache on a persistent volume) is reported separately from its defaults.

## 3. Results

### 3.1 Fresh migration, mixed dataset (3,280 messages, 395 MB; medians of 3)

| | imapsync | imapsync tuned | IMAPLANE | IMAPLANE streaming |
|---|---|---|---|---|
| wall time | **64.7 s** | 65.9 s | 244 s | 240 s |
| messages/s, MiB/s | 50.7, 5.8 | 49.8, 5.7 | 13.4, 1.5 | 13.7, 1.6 |
| CPU time | 16.0 s | 15.5 s | 32.2 s | 26.1 s |
| peak RSS | 196 MiB | 193 MiB | 35 MiB | **17 MiB** |
| IMAP commands (both servers) | 6,517 | 6,678 | 16,473 | 16,473 |
| network (tool container, TLS included) | 808 MB | 819 MB | 1,226 MB | 1,241 MB |
| disk written by the tool | 1 MB | 1 MB | **484 MB** | **484 MB** |
| messages copied exactly | **3,120 / 3,280** | 3,280 / 3,280 | 3,280 / 3,280* | 3,280 / 3,280* |

\* 30 messages carry the `\Deleted` flag in the source; IMAPLANE never copies `\Deleted` (documented design), so its
copy differs from the source in that one flag for those 30 messages. The verifier reports this separately as
"only `\Deleted` differs"; content and dates are exact. imapsync copies the flag.

imapsync (default) left 160 source messages uncopied in all 3 runs and exited 0: its header-based duplicate
detection treats exact duplicates and same-Message-ID messages as "already there". No duplicates, nothing foreign.
This is imapsync's documented design, and `--useuid` (tuned) copies all of them.

### 3.2 No-change rerun and new mail (mixed dataset, medians)

| | imapsync | imapsync tuned | IMAPLANE | IMAPLANE streaming |
|---|---|---|---|---|
| rerun, nothing changed (**default level**) | 2.1 s, 301 cmds | 1.2 s, 106 cmds | **0.4 s, 74 cmds** (metadata) | 0.4 s |
| rerun, existence only | | | 0.4 s, 81 cmds | 0.4 s |
| rerun with **full content check** (`--verify-history full` / `verify`) | no equivalent | no equivalent | 7.7-7.9 s, 6,6xx cmds | 5.6-6.0 s |
| 200 new messages, default level | 6.0 s | 4.9 s | 15.2 s, 1,079 cmds | 14.9 s |
| 200 new messages + full history re-verify | no equivalent | no equivalent | 22.9 s, 8,029 cmds | 20.7 s |

All new-mail steps were verified exact with no duplicates. IMAPLANE's cheap default rerun is **not** a content check
(section 2); its full check of 395 MB takes about 8 s.

### 3.3 Scaling (small messages; medians of 2; copy exact in every run)

| messages (size) | imapsync | imapsync tuned | IMAPLANE | IMAPLANE peak RSS |
|---|---|---|---|---|
| 1,000 (2 MB) fresh | 17.8 s | 17.4 s | 68.7 s | 16 MiB (imapsync 176) |
| 5,000 (9 MB) fresh | 86.4 s | 84.7 s | 343 s | 21 MiB (imapsync 184) |
| 1,000 rerun, default level | 1.1 s | 0.8 s | 0.2 s | |
| 5,000 rerun, default level | 2.5 s | 1.3 s | 0.3 s | |
| 5,000 rerun, full content check | none | none | 3.0-3.7 s | |

IMAPLANE's cost is **linear at about 69 ms per message regardless of message size or job size** (disk writes about
150 KB per message). The 20,000-message test was deferred, as agreed, until after optimization.

### 3.4 Interrupted migrations: SIGKILL during the transfer, then resume (4 kills per tool; every message checked afterwards)

| | imapsync | IMAPLANE | IMAPLANE streaming |
|---|---|---|---|
| kills / killed at (fraction of a normal run) | 4 | 4 | 4 |
| **duplicate messages after resume** | **0** | **0** | **0** |
| resume time, median | 37 s | 80 s | 121 s |
| destination exact after **one plain rerun** | 4/4 (same 160 skipped as an uninterrupted run) | 3/4 | 2/4 |
| needed an **operator step** (`recover`/`resolve`) | 0/4 | 2/4 | 2/4 |
| exact after the documented operator steps | 4/4 | **4/4** | **4/4** |
| messages silently lost | 0 | 0 | 0 |

When the kill lands between "message delivered" and "journal records it", IMAPLANE leaves exactly one message
`uncertain` and refuses to guess; its destination was sometimes already complete, but the tool cannot prove it
without the operator step. imapsync re-derived the state from the destination by itself every time. Both tools
produced zero duplicates; IMAPLANE's price for its stronger evidence is a manual step in about half the kills.
The sample is small (4 per tool), so read these as counts, not rates.

## 4. Correctness and recovery comparison

* **Copy completeness:** IMAPLANE copied every message, including every duplicate-looking one. imapsync default
  skipped 160 of 3,280 and reported success; tuned imapsync copied all.
* **Content, dates, flags:** exact for both, with IMAPLANE omitting `\Deleted` by design.
* **Source immutability:** unchanged in every run of both tools.
* **Crash behavior:** no duplicates and no silent loss in 12 SIGKILLs. IMAPLANE: conservative and journalled, may
  need `recover`/`resolve`. imapsync: automatic, because it re-matches by header id.
* **Both tools are idempotent** on a no-change rerun when configured correctly. Misconfigured, imapsync is not:
  see the harness defect H1 below, where `--useuid` without a persistent cache re-copied the whole mailbox on every
  run and accumulated duplicates (a real trap for imapsync users, though caused by my container setup).

## 5. Where imapsync is ahead of IMAPLANE (do not read this as a closed list)

1. Fresh-copy speed: **3.8x faster** here (mixed), and for every small-message size tested.
2. Automatic resumption after a hard kill, with no operator step.
3. Feature breadth beyond this test (not evaluated): OAuth flows, folder renaming, filters, sync of deletions.
4. Rerun: for a no-change rerun with comparable header-level confidence imapsync's 1.2-2.1 s is fine, though
   IMAPLANE's default (0.4 s) is faster, and not comparable in strength.

No case was found where IMAPLANE failed to copy a message that imapsync copied correctly, apart from `\Deleted` flags
by design. IMAPLANE's weaknesses seen here are speed, disk write volume, network volume (read-back, inherent to exact
verification) and the manual step after some crashes.

## 6. Harness defects, listed separately from product defects

| # | Harness defect | Effect | Fix |
|---|---|---|---|
| H1 | `imapsync-tuned` (`--useuid`) cache in imapsync's temp dir was lost between throwaway containers | tuned reruns re-copied everything and created duplicates; those steps invalidated and redone as `main-mixed-tuned-fixed` | cache on the persistent volume |
| H2 | a second launch of the stage script rebuilt a golden dataset under a running stage | one scaling stage crashed, no data recorded | execution lock, per-run networks/containers/directories, read-only golden copy with hash checks before and after every run, stale-state preflight |
| H3 | password file mode 0644 | IMAPLANE (correctly) refused it | mode 0600 |
| H4 | Dovecot image has no `rawlog` plugin | no command counting | switched to Dovecot's exported `imap_command_finished` events |
| H5 | profiling shim injected into the measuring script, output file name collided | first shim run unusable | shim attached to the tool process only, own file |
| H6 | verifier time conversion used UTC for a local-time tuple; golden-manifest comparison was order sensitive | caught by the golden dataset self-check before any result | fixed before use |
| H7 | stale-process check matched my own shell | false refusal | pattern tightened |

**Product defects found by the benchmark: none affecting correctness.** One product behavior matters for users:
journal commit cost (below). IMAPLANE's `status` bug found during I4 regression was fixed before this benchmark.
Invalid or discarded runs are kept and listed in `results/INVALID.md`.

## 7. Where the time goes (profiling; analysis only)

Method: the same 1,000-message copy (68 s), observed from outside the **unmodified** release binary with an
LD_PRELOAD shim (fsync/write counts per file), IMAPLANE's own `--diagnostics-file`, Dovecot's per-verb accounting,
and an isolated diagnostic build with timers and experiment switches. Raw data: `results/profile-*`.

| Component (1,000 messages, 68 s) | Time | Share |
|---|---|---|
| 4 durable journal commits per message (planned, literal-authorized, acknowledged, confirmed), ~12.3 ms each | 49 s | **72%** |
| destination APPEND processing inside Dovecot (13 ms each; imapsync pays the same) | 13-15 s | |
| read-back (fetch + SHA-256) | 1.8 s | 3% |
| source read | 1.7 s | 2% |

Cause: the journal runs SQLite in its **default rollback-journal mode** with `synchronous=FULL`. Each commit creates,
syncs and deletes a journal file and syncs the database and its directory: **16,025 fsyncs, 46.9 s, 4,006 journal
files created and deleted, 114 MB of journal writes** per 1,000 messages.

Experiments (isolated build; each row changes one thing, runs verified exact):

| Variant (1,000 messages) | wall | fsync/fdatasync | commit | disk writes | acceptable? |
|---|---|---|---|---|---|
| production (rollback journal, FULL) | 67.2 s | 16,025 fsync | 12.3 ms | 146 MB | baseline |
| rollback, TRUNCATE journal mode | 81.3 s | | | | slower |
| rollback, PERSIST journal mode | 85.6 s | | | | slower |
| rollback, FULL, **fdatasync** build | 52.9 s | 16,024 fdatasync (2.0 ms each) | 8.4 ms | 146 MB | yes |
| **WAL, FULL** | **34.5 / 36.1 s** | 4,051 fsync (3.9 ms) | 4.1 ms | 58 MB | yes |
| **WAL, FULL, fdatasync** | **28.3 s** | 4,050 fdatasync (2.1 ms) | 2.3 ms | 58 MB | yes |
| WAL, NORMAL sync | 18.2 s | 48 | 0.2 ms | 42 MB | **no** (loses durability) |
| rollback, sync OFF | 19.3 s | 13 | 0.4 ms | 0 | **no** |
| skip read-back | 53.7 s | | | 121 MB | **no** (removes exact verification) |

On the mixed dataset (3,280 messages, 395 MB): production 244 s; fdatasync only 205 s; **WAL + fdatasync 81.6 s**
(disk writes 484 MB -> 194 MB), with the destination verified exact. With the journal cost removed entirely IMAPLANE
would run at about the speed of imapsync's 17.8 s on the small set, so the whole gap is journal durability cost.
Absolute fsync latency is a property of this machine's storage (about 2-4 ms); on faster-fsync storage the gap
shrinks, on slower it grows.

## 8. Ranked optimization proposals (all preserve durability, exact verification and duplicate prevention)

Nothing below has been implemented in the product.

**1. WAL journal mode, `synchronous=FULL` unchanged.** Measured: -48% wall time (67 -> 34.5-36.1 s per 1,000
messages), -60% disk writes. Every commit is still fsynced before it returns, so the pre-literal fence, the
acknowledged-before-verify ordering and all state transitions keep their meaning.
* Risks: the journal becomes three files (`-wal`, `-shm`); moving or copying only the main file loses committed data
  (must be documented and guarded); WAL does not work on network filesystems (detect and fall back to rollback mode
  with a warning); read-only `status` needs access to the `-shm` (or immutable/`mode=ro` handling); one-time
  conversion of existing journals; `backup_before_upgrade` and schema-upgrade paths must be re-proven with a pending
  WAL; checkpoint and file-size growth need a policy (`journal_size_limit`, checkpoint at exit).
* Tests required: both crash matrices and the randomized SIGKILL stress in normal and forced-spool modes; fault
  points for every commit; reopen/recovery with a non-empty WAL; read-only `status`, `verify`, dry run; upgrade and
  backup with pending WAL; journal copied without sidecars (must refuse or warn); network-filesystem fallback;
  schema 1-5 jobs converting safely.

**2. `fdatasync` instead of `fsync` for SQLite (standard Linux SQLite configuration, enabled with the
`HAVE_FDATASYNC` build define for the bundled SQLite).** Measured: per-sync cost 3.9 -> 2.0 ms; another -20%
(34.5-36.1 -> 28.3 s with WAL; 67 -> 52.9 s without). Together with #1: **-58% on the small set (67 -> 28 s) and
-67% on the mixed set (244 -> 82 s)**.
* Risks: a build-flag change; durability equivalence relies on SQLite's own use of fdatasync (it flushes the data and
  the size needed to read it back); should be confirmed with the shim (counts) and, ideally, on a second filesystem.
* Tests: shim-based assertion that fdatasync (not fsync) is used and counted per commit; the same crash and stress
  suites as #1; build reproducibility check.

**3. One round trip instead of two for small messages, on the source read and the destination read-back.** Today
each message needs a size FETCH and then a body FETCH on both sides (5 commands per message; 3 would do). Measured
now: only about 1.5-2 ms per message of 28 on this LAN (about 6%), because the round trip is cheap here. **Expected to
matter more on a real network** (two fewer sequential round trips per message, about 40% of the exchanges); not
measured, because this benchmark ran at LAN latency. Bounded fetch (`BODY.PEEK[]<0.limit>` plus `RFC822.SIZE`) keeps
the memory bound; larger messages keep the existing streaming path.
* Risks: the size pre-check exists to enforce `max_message_bytes` and the streaming threshold before reading;
  size-mismatch and permanent-error classification must stay identical.
* Tests: the existing size-mismatch, truncation, streaming-equivalence and permanent-error tests for both paths;
  a latency-injected benchmark to quantify the gain before deciding.

Considered and **rejected** because they would weaken a guarantee: `synchronous=NORMAL` or OFF; merging the
"prepared" and "literal authorized" commits (weakens the pre-literal fence); merging "acknowledged" and "confirmed"
(more uncertain records after a crash); skipping or deferring the read-back; MULTIAPPEND or `LITERAL+` (conflict
with per-message acknowledgement and the pre-literal fence). Higher-risk, larger-effort options for later:
overlapping message N's read-back with message N+1's APPEND, and parallel folder workers; both need an extended crash
model first.

Projected result of #1-#3 on the mixed dataset: about 75-80 s against imapsync's 65 s, i.e. roughly 1.2x, while still
doing a full read-back and a durable journal.

## 9. Independent judgment

* **Safety and correctness: IMAPLANE is clearly better.** It copied everything exactly (including 160 messages
  imapsync's default silently skipped), proves every copy by read-back, kept the source untouched, and survived 8
  SIGKILLs without a duplicate or a loss; its evidence-based recovery is the point of the design.
* **Convenience after a crash: imapsync is better.** It resumes by itself; IMAPLANE needed an operator step in about
  half the kills (small sample).
* **Speed today: imapsync is better, by about 3.8x.** This is a measured, explained, fixable cost of the journal
  configuration, not of verification (read-back is 3% of the time) or the Rust engine.
* **Memory: IMAPLANE is better** (17-35 MiB against about 190 MiB).
* **No-change reruns: not comparable.** IMAPLANE's default is faster but weaker; its full check has no imapsync
  equivalent; imapsync's tuned rerun is fast and header-level only.
* **Not covered here (inconclusive, do not extrapolate):** wide-area latency, real providers (Gmail/Microsoft 365),
  mailboxes beyond 5,000 messages (20,000 deferred), concurrent jobs, other IMAP servers, and imapsync features
  outside this test. Measurements come from one laptop, one filesystem, one Dovecot version.
