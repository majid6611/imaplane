# Write-ahead-log journal (Phase 1 of the performance work)

Status: implemented in the commit that adds this file. Nothing here relaxes a durability setting: the journal
still commits with `synchronous=FULL`, and the four durable commit boundaries per message and the pre-literal
authorization fence are unchanged. Only the way SQLite makes each commit durable changed.

## 1. Why this was deferred, and the root cause

The H5 safety work (`docs/H5_SAFETY_AND_RESULTS.md`) excluded WAL on purpose. Reason: SQLite's **WAL-reset bug**
(<https://www.sqlite.org/wal.html#walresetbug>, found and fixed 2026-03-03):

* Present in every SQLite from 3.7.0 (2010) through **3.51.2**; fixed in **3.51.3** (2026-03-13), with backports 3.50.7
  and 3.44.6. IMAPLANE bundled **3.51.1** (`libsqlite3-sys 0.36.0`), an affected release.
* Mechanism: a checkpoint completes; a second checkpoint starts; while it starts, **another connection** commits a
  transaction that resets the WAL and writes at its start; because of a data race the second checkpoint does not notice
  the reset and leaves a wrong "already checkpointed" field in the WAL index; later commits grow the log; a third
  checkpoint then skips part of the transaction written in step 3, which never reaches the database file. Result:
  corruption.
* Precondition: **two or more connections, in separate threads or processes, writing or checkpointing the same WAL
  database at the same instant.** The SQLite team could not reproduce it without a special test hook; a later
  reproducer without the hook exists (linked from the advisory). Consequences are serious but the exposure needs
  concurrent writers.

IMAPLANE's exposure, analysed: a job has exactly one writer. `job.lock` (an exclusive file lock taken before the
journal is opened) excludes every second migrating process; a second process refuses with "another process holds this
migration job lock". `status` and the incremental dry run open the journal **read-only** (no lock) and a read-only
connection can neither write nor checkpoint. Inside the process there is one write connection. So the precondition
(two concurrent writers or checkpointers) does not arise in normal operation, and the earlier decision not to rely on
that argument alone, with an unpatched library, was correct. Phase 1 therefore does both:

1. **Removes the vulnerable library**: `rusqlite 0.38.0` -> `0.39.0`, `libsqlite3-sys 0.36.0` -> `0.37.0`, which bundles
   **SQLite 3.51.3**, the first release with the fix (checked in the vendored header, `SQLITE_VERSION "3.51.3"`). Exactly
   those two packages change in `Cargo.lock`; the code needed no source change. (`rusqlite 0.40.2` / `libsqlite3-sys
   0.38.2` bundle 3.53.2; the minimal fixed version was chosen to keep the dependency change small.)
2. **Guards at run time**: write-ahead logging is never enabled, and an already-WAL journal is refused, if the linked
   SQLite is older than 3.51.3 (`wal_safe_version`, also asserted by a test against the bundled library).
3. **Keeps the single-writer architecture**, documented here as a requirement: any future feature that adds a second
   writing or checkpointing connection to the journal needs its own review.

## 2. What changed

| | before | now |
|---|---|---|
| journal storage | SQLite rollback journal (default), `synchronous=FULL` | write-ahead log, `synchronous=FULL` (verified after every switch) |
| fsyncs per commit | 4 (measured: 2 on the rollback journal, 1 on the database, 1 on the directory) | 1 (the log; measured 35 syncs for 32 commits including setup) |
| files | `journal.sqlite3` (+ a transient `-journal`) | `journal.sqlite3` plus `-wal` and `-shm` while a job runs; a clean exit checkpoints and removes them |
| commits per message | 4 durable commits | **unchanged: 4** (prepare, literal-authorized, acknowledged, confirmed) |

Why the durable guarantee is unchanged: with `synchronous=FULL`, SQLite syncs the log before a commit returns, in
WAL mode exactly as in rollback mode. A killed process leaves a pending log that the next open recovers; a torn log
tail is discarded back to the last whole commit (tested by cutting a real log at 20+ offsets).

## 3. Rules the code enforces

* **When WAL is enabled**: only on a write open (`migrate`, `verify`, `resolve`, `recover`, `skip`, `unskip`), only if
  SQLite >= 3.51.3, only if the state directory is not on a filesystem where WAL cannot be trusted
  (NFS, SMB/CIFS, FUSE, 9p, NCP, AFS, Ceph, Lustre, vboxsf, OCFS2; judged from `statfs`). Otherwise the journal stays in
  rollback mode and a warning is printed (safe, slower).
* **After any switch** the connection is checked: `journal_mode` really is `wal` and `synchronous` really is `FULL`
  (2); anything else refuses to continue. `journal_size_limit` is set to 16 MiB so a finished log does not stay large.
* **Existing journals**: converted once, on the first write open, after a **verified backup** (`journal.sqlite3.prewal.bak`,
  `quick_check`-verified, never overwritten; if a schema-upgrade backup is made in the same open, that one covers it). A new
  empty journal has nothing to protect and gets no backup. Conversion changes no row (tested). A journal can be moved
  back with `journal_mode = "rollback"` (backup `prerollback`).
* **Fail closed**: a journal that is already in WAL mode on an unsupported filesystem, or under an unpatched SQLite,
  is **refused** with an explanation; it is not silently switched.
* **Read-only commands** (`status`, `migrate --dry-run`, `--incremental --dry-run`) never convert, upgrade,
  checkpoint or write the database. They need the `-shm` index; in an unwritable directory a journal with no pending
  log is read as `immutable`, and one with a pending log is refused with an explanation rather than read as if the log
  were absent. `status` now shows the storage mode and any pending log.
* **Sidecars** are created by SQLite with the journal's private permissions (0600) and are verified (regular file, owner,
  no group/world access) when a job opens, like the journal itself.
* **Backups and upgrades** use SQLite's online backup, which reads committed pages including those still in the log
  (tested with a log that was never checkpointed). Schema upgrades are ordinary transactions and are interrupted-safe in
  WAL mode (tested at every upgrade fault point, on legacy and new journals).

## 4. Operating notes

* **Copying or moving a journal**: stop IMAPLANE first (a clean exit removes the sidecars) and copy `journal.sqlite3`.
  If a `-wal` file exists (after a crash or kill), copy it **with** the journal; the log holds committed data.
  `imaplane status` reports a pending log. Copying only the main file after a crash loses the commits that are still in the log.
* **Backups before changes** keep their names (`journal.sqlite3.v4.bak`, `.prewal.bak`); they are single files in the
  legacy format, safe to copy alone.
* **Older IMAPLANE versions** can still open a WAL journal (SQLite reads either mode), but should not be mixed with a
  newer one running at the same time; `job.lock` prevents that.
* **Setting `journal_mode = "rollback"`** in the configuration keeps the legacy storage (and converts a WAL journal
  back). It is the escape hatch for unusual filesystems.

## 5. Tests added for this change

`tests/wal.rs` (14 tests): WAL and `synchronous=FULL` verified on the live connection and the header; clean close
removes sidecars; sidecar permissions; the version gate against the bundled library and the filesystem classification;
one-time conversion with a verified backup and identical rows; no second conversion or backup; empty journal needs no
backup; rollback preference restores legacy storage; read-only opens do not change a legacy file by a byte and see
committed rows while a writer is open; unwritable directory behaviour; online backup of a journal with a pending log
restores; (fault-injection build) SIGKILL right after a commit leaves a pending log that recovers every commit; a log
cut at 20+ offsets always recovers a whole-commit prefix; conversion interrupted at each of four steps loses nothing and
converges; upgrade of a legacy journal interrupted at seven points converges with old evidence intact; an already-WAL
journal on a simulated NFS is refused and a legacy one stays legacy. Plus the existing 98+ Rust tests, both crash
matrices, the randomized SIGKILL stresses and the incremental suites, run in normal and forced-spool modes.

## 6. Phase 2: fdatasync instead of fsync

What it is: the bundled SQLite is compiled with `-DHAVE_FDATASYNC=1`, the setting of the standard SQLite build for
Linux. Without it SQLite maps `fdatasync` to `fsync`. With it, syncing the write-ahead log calls `fdatasync()`, which
flushes the file's data and the metadata needed to read that data back (including its size) and skips unrelated
metadata such as timestamps. SQLite's commit protocol needs exactly that; `synchronous=FULL`, the number of syncs per
commit and the four commit boundaries per message are unchanged. Measured on the profiled machine: 3.9 ms -> 2.0 ms per sync.

How it is applied, and how losing it is detected:

* `.cargo/config.toml` sets `LIBSQLITE3_FLAGS=-DHAVE_FDATASYNC=1` (`force = true`) for every Cargo build in the repository.
  `libsqlite3-sys`' build script appends it to its own flags.
* The packaging build copies `.cargo/` into its container (`packaging/Dockerfile`, `.dockerignore`); the explicit copy list
  there would otherwise have dropped it silently.
* `scripts/check-elf.py` (run for every package) fails unless the binary imports `fdatasync` from libc, which it does
  exactly when SQLite was built with the flag; CI runs it on the release binary as well.
* `tests/local/wal_sync.py` fails unless the log is synced with `fdatasync` (at least once per durable commit) and never
  with a plain `fsync`.

What it does not change: directory syncs, file creation and removal, the WAL-reset guard, the filesystem refusals, backups,
recovery behaviour. Losing the flag would never corrupt anything (SQLite falls back to `fsync`, as before Phase 2); it
would only make commits slower, and the three checks above exist so that this cannot go unnoticed.

Limits of the evidence: tested on ext4 on NVMe through Docker bind mounts. Behaviour on other local filesystems (xfs, btrfs,
zfs) follows their `fdatasync` implementations, which the SQLite project relies on in its default Linux build; it was not
tested here. A real power-loss test is not possible in this environment; the durability argument rests on SQLite's own
commit protocol, the unchanged sync count per commit (asserted), and the kill/crash tests.

Operational note (found while rehearsing the package build): Cargo does not rebuild an existing build directory's SQLite
when `.cargo/config.toml` first appears or changes; after pulling this change run `cargo clean -p libsqlite3-sys` (per
target directory) once. Fresh builds, CI and the packaging container are unaffected, and the three checks above would
catch a stale build.
