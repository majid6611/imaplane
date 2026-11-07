//! Phase 1 of the optimization work: the journal runs in SQLite's write-ahead-log mode with `synchronous=FULL`.
//! These tests pin what that must never change: commits stay durable boundaries, existing journals convert once
//! and only after a verified backup, read-only commands never convert, unsupported setups fail closed, and a
//! journal killed mid-run (pending WAL, torn WAL tail, interrupted conversion) recovers to a whole commit.
use imaplane::journal::{
    Journal, JournalPref, MessageKey, WAL_MIN_SQLITE_VERSION_NUMBER, wal_safe_version,
    wal_unsafe_filesystem,
};
use rusqlite::Connection;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const BINDING: &str = r#"{"source":["h","993","u"],"destination":["h","993","u"],"folders":[{"source":"INBOX","destination":"INBOX"}]}"#;

fn key(uid: u32) -> MessageKey {
    MessageKey {
        folder: "INBOX".into(),
        uid_validity: 10,
        uid,
    }
}

/// A journal with `n` confirmed messages (each step is a separate durable commit).
fn populated(dir: &Path, n: u32, pref: JournalPref) -> (PathBuf, Journal) {
    let path = dir.join("journal.sqlite3");
    let mut j = Journal::create_with(&path, BINDING, pref).unwrap();
    let uids: Vec<u32> = (1..=n).collect();
    j.snapshot("INBOX", 10, &uids).unwrap();
    for uid in uids {
        let k = key(uid);
        let body = format!("body{uid}");
        j.plan(&k, body.as_bytes()).unwrap();
        j.metadata(&k, 100, &["\\Seen".into()], &[], (20, 4))
            .unwrap();
        j.begin_append(&k).unwrap();
        j.resolve_attribution(&k, 20, uid + 100).unwrap();
        j.confirm_content(&k, 20, uid + 100, body.as_bytes())
            .unwrap();
    }
    (path, j)
}

fn header_versions(path: &Path) -> (u8, u8) {
    let b = fs::read(path).unwrap();
    (b[18], b[19])
}
fn mode(path: &Path) -> String {
    Connection::open(path)
        .unwrap()
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap()
}
fn integrity(path: &Path) {
    let r: String = Connection::open(path)
        .unwrap()
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(r, "ok");
}
fn dump(path: &Path) -> BTreeMap<String, Vec<String>> {
    let c = Connection::open(path).unwrap();
    let names: Vec<String> = c
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut out = BTreeMap::new();
    for t in names {
        let mut st = c
            .prepare(&format!("SELECT * FROM \"{t}\" ORDER BY rowid"))
            .unwrap();
        let n = st.column_count();
        let rows = st
            .query_map([], |r| {
                Ok((0..n)
                    .map(|i| format!("{:?}", r.get_ref(i).unwrap()))
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        out.insert(t, rows);
    }
    out
}
fn backups(dir: &Path, label: &str) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(&format!(".{label}.bak")))
        .collect();
    v.sort();
    v
}
fn sidecar(path: &Path, s: &str) -> PathBuf {
    let mut n = path.as_os_str().to_owned();
    n.push(s);
    PathBuf::from(n)
}

#[test]
fn new_journals_use_wal_with_full_synchronous_and_a_clean_close_leaves_no_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let (path, j) = populated(dir.path(), 3, JournalPref::Auto);
    assert_eq!(
        j.pragmas().unwrap(),
        ("wal".to_owned(), 2),
        "WAL, and synchronous FULL (2) in force on this connection"
    );
    assert!(
        sidecar(&path, "-wal").exists() && sidecar(&path, "-shm").exists(),
        "sidecars exist while open"
    );
    // sidecars carry the journal's private permissions
    for s in ["-wal", "-shm"] {
        assert_eq!(
            fs::metadata(sidecar(&path, s))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0,
            "{s} must not be group/world accessible"
        );
    }
    drop(j);
    assert!(
        !sidecar(&path, "-wal").exists() && !sidecar(&path, "-shm").exists(),
        "a clean close checkpoints and removes the sidecars"
    );
    assert_eq!(header_versions(&path), (2, 2), "file header says WAL");
    integrity(&path);
}

#[test]
fn the_sqlite_version_gate_and_filesystem_classification() {
    assert!(
        !wal_safe_version(3_051_002) && wal_safe_version(3_051_003) && wal_safe_version(3_053_002)
    );
    assert!(
        wal_safe_version(rusqlite::version_number()),
        "the bundled SQLite must be a fixed release: {}",
        rusqlite::version()
    );
    assert!(rusqlite::version_number() >= WAL_MIN_SQLITE_VERSION_NUMBER);
    for (magic, name) in [
        (0x6969, "nfs"),
        (0xFF53_4D42, "cifs/smb2"),
        (0x6573_5546, "fuse"),
        (0x0102_1997, "9p"),
    ] {
        assert_eq!(wal_unsafe_filesystem(magic), Some(name));
    }
    for local in [
        0xEF53u64,   /*ext4*/
        0x9123_683E, /*btrfs*/
        0x5846_5342, /*xfs*/
        0x0102_1994, /*tmpfs*/
        0x794c_7630, /*overlayfs*/
    ] {
        assert_eq!(wal_unsafe_filesystem(local), None, "{local:#x}");
    }
}

#[test]
fn a_legacy_rollback_journal_converts_once_after_a_verified_backup_without_changing_a_row() {
    let dir = tempfile::tempdir().unwrap();
    let (path, j) = populated(dir.path(), 4, JournalPref::Rollback);
    assert_eq!(j.pragmas().unwrap().0, "delete");
    drop(j);
    assert_eq!(header_versions(&path), (1, 1), "legacy file header");
    let before = dump(&path);
    assert!(backups(dir.path(), "prewal").is_empty());
    let j = Journal::open(&path).unwrap();
    assert_eq!(j.pragmas().unwrap(), ("wal".to_owned(), 2));
    drop(j);
    assert_eq!(header_versions(&path), (2, 2));
    assert_eq!(dump(&path), before, "conversion changes no row");
    let b = backups(dir.path(), "prewal");
    assert_eq!(b, ["journal.sqlite3.prewal.bak"]);
    assert_eq!(
        header_versions(&dir.path().join(&b[0])).0,
        1,
        "the backup is the pre-conversion image"
    );
    integrity(&dir.path().join(&b[0]));
    assert_eq!(dump(&dir.path().join(&b[0])), before);
    // idempotent: further opens neither convert again nor back up again
    drop(Journal::open(&path).unwrap());
    assert_eq!(backups(dir.path(), "prewal").len(), 1);
}

#[test]
fn an_empty_new_journal_needs_no_conversion_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.sqlite3");
    drop(Journal::create(&path, BINDING).unwrap());
    assert!(backups(dir.path(), "prewal").is_empty());
    assert_eq!(mode(&path), "wal");
}

#[test]
fn the_rollback_preference_restores_legacy_storage_after_a_backup_and_keeps_every_row() {
    let dir = tempfile::tempdir().unwrap();
    let (path, j) = populated(dir.path(), 3, JournalPref::Auto);
    drop(j);
    let before = dump(&path);
    let j = Journal::open_with(&path, JournalPref::Rollback).unwrap();
    assert_eq!(
        j.pragmas().unwrap(),
        ("delete".to_owned(), 2),
        "rollback mode, still synchronous FULL"
    );
    drop(j);
    assert_eq!(header_versions(&path), (1, 1));
    assert_eq!(dump(&path), before);
    assert_eq!(backups(dir.path(), "prerollback").len(), 1);
    // and Auto brings it back to WAL
    drop(Journal::open(&path).unwrap());
    assert_eq!(mode(&path), "wal");
    assert_eq!(dump(&path), before);
}

#[test]
fn read_only_opens_never_convert_or_checkpoint_and_see_committed_data_while_a_writer_is_open() {
    // legacy file: read-only access leaves it a legacy file, byte for byte
    let dir = tempfile::tempdir().unwrap();
    let (path, j) = populated(dir.path(), 2, JournalPref::Rollback);
    drop(j);
    let bytes = fs::read(&path).unwrap();
    let ro = Journal::open_read_only(&path).unwrap();
    assert_eq!(ro.summary().unwrap().confirmed, 2);
    drop(ro);
    assert_eq!(
        fs::read(&path).unwrap(),
        bytes,
        "status-style access wrote nothing"
    );
    assert_eq!(header_versions(&path), (1, 1));
    // WAL file with a writer still open and commits pending in the log
    let dir2 = tempfile::tempdir().unwrap();
    let (path2, writer) = populated(dir2.path(), 3, JournalPref::Auto);
    assert!(
        fs::metadata(sidecar(&path2, "-wal")).unwrap().len() > 0,
        "commits are pending in the WAL"
    );
    let ro = Journal::open_read_only(&path2).unwrap();
    assert_eq!(
        ro.summary().unwrap().confirmed,
        3,
        "a reader sees every committed row"
    );
    let s = ro.storage(&path2).unwrap();
    assert_eq!(s.mode, "wal");
    assert!(s.wal_pending && s.wal_bytes > 0);
    drop(ro);
    drop(writer);
}

#[test]
fn read_only_in_an_unwritable_directory_reads_a_clean_journal_and_refuses_one_with_a_pending_log() {
    let clean = tempfile::tempdir().unwrap();
    let (path, j) = populated(clean.path(), 2, JournalPref::Auto);
    drop(j);
    fs::set_permissions(clean.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let ro = Journal::open_read_only(&path);
    fs::set_permissions(clean.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        ro.unwrap().summary().unwrap().confirmed,
        2,
        "a clean WAL journal is readable from a read-only directory"
    );

    // a pending log copied into a read-only directory must be refused, not read as if the log were absent
    let src = tempfile::tempdir().unwrap();
    let (spath, writer) = populated(src.path(), 3, JournalPref::Auto);
    let dst = tempfile::tempdir().unwrap();
    let dpath = dst.path().join("journal.sqlite3");
    fs::copy(&spath, &dpath).unwrap();
    fs::copy(sidecar(&spath, "-wal"), sidecar(&dpath, "-wal")).unwrap();
    drop(writer);
    fs::remove_file(sidecar(&dpath, "-shm")).ok();
    fs::set_permissions(dst.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let ro = Journal::open_read_only(&dpath);
    fs::set_permissions(dst.path(), fs::Permissions::from_mode(0o755)).unwrap();
    match ro {
        Err(e) => assert!(e.to_string().contains("pending write-ahead log"), "{e}"),
        Ok(j) => assert_eq!(
            j.summary().unwrap().confirmed,
            3,
            "if SQLite could recover it, it must show every commit"
        ),
    }
}

#[test]
fn an_online_backup_of_a_journal_with_a_pending_log_is_complete_and_restorable() {
    // upgrade_to_v5 backs the schema-4 journal up first; its commits are still in the log at that moment
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = populated(dir.path(), 5, JournalPref::Auto);
    assert!(fs::metadata(sidecar(&path, "-wal")).unwrap().len() > 0);
    let before = dump(&path);
    assert!(j.upgrade_to_v5(&path).unwrap());
    drop(j);
    let bak = dir.path().join("journal.sqlite3.v4.bak");
    integrity(&bak);
    assert_eq!(
        dump(&bak),
        before,
        "the backup holds every commit that was only in the log"
    );
    // restore it as the journal in a new directory: it opens, passes integrity and keeps its schema
    let restore = tempfile::tempdir().unwrap();
    let rpath = restore.path().join("journal.sqlite3");
    fs::copy(&bak, &rpath).unwrap();
    let r = Journal::open(&rpath).unwrap();
    assert_eq!(r.schema_version().unwrap(), 4);
    assert_eq!(r.summary().unwrap().confirmed, 5);
}

#[cfg(feature = "fault-injection")]
mod crash {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    /// Child process: re-executes this test binary running only `crash_child`, with a fault point armed.
    fn run_child(
        action: &str,
        path: &Path,
        point: &str,
        nth: u32,
        extra: &[(&str, &str)],
    ) -> std::process::ExitStatus {
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args(["--exact", "crash::crash_child", "--test-threads=1"])
            .env("IMAPLANE_T_ACTION", action)
            .env("IMAPLANE_T_DB", path)
            .env("IMAPLANE_FAULT_POINT", point)
            .env("IMAPLANE_FAULT_NTH", nth.to_string());
        for (k, v) in extra {
            c.env(k, v);
        }
        // the child's own test-harness output (and its deliberate panics) are noise for the parent's log
        c.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        c.status().unwrap()
    }

    #[test]
    fn crash_child() {
        let Ok(action) = std::env::var("IMAPLANE_T_ACTION") else {
            return;
        };
        let path = PathBuf::from(std::env::var("IMAPLANE_T_DB").unwrap());
        match action.as_str() {
            "commits" => {
                // plan() commits once per message; the armed fault point kills the process right after a commit
                let mut j = Journal::create(&path, BINDING).unwrap();
                let n: u32 = std::env::var("IMAPLANE_T_N").unwrap().parse().unwrap();
                j.snapshot("INBOX", 10, &(1..=n).collect::<Vec<_>>())
                    .unwrap();
                for uid in 1..=n {
                    j.plan(&key(uid), format!("body{uid}").as_bytes()).unwrap();
                }
            }
            "open" => drop(Journal::open(&path).unwrap()),
            "open_upgrade" => {
                let mut j = Journal::open(&path).unwrap();
                j.upgrade_to_v5(&path).unwrap();
            }
            other => panic!("unknown action {other}"),
        }
    }

    fn rows(path: &Path) -> i64 {
        Connection::open(path)
            .unwrap()
            .query_row("SELECT count(*) FROM transfers", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn a_process_killed_right_after_a_commit_leaves_a_pending_wal_that_recovers_with_every_commit()
    {
        for kill_after in [1u32, 3, 7] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("journal.sqlite3");
            let status = run_child(
                "commits",
                &path,
                "after_plan",
                kill_after,
                &[("IMAPLANE_T_N", "10")],
            );
            assert_eq!(status.signal(), Some(9), "killed by SIGKILL");
            assert!(
                fs::metadata(sidecar(&path, "-wal")).unwrap().len() > 0,
                "the commits are still only in the log"
            );
            let j = Journal::open(&path).unwrap(); // recovery happens here
            assert_eq!(j.pragmas().unwrap(), ("wal".to_owned(), 2));
            drop(j);
            assert_eq!(
                rows(&path),
                i64::from(kill_after),
                "exactly the commits that returned are durable"
            );
            integrity(&path);
        }
    }

    #[test]
    fn a_torn_log_tail_recovers_to_a_whole_commit_never_a_partial_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.sqlite3");
        let n = 12;
        let status = run_child("commits", &path, "after_plan", n, &[("IMAPLANE_T_N", "12")]);
        assert_eq!(status.signal(), Some(9));
        let wal = fs::read(sidecar(&path, "-wal")).unwrap();
        let main = fs::read(&path).unwrap();
        assert!(wal.len() > 4096 * 4);
        let mut last = 0i64;
        let mut cuts = 0;
        let mut points: Vec<usize> = (0..=wal.len()).step_by(997).collect(); // odd stride so cuts land inside frames
        points.push(wal.len()); // and the whole, untruncated log
        for cut in points {
            let t = tempfile::tempdir().unwrap();
            let p = t.path().join("journal.sqlite3");
            fs::write(&p, &main).unwrap();
            fs::write(sidecar(&p, "-wal"), &wal[..cut]).unwrap();
            let c = Connection::open(&p).unwrap();
            let seen: i64 = c
                .query_row("SELECT count(*) FROM transfers", [], |r| r.get(0))
                .unwrap();
            let ok: String = c
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap();
            assert_eq!(ok, "ok", "cut at {cut}");
            assert!((0..=i64::from(n)).contains(&seen), "cut {cut}: {seen}");
            assert!(
                seen >= last,
                "a longer log never shows fewer commits ({cut}: {seen} < {last})"
            );
            last = seen;
            cuts += 1;
        }
        assert!(cuts > 10);
        assert_eq!(
            last,
            i64::from(n),
            "the untruncated log recovers every commit"
        );
    }

    #[test]
    fn conversion_interrupted_by_sigkill_at_any_step_loses_nothing_and_converges() {
        for point in [
            "before_wal_backup",
            "after_wal_backup",
            "before_wal_switch",
            "after_wal_switch",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (path, j) = populated(dir.path(), 4, JournalPref::Rollback);
            drop(j);
            let before = dump(&path);
            let status = run_child("open", &path, point, 1, &[]);
            assert_eq!(status.signal(), Some(9), "{point}");
            integrity(&path);
            assert_eq!(
                dump(&path),
                before,
                "{point}: killed conversion changed no row"
            );
            for b in backups(dir.path(), "prewal") {
                integrity(&dir.path().join(&b));
                assert_eq!(
                    dump(&dir.path().join(&b)),
                    before,
                    "{point}: every backup is a valid pre-conversion image"
                );
            }
            // the retry converges to WAL with the same data
            let j = Journal::open(&path).unwrap();
            assert_eq!(j.pragmas().unwrap(), ("wal".to_owned(), 2), "{point}");
            drop(j);
            assert_eq!(dump(&path), before, "{point}: after the retry");
            integrity(&path);
        }
    }

    #[test]
    fn upgrade_of_a_legacy_journal_interrupted_at_any_point_converges_with_old_evidence_intact() {
        for point in [
            "before_wal_switch",
            "after_wal_switch",
            "before_v5_backup",
            "after_v5_backup",
            "before_v5_upgrade",
            "v5_upgrade_before_commit",
            "after_v5_upgrade",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (path, j) = populated(dir.path(), 3, JournalPref::Rollback);
            drop(j);
            let before = dump(&path);
            let status = run_child("open_upgrade", &path, point, 1, &[]);
            assert_eq!(status.signal(), Some(9), "{point}");
            integrity(&path);
            let old: Vec<String> = before.keys().cloned().collect();
            let now = dump(&path);
            for t in &old {
                assert_eq!(
                    now.get(t),
                    before.get(t),
                    "{point}: table {t} unchanged by the interrupted run"
                );
            }
            let mut j = Journal::open(&path).unwrap();
            j.upgrade_to_v5(&path).unwrap();
            assert_eq!(j.schema_version().unwrap(), 5, "{point}");
            assert_eq!(j.pragmas().unwrap().0, "wal", "{point}");
            drop(j);
            integrity(&path);
            let after = dump(&path);
            for t in &old {
                assert_eq!(
                    after.get(t),
                    before.get(t),
                    "{point}: table {t} unchanged after the retry"
                );
            }
        }
    }

    #[test]
    fn a_wal_journal_on_an_unsupported_filesystem_is_refused_and_a_rollback_one_stays_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let (path, j) = populated(dir.path(), 2, JournalPref::Auto);
        drop(j);
        let child = |action: &str| {
            run_child(
                action,
                &path,
                "none",
                1,
                &[("IMAPLANE_TEST_FS_TYPE", "6969")],
            )
            .code()
        };
        assert_ne!(
            child("open"),
            Some(0),
            "an already-WAL journal on NFS must be refused, not used"
        );
        // a legacy journal on NFS stays in rollback mode (safe), keeps working, and nothing is converted
        let dir2 = tempfile::tempdir().unwrap();
        let (path2, j) = populated(dir2.path(), 2, JournalPref::Rollback);
        drop(j);
        let status = run_child(
            "open",
            &path2,
            "none",
            1,
            &[("IMAPLANE_TEST_FS_TYPE", "6969")],
        );
        assert_eq!(status.code(), Some(0));
        assert_eq!(
            header_versions(&path2),
            (1, 1),
            "not converted on an unsupported filesystem"
        );
        assert!(backups(dir2.path(), "prewal").is_empty());
    }
}

fn tree(dir: &Path) -> BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                format!("{:x}", Sha256::digest(fs::read(e.path()).unwrap()))
                    .chars()
                    .take(12)
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn merely_opening_and_closing_a_clean_wal_journal_leaves_the_directory_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let (path, j) = populated(dir.path(), 3, JournalPref::Auto);
    drop(j);
    let before = tree(dir.path());
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        ["journal.sqlite3"],
        "clean close leaves only the journal"
    );
    drop(Journal::open_deferred(&path, JournalPref::Auto).unwrap());
    assert_eq!(
        tree(dir.path()),
        before,
        "a deferred open (what a refused command does) changes nothing"
    );
    drop(Journal::open_read_only(&path).unwrap());
    println!("after read-only: {:?}", tree(dir.path()));
}
