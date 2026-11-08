//! Schema 6 and the client-side duplicate-hold evidence (P1): the upgrade is explicit, additive, backed up and
//! crash safe; a hold is evidence next to a planned transfer, never a state; it is deduplicated, append-only,
//! never coupled to server rejections, and `skip` accepts it as evidence.
use imaplane::journal::{Journal, MessageKey};
use rusqlite::Connection;
use std::{collections::BTreeMap, path::Path};

const BINDING: &str = r#"{"source":["h","993","u"],"destination":["h","993","u"],"folders":[{"source":"INBOX","destination":"INBOX"}]}"#;

fn key(uid: u32) -> MessageKey {
    MessageKey {
        folder: "INBOX".into(),
        uid_validity: 10,
        uid,
    }
}
fn fp(body: &[u8]) -> String {
    imaplane::journal::fingerprint(body)
}

/// A schema-4 journal: UID 2 confirmed, UID 3 planned.
fn v4(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("journal.sqlite3");
    drop(Journal::create(&path, BINDING).unwrap());
    let mut j = Journal::open(&path).unwrap();
    j.snapshot("INBOX", 10, &[2, 3, 4, 5]).unwrap();
    let k = key(2);
    j.plan(&k, b"body").unwrap();
    j.metadata(&k, 100, &["\\Seen".into()], &[], (20, 4))
        .unwrap();
    j.begin_append(&k).unwrap();
    j.resolve_attribution(&k, 20, 4).unwrap();
    j.confirm_content(&k, 20, 4, b"body").unwrap();
    j.plan(&key(3), b"other").unwrap();
    path
}
fn v6(dir: &Path) -> (std::path::PathBuf, Journal) {
    let path = v4(dir);
    let mut j = Journal::open(&path).unwrap();
    assert!(j.upgrade_to_v6(&path).unwrap());
    (path, j)
}

fn dump(path: &Path, only: &[&str]) -> BTreeMap<String, Vec<String>> {
    let conn = Connection::open(path).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut result = BTreeMap::new();
    for table in tables {
        if !only.is_empty() && !only.contains(&table.as_str()) {
            continue;
        }
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))
            .unwrap();
        let columns = stmt.column_count();
        let rows = stmt
            .query_map([], |r| {
                Ok((0..columns)
                    .map(|i| format!("{:?}", r.get_ref(i).unwrap()))
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        result.insert(table, rows);
    }
    result
}
fn version(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}
fn has_table(path: &Path, name: &str) -> bool {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [name],
            |r| r.get(0),
        )
        .unwrap()
}
fn backups(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".bak"))
        .collect();
    names.sort();
    names
}
fn integrity(path: &Path) {
    let r: String = Connection::open(path)
        .unwrap()
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(r, "ok");
}
fn event_count(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT count(*) FROM client_hold_events", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn upgrade_from_schema_four_goes_through_five_with_verified_backups_and_changes_nothing_old() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    let before = dump(&path, &[]);
    let old: Vec<&str> = before.keys().map(String::as_str).collect();
    let mut j = Journal::open(&path).unwrap();
    assert!(j.upgrade_to_v6(&path).unwrap());
    assert_eq!(j.schema_version().unwrap(), 6);
    assert!(!j.upgrade_to_v6(&path).unwrap(), "idempotent");
    drop(j);
    assert_eq!(version(&path), 6);
    assert!(has_table(&path, "client_hold_events") && has_table(&path, "scans"));
    assert_eq!(dump(&path, &old), before, "no existing row changes");
    integrity(&path);
    let names = backups(temp.path());
    assert_eq!(names.len(), 2, "{names:?}");
    // Each backup is a valid journal at the version it was taken from.
    for name in &names {
        let v = version(&temp.path().join(name));
        assert!(v == 4 || v == 5, "{name} v{v}");
        integrity(&temp.path().join(name));
    }
    // A second open of a schema 6 journal needs no upgrade and makes no new backup.
    drop(Journal::open(&path).unwrap());
    assert_eq!(backups(temp.path()).len(), 2);
}

#[test]
fn a_schema_five_journal_upgrades_with_one_more_backup_and_a_schema_four_job_stays_four_without_it()
{
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    // Ordinary use never enters schema 5 or 6.
    drop(Journal::open(&path).unwrap());
    assert_eq!(version(&path), 4);
    assert!(!has_table(&path, "client_hold_events"));
    let mut j = Journal::open(&path).unwrap();
    j.upgrade_to_v5(&path).unwrap();
    assert!(j.upgrade_to_v6(&path).unwrap());
    assert_eq!(version(&path), 6);
    assert_eq!(backups(temp.path()).len(), 2);
}

#[test]
fn an_unknown_newer_schema_is_refused_so_an_older_binary_fails_closed() {
    // The supported list stops at 6; anything above is refused, exactly what a pre-6 binary does with 6.
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 7)
        .unwrap();
    assert!(Journal::open(&path).is_err());
    assert!(Journal::open_read_only(&path).is_err());
}

#[test]
fn holds_need_schema_six_and_a_planned_never_attributed_transfer() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    let mut j = Journal::open(&path).unwrap();
    assert!(
        j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &fp(b"other"), "x")
            .is_err(),
        "schema 4"
    );
    assert!(j.held_events().unwrap().is_empty());
    assert_eq!(j.summary().unwrap().held, 0);
    j.upgrade_to_v6(&path).unwrap();
    // Confirmed (UID 2) can never be held; neither can content that differs from the stored fingerprint.
    assert!(
        j.record_hold(&key(2), "SAME_CONTENT_EXISTING", &fp(b"body"), "x")
            .is_err()
    );
    assert!(
        j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &fp(b"different"), "x")
            .is_err()
    );
    assert!(
        j.record_hold(&key(3), "NOT_A_REASON", &fp(b"other"), "x")
            .is_err()
    );
    assert_eq!(event_count(&path), 0);
}

#[test]
fn a_hold_is_evidence_next_to_a_planned_row_never_a_state_and_never_an_attempt() {
    let temp = tempfile::tempdir().unwrap();
    let (path, mut j) = v6(temp.path());
    // UID 4 has no transfer row yet: the hold creates the planned row in the same transaction.
    assert!(
        j.record_hold(
            &key(4),
            "SAME_ID_AND_BODY_EXISTING",
            &fp(b"dup"),
            "gm_msgid=123 labels=INBOX"
        )
        .unwrap()
    );
    let r = j.record(&key(4)).unwrap().unwrap();
    assert_eq!(r.state, "planned");
    assert!(r.destination.is_none() && r.date.is_none());
    let attempts: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM append_attempts WHERE uid=4",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(attempts, 0, "no fence, no literal ever authorized");
    let held = j.held_events().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(
        (held[0].uid, held[0].reason.as_str()),
        (4, "SAME_ID_AND_BODY_EXISTING")
    );
    let s = j.summary().unwrap();
    assert_eq!((s.held, s.confirmed, s.planned, s.skipped), (1, 1, 2, 0));
    // The normal path still works from this planned row: nothing about a hold blocks prepare_append.
    assert_eq!(j.latest_hold(&key(4)).unwrap().unwrap().kind, "hold");
}

#[test]
fn identical_findings_add_no_rows_and_a_changed_finding_adds_one() {
    let temp = tempfile::tempdir().unwrap();
    let (path, mut j) = v6(temp.path());
    let f = fp(b"other");
    assert!(
        j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &f, "a")
            .unwrap()
    );
    for _ in 0..50 {
        assert!(
            !j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &f, "a")
                .unwrap()
        );
    }
    assert_eq!(event_count(&path), 1, "reruns do not grow the log");
    assert!(
        j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &f, "b")
            .unwrap()
    );
    assert!(
        j.record_hold(&key(3), "SIBLING_UNCERTAIN", &f, "b")
            .unwrap()
    );
    assert_eq!(event_count(&path), 3);
}

#[test]
fn a_release_ends_the_hold_and_a_later_hold_starts_again() {
    let temp = tempfile::tempdir().unwrap();
    let (path, mut j) = v6(temp.path());
    let f = fp(b"other");
    assert!(!j.record_release(&key(3)).unwrap(), "nothing to release");
    j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &f, "a")
        .unwrap();
    assert!(j.record_release(&key(3)).unwrap());
    assert!(!j.record_release(&key(3)).unwrap(), "already released");
    assert!(j.held_events().unwrap().is_empty());
    assert_eq!(j.summary().unwrap().held, 0);
    assert!(j.latest_hold(&key(3)).unwrap().is_none());
    assert!(
        j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &f, "a")
            .unwrap(),
        "same finding after a release is new"
    );
    assert_eq!(j.held_events().unwrap().len(), 1);
    assert_eq!(event_count(&path), 3);
}

#[test]
fn the_hold_log_is_append_only() {
    let temp = tempfile::tempdir().unwrap();
    let (path, mut j) = v6(temp.path());
    j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &fp(b"other"), "a")
        .unwrap();
    let c = Connection::open(&path).unwrap();
    assert!(
        c.execute("UPDATE client_hold_events SET detail='x'", [])
            .is_err()
    );
    assert!(c.execute("DELETE FROM client_hold_events", []).is_err());
    assert_eq!(event_count(&path), 1);
}

#[test]
fn holds_never_touch_rejections_or_the_breaker_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let (path, mut j) = v6(temp.path());
    for uid in [3u32, 4, 5] {
        let body = format!("m{uid}");
        let k = key(uid);
        if uid != 3 {
            j.plan(&k, body.as_bytes()).unwrap();
        }
        let f = if uid == 3 {
            fp(b"other")
        } else {
            fp(body.as_bytes())
        };
        j.record_hold(&k, "SAME_CONTENT_EXISTING", &f, "d").unwrap();
    }
    let c = Connection::open(&path).unwrap();
    let rejections: i64 = c
        .query_row("SELECT count(*) FROM append_rejections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rejections, 0);
    assert_eq!(j.held_events().unwrap().len(), 3);
}

#[test]
fn skip_accepts_a_hold_as_evidence_and_unskip_returns_the_message_to_the_check() {
    let temp = tempfile::tempdir().unwrap();
    let (path, mut j) = v6(temp.path());
    let f = fp(b"other");
    // Without a hold or a rejection there is nothing to skip.
    assert!(j.skip_rejected(&key(3), "because").is_err());
    j.record_hold(&key(3), "SAME_ID_AND_BODY_EXISTING", &f, "gm_msgid=9")
        .unwrap();
    assert!(
        j.skip_rejected(&key(3), "").is_err(),
        "a reason is required"
    );
    j.skip_rejected(
        &key(3),
        "operator reviewed; the existing copy is the same mail",
    )
    .unwrap();
    assert!(j.active_skip(&key(3)).unwrap().is_some());
    let s = j.summary().unwrap();
    assert_eq!(
        (s.skipped, s.held, s.confirmed),
        (1, 0, 1),
        "a skipped message is not also held and is not migrated"
    );
    let evidence: String = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT rejection_evidence FROM operator_skip_events WHERE uid=3",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        evidence.contains("client-side duplicate hold SAME_ID_AND_BODY_EXISTING")
            && evidence.contains("gm_msgid=9")
    );
    j.unskip(&key(3), "changed my mind").unwrap();
    assert_eq!(
        j.held_events().unwrap().len(),
        1,
        "a standing hold is visible again after unskip"
    );
    assert_eq!(j.summary().unwrap().skipped, 0);
}

#[test]
fn a_sibling_lookup_finds_uncertain_accepted_and_confirmed_copies_of_the_same_content() {
    let temp = tempfile::tempdir().unwrap();
    let (_path, j) = v6(temp.path());
    // UID 2 (content "body") is confirmed.
    let found = j
        .sibling_with_fingerprint(&fp(b"body"), &key(9))
        .unwrap()
        .unwrap();
    assert_eq!((found.0.uid, found.1.as_str()), (2, "confirmed"));
    assert!(
        j.sibling_with_fingerprint(&fp(b"body"), &key(2))
            .unwrap()
            .is_none(),
        "never itself"
    );
    assert!(
        j.sibling_with_fingerprint(&fp(b"other"), &key(9))
            .unwrap()
            .is_none(),
        "planned does not count"
    );
}

#[test]
fn a_journal_without_the_table_is_unaffected_by_every_read() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    let j = Journal::open(&path).unwrap();
    assert!(j.held_events().unwrap().is_empty());
    assert!(j.latest_hold(&key(3)).unwrap().is_none());
    let ro = Journal::open_read_only(&path).unwrap();
    assert_eq!(ro.summary().unwrap().held, 0);
}

#[cfg(feature = "fault-injection")]
#[test]
fn crash_child() {
    let Ok(path) = std::env::var("IMAPLANE_T_CRASH_DB") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let mut j = Journal::open(&path).unwrap();
    match std::env::var("IMAPLANE_T_CRASH_OP").as_deref() {
        Ok("hold") => {
            j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &fp(b"other"), "d")
                .unwrap();
        }
        Ok("release") => {
            j.record_release(&key(3)).unwrap();
        }
        _ => {
            j.upgrade_to_v6(&path).unwrap();
        }
    }
}

#[cfg(feature = "fault-injection")]
fn kill_child(path: &Path, point: &str, op: &str) {
    use std::os::unix::process::ExitStatusExt;
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--test-threads=1", "--nocapture"])
        .env("IMAPLANE_T_CRASH_DB", path)
        .env("IMAPLANE_T_CRASH_OP", op)
        .env("IMAPLANE_FAULT_POINT", point)
        .status()
        .unwrap();
    assert_eq!(
        status.signal(),
        Some(9),
        "{point}: the child must die by SIGKILL"
    );
}

#[cfg(feature = "fault-injection")]
#[test]
fn the_upgrade_survives_sigkill_at_every_point() {
    // (point, version afterwards, new table present)
    for (point, expect, table) in [
        ("before_v5_backup", 4, false),
        ("v5_upgrade_before_commit", 4, false),
        ("after_v5_upgrade", 5, false),
        ("before_v6_backup", 5, false),
        ("after_v6_backup", 5, false),
        ("before_v6_upgrade", 5, false),
        ("v6_upgrade_before_commit", 5, false),
        ("after_v6_upgrade", 6, true),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = v4(temp.path());
        let before = dump(&path, &[]);
        kill_child(&path, point, "upgrade");
        assert_eq!(version(&path), expect, "{point}");
        assert_eq!(
            has_table(&path, "client_hold_events"),
            table,
            "{point}: no partial schema"
        );
        integrity(&path);
        let old: Vec<&str> = before.keys().map(String::as_str).collect();
        assert_eq!(dump(&path, &old), before, "{point}: old evidence unchanged");
        let mut j = Journal::open(&path).unwrap();
        j.upgrade_to_v6(&path).unwrap();
        assert_eq!(j.schema_version().unwrap(), 6);
        drop(j);
        integrity(&path);
        assert_eq!(
            dump(&path, &old),
            before,
            "{point}: still unchanged after the retry"
        );
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn a_hold_or_release_survives_sigkill_at_each_new_boundary_with_no_partial_state() {
    for (point, op, events) in [
        ("hold_before_commit", "hold", 0),
        ("after_hold", "hold", 1),
        ("release_before_commit", "release", 1),
        ("after_release", "release", 2),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (path, mut j) = v6(temp.path());
        if op == "release" {
            j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &fp(b"other"), "d")
                .unwrap();
        }
        drop(j);
        kill_child(&path, point, op);
        integrity(&path);
        assert_eq!(event_count(&path), events, "{point}");
        let j = Journal::open(&path).unwrap();
        let r = j.record(&key(3)).unwrap().unwrap();
        assert_eq!(r.state, "planned", "{point}: never any other state");
        let attempts: i64 = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM append_attempts WHERE uid=3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(attempts, 0, "{point}");
        // The next run simply re-evaluates: a repeated hold or release is idempotent.
        drop(j);
        let mut j = Journal::open(&path).unwrap();
        j.record_hold(&key(3), "SAME_CONTENT_EXISTING", &fp(b"other"), "d")
            .unwrap();
        assert_eq!(j.held_events().unwrap().len(), 1, "{point}");
    }
}
