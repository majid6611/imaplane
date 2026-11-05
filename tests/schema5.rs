//! Schema 5 (incremental migration groundwork, phase I0): the upgrade is explicit, additive,
//! backed up, crash safe and reversible by restoring the backup; schema-4 jobs are untouched.
use imaplane::journal::{Journal, MessageKey};
use rusqlite::Connection;
use std::{collections::BTreeMap, path::Path};

const BINDING: &str = r#"{"source":["h","993","u"],"destination":["h","993","u"],"folders":[{"source":"INBOX","destination":"INBOX"},{"source":"A","destination":"B"}]}"#;
const NEW_TABLES: [&str; 4] = [
    "scans",
    "job_folders",
    "verification_events",
    "verification_runs",
];

fn key(folder: &str, validity: u32, uid: u32) -> MessageKey {
    MessageKey {
        folder: folder.into(),
        uid_validity: validity,
        uid,
    }
}

/// A schema-4 journal with a snapshot per folder, one confirmed and one planned message.
fn v4(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("journal.sqlite3");
    drop(Journal::create(&path, BINDING).unwrap());
    let mut j = Journal::open(&path).unwrap();
    assert_eq!(j.schema_version().unwrap(), 4);
    j.snapshot("INBOX", 10, &[2, 3]).unwrap();
    j.snapshot("A", 7, &[1]).unwrap();
    let k = key("INBOX", 10, 2);
    j.plan(&k, b"body").unwrap();
    j.metadata(&k, 100, &["\\Seen".into()], &[], (20, 4))
        .unwrap();
    j.begin_append(&k).unwrap();
    j.resolve_attribution(&k, 20, 4).unwrap();
    j.confirm_content(&k, 20, 4, b"body").unwrap();
    j.plan(&key("INBOX", 10, 3), b"other").unwrap();
    path
}

/// Every row of every table that exists at schema 4, as text, for before/after comparison.
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
fn tables(path: &Path) -> Vec<String> {
    Connection::open(path)
        .unwrap()
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
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

#[test]
fn upgrade_is_additive_seeds_folders_and_leaves_a_valid_backup() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    let before = dump(&path, &[]);
    let mut j = Journal::open(&path).unwrap();
    assert!(j.job_folders().unwrap().is_empty());
    assert!(j.upgrade_to_v5(&path).unwrap());
    assert_eq!(j.schema_version().unwrap(), 5);
    drop(j);
    integrity(&path);
    // Every schema-4 table is byte-for-byte unchanged; only the four new tables exist beyond them.
    let after = dump(&path, &[]);
    for (table, rows) in &before {
        assert_eq!(after.get(table), Some(rows), "table {table} changed");
    }
    let added: Vec<_> = after
        .keys()
        .filter(|t| !before.contains_key(*t))
        .cloned()
        .collect();
    let mut expected: Vec<_> = NEW_TABLES.iter().map(|t| t.to_string()).collect();
    expected.sort();
    assert_eq!(added, expected);
    let j = Journal::open(&path).unwrap();
    assert_eq!(
        j.job_folders().unwrap(),
        vec![
            ("INBOX".into(), "INBOX".into(), "binding".into()),
            ("A".into(), "B".into(), "binding".into())
        ]
    );
    // The backup is a schema-4 file with none of the new tables and the same evidence.
    let names = backups(temp.path());
    assert_eq!(names, vec!["journal.sqlite3.v4.bak".to_string()]);
    let backup = temp.path().join(&names[0]);
    assert_eq!(version(&backup), 4);
    integrity(&backup);
    assert!(
        tables(&backup)
            .iter()
            .all(|t| !NEW_TABLES.contains(&t.as_str()))
    );
    assert_eq!(dump(&backup, &[]), before);
}

#[test]
fn upgrade_is_idempotent_and_never_makes_a_second_backup() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    let mut j = Journal::open(&path).unwrap();
    assert!(j.upgrade_to_v5(&path).unwrap());
    let once = dump(&path, &[]);
    assert!(!j.upgrade_to_v5(&path).unwrap());
    drop(j);
    let mut j = Journal::open(&path).unwrap();
    assert!(!j.upgrade_to_v5(&path).unwrap());
    drop(j);
    assert_eq!(dump(&path, &[]), once);
    assert_eq!(backups(temp.path()).len(), 1);
}

#[test]
fn a_failed_upgrade_leaves_schema_four_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    // A collision on the LAST table makes the transaction fail midway, after earlier tables were
    // created: nothing may survive.
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE verification_runs (x)")
        .unwrap();
    let before = dump(&path, &[]);
    let mut j = Journal::open(&path).unwrap();
    assert!(j.upgrade_to_v5(&path).is_err());
    drop(j);
    assert_eq!(version(&path), 4);
    assert_eq!(dump(&path, &[]), before);
    for table in ["scans", "job_folders", "verification_events"] {
        assert!(
            !tables(&path).contains(&table.to_string()),
            "{table} must have been rolled back"
        );
    }
    integrity(&path);
}

#[test]
fn an_unsound_binding_or_foreign_evidence_refuses_the_upgrade_without_changes() {
    for (binding, folder) in [("job", "INBOX"), (BINDING, "SURPRISE")] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("journal.sqlite3");
        drop(Journal::create(&path, binding).unwrap());
        let mut j = Journal::open(&path).unwrap();
        j.snapshot(folder, 1, &[1]).unwrap();
        let before = dump(&path, &[]);
        assert!(j.upgrade_to_v5(&path).is_err(), "{binding} {folder}");
        drop(j);
        assert_eq!(version(&path), 4);
        assert_eq!(dump(&path, &[]), before);
        assert!(
            backups(temp.path()).is_empty(),
            "no backup before the checks pass"
        );
    }
}

#[test]
fn only_schema_four_upgrades_and_unknown_schemas_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 6)
        .unwrap();
    assert!(Journal::open(&path).is_err());
    assert!(Journal::open_read_only(&path).is_err());
}

#[test]
fn ordinary_open_never_creates_schema_five() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    let before = dump(&path, &[]);
    for _ in 0..2 {
        let j = Journal::open(&path).unwrap();
        assert_eq!(j.schema_version().unwrap(), 4);
        j.summary().unwrap();
        drop(Journal::open_read_only(&path).unwrap());
    }
    assert_eq!(version(&path), 4);
    assert_eq!(dump(&path, &[]), before);
    assert!(backups(temp.path()).is_empty());
}

#[test]
fn new_tables_are_append_only_and_mappings_immutable() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    Journal::open(&path).unwrap().upgrade_to_v5(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute("INSERT INTO scans VALUES ('INBOX',10,1,5,'[4]','t')", [])
        .unwrap();
    conn.execute(
        "INSERT INTO verification_events VALUES ('INBOX',10,2,'full','ok',4,'t','')",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO verification_runs (level,started_at,finished_at,checked,drift,problems) VALUES ('metadata','a','b',1,0,0)", []).unwrap();
    for sql in [
        "UPDATE scans SET uids='[]'",
        "DELETE FROM scans",
        "UPDATE job_folders SET destination='X'",
        "DELETE FROM job_folders",
        "UPDATE verification_events SET result='x'",
        "DELETE FROM verification_events",
        "UPDATE verification_runs SET checked=9",
        "DELETE FROM verification_runs",
    ] {
        assert!(conn.execute(sql, []).is_err(), "{sql} must be refused");
    }
    // Constraint checks: one destination cannot serve two sources, generations are positive.
    assert!(
        conn.execute("INSERT INTO job_folders VALUES ('Z','B','added','t')", [])
            .is_err()
    );
    assert!(
        conn.execute("INSERT INTO scans VALUES ('INBOX',10,0,5,'[]','t')", [])
            .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO verification_events VALUES ('INBOX',10,2,'metadata','ok',4,'t','')",
            []
        )
        .is_err()
    );
}

#[test]
fn a_schema_five_journal_behaves_like_schema_four_for_ordinary_work() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    let before_summary =
        serde_json::to_string(&Journal::open(&path).unwrap().summary().unwrap()).unwrap();
    let before_plan = Journal::open(&path).unwrap().work_list().unwrap();
    Journal::open(&path).unwrap().upgrade_to_v5(&path).unwrap();
    let mut j = Journal::open(&path).unwrap();
    assert_eq!(
        serde_json::to_string(&j.summary().unwrap()).unwrap(),
        before_summary
    );
    assert_eq!(j.work_list().unwrap(), before_plan);
    assert_eq!(
        j.snapshot("INBOX", 10, &[9]).unwrap(),
        vec![2, 3],
        "the snapshot stays immutable"
    );
    j.check_binding(BINDING).unwrap();
    assert!(j.check_binding(&BINDING.replace("\"B\"", "\"C\"")).is_err());
    // The usual transitions still work on schema 5.
    let k = key("INBOX", 10, 3);
    j.metadata(&k, 5, &[], &[], (20, 5)).unwrap();
    j.begin_append(&k).unwrap();
    j.resolve_attribution(&k, 20, 5).unwrap();
    j.confirm_content(&k, 20, 5, b"other").unwrap();
    drop(j);
    drop(Journal::open_read_only(&path).unwrap());
    integrity(&path);
}

#[test]
fn the_work_list_extends_the_snapshot_and_rejects_inconsistent_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    Journal::open(&path).unwrap().upgrade_to_v5(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    let j = Journal::open(&path).unwrap();
    assert_eq!(
        j.work_list().unwrap(),
        vec![("A".into(), 7, vec![1]), ("INBOX".into(), 10, vec![2, 3])]
    );
    conn.execute("INSERT INTO scans VALUES ('INBOX',10,1,9,'[8,5]','t')", [])
        .unwrap();
    conn.execute("INSERT INTO scans VALUES ('INBOX',10,2,12,'[11]','t')", [])
        .unwrap();
    assert_eq!(
        j.work_list().unwrap(),
        vec![
            ("A".into(), 7, vec![1]),
            ("INBOX".into(), 10, vec![2, 3, 8, 5, 11])
        ],
        "recorded order is kept, snapshot first"
    );
    // The snapshot itself is still exactly the original.
    assert_eq!(j.snapshots().unwrap()[1], ("INBOX".into(), 10, vec![2, 3]));
    // A UID listed again, in the snapshot or in another scan, is an error and is not merged.
    conn.execute("INSERT INTO scans VALUES ('A',7,1,3,'[1]','t')", [])
        .unwrap();
    assert!(j.work_list().is_err());
    // So is a scan with another UIDVALIDITY.
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    Journal::open(&path).unwrap().upgrade_to_v5(&path).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute("INSERT INTO scans VALUES ('A',8,1,9,'[5]','t')", [])
        .unwrap();
    assert!(Journal::open(&path).unwrap().work_list().is_err());
}

#[test]
fn recorded_folder_mappings_are_the_authority_for_the_binding() {
    let temp = tempfile::tempdir().unwrap();
    let path = v4(temp.path());
    Journal::open(&path).unwrap().upgrade_to_v5(&path).unwrap();
    // Even with an unchanged binding string, a different recorded mapping refuses the job.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("DROP TRIGGER job_folders_no_update; UPDATE job_folders SET destination='ELSEWHERE' WHERE source='A'").unwrap();
    let j = Journal::open(&path).unwrap();
    assert!(j.check_binding(BINDING).is_err());
}

/// Child half of the crash test: does nothing unless started by the parent below.
#[test]
fn crash_child() {
    if let Ok(path) = std::env::var("IMAPLANE_T_CRASH_DB") {
        let path = std::path::PathBuf::from(path);
        Journal::open(&path).unwrap().upgrade_to_v5(&path).unwrap();
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn upgrade_survives_sigkill_at_every_point() {
    use std::os::unix::process::ExitStatusExt;
    for (point, expect) in [
        ("before_v5_backup", 4),
        ("after_v5_backup", 4),
        ("before_v5_upgrade", 4),
        ("v5_upgrade_before_commit", 4),
        ("after_v5_upgrade", 5),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = v4(temp.path());
        let before = dump(&path, &[]);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--test-threads=1"])
            .env("IMAPLANE_T_CRASH_DB", &path)
            .env("IMAPLANE_FAULT_POINT", point)
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(9),
            "{point}: the child must die by SIGKILL"
        );
        assert_eq!(version(&path), expect, "{point}");
        integrity(&path);
        let old_tables: Vec<&str> = before.keys().map(String::as_str).collect();
        assert_eq!(
            dump(&path, &old_tables),
            before,
            "{point}: old evidence unchanged"
        );
        if expect == 4 {
            assert!(
                !tables(&path).contains(&"scans".to_string()),
                "{point}: no partial schema"
            );
        }
        // Whatever happened, the next upgrade completes and yields the same final state.
        let mut j = Journal::open(&path).unwrap();
        j.upgrade_to_v5(&path).unwrap();
        assert_eq!(j.schema_version().unwrap(), 5);
        assert_eq!(j.job_folders().unwrap().len(), 2);
        drop(j);
        integrity(&path);
        assert_eq!(
            dump(&path, &old_tables),
            before,
            "{point}: still unchanged after the retry"
        );
    }
}
