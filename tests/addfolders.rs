//! Phase I3: adding folders to an existing schema-5 job. Mappings are immutable, an added folder's
//! mapping and baseline scan are one atomic transaction, nothing historical is rewritten, and the
//! durable plan stays readable by ordinary commands.
use imaplane::journal::{Journal, MessageKey};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

const BINDING: &str = r#"{"source":["h","993","u"],"destination":["h","993","u"],"folders":[{"source":"INBOX","destination":"INBOX"},{"source":"A","destination":"B"}]}"#;

fn binding_with(extra: &[(&str, &str)]) -> String {
    let mut v: serde_json::Value = serde_json::from_str(BINDING).unwrap();
    for (s, d) in extra {
        v["folders"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"source":s,"destination":d}));
    }
    serde_json::to_string(&v).unwrap()
}
fn key(folder: &str, validity: u32, uid: u32) -> MessageKey {
    MessageKey {
        folder: folder.into(),
        uid_validity: validity,
        uid,
    }
}

/// A schema-5 job (upgraded from schema 4) with snapshots for both folders.
fn v5(dir: &Path) -> (PathBuf, Journal) {
    let path = dir.join("journal.sqlite3");
    drop(Journal::create(&path, BINDING).unwrap());
    let mut j = Journal::open(&path).unwrap();
    j.snapshot("INBOX", 10, &[1, 2]).unwrap();
    j.snapshot("A", 7, &[1]).unwrap();
    j.plan(&key("INBOX", 10, 1), b"x").unwrap();
    assert!(j.upgrade_to_v5(&path).unwrap());
    (path, j)
}
fn dump(path: &Path, table: &str) -> Vec<String> {
    let c = Connection::open(path).unwrap();
    let mut stmt = c
        .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
        .unwrap();
    let n = stmt.column_count();
    stmt.query_map([], |r| {
        Ok((0..n)
            .map(|i| format!("{:?}", r.get_ref(i).unwrap()))
            .collect::<Vec<_>>()
            .join("|"))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

#[test]
fn a_new_mapping_is_admitted_only_when_asked_and_is_returned_not_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let (path, j) = v5(dir.path());
    let wanted = binding_with(&[("C", "D")]);
    let before = dump(&path, "job_folders");
    let err = j.check_binding(&wanted).unwrap_err().to_string();
    assert!(
        err.contains("add-new-folders") && err.contains("\"C\""),
        "{err}"
    );
    assert_eq!(
        j.check_binding_mode(&wanted, true).unwrap(),
        [("C".to_owned(), "D".to_owned())]
    );
    assert_eq!(j.check_binding_mode(BINDING, true).unwrap(), []);
    assert_eq!(
        dump(&path, "job_folders"),
        before,
        "checking records nothing"
    );
}

#[test]
fn recorded_mappings_cannot_be_removed_renamed_or_remapped_and_destinations_cannot_collide() {
    let dir = tempfile::tempdir().unwrap();
    let (_, j) = v5(dir.path());
    let refuse = |binding: String, needle: &str| {
        for allow in [false, true] {
            let e = j
                .check_binding_mode(&binding, allow)
                .unwrap_err()
                .to_string();
            assert!(e.contains(needle), "{needle}: {e}");
        }
    };
    // removal, and renaming (a removal plus an addition)
    refuse(
        BINDING.replace(r#",{"source":"A","destination":"B"}"#, ""),
        "missing from the configuration",
    );
    refuse(
        BINDING.replace(r#""source":"A""#, r#""source":"A2""#),
        "missing from the configuration",
    );
    // remapping
    refuse(
        BINDING.replace(r#""destination":"B""#, r#""destination":"Z""#),
        "remapping is refused",
    );
    // a new source onto a recorded destination
    refuse(binding_with(&[("C", "B")]), "conflicting folder mapping");
    // another account is another job
    refuse(BINDING.replace(r#""u"]"#, r#""v"]"#), "different migration");
    // INBOX aliases are one folder
    refuse(
        BINDING.replace(r#""source":"INBOX""#, r#""source":"inbox""#),
        "",
    );
}

#[test]
fn schema_four_compares_byte_for_byte_unless_adding_and_adds_nothing_itself() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.sqlite3");
    drop(Journal::create(&path, BINDING).unwrap());
    let mut j = Journal::open(&path).unwrap();
    j.check_binding(BINDING).unwrap();
    assert!(j.check_binding(&binding_with(&[("C", "D")])).is_err());
    assert_eq!(
        j.check_binding_mode(&binding_with(&[("C", "D")]), true)
            .unwrap(),
        [("C".to_owned(), "D".to_owned())]
    );
    assert!(
        j.add_folder("C", "D", 5, 3, &[1, 2]).is_err(),
        "schema 4 cannot hold a folder"
    );
}

#[test]
fn adding_a_folder_is_one_transaction_and_touches_no_history() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = v5(dir.path());
    let history: Vec<_> = ["snapshots", "transfers", "job", "scans"]
        .iter()
        .map(|t| dump(&path, t))
        .collect();
    j.add_folder("C", "D", 5, 4, &[1, 3]).unwrap();
    let after: Vec<_> = ["snapshots", "transfers", "job", "scans"]
        .iter()
        .map(|t| dump(&path, t))
        .collect();
    assert_eq!(history[0], after[0]);
    assert_eq!(history[1], after[1]);
    assert_eq!(
        history[2], after[2],
        "the historical binding is never rewritten"
    );
    assert_eq!(after[3].len(), 1, "exactly the baseline scan");
    let folders = j.job_folders().unwrap();
    assert_eq!(folders.len(), 3);
    assert_eq!(folders[2], ("C".into(), "D".into(), "added".into()));
    // The plan lists the added folder through its baseline; ordinary readers see it.
    let plan = j.work_list().unwrap();
    assert_eq!(
        plan.iter().find(|p| p.0 == "C").unwrap(),
        &("C".to_owned(), 5, vec![1, 3])
    );
    assert!(j.is_scan_only("C").unwrap() && !j.is_scan_only("A").unwrap());
    // Now the configuration must contain it, and with it the exact check passes.
    j.check_binding(&binding_with(&[("C", "D")])).unwrap();
    assert!(j.check_binding(BINDING).is_err());
    // A later scan builds on the baseline; an original snapshot can never be invented.
    assert_eq!(j.record_scan("C", 5, 7, &[4, 6]).unwrap(), 2);
    assert!(j.snapshot("C", 5, &[1, 3, 4, 6]).is_err());
}

#[test]
fn an_empty_folder_still_records_its_validity_and_horizon() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = v5(dir.path());
    j.add_folder("C", "D", 5, 1, &[]).unwrap();
    assert_eq!(dump(&path, "scans").len(), 1);
    assert!(
        j.work_list()
            .unwrap()
            .iter()
            .any(|p| p.0 == "C" && p.1 == 5 && p.2.is_empty())
    );
    assert!(
        j.record_scan("C", 6, 3, &[1]).is_err(),
        "another UIDVALIDITY is refused"
    );
    assert!(
        j.record_scan("C", 5, 1, &[1]).is_err(),
        "a UID at the horizon is refused"
    );
    assert_eq!(j.record_scan("C", 5, 3, &[1, 2]).unwrap(), 2);
}

#[test]
fn every_refusal_leaves_the_journal_exactly_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = v5(dir.path());
    let tables = ["job_folders", "scans", "snapshots", "transfers"];
    let before: Vec<_> = tables.iter().map(|t| dump(&path, t)).collect();
    // already part of the job (also through the INBOX alias), destination in use, evidence present,
    // invalid baselines
    assert!(j.add_folder("A", "Q", 5, 3, &[1]).is_err());
    assert!(j.add_folder("inbox", "Q", 5, 3, &[1]).is_err());
    assert!(j.add_folder("C", "B", 5, 3, &[1]).is_err());
    assert!(j.add_folder("C", "inbox", 5, 3, &[1]).is_err());
    assert!(j.add_folder("C", "D", 0, 3, &[1]).is_err());
    assert!(j.add_folder("C", "D", 5, 0, &[]).is_err());
    assert!(j.add_folder("C", "D", 5, 3, &[2, 1]).is_err());
    assert!(
        j.add_folder("C", "D", 5, 3, &[1, 3]).is_err(),
        "a UID at UIDNEXT"
    );
    assert!(j.add_folder("C", "D", 5, 3, &[0]).is_err());
    // evidence for a folder the job never declared (corruption) blocks the addition
    drop(j);
    Connection::open(&path)
        .unwrap()
        .execute("INSERT INTO snapshots VALUES ('E',3,'[1]')", [])
        .unwrap();
    let mut j = Journal::open(&path).unwrap();
    assert!(j.add_folder("E", "F", 3, 2, &[1]).is_err());
    let after: Vec<_> = tables.iter().map(|t| dump(&path, t)).collect();
    assert_eq!(before[0], after[0]);
    assert_eq!(before[1], after[1]);
    assert_eq!(before[3], after[3]);
}

#[test]
fn recorded_mappings_stay_immutable_in_sql() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = v5(dir.path());
    j.add_folder("C", "D", 5, 2, &[1]).unwrap();
    let c = Connection::open(&path).unwrap();
    assert!(
        c.execute(
            "UPDATE job_folders SET destination='X' WHERE source='C'",
            []
        )
        .is_err()
    );
    assert!(
        c.execute("DELETE FROM job_folders WHERE source='C'", [])
            .is_err()
    );
    assert!(c.execute("DELETE FROM scans WHERE folder='C'", []).is_err());
}
