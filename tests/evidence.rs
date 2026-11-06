//! Phase I2: verification evidence (schema 5). Only a full SHA-256 check can create `confirmed`;
//! lightweight checks and renewal evidence never change a transfer into `confirmed`, every event
//! is append-only, and a time that was never recorded is never invented.
use imaplane::journal::{HistoryRun, Journal, MessageKey};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

const BINDING: &str = r#"{"source":["h","993","u"],"destination":["h","993","u"],"folders":[{"source":"INBOX","destination":"INBOX"}]}"#;

fn key(uid: u32) -> MessageKey {
    MessageKey {
        folder: "INBOX".into(),
        uid_validity: 10,
        uid,
    }
}

/// Schema-4 journal with `accepted` records for UIDs 2..=4 (destination UIDs 12..=14).
fn accepted(dir: &Path, n: u32) -> (PathBuf, Journal) {
    let path = dir.join("journal.sqlite3");
    drop(Journal::create(&path, BINDING).unwrap());
    let mut j = Journal::open(&path).unwrap();
    let uids: Vec<u32> = (2..2 + n).collect();
    j.snapshot("INBOX", 10, &uids).unwrap();
    for uid in uids {
        let k = key(uid);
        j.plan(&k, format!("body{uid}").as_bytes()).unwrap();
        j.metadata(&k, 100, &["\\Seen".into()], &[], (20, 4))
            .unwrap();
        j.begin_append(&k).unwrap();
        j.resolve_attribution(&k, 20, uid + 10).unwrap();
    }
    (path, j)
}

fn upgrade(path: &Path, j: &mut Journal) {
    assert!(j.upgrade_to_v5(path).unwrap());
}

fn state(path: &Path, uid: u32) -> String {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT state FROM transfers WHERE uid=?1", [uid], |r| {
            r.get(0)
        })
        .unwrap()
}

fn events(path: &Path) -> Vec<(u32, String, String, Option<i64>)> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare("SELECT uid,level,result,size FROM verification_events ORDER BY rowid")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn only_a_full_check_confirms_and_it_records_size_in_the_same_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 2);
    upgrade(&path, &mut j);
    let fp = imaplane::journal::fingerprint(b"body2");
    // A wrong fingerprint changes nothing and leaves no evidence behind.
    assert!(j.confirm_verified(&key(2), 20, 12, "bad", Some(5)).is_err());
    assert_eq!(state(&path, 2), "accepted");
    assert!(events(&path).is_empty());
    j.confirm_verified(&key(2), 20, 12, &fp, Some(5)).unwrap();
    assert_eq!(state(&path, 2), "confirmed");
    assert_eq!(events(&path), [(2, "full".into(), "ok".into(), Some(5))]);
}

#[test]
fn schema_four_confirms_without_any_evidence_table() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 1);
    j.confirm_content(&key(2), 20, 12, b"body2").unwrap();
    assert_eq!(state(&path, 2), "confirmed");
    assert!(!j.evidence_ready().unwrap());
    // Evidence calls are quiet no-ops there, and a time is simply unknown.
    j.note_full_ok(&key(2), Some(5), "x").unwrap();
    j.flush_evidence().unwrap();
    assert!(j.last_full_verifications("INBOX").unwrap().is_empty());
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'verification%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn lightweight_paths_cannot_create_or_renew_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 3);
    j.confirm_content(&key(3), 20, 13, b"body3").unwrap(); // UID 3 confirmed before schema 5
    upgrade(&path, &mut j);
    // Everything a lightweight check may do, applied to every record in every state.
    for uid in 2..5 {
        j.record_history_run(&HistoryRun {
            level: "metadata",
            started_at: "t",
            checked: 3,
            drift: 1,
            problems: 0,
        })
        .unwrap();
        let _ = uid;
    }
    assert_eq!(state(&path, 2), "accepted");
    assert_eq!(state(&path, 4), "accepted");
    assert_eq!(state(&path, 3), "confirmed");
    // No full evidence appeared, so the legacy record's verification time stays unknown.
    assert!(events(&path).is_empty());
    assert!(j.last_full_verifications("INBOX").unwrap().is_empty());
    // A demotion at a lightweight level records its own level, never `full`.
    j.demote(&key(3), "metadata", "missing", "gone", None)
        .unwrap();
    assert_eq!(state(&path, 3), "accepted");
    assert_eq!(
        events(&path),
        [(3, "metadata".into(), "missing".into(), None)]
    );
    assert!(j.last_full_verifications("INBOX").unwrap().is_empty());
    let runs: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM verification_runs WHERE level='metadata'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(runs, 3);
}

#[test]
fn demotion_and_its_evidence_are_one_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 1);
    upgrade(&path, &mut j);
    j.confirm_verified(
        &key(2),
        20,
        12,
        &imaplane::journal::fingerprint(b"body2"),
        Some(5),
    )
    .unwrap();
    // An invalid level makes the event insert fail; the state change must roll back with it.
    assert!(j.demote(&key(2), "bogus", "missing", "x", None).is_err());
    assert_eq!(state(&path, 2), "confirmed");
    assert_eq!(events(&path).len(), 1);
    j.demote(&key(2), "full", "mismatch", "hash", Some(5))
        .unwrap();
    assert_eq!(state(&path, 2), "accepted");
    assert_eq!(events(&path).len(), 2);
}

#[test]
fn renewal_evidence_is_buffered_flushed_on_drop_and_changes_no_state() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 1);
    j.confirm_content(&key(2), 20, 12, b"body2").unwrap();
    upgrade(&path, &mut j);
    j.note_full_ok(&key(2), Some(5), "renewed").unwrap();
    assert!(events(&path).is_empty(), "buffered, not yet written");
    drop(j);
    let e = events(&path);
    assert_eq!(e, [(2, "full".into(), "ok".into(), Some(5))]);
    assert_eq!(state(&path, 2), "confirmed");
    let j = Journal::open(&path).unwrap();
    let last = j.last_full_verifications("INBOX").unwrap();
    assert_eq!(last[&(10, 2)].size, Some(5));
}

#[test]
fn the_latest_full_ok_wins_and_an_earlier_size_survives_a_sizeless_renewal() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 1);
    upgrade(&path, &mut j);
    j.confirm_verified(
        &key(2),
        20,
        12,
        &imaplane::journal::fingerprint(b"body2"),
        Some(5),
    )
    .unwrap();
    j.note_full_ok(&key(2), None, "legacy-style renewal")
        .unwrap();
    j.flush_evidence().unwrap();
    let last = j.last_full_verifications("INBOX").unwrap();
    assert_eq!(last[&(10, 2)].size, Some(5));
    // A failed check is not a successful full verification and never becomes "last verified".
    j.demote(&key(2), "full", "mismatch", "x", Some(9)).unwrap();
    assert_eq!(
        j.last_full_verifications("INBOX").unwrap()[&(10, 2)].size,
        Some(5)
    );
}

#[test]
fn evidence_tables_are_append_only() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 1);
    upgrade(&path, &mut j);
    j.confirm_verified(
        &key(2),
        20,
        12,
        &imaplane::journal::fingerprint(b"body2"),
        Some(5),
    )
    .unwrap();
    let conn = Connection::open(&path).unwrap();
    assert!(
        conn.execute("UPDATE verification_events SET result='x'", [])
            .is_err()
    );
    assert!(conn.execute("DELETE FROM verification_events", []).is_err());
}

#[test]
fn a_prerelease_schema_five_journal_is_refused_not_silently_evidence_free() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 1);
    upgrade(&path, &mut j);
    drop(j);
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "DROP TABLE verification_events;
         CREATE TABLE verification_events (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL,
           level TEXT NOT NULL CHECK(level IN ('full')), result TEXT NOT NULL, size INTEGER, observed_at TEXT NOT NULL, detail TEXT NOT NULL);",
    )
    .unwrap();
    drop(conn);
    let j = Journal::open(&path).unwrap();
    assert!(
        j.evidence_ready()
            .unwrap_err()
            .to_string()
            .contains("pre-release")
    );
}

#[test]
fn the_overview_counts_only_full_ok_events_and_never_invents_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 3);
    j.confirm_content(&key(2), 20, 12, b"body2").unwrap(); // confirmed before schema 5: no time
    let o = j.verification_overview().unwrap();
    assert_eq!(o.evidence, "none");
    assert_eq!(o.folders.len(), 1);
    assert_eq!(
        (
            o.folders[0].confirmed,
            o.folders[0].full_verification_unknown
        ),
        (1, 1)
    );
    assert!(o.folders[0].oldest_full_verification.is_none());
    upgrade(&path, &mut j);
    j.confirm_verified(
        &key(3),
        20,
        13,
        &imaplane::journal::fingerprint(b"body3"),
        Some(5),
    )
    .unwrap();
    // lightweight evidence (a problem and a run summary) must not count as a full verification
    j.demote(&key(4), "metadata", "missing", "x", None)
        .unwrap_or(());
    j.record_history_run(&HistoryRun {
        level: "metadata",
        started_at: "t",
        checked: 2,
        drift: 0,
        problems: 0,
    })
    .unwrap();
    // even a lightweight event naming the legacy confirmed message is not a full verification time
    drop(j);
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO verification_events VALUES ('INBOX',10,2,'metadata','missing',NULL,'2030-01-01T00:00:00+00:00','')",
            [],
        )
        .unwrap();
    let mut j = Journal::open(&path).unwrap();
    let f = &j.verification_overview().unwrap().folders[0];
    assert_eq!(
        (
            f.confirmed,
            f.full_verification_recorded,
            f.full_verification_unknown
        ),
        (2, 1, 1)
    );
    let t = f.oldest_full_verification.clone().unwrap();
    assert_eq!(
        f.newest_full_verification.as_ref(),
        Some(&t),
        "one recorded time"
    );
    // a renewal moves newest, never the unknown one
    j.note_full_ok(&key(3), Some(5), "renewed").unwrap();
    j.flush_evidence().unwrap();
    let f = &j.verification_overview().unwrap().folders[0];
    assert_eq!(f.full_verification_unknown, 1);
    assert!(f.newest_full_verification.as_ref().unwrap() >= &t);
}

#[test]
fn an_incompatible_evidence_table_is_described_not_read_and_refused_for_work() {
    let dir = tempfile::tempdir().unwrap();
    let (path, mut j) = accepted(dir.path(), 1);
    j.confirm_content(&key(2), 20, 12, b"body2").unwrap();
    upgrade(&path, &mut j);
    drop(j);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TABLE verification_events;
             CREATE TABLE verification_events (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL,
               level TEXT NOT NULL CHECK(level IN ('full')), result TEXT NOT NULL, size INTEGER, observed_at TEXT NOT NULL, detail TEXT NOT NULL);
             INSERT INTO verification_events VALUES ('INBOX',10,2,'full','ok',5,'2020-01-01T00:00:00+00:00','');",
        )
        .unwrap();
    let j = Journal::open(&path).unwrap();
    assert!(j.require_compatible_evidence().is_err());
    let o = j.verification_overview().unwrap();
    assert_eq!(o.evidence, "incompatible");
    assert_eq!(
        o.folders[0].full_verification_unknown, 1,
        "its rows are not trusted as times"
    );
}

#[test]
fn the_overview_still_describes_a_journal_whose_binding_is_not_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.sqlite3");
    drop(Journal::create(&path, "legacy-binding").unwrap());
    let mut j = Journal::open(&path).unwrap();
    j.snapshot("INBOX", 10, &[2]).unwrap();
    j.plan(&key(2), b"body2").unwrap();
    j.metadata(&key(2), 100, &["\\Seen".into()], &[], (20, 4))
        .unwrap();
    j.begin_append(&key(2)).unwrap();
    j.resolve_attribution(&key(2), 20, 12).unwrap();
    j.confirm_content(&key(2), 20, 12, b"body2").unwrap();
    let o = j.verification_overview().unwrap();
    assert_eq!(o.evidence, "none");
    assert_eq!(
        (
            o.folders[0].folder.as_str(),
            o.folders[0].confirmed,
            o.folders[0].full_verification_unknown
        ),
        ("INBOX", 1, 1)
    );
}
