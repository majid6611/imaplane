use imaplane::{
    folders::{FolderEncoding as E, negotiated_encoding},
    journal::{Journal, MessageKey},
};

#[test]
fn protocol_mode_requires_successful_enable_on_dual_server() {
    assert_eq!(
        negotiated_encoding(true, true, false, false, false).unwrap(),
        E::ModifiedUtf7
    );
    assert_eq!(
        negotiated_encoding(true, true, true, false, false).unwrap(),
        E::Utf8
    );
    assert_eq!(
        negotiated_encoding(false, true, false, false, false).unwrap(),
        E::Utf8
    );
    assert_eq!(
        negotiated_encoding(true, false, false, true, false).unwrap(),
        E::Utf8
    );
    assert!(negotiated_encoding(true, false, false, false, true).is_err());
    assert!(negotiated_encoding(false, false, false, false, false).is_err());
    assert!(negotiated_encoding(true, false, true, false, false).is_err());
}

#[test]
fn unicode_folder_round_trips_without_normalization() {
    for name in [
        "INBOX",
        "台北/日本語",
        "رسائل",
        "A&B",
        "📬",
        "é",
        "e\u{301}",
        "a. b/空",
    ] {
        for codec in [E::Utf8, E::ModifiedUtf7] {
            assert_eq!(
                codec
                    .decode(codec.encode(name).unwrap().as_bytes())
                    .unwrap(),
                name
            );
        }
    }
    assert_eq!(
        E::ModifiedUtf7.encode("~peter/mail/台北/日本語").unwrap(),
        "~peter/mail/&U,BTFw-/&ZeVnLIqe-"
    );
    assert_eq!(E::ModifiedUtf7.encode("A&B").unwrap(), "A&-B");
    assert_ne!(
        E::ModifiedUtf7.encode("é").unwrap(),
        E::ModifiedUtf7.encode("e\u{301}").unwrap()
    );
}

#[test]
fn malformed_or_unsafe_names_fail_closed() {
    for name in [
        "",
        "a\r\nb",
        "a\0b",
        "&",
        "&AAAA-",
        "&2AA-",
        "&AGE-",
        "台北",
        "&U/BTFw-",
        "&U,BTFw==-",
        "&U,BT-&Fw-",
    ] {
        assert!(
            E::ModifiedUtf7.decode(name.as_bytes()).is_err(),
            "accepted {name:?}"
        );
    }
    assert!(E::Utf8.decode(&[0xff]).is_err());
    assert!(E::Utf8.encode("a\nb").is_err());
}

fn key(uid: u32) -> MessageKey {
    MessageKey {
        folder: "受信箱".into(),
        uid_validity: 42,
        uid,
    }
}

#[test]
fn interrupted_append_stays_uncertain_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let mut journal = Journal::create(&path, "source=>destination").unwrap();
    journal.plan(&key(1), b"original bytes").unwrap();
    journal.begin_append(&key(1)).unwrap();
    drop(journal); // Simulate process stopping without an APPEND reply.
    let mut journal = Journal::open(&path).unwrap();
    assert_eq!(journal.summary().unwrap().uncertain, 1);
    assert!(journal.begin_append(&key(1)).is_err());
    assert!(
        journal
            .confirm_content(&key(1), 9, 10, b"original bytes")
            .is_err()
    );
    journal.check_binding("source=>destination").unwrap();
    assert!(journal.check_binding("another destination").is_err());
    assert!(Journal::create(&path, "replacement").is_err());
}

// Invoked in a subprocess by the next test. process::exit bypasses all Rust
// destructors so persistence cannot depend on dropping the connection.
#[test]
fn abrupt_exit_writer() {
    let Some(path) = std::env::var_os("IMAPLANE_TEST_CRASH_JOURNAL") else {
        return;
    };
    let mut journal = Journal::create(std::path::Path::new(&path), "crash job").unwrap();
    journal.plan(&key(1), b"message").unwrap();
    journal.begin_append(&key(1)).unwrap();
    std::process::exit(77);
}

#[test]
fn committed_uncertainty_survives_process_exit_without_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.sqlite3");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "abrupt_exit_writer"])
        .env("IMAPLANE_TEST_CRASH_JOURNAL", &path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(77));
    let mut journal = Journal::open(&path).unwrap();
    assert_eq!(journal.summary().unwrap().uncertain, 1);
    assert!(journal.begin_append(&key(1)).is_err());
}

#[test]
fn confirmation_requires_acknowledgment_identity_and_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let mut journal = Journal::create(&path, "job").unwrap();
    journal.plan(&key(1), b"a\r\nb").unwrap();
    assert!(journal.acknowledge(&key(1), 9, 10).is_err());
    journal.begin_append(&key(1)).unwrap();
    assert!(journal.acknowledge(&key(1), 0, 10).is_err());
    journal.acknowledge(&key(1), 9, 10).unwrap();
    assert_eq!(journal.summary().unwrap().accepted, 1);
    assert!(journal.confirm_content(&key(1), 9, 11, b"a\r\nb").is_err());
    assert!(journal.confirm_content(&key(1), 8, 10, b"a\r\nb").is_err());
    assert!(journal.confirm_content(&key(1), 9, 10, b"a\nb").is_err());
    journal.confirm_content(&key(1), 9, 10, b"a\r\nb").unwrap();
    journal.plan(&key(1), b"a\r\nb").unwrap();
    assert_eq!(journal.summary().unwrap().confirmed, 1);
    assert!(journal.begin_append(&key(1)).is_err());
}

#[test]
fn legitimate_identical_messages_are_distinct_and_source_changes_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = Journal::create(&dir.path().join("state.sqlite3"), "job").unwrap();
    journal.plan(&key(1), b"same").unwrap();
    journal.plan(&key(2), b"same").unwrap();
    assert_eq!(journal.summary().unwrap().planned, 2);
    assert!(journal.plan(&key(1), b"changed").is_err());
    let changed = MessageKey {
        uid_validity: 43,
        ..key(3)
    };
    assert!(journal.plan(&changed, b"same").is_err());
    assert!(journal.plan(&key(0), b"same").is_err());
    journal.begin_append(&key(1)).unwrap();
    journal.acknowledge(&key(1), 100, 1).unwrap();
    journal.begin_append(&key(2)).unwrap();
    assert!(journal.acknowledge(&key(2), 100, 1).is_err());
    assert_eq!(journal.summary().unwrap().uncertain, 1);
}

#[test]
fn cli_status_labels_evidence_and_never_claims_completion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let mut journal = Journal::create(&path, "job").unwrap();
    journal.plan(&key(1), b"message").unwrap();
    journal.begin_append(&key(1)).unwrap();
    drop(journal);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_imaplane"))
        .args(["status", "--state", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["uncertain"], 1);
    assert_eq!(report["confirmed"], 0);
    assert!(
        report["scope"]
            .as_str()
            .unwrap()
            .contains("no live or metadata verification")
    );
    let missing = dir.path().join("missing.sqlite3");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_imaplane"))
        .args(["status", "--state", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!missing.exists());
}

#[test]
fn journal_permissions_schema_and_missing_path_are_checked() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    assert!(Journal::open(&path).is_err());
    assert!(!path.exists());
    drop(Journal::create(&path, "job").unwrap());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", 999).unwrap();
    drop(conn);
    assert!(Journal::open(&path).is_err());
}
