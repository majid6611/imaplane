use imaplane::{
    config::Config,
    job::Job,
    journal::{Journal, MessageKey},
};
use std::{fs, os::unix::fs::PermissionsExt};
fn key() -> MessageKey {
    MessageKey {
        folder: "INBOX".into(),
        uid_validity: 10,
        uid: 2,
    }
}
#[test]
fn snapshot_survives_new_arrivals_and_rejects_changed_uidvalidity() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("journal.sqlite3");
    let mut j = Journal::create(&path, "job").unwrap();
    assert_eq!(j.snapshot("INBOX", 10, &[2, 3]).unwrap(), vec![2, 3]);
    drop(j);
    let mut j = Journal::open(&path).unwrap();
    assert_eq!(j.snapshot("INBOX", 10, &[3, 4]).unwrap(), vec![2, 3]);
    assert!(j.snapshot("INBOX", 11, &[2, 3]).is_err());
    j.plan(&key(), b"body").unwrap();
    j.metadata(
        &key(),
        100,
        &["\\Seen".into()],
        &["\\Deleted".into()],
        (20, 4),
    )
    .unwrap();
    assert!(j.metadata(&key(), 101, &[], &[], (20, 4)).is_err());
    j.begin_append(&key()).unwrap();
    assert!(j.refresh_baseline(&key(), (20, 5)).is_err());
    j.resolve_attribution(&key(), 20, 4).unwrap();
    j.confirm_content(&key(), 20, 4, b"body").unwrap();
    j.invalidate(&key()).unwrap();
    let record = j.record(&key()).unwrap().unwrap();
    assert_eq!(record.state, "accepted");
    assert_eq!(record.date, Some(100));
    assert_eq!(record.flags, Some(vec!["\\Seen".into()]));
    assert_eq!(record.omitted, vec!["\\Deleted"]);
    let c = rusqlite::Connection::open(path).unwrap();
    assert_eq!(
        c.query_row("SELECT count(*) FROM resolutions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
fn config_text(state: &std::path::Path, password: &std::path::Path) -> String {
    format!(
        r#"state_dir = {:?}
[source]
host = "source.example.test"
username = "user"
password_file = {:?}
[destination]
host = "destination.example.test"
username = "user"
[[folders]]
source = "INBOX"
destination = "INBOX"
"#,
        state, password
    )
}
#[test]
fn private_credentials_and_exclusive_job_binding() {
    let temp = tempfile::tempdir().unwrap();
    let password = temp.path().join("password");
    fs::write(&password, "secret\n").unwrap();
    fs::set_permissions(&password, fs::Permissions::from_mode(0o644)).unwrap();
    let path = temp.path().join("config.toml");
    fs::write(&path, config_text(&temp.path().join("state"), &password)).unwrap();
    let c = Config::load(&path).unwrap();
    assert!(c.source.password("test").is_err());
    fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(c.source.password("test").unwrap().as_str(), "secret");
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&password, &link).unwrap();
    let mut endpoint = c.source.clone();
    endpoint.password_file = Some(link);
    assert!(endpoint.password("test").is_err());
    let job = Job::open(&c, true).unwrap();
    assert!(Job::open(&c, true).is_err());
    assert!(!c.binding().unwrap().contains("secret"));
    drop(job);
    let mut changed = c.clone();
    changed.destination.username = "other".into();
    assert!(Job::open(&changed, false).is_err());
    assert!(Job::open(&c, false).is_ok());
}
#[test]
fn config_rejects_unknown_fields_and_duplicate_inbox_aliases_without_echoing_input() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    let text = config_text(&temp.path().join("state"), &temp.path().join("password"));
    fs::write(&path, format!("password = \"accidental-secret\"\n{text}")).unwrap();
    let error = Config::load(&path).err().unwrap().to_string();
    assert!(!error.contains("accidental-secret"));
    fs::write(
        &path,
        format!("{text}\n[[folders]]\nsource = \"inbox\"\ndestination = \"another\"\n"),
    )
    .unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn legacy_journal_upgrade_preserves_evidence_and_status_is_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("legacy.sqlite3");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("CREATE TABLE job (id INTEGER PRIMARY KEY,binding TEXT NOT NULL);
        INSERT INTO job VALUES (1,'legacy-binding');
        CREATE TABLE transfers (folder TEXT NOT NULL,uid_validity INTEGER NOT NULL,uid INTEGER NOT NULL,fingerprint TEXT NOT NULL,state TEXT NOT NULL,destination_validity INTEGER,destination_uid INTEGER,PRIMARY KEY(folder,uid_validity,uid),UNIQUE(folder,destination_validity,destination_uid));
        INSERT INTO transfers VALUES ('INBOX',10,2,'original-fingerprint','uncertain',NULL,NULL);
        PRAGMA user_version=1;").unwrap();
    drop(c);
    let original = fs::read(&path).unwrap();
    let readonly = Journal::open_read_only(&path).unwrap();
    assert_eq!(readonly.summary().unwrap().uncertain, 1);
    drop(readonly);
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut j = Journal::open(&path).unwrap();
    j.check_binding("legacy-binding").unwrap();
    let r = j.record(&key()).unwrap().unwrap();
    assert_eq!(r.hash, "original-fingerprint");
    assert_eq!(r.state, "uncertain");
    assert!(r.date.is_none());
    assert!(j.snapshot("INBOX", 11, &[2]).is_err());
    assert!(j.begin_append(&key()).is_err());
    drop(j);
    let c = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn journal_publication_does_not_clobber_existing_file_or_follow_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("existing");
    fs::write(&path, b"preserve").unwrap();
    assert!(Journal::create(&path, "job").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"preserve");
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(Journal::open(&link).is_err());
    assert!(Journal::open_read_only(&link).is_err());
    let corrupt = temp.path().join("corrupt");
    fs::write(&corrupt, b"not a database").unwrap();
    assert!(Journal::open(&corrupt).is_err());
}

#[test]
fn auth_and_transport_changes_do_not_rebind_existing_accounts() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    let text = config_text(&temp.path().join("state"), &temp.path().join("password"));
    fs::write(&path, &text).unwrap();
    let old = Config::load(&path).unwrap();
    let mut updated = old.clone();
    updated.source.auth = imaplane::config::Auth::Xoauth2;
    updated.source.password_file = None;
    updated.source.access_token_file = Some(temp.path().join("token"));
    updated.source.security = imaplane::config::Security::Starttls;
    assert_eq!(old.binding().unwrap(), updated.binding().unwrap());
    let j = Job::open(&old, true).unwrap();
    drop(j);
    assert!(Job::open(&updated, false).is_ok());
}
