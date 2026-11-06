//! Conservative, durable transfer state. No message content or credentials stored.
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Schema every ordinary open upgrades to. Schema 5 (incremental migration) is never entered
/// implicitly: only `Journal::upgrade_to_v5` creates it, so jobs that never use incremental
/// migration keep a schema-4 file.
const SCHEMA_VERSION: i64 = 4;
const SCHEMA_V5: i64 = 5;
const SUPPORTED_SCHEMAS: [i64; 5] = [1, 2, 3, SCHEMA_VERSION, SCHEMA_V5];

const V5_SCHEMA: &str = "
CREATE TABLE scans (
    folder TEXT NOT NULL,
    validity INTEGER NOT NULL CHECK(validity BETWEEN 1 AND 4294967295),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    observed_uidnext INTEGER NOT NULL CHECK(observed_uidnext >= 1),
    uids TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    PRIMARY KEY(folder, validity, generation)
);
CREATE TABLE job_folders (
    source TEXT PRIMARY KEY,
    destination TEXT NOT NULL UNIQUE,
    origin TEXT NOT NULL CHECK(origin IN ('binding','added')),
    added_at TEXT NOT NULL
);
CREATE TABLE verification_events (
    folder TEXT NOT NULL,
    validity INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    level TEXT NOT NULL CHECK(level IN ('existence','metadata','full')),
    result TEXT NOT NULL,
    size INTEGER,
    observed_at TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE verification_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL CHECK(level IN ('existence','metadata','full')),
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    checked INTEGER NOT NULL,
    drift INTEGER NOT NULL,
    problems INTEGER NOT NULL
);
CREATE TRIGGER scans_no_update BEFORE UPDATE ON scans BEGIN SELECT RAISE(ABORT, 'scans are append-only'); END;
CREATE TRIGGER scans_no_delete BEFORE DELETE ON scans BEGIN SELECT RAISE(ABORT, 'scans are append-only'); END;
CREATE TRIGGER job_folders_no_update BEFORE UPDATE ON job_folders BEGIN SELECT RAISE(ABORT, 'folder mappings are immutable'); END;
CREATE TRIGGER job_folders_no_delete BEFORE DELETE ON job_folders BEGIN SELECT RAISE(ABORT, 'folder mappings are immutable'); END;
CREATE TRIGGER verification_events_no_update BEFORE UPDATE ON verification_events BEGIN SELECT RAISE(ABORT, 'verification events are append-only'); END;
CREATE TRIGGER verification_events_no_delete BEFORE DELETE ON verification_events BEGIN SELECT RAISE(ABORT, 'verification events are append-only'); END;
CREATE TRIGGER verification_runs_no_update BEFORE UPDATE ON verification_runs BEGIN SELECT RAISE(ABORT, 'verification runs are append-only'); END;
CREATE TRIGGER verification_runs_no_delete BEFORE DELETE ON verification_runs BEGIN SELECT RAISE(ABORT, 'verification runs are append-only'); END;
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKey {
    pub folder: String,
    pub uid_validity: u32,
    pub uid: u32,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub report_version: u32,
    pub scope: &'static str,
    pub planned: u64,
    pub uncertain: u64,
    pub accepted: u64,
    pub confirmed: u64,
    /// Planned messages an operator has explicitly skipped. They are NOT migrated.
    pub skipped: u64,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub key: MessageKey,
    pub hash: String,
    pub state: String,
    pub destination: Option<(u32, u32)>,
    pub date: Option<i64>,
    pub flags: Option<Vec<String>>,
    pub omitted: Vec<String>,
    pub baseline: Option<(u32, u32)>,
}

pub(crate) struct AppendMetadata<'a> {
    pub date: i64,
    pub flags: &'a [String],
    pub omitted: &'a [String],
    pub baseline: (u32, u32),
}

pub struct Journal(Connection, Evidence);

/// Verification evidence not yet written. Only full-content successes for records that are
/// already confirmed are buffered (they renew evidence but change no state); every state change
/// and every problem is written in its own transaction. Losing buffered rows in a crash costs
/// evidence, never correctness: nothing is claimed that is not durable.
#[derive(Default)]
struct Evidence {
    ready: std::cell::Cell<Option<bool>>,
    pending: Vec<PendingEvent>,
}
struct PendingEvent {
    key: MessageKey,
    size: Option<u64>,
    detail: String,
    observed_at: String,
}
const EVIDENCE_FLUSH_AT: usize = 256;
const INCOMPATIBLE_EVIDENCE: &str = "this schema-5 journal was created by a pre-release development build whose evidence tables cannot record lightweight checks; it is refused (nothing was changed). Schema 5 was never released: finish or abandon the job with that build, or start a new job";

/// What a journal can hold for verification evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceState {
    Absent,
    Current,
    Incompatible,
}

/// Verification times for one folder's confirmed messages (see `Journal::verification_overview`).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct FolderVerification {
    pub folder: String,
    pub confirmed: u64,
    /// Confirmed messages whose last successful full read-back has a recorded time.
    pub full_verification_recorded: u64,
    /// Confirmed messages with no recorded full-verification time (never invented).
    pub full_verification_unknown: u64,
    pub oldest_full_verification: Option<String>,
    pub newest_full_verification: Option<String>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct VerificationOverview {
    pub evidence: &'static str,
    pub note: &'static str,
    pub folders: Vec<FolderVerification>,
}

/// The most recent full (SHA-256) verification that succeeded for a message, if one was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullVerification {
    pub observed_at: String,
    pub size: Option<u64>,
}

/// A summary of one lightweight (existence or metadata) pass over already-confirmed records.
pub struct HistoryRun<'a> {
    pub level: &'a str,
    pub started_at: &'a str,
    pub checked: u64,
    pub drift: u64,
    pub problems: u64,
}

impl Journal {
    /// Existing journals only. A status typo must not create a new empty job.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        Self::configure(conn, Some(path))
    }

    /// Create a new private file without overwriting any existing job.
    pub fn create(path: &Path, binding: &str) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let temporary = tempfile::NamedTempFile::new_in(parent)?;
        let mut conn = Connection::open(temporary.path())?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction()?;
        tx.execute_batch(
            "CREATE TABLE job (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL);
            CREATE TABLE transfers (
                folder TEXT NOT NULL,
                uid_validity INTEGER NOT NULL CHECK(uid_validity BETWEEN 1 AND 4294967295),
                uid INTEGER NOT NULL CHECK(uid BETWEEN 1 AND 4294967295),
                fingerprint TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('planned','uncertain','accepted','confirmed')),
                destination_validity INTEGER,
                destination_uid INTEGER,
                date INTEGER, flags TEXT, omitted TEXT, baseline_validity INTEGER, baseline_next INTEGER,
                PRIMARY KEY(folder, uid_validity, uid),
                UNIQUE(folder, destination_validity, destination_uid)
            );
            CREATE TABLE snapshots (folder TEXT PRIMARY KEY, validity INTEGER NOT NULL, uids TEXT NOT NULL);
            CREATE TABLE resolutions (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL, destination_validity INTEGER NOT NULL, destination_uid INTEGER NOT NULL, observed_at TEXT NOT NULL);",
        )?;
        tx.execute("INSERT INTO job VALUES (1, ?1)", [binding])?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;
        drop(Self::configure(conn, None)?);
        temporary.persist_noclobber(path).map_err(|e| e.error)?;
        std::fs::File::open(parent)?.sync_all()?;
        Self::open(path)
    }

    pub fn open_read_only(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !SUPPORTED_SCHEMAS.contains(&version) {
            bail!("unsupported journal schema {version}");
        }
        Ok(Self(conn, Evidence::default()))
    }

    fn configure(mut conn: Connection, path: Option<&Path>) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !SUPPORTED_SCHEMAS.contains(&version) {
            bail!("unsupported journal schema {version}");
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        if version < SCHEMA_VERSION {
            if let Some(path) = path {
                crate::fault::point("before_upgrade_backup");
                backup_before_upgrade(&conn, path, version)?;
                crate::fault::point("after_upgrade_backup");
            }
            crate::fault::point("before_schema_upgrade");
        }
        if version == 1 {
            // Transactional additive upgrade. Never invent metadata or transfer evidence.
            let tx = conn.transaction()?;
            tx.execute_batch("ALTER TABLE transfers ADD COLUMN date INTEGER;
                ALTER TABLE transfers ADD COLUMN flags TEXT;
                ALTER TABLE transfers ADD COLUMN omitted TEXT;
                ALTER TABLE transfers ADD COLUMN baseline_validity INTEGER;
                ALTER TABLE transfers ADD COLUMN baseline_next INTEGER;
                CREATE TABLE snapshots (folder TEXT PRIMARY KEY, validity INTEGER NOT NULL, uids TEXT NOT NULL);
                CREATE TABLE resolutions (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL, destination_validity INTEGER NOT NULL, destination_uid INTEGER NOT NULL, observed_at TEXT NOT NULL);")?;
            tx.pragma_update(None, "user_version", 2)?;
            crate::fault::point("v1_upgrade_before_commit");
            tx.commit()?;
        } else if !(2..=SCHEMA_V5).contains(&version) {
            bail!("unsupported journal schema {version}; expected {SCHEMA_VERSION} or {SCHEMA_V5}");
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        if version < 3 {
            let tx = conn.transaction()?;
            tx.execute_batch("CREATE TABLE append_attempts (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('prepared','literal_authorized')), PRIMARY KEY(folder,validity,uid));
                CREATE TABLE recovery_events (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL, observed_at TEXT NOT NULL, evidence TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS append_rejections (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL, observed_at TEXT NOT NULL, evidence TEXT NOT NULL);")?;
            tx.pragma_update(None, "user_version", 3)?;
            crate::fault::point("schema_upgrade_before_commit");
            tx.commit()?;
            crate::fault::point("after_schema_upgrade");
        }
        if version < 4 {
            // Additive and audit-only: an append-only event log, no existing row changes.
            let tx = conn.transaction()?;
            tx.execute_batch("CREATE TABLE IF NOT EXISTS operator_skip_events (folder TEXT NOT NULL, validity INTEGER NOT NULL, uid INTEGER NOT NULL, action TEXT NOT NULL CHECK(action IN ('skip','unskip')), observed_at TEXT NOT NULL, reason TEXT NOT NULL, fingerprint TEXT NOT NULL, rejection_evidence TEXT NOT NULL);")?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            crate::fault::point("skip_schema_upgrade_before_commit");
            tx.commit()?;
            crate::fault::point("after_skip_schema_upgrade");
        }
        conn.pragma_update(None, "trusted_schema", false)?;
        Ok(Self(conn, Evidence::default()))
    }

    pub(crate) fn reject_append(
        &mut self,
        key: &MessageKey,
        proof: &crate::transport::AppendRejection,
    ) -> Result<()> {
        let tx = self.0.transaction()?;

        let changed = tx.execute("UPDATE transfers SET state='planned' WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='uncertain' AND destination_uid IS NULL", params![key.folder, key.uid_validity, key.uid])?;
        if changed != 1 {
            bail!("APPEND rejection requires an uncertain record without attribution");
        }
        tx.execute(
            "INSERT INTO append_rejections VALUES (?1,?2,?3,?4,?5)",
            params![
                key.folder,
                key.uid_validity,
                key.uid,
                chrono::Utc::now().to_rfc3339(),
                format!(
                    "matching tagged {} [{}] scope={}",
                    proof.status,
                    proof.code,
                    proof.scope().name()
                )
            ],
        )?;
        crate::fault::point("rejection_before_commit");
        tx.commit()?;
        crate::fault::point("after_rejection");
        Ok(())
    }

    /// Explicit, additive, crash-safe upgrade from schema 4 to schema 5 (incremental migration).
    /// Returns false when the journal is already at schema 5.
    ///
    /// Safety properties: a consistent backup is written first (never overwriting an earlier one);
    /// everything happens in ONE transaction, so a crash leaves schema 4 untouched; only new tables
    /// and triggers are created, no existing row or table changes; `job_folders` is seeded from the
    /// stored binding, and the upgrade is refused (nothing changed) if the journal's evidence names
    /// a folder the binding does not.
    pub fn upgrade_to_v5(&mut self, path: &Path) -> Result<bool> {
        // Whether evidence tables exist changes with this call; never trust an earlier answer.
        self.1.ready.set(None);
        let version: i64 = self
            .0
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == SCHEMA_V5 {
            return Ok(false);
        }
        if version != SCHEMA_VERSION {
            bail!(
                "only a schema {SCHEMA_VERSION} journal can be upgraded to schema {SCHEMA_V5} (found {version})"
            );
        }
        let folders = self.binding_folders()?;
        self.check_folders_declared(&folders)?;
        crate::fault::point("before_v5_backup");
        backup_before_upgrade(&self.0, path, version)?;
        crate::fault::point("after_v5_backup");
        crate::fault::point("before_v5_upgrade");
        let now = chrono::Utc::now().to_rfc3339();
        let tx = self.0.transaction()?;
        tx.execute_batch(V5_SCHEMA)?;
        for (source, destination) in &folders {
            tx.execute(
                "INSERT INTO job_folders (source,destination,origin,added_at) VALUES (?1,?2,'binding',?3)",
                params![source, destination, now],
            )?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_V5)?;
        crate::fault::point("v5_upgrade_before_commit");
        tx.commit()?;
        crate::fault::point("after_v5_upgrade");
        Ok(true)
    }

    /// The folder mappings recorded in the (never rewritten) job binding.
    fn binding_folders(&self) -> Result<Vec<(String, String)>> {
        let binding: String = self
            .0
            .query_row("SELECT binding FROM job WHERE id=1", [], |r| r.get(0))?;
        let value: serde_json::Value =
            serde_json::from_str(&binding).context("job binding is not valid JSON")?;
        let list = value
            .get("folders")
            .and_then(|f| f.as_array())
            .context("job binding has no folder list")?;
        let mut seen_source = std::collections::BTreeSet::new();
        let mut seen_destination = std::collections::BTreeSet::new();
        let mut result = Vec::new();
        for item in list {
            let field = |name: &str| {
                item.get(name)
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .with_context(|| format!("job binding folder lacks {name}"))
            };
            let (source, destination) = (field("source")?, field("destination")?);
            if !seen_source.insert(source.clone()) || !seen_destination.insert(destination.clone())
            {
                bail!("job binding folder mappings are not one-to-one");
            }
            result.push((source, destination));
        }
        if result.is_empty() {
            bail!("job binding has no folders");
        }
        Ok(result)
    }

    /// Every folder that has journal evidence must be one the binding declares.
    fn check_folders_declared(&self, declared: &[(String, String)]) -> Result<()> {
        let mut stmt = self
            .0
            .prepare("SELECT folder FROM transfers UNION SELECT folder FROM snapshots")?;
        for row in stmt.query_map([], |r| r.get::<_, String>(0))? {
            let folder = row?;
            if !declared.iter().any(|(source, _)| *source == folder) {
                bail!(
                    "journal has evidence for a folder the job binding does not declare; refusing to upgrade"
                );
            }
        }
        Ok(())
    }

    fn has_table(&self, name: &str) -> Result<bool> {
        Ok(self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [name],
            |r| r.get(0),
        )?)
    }

    /// Folder mappings recorded by a schema-5 journal (empty before schema 5).
    pub fn job_folders(&self) -> Result<Vec<(String, String, String)>> {
        if !self.has_table("job_folders")? {
            return Ok(Vec::new());
        }
        let mut stmt = self
            .0
            .prepare("SELECT source,destination,origin FROM job_folders ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .0
            .pragma_query_value(None, "user_version", |r| r.get(0))?)
    }

    /// The durable plan: for each folder the immutable generation-0 snapshot followed by every
    /// later discovery scan, in recorded order. On a schema-4 journal this is exactly `snapshots()`.
    /// Inconsistent evidence (a scan with another UIDVALIDITY, or a UID listed twice) is an error,
    /// never silently merged.
    pub fn work_list(&self) -> Result<Vec<(String, u32, Vec<u32>)>> {
        let mut plan: std::collections::BTreeMap<String, (u32, Vec<u32>)> = self
            .snapshots()?
            .into_iter()
            .map(|(folder, validity, uids)| (folder, (validity, uids)))
            .collect();
        if self.has_table("scans")? {
            let mut stmt = self.0.prepare(
                "SELECT folder,validity,uids FROM scans ORDER BY folder,validity,generation",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (folder, validity, json) = row?;
                let uids: Vec<u32> = serde_json::from_str(&json)?;
                let entry = plan.entry(folder.clone()).or_insert((validity, Vec::new()));
                if entry.0 != validity {
                    bail!("scan UIDVALIDITY differs from the recorded plan for {folder:?}");
                }
                entry.1.extend(uids);
            }
        }
        let mut result = Vec::new();
        for (folder, (validity, uids)) in plan {
            let distinct: std::collections::BTreeSet<_> = uids.iter().collect();
            if distinct.len() != uids.len() {
                bail!("a UID appears twice in the durable plan for {folder:?}");
            }
            result.push((folder, validity, uids));
        }
        Ok(result)
    }

    /// Every UID the journal already knows for a folder and UIDVALIDITY, whatever its transfer
    /// state (planned, skipped, rejected, uncertain, accepted, confirmed): the original snapshot,
    /// every recorded scan and every transfer row. Discovery treats only UIDs outside this set as new.
    pub fn known_uids(
        &self,
        folder: &str,
        validity: u32,
    ) -> Result<std::collections::BTreeSet<u32>> {
        known_in(&self.0, folder, validity)
    }

    /// Highest `UIDNEXT` observed by a recorded scan of this folder, if any.
    pub fn last_scan_uidnext(&self, folder: &str, validity: u32) -> Result<Option<u32>> {
        if !self.has_table("scans")? {
            return Ok(None);
        }
        Ok(self.0.query_row(
            "SELECT MAX(observed_uidnext) FROM scans WHERE folder=?1 AND validity=?2",
            params![folder, validity],
            |r| r.get(0),
        )?)
    }

    /// Record one discovery scan atomically: the new UIDs and the `UIDNEXT` they were found under
    /// become durable together or not at all. Only schema 5 can record a scan. The scan is refused
    /// if the folder has no plan, another UIDVALIDITY, a UID the journal already knows, a UID at or
    /// above `observed_uidnext`, or a `UIDNEXT` lower than an earlier observation. Returns the
    /// scan's generation.
    pub fn record_scan(
        &mut self,
        folder: &str,
        validity: u32,
        observed_uidnext: u32,
        uids: &[u32],
    ) -> Result<u32> {
        if self.schema_version()? != SCHEMA_V5 {
            bail!("recording a scan requires a schema 5 journal");
        }
        if uids.is_empty() || uids.windows(2).any(|w| w[0] >= w[1]) {
            bail!("a scan must list at least one UID, ascending and without repeats");
        }
        if uids.iter().any(|u| *u == 0 || *u >= observed_uidnext) {
            bail!("a scan UID lies outside the observed UIDNEXT horizon");
        }
        let tx = self.0.transaction()?;
        let planned: Option<u32> = tx
            .query_row(
                "SELECT validity FROM snapshots WHERE folder=?1",
                [folder],
                |r| r.get(0),
            )
            .optional()?;
        // A folder added after the job began has no original snapshot; its first scan is its baseline.
        let planned = match planned {
            Some(v) => Some(v),
            None => tx
                .query_row(
                    "SELECT validity FROM scans WHERE folder=?1 ORDER BY generation LIMIT 1",
                    [folder],
                    |r| r.get(0),
                )
                .optional()?,
        };
        if planned != Some(validity) {
            bail!("scan UIDVALIDITY differs from the folder's recorded plan");
        }
        let known = known_in(&tx, folder, validity)?;
        if uids.iter().any(|u| known.contains(u)) {
            bail!("a scan UID is already known to the journal");
        }
        let (previous_next, generation): (Option<u32>, u32) = tx.query_row(
            "SELECT MAX(observed_uidnext), COALESCE(MAX(generation),0)+1 FROM scans WHERE folder=?1 AND validity=?2",
            params![folder, validity],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if previous_next.is_some_and(|p| observed_uidnext < p)
            || known.last().is_some_and(|k| *k >= observed_uidnext)
        {
            bail!("source UIDNEXT is lower than earlier evidence; refusing to record the scan");
        }
        tx.execute(
            "INSERT INTO scans (folder,validity,generation,observed_uidnext,uids,scanned_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                folder,
                validity,
                generation,
                observed_uidnext,
                serde_json::to_string(uids)?,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        crate::fault::point("scan_before_commit");
        tx.commit()?;
        crate::fault::point("scan_after_commit");
        Ok(generation)
    }

    /// UIDs of unresolved `uncertain` transfers in a folder (any UIDVALIDITY).
    pub fn uncertain_uids(&self, folder: &str) -> Result<Vec<u32>> {
        let mut stmt = self.0.prepare(
            "SELECT uid FROM transfers WHERE folder=?1 AND state='uncertain' ORDER BY uid",
        )?;
        let rows = stmt.query_map([folder], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Destination UIDVALIDITY values recorded by transfers of a folder.
    pub fn destination_validities(&self, folder: &str) -> Result<std::collections::BTreeSet<u32>> {
        let mut stmt = self.0.prepare(
            "SELECT DISTINCT destination_validity FROM transfers WHERE folder=?1 AND destination_validity IS NOT NULL",
        )?;
        let rows = stmt.query_map([folder], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Identity check used by every command that does not add folders: the journal must belong to
    /// this configuration, and (schema 5) the configured folder mappings must be exactly the recorded ones.
    pub fn check_binding(&self, expected: &str) -> Result<()> {
        self.check_binding_mode(expected, false).map(|_| ())
    }

    /// Identity check that may admit new folders. The account part of the binding (hosts, ports,
    /// users) must match exactly. Every recorded mapping must be in the configuration, unchanged;
    /// a recorded folder that is missing, renamed or mapped elsewhere, and a new mapping that
    /// reuses a recorded destination, are refused. Mappings the job does not record yet are
    /// returned when `allow_new`, and refused (naming them) otherwise. A schema-4 journal with
    /// `allow_new == false` is compared byte for byte, exactly as before schema 5 existed.
    pub fn check_binding_mode(
        &self,
        expected: &str,
        allow_new: bool,
    ) -> Result<Vec<(String, String)>> {
        let actual: String = self
            .0
            .query_row("SELECT binding FROM job WHERE id=1", [], |r| r.get(0))?;
        if !self.has_table("job_folders")? && !allow_new {
            if actual != expected {
                // Same accounts and every recorded folder, only more folders configured: say how to add them.
                if let Ok(new) = self.check_binding_mode(expected, true) {
                    if !new.is_empty() {
                        let names: Vec<_> = new.iter().map(|(s, _)| s.as_str()).collect();
                        bail!(
                            "the configuration lists folder(s) {names:?} that this job does not record; folder mappings of an existing job are immutable except through `migrate --incremental --add-new-folders`"
                        );
                    }
                }
                bail!("journal belongs to a different migration");
            }
            return Ok(Vec::new());
        }
        let parse = |text: &str| -> Result<serde_json::Value> {
            serde_json::from_str(text).context("binding is not valid JSON")
        };
        let (have, want) = (parse(&actual)?, parse(expected)?);
        if have["source"] != want["source"] || have["destination"] != want["destination"] {
            bail!("journal belongs to a different migration");
        }
        let configured: Vec<(String, String)> = want["folders"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|f| {
                        (
                            f["source"].as_str().unwrap_or_default().to_owned(),
                            f["destination"].as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let recorded = self.recorded_folders()?;
        let canon = |n: &str| {
            if n.eq_ignore_ascii_case("INBOX") {
                "INBOX".to_owned()
            } else {
                n.to_owned()
            }
        };
        for (rs, rd) in &recorded {
            match configured.iter().find(|(s, _)| s == rs) {
                None => bail!(
                    "folder {rs:?} is recorded in this job but missing from the configuration; folder mappings are immutable (removing or renaming a folder is refused)"
                ),
                Some((_, d)) if d != rd => bail!(
                    "folder {rs:?} is recorded as mapped to {rd:?} but the configuration maps it to {d:?}; folder mappings are immutable (remapping is refused)"
                ),
                Some(_) => {}
            }
        }
        let mut new = Vec::new();
        for (s, d) in &configured {
            if recorded.iter().any(|(rs, _)| rs == s) {
                continue;
            }
            if let Some((rs, _)) = recorded.iter().find(|(_, rd)| canon(rd) == canon(d)) {
                bail!(
                    "destination {d:?} is already used by recorded source folder {rs:?}; a conflicting folder mapping is refused"
                );
            }
            new.push((s.clone(), d.clone()));
        }
        if !new.is_empty() && !allow_new {
            let names: Vec<_> = new.iter().map(|(s, _)| s.as_str()).collect();
            bail!(
                "the configuration lists folder(s) {names:?} that this job does not record; folder mappings of an existing job are immutable except through `migrate --incremental --add-new-folders`"
            );
        }
        Ok(new)
    }

    /// The job's folder mappings: `job_folders` on schema 5 (the authority, including added
    /// folders), otherwise the mappings in the never-rewritten binding.
    pub fn recorded_folders(&self) -> Result<Vec<(String, String)>> {
        if self.has_table("job_folders")? {
            return Ok(self
                .job_folders()?
                .into_iter()
                .map(|(s, d, _)| (s, d))
                .collect());
        }
        self.binding_folders()
    }

    /// True for a folder whose plan consists only of scans (it was added after the job began).
    pub fn is_scan_only(&self, folder: &str) -> Result<bool> {
        if !self.has_table("scans")? {
            return Ok(false);
        }
        Ok(self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM scans WHERE folder=?1) AND NOT EXISTS(SELECT 1 FROM snapshots WHERE folder=?1)",
            [folder],
            |r| r.get(0),
        )?)
    }

    /// Add a folder to an existing schema-5 job, atomically: its immutable mapping and its first
    /// scan (the full, consistent UID listing; the baseline that fixes its source UIDVALIDITY and
    /// UIDNEXT, empty if the folder is empty) become durable together or not at all. Refused if the
    /// source or destination is already recorded or the journal holds any evidence for the folder.
    /// No existing snapshot, scan or mapping is touched.
    pub fn add_folder(
        &mut self,
        source: &str,
        destination: &str,
        validity: u32,
        observed_uidnext: u32,
        uids: &[u32],
    ) -> Result<()> {
        if self.schema_version()? != SCHEMA_V5 {
            bail!("adding a folder requires a schema 5 journal");
        }
        if validity == 0 || observed_uidnext == 0 {
            bail!("a folder baseline needs a nonzero UIDVALIDITY and UIDNEXT");
        }
        if uids.windows(2).any(|w| w[0] >= w[1])
            || uids.iter().any(|u| *u == 0 || *u >= observed_uidnext)
        {
            bail!("a folder baseline must list ascending UIDs below UIDNEXT");
        }
        let tx = self.0.transaction()?;
        let canon = |n: &str| {
            if n.eq_ignore_ascii_case("INBOX") {
                "INBOX".to_owned()
            } else {
                n.to_owned()
            }
        };
        let mappings: Vec<(String, String)> = {
            let mut stmt = tx.prepare("SELECT source,destination FROM job_folders")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        if mappings.iter().any(|(s, _)| canon(s) == canon(source)) {
            bail!("folder {source:?} is already part of this job");
        }
        if mappings.iter().any(|(_, d)| canon(d) == canon(destination)) {
            bail!("destination {destination:?} is already used by another folder of this job");
        }
        let evidence: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM transfers WHERE folder=?1) OR EXISTS(SELECT 1 FROM snapshots WHERE folder=?1) OR EXISTS(SELECT 1 FROM scans WHERE folder=?1)",
            [source],
            |r| r.get(0),
        )?;
        if evidence {
            bail!("the journal already holds evidence for folder {source:?}; refusing to add it");
        }
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO job_folders (source,destination,origin,added_at) VALUES (?1,?2,'added',?3)",
            params![source, destination, now],
        )?;
        tx.execute(
            "INSERT INTO scans (folder,validity,generation,observed_uidnext,uids,scanned_at) VALUES (?1,?2,1,?3,?4,?5)",
            params![
                source,
                validity,
                observed_uidnext,
                serde_json::to_string(uids)?,
                now
            ],
        )?;
        crate::fault::point("folder_add_before_commit");
        tx.commit()?;
        crate::fault::point("folder_add_after_commit");
        Ok(())
    }

    pub fn plan(&mut self, key: &MessageKey, body: &[u8]) -> Result<()> {
        crate::fault::point("before_plan");
        if key.uid == 0 || key.uid_validity == 0 {
            bail!("UID and UIDVALIDITY must be nonzero");
        }
        let hash = fingerprint(body);
        let tx = self.0.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT fingerprint FROM transfers WHERE folder=?1 AND uid_validity=?2 AND uid=?3",
                params![key.folder, key.uid_validity, key.uid],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            if old != hash {
                bail!("source content changed for an existing UID; refusing to replace evidence");
            }
        } else {
            let other: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM transfers WHERE folder=?1 AND uid_validity<>?2)",
                params![key.folder, key.uid_validity],
                |r| r.get(0),
            )?;
            if other {
                bail!("source UIDVALIDITY changed; re-planning required");
            }
            tx.execute(
                "INSERT INTO transfers (folder,uid_validity,uid,fingerprint,state) VALUES (?1,?2,?3,?4,'planned')",
                params![key.folder, key.uid_validity, key.uid, hash],
            )?;
        }
        tx.commit()?;
        crate::fault::point("after_plan");
        Ok(())
    }

    /// One FULL preparation commit; no externally visible operation precedes it.
    /// Legacy public transition helpers remain for compatibility and focused tests.
    pub(crate) fn prepare_append(
        &mut self,
        key: &MessageKey,
        body: &[u8],
        metadata: AppendMetadata<'_>,
    ) -> Result<Record> {
        self.prepare_append_fingerprint(key, &fingerprint(body), metadata)
    }

    /// The same single FULL preparation commit, for content whose SHA-256 was computed while
    /// streaming. Identical checks: a differing stored fingerprint refuses to replace evidence.
    pub(crate) fn prepare_append_fingerprint(
        &mut self,
        key: &MessageKey,
        hash: &str,
        metadata: AppendMetadata<'_>,
    ) -> Result<Record> {
        crate::fault::point("before_plan");
        if key.uid == 0
            || key.uid_validity == 0
            || metadata.baseline.0 == 0
            || metadata.baseline.1 == 0
        {
            bail!("invalid append identity or baseline");
        }
        let hash = hash.to_string();
        let tx = self.0.transaction()?;
        let old: Option<(String, String, Option<i64>)> = tx.query_row("SELECT fingerprint,state,date FROM transfers WHERE folder=?1 AND uid_validity=?2 AND uid=?3", params![key.folder,key.uid_validity,key.uid], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((previous, state, date)) = &old {
            if previous != &hash {
                bail!("source content changed for an existing UID; refusing to replace evidence");
            }
            if state != "planned" {
                bail!(
                    "only a planned transfer can prepare an APPEND; uncertain transfers cannot be retried"
                );
            }
            if date.is_some_and(|date| date != metadata.date) {
                bail!("source INTERNALDATE changed since planning");
            }
        } else {
            let changed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM transfers WHERE folder=?1 AND uid_validity<>?2)",
                params![key.folder, key.uid_validity],
                |r| r.get(0),
            )?;
            if changed {
                bail!("source UIDVALIDITY changed; re-planning required");
            }
            tx.execute("INSERT INTO transfers (folder,uid_validity,uid,fingerprint,state) VALUES (?1,?2,?3,?4,'planned')", params![key.folder,key.uid_validity,key.uid,hash])?;
        }
        crate::fault::point("after_plan");
        crate::fault::point("before_metadata");
        // Preserve frozen date/flags on a previously planned, definitely rejected attempt.
        if old.as_ref().is_none_or(|(_, _, date)| date.is_none()) {
            require_one(tx.execute("UPDATE transfers SET date=?4,flags=?5,omitted=?6 WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='planned' AND date IS NULL", params![key.folder,key.uid_validity,key.uid,metadata.date,serde_json::to_string(metadata.flags)?,serde_json::to_string(metadata.omitted)?])?)?;
        }
        crate::fault::point("after_metadata");
        crate::fault::point("before_baseline");
        require_one(tx.execute("UPDATE transfers SET baseline_validity=?4,baseline_next=?5 WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='planned'", params![key.folder,key.uid_validity,key.uid,metadata.baseline.0,metadata.baseline.1])?)?;
        crate::fault::point("after_baseline");
        crate::fault::point("before_begin_append");
        require_one(tx.execute("UPDATE transfers SET state='uncertain' WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='planned'", params![key.folder,key.uid_validity,key.uid])?)?;
        tx.execute("INSERT INTO append_attempts VALUES (?1,?2,?3,'prepared') ON CONFLICT(folder,validity,uid) DO UPDATE SET phase='prepared'", params![key.folder,key.uid_validity,key.uid])?;
        crate::fault::point("begin_append_before_commit");
        tx.commit()?;
        crate::fault::point("after_begin_append");
        self.record(key)?.context("prepared record missing")
    }

    /// Must commit successfully before any APPEND bytes may be sent.
    /// An uncertain record cannot begin another upload, even after restart.
    pub fn begin_append(&mut self, key: &MessageKey) -> Result<()> {
        crate::fault::point("before_begin_append");
        let tx = self.0.transaction()?;
        require_one(tx.execute("UPDATE transfers SET state='uncertain' WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='planned'", params![key.folder,key.uid_validity,key.uid])?)?;
        tx.execute("INSERT INTO append_attempts VALUES (?1,?2,?3,'prepared') ON CONFLICT(folder,validity,uid) DO UPDATE SET phase='prepared'", params![key.folder,key.uid_validity,key.uid])?;
        crate::fault::point("begin_append_before_commit");
        tx.commit()?;
        crate::fault::point("after_begin_append");
        Ok(())
    }

    /// FULL commit must succeed BEFORE the adapter sends any literal bytes.
    pub(crate) fn authorize_literal(&mut self, key: &MessageKey) -> Result<()> {
        crate::fault::point("before_authorize_literal");
        let tx = self.0.transaction()?;
        require_one(tx.execute("UPDATE append_attempts SET phase='literal_authorized' WHERE folder=?1 AND validity=?2 AND uid=?3 AND phase='prepared' AND EXISTS(SELECT 1 FROM transfers WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='uncertain')", params![key.folder,key.uid_validity,key.uid])?)?;
        crate::fault::point("authorize_literal_before_commit");
        tx.commit()?;
        crate::fault::point("after_authorize_literal");
        Ok(())
    }

    /// Absence of this new fence on legacy records is NOT evidence of no send.
    pub(crate) fn recover_not_sent(
        &mut self,
        key: &MessageKey,
        destination_validity: u32,
    ) -> Result<()> {
        let tx = self.0.transaction()?;
        require_one(tx.execute("UPDATE transfers SET state='planned' WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='uncertain' AND destination_uid IS NULL AND baseline_validity=?4 AND EXISTS(SELECT 1 FROM append_attempts WHERE folder=?1 AND validity=?2 AND uid=?3 AND phase='prepared')", params![key.folder,key.uid_validity,key.uid,destination_validity])?).context("no durable proof that literal sending was never authorized; manual review required")?;
        tx.execute("INSERT INTO recovery_events VALUES (?1,?2,?3,?4,'literal never authorized; operator recovery')", params![key.folder,key.uid_validity,key.uid,chrono::Utc::now().to_rfc3339()])?;
        tx.execute(
            "DELETE FROM append_attempts WHERE folder=?1 AND validity=?2 AND uid=?3",
            params![key.folder, key.uid_validity, key.uid],
        )?;
        crate::fault::point("recovery_before_commit");
        tx.commit()?;
        crate::fault::point("after_recovery");
        Ok(())
    }

    /// Call only for a tagged success carrying valid APPENDUID evidence.
    pub fn acknowledge(&mut self, key: &MessageKey, validity: u32, uid: u32) -> Result<()> {
        if validity == 0 || uid == 0 {
            bail!("invalid destination APPENDUID");
        }
        crate::fault::point("before_acknowledge");
        let tx = self.0.transaction()?;
        let count = tx.execute(
            "UPDATE transfers SET state='accepted',destination_validity=?4,destination_uid=?5
             WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='uncertain'",
            params![key.folder, key.uid_validity, key.uid, validity, uid],
        )?;
        require_one(count)?;
        crate::fault::point("acknowledge_before_commit");
        tx.commit()?;
        crate::fault::point("after_acknowledge");
        Ok(())
    }

    /// The engine verifies date and flags before this content/identity transition.
    /// Identity must match the acknowledged destination, not merely a hash match.
    pub fn confirm_content(
        &mut self,
        key: &MessageKey,
        validity: u32,
        uid: u32,
        body: &[u8],
    ) -> Result<()> {
        self.confirm_content_fingerprint(key, validity, uid, &fingerprint(body))
    }

    /// Same transition with a fingerprint already computed (for example while streaming).
    /// The SQL still requires it to equal the stored fingerprint, so a digest that does not
    /// match the journaled content can never confirm.
    pub fn confirm_content_fingerprint(
        &mut self,
        key: &MessageKey,
        validity: u32,
        uid: u32,
        fingerprint: &str,
    ) -> Result<()> {
        self.confirm_verified(key, validity, uid, fingerprint, None)
    }

    /// The only transition that creates `confirmed`. It is reached only after a full SHA-256
    /// read-back, and on a schema-5 journal it appends the matching `full`/`ok` evidence event in
    /// the same transaction (so the observed size is durable exactly when the state is).
    pub fn confirm_verified(
        &mut self,
        key: &MessageKey,
        validity: u32,
        uid: u32,
        fingerprint: &str,
        size: Option<u64>,
    ) -> Result<()> {
        crate::fault::point("before_confirm");
        let evidence = self.evidence_ready()?;
        let tx = self.0.transaction()?;
        let count = tx.execute(
            "UPDATE transfers SET state='confirmed' WHERE folder=?1 AND uid_validity=?2 AND uid=?3
             AND state='accepted' AND destination_validity=?4 AND destination_uid=?5 AND fingerprint=?6",
            params![key.folder, key.uid_validity, key.uid, validity, uid, fingerprint],
        ).context("persist content verification")?;
        require_one(count)?;
        if evidence {
            insert_event(
                &tx,
                key,
                "full",
                "ok",
                size,
                "content, INTERNALDATE and flags matched; record confirmed",
                &chrono::Utc::now().to_rfc3339(),
            )?;
        }
        tx.commit()?;
        crate::fault::point("after_confirm");
        Ok(())
    }

    /// Persist the UID set once. Resumes retain it; new arrivals need a new job.
    pub fn snapshot(&mut self, folder: &str, validity: u32, uids: &[u32]) -> Result<Vec<u32>> {
        let changed: bool = self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM transfers WHERE folder=?1 AND uid_validity<>?2)",
            params![folder, validity],
            |r| r.get(0),
        )?;
        if changed {
            bail!("source UIDVALIDITY differs from existing journal evidence");
        }

        let old: Option<(u32, String)> = self
            .0
            .query_row(
                "SELECT validity,uids FROM snapshots WHERE folder=?1",
                [folder],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((old_validity, json)) = old {
            if old_validity != validity {
                bail!("source UIDVALIDITY changed for {folder:?}; refusing to reuse the snapshot");
            }
            return Ok(serde_json::from_str(&json)?);
        }
        // A folder that exists only as discovery scans has no original snapshot, and one must never
        // be invented for it: that would re-plan every message the scans already cover.
        if self.has_table("scans")? {
            let scanned: bool = self.0.query_row(
                "SELECT EXISTS(SELECT 1 FROM scans WHERE folder=?1)",
                [folder],
                |r| r.get(0),
            )?;
            if scanned {
                bail!(
                    "folder {folder:?} has discovery scans but no original snapshot; refusing to create one"
                );
            }
        }
        self.0.execute(
            "INSERT INTO snapshots VALUES (?1,?2,?3)",
            params![folder, validity, serde_json::to_string(uids)?],
        )?;
        Ok(uids.to_vec())
    }

    pub fn snapshots(&self) -> Result<Vec<(String, u32, Vec<u32>)>> {
        let mut stmt = self
            .0
            .prepare("SELECT folder,validity,uids FROM snapshots ORDER BY folder")?;
        let mut result = Vec::new();
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
            ))
        })? {
            let (f, v, json) = row?;
            result.push((f, v, serde_json::from_str(&json)?));
        }
        Ok(result)
    }

    pub fn metadata(
        &mut self,
        key: &MessageKey,
        date: i64,
        flags: &[String],
        omitted: &[String],
        baseline: (u32, u32),
    ) -> Result<()> {
        crate::fault::point("before_metadata");
        let flags = serde_json::to_string(flags)?;
        let omitted = serde_json::to_string(omitted)?;
        let changed = self.0.execute(
            "UPDATE transfers SET date=?4,flags=?5,omitted=?6,baseline_validity=?7,baseline_next=?8
            WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='planned' AND date IS NULL",
            params![
                key.folder,
                key.uid_validity,
                key.uid,
                date,
                flags,
                omitted,
                baseline.0,
                baseline.1
            ],
        )?;
        if changed != 1 {
            bail!("metadata already frozen or transfer is not planned");
        }
        crate::fault::point("after_metadata");
        Ok(())
    }

    /// Only an upload not yet attempted may refresh its destination baseline.
    pub fn refresh_baseline(&mut self, key: &MessageKey, baseline: (u32, u32)) -> Result<()> {
        crate::fault::point("before_baseline");
        let result = require_one(self.0.execute("UPDATE transfers SET baseline_validity=?4,baseline_next=?5 WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='planned'",
            params![key.folder,key.uid_validity,key.uid,baseline.0,baseline.1])?);
        result?;
        crate::fault::point("after_baseline");
        Ok(())
    }

    pub fn record(&self, key: &MessageKey) -> Result<Option<Record>> {
        Ok(self.0.query_row(
            "SELECT folder,uid_validity,uid,fingerprint,state,destination_validity,destination_uid,date,flags,omitted,baseline_validity,baseline_next FROM transfers WHERE folder=?1 AND uid_validity=?2 AND uid=?3",
            params![key.folder,key.uid_validity,key.uid], read_record).optional()?)
    }

    pub fn records(&self) -> Result<Vec<Record>> {
        let mut stmt = self.0.prepare("SELECT folder,uid_validity,uid,fingerprint,state,destination_validity,destination_uid,date,flags,omitted,baseline_validity,baseline_next FROM transfers ORDER BY folder,uid")?;
        let rows = stmt.query_map([], read_record)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn resolve_attribution(&mut self, key: &MessageKey, validity: u32, uid: u32) -> Result<()> {
        let tx = self.0.transaction()?;
        let count = tx.execute("UPDATE transfers SET state='accepted',destination_validity=?4,destination_uid=?5 WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='uncertain'",params![key.folder,key.uid_validity,key.uid,validity,uid])?;
        require_one(count)?;
        tx.execute(
            "INSERT INTO resolutions VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                key.folder,
                key.uid_validity,
                key.uid,
                validity,
                uid,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        crate::fault::point("resolution_before_commit");
        tx.commit()?;
        crate::fault::point("after_resolution");
        Ok(())
    }

    pub fn invalidate(&mut self, key: &MessageKey) -> Result<()> {
        crate::fault::point("before_invalidate");
        self.0.execute("UPDATE transfers SET state='accepted' WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='confirmed'",params![key.folder,key.uid_validity,key.uid])?;
        crate::fault::point("after_invalidate");
        Ok(())
    }

    /// Demote a `confirmed` record to `accepted` because a check observed a real problem, and
    /// append the evidence (level, result, observed size) in the same transaction on schema 5.
    /// Nothing is deleted and nothing is re-uploaded: the destination identity stays recorded.
    pub fn demote(
        &mut self,
        key: &MessageKey,
        level: &str,
        result: &str,
        detail: &str,
        size: Option<u64>,
    ) -> Result<()> {
        crate::fault::point("before_invalidate");
        let evidence = self.evidence_ready()?;
        let tx = self.0.transaction()?;
        tx.execute("UPDATE transfers SET state='accepted' WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='confirmed'",params![key.folder,key.uid_validity,key.uid])?;
        if evidence {
            insert_event(
                &tx,
                key,
                level,
                result,
                size,
                detail,
                &chrono::Utc::now().to_rfc3339(),
            )?;
        }
        tx.commit()?;
        crate::fault::point("after_invalidate");
        Ok(())
    }

    /// What this journal can hold for verification evidence: nothing (before schema 5), the
    /// current tables, or tables made by a pre-release development build that cannot record
    /// lightweight checks. Never fails on an incompatible file, so read-only reporting can describe it.
    pub fn evidence_state(&self) -> Result<EvidenceState> {
        if !self.has_table("verification_events")? {
            return Ok(EvidenceState::Absent);
        }
        let ddl: String = self.0.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='verification_events'",
            [],
            |r| r.get(0),
        )?;
        Ok(if ddl.contains("'existence'") {
            EvidenceState::Current
        } else {
            EvidenceState::Incompatible
        })
    }

    /// True when this journal can hold verification evidence: schema 5 with the current table
    /// definition. A schema-5 journal made by a pre-release build (events limited to `full`) is an
    /// error, never silently treated as evidence-free.
    pub fn evidence_ready(&self) -> Result<bool> {
        if let Some(ready) = self.1.ready.get() {
            return Ok(ready);
        }
        let ready = match self.evidence_state()? {
            EvidenceState::Absent => false,
            EvidenceState::Current => true,
            EvidenceState::Incompatible => bail!(INCOMPATIBLE_EVIDENCE),
        };
        self.1.ready.set(Some(ready));
        Ok(ready)
    }

    /// Refuse, before any network or write, a journal whose evidence tables came from a pre-release
    /// development build.
    pub fn require_compatible_evidence(&self) -> Result<()> {
        if self.evidence_state()? == EvidenceState::Incompatible {
            bail!(INCOMPATIBLE_EVIDENCE);
        }
        Ok(())
    }

    /// Per folder: how many messages are confirmed, when the content of those was last proven by a
    /// full SHA-256 read-back (oldest and newest recorded), and how many have no recorded time at
    /// all. Read-only and valid on any schema; nothing is invented for older journals.
    pub fn verification_overview(&self) -> Result<VerificationOverview> {
        let state = self.evidence_state()?;
        let mut latest: std::collections::HashMap<(String, u32, u32), String> =
            std::collections::HashMap::new();
        if state == EvidenceState::Current {
            let mut stmt = self.0.prepare(
                "SELECT folder,validity,uid,observed_at FROM verification_events WHERE level='full' AND result='ok' ORDER BY rowid",
            )?;
            for row in stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })? {
                let (f, v, u, at) = row?;
                latest.insert((f, v, u), at);
            }
        }
        // Status must describe any journal it can open; an unreadable binding only costs the list of
        // folders that have no confirmed message yet (the others are found from the transfers).
        let mut folders: std::collections::BTreeMap<String, FolderVerification> = self
            .recorded_folders()
            .unwrap_or_default()
            .into_iter()
            .map(|(source, _)| {
                (
                    source.clone(),
                    FolderVerification {
                        folder: source,
                        ..FolderVerification::default()
                    },
                )
            })
            .collect();
        let mut stmt = self
            .0
            .prepare("SELECT folder,uid_validity,uid FROM transfers WHERE state='confirmed'")?;
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, u32>(2)?,
            ))
        })? {
            let (f, v, u) = row?;
            let entry = folders
                .entry(f.clone())
                .or_insert_with(|| FolderVerification {
                    folder: f.clone(),
                    ..FolderVerification::default()
                });
            entry.confirmed += 1;
            match latest.get(&(f, v, u)) {
                Some(at) => {
                    entry.full_verification_recorded += 1;
                    if entry
                        .oldest_full_verification
                        .as_ref()
                        .is_none_or(|o| at < o)
                    {
                        entry.oldest_full_verification = Some(at.clone());
                    }
                    if entry
                        .newest_full_verification
                        .as_ref()
                        .is_none_or(|n| at > n)
                    {
                        entry.newest_full_verification = Some(at.clone());
                    }
                }
                None => entry.full_verification_unknown += 1,
            }
        }
        let (evidence, note) = match state {
            EvidenceState::Absent => (
                "none",
                "this journal predates schema 5 and records no verification times: every confirmed message has an unknown last full verification",
            ),
            EvidenceState::Current => (
                "recorded",
                "times are the last recorded successful full SHA-256 read-backs; messages confirmed before schema 5 have no recorded time. A metadata or existence check is never counted here",
            ),
            EvidenceState::Incompatible => (
                "incompatible",
                "the evidence tables were made by a pre-release development build and are not read; every confirmed message is reported with an unknown last full verification",
            ),
        };
        Ok(VerificationOverview {
            evidence,
            note,
            folders: folders.into_values().collect(),
        })
    }

    /// A full-content check passed for an already-confirmed record. This renews evidence only; it
    /// changes no state. Buffered and written in batches (see `Evidence`).
    pub fn note_full_ok(
        &mut self,
        key: &MessageKey,
        size: Option<u64>,
        detail: &str,
    ) -> Result<()> {
        if !self.evidence_ready()? {
            return Ok(());
        }
        self.1.pending.push(PendingEvent {
            key: key.clone(),
            size,
            detail: detail.into(),
            observed_at: chrono::Utc::now().to_rfc3339(),
        });
        if self.1.pending.len() >= EVIDENCE_FLUSH_AT {
            self.flush_evidence()?;
        }
        Ok(())
    }

    /// Write buffered renewal evidence in one transaction.
    pub fn flush_evidence(&mut self) -> Result<()> {
        if self.1.pending.is_empty() {
            return Ok(());
        }
        let tx = self.0.transaction()?;
        for e in &self.1.pending {
            insert_event(&tx, &e.key, "full", "ok", e.size, &e.detail, &e.observed_at)?;
        }
        crate::fault::point("evidence_before_commit");
        tx.commit()?;
        crate::fault::point("evidence_after_commit");
        self.1.pending.clear();
        Ok(())
    }

    /// Latest successful full verification per message of one folder, from the event table. A
    /// message with no such event (anything confirmed before schema 5) is simply absent: its
    /// verification time is unknown and is never reconstructed.
    pub fn last_full_verifications(
        &self,
        folder: &str,
    ) -> Result<std::collections::HashMap<(u32, u32), FullVerification>> {
        let mut map = std::collections::HashMap::new();
        if !self.evidence_ready()? {
            return Ok(map);
        }
        let mut stmt = self.0.prepare(
            "SELECT validity,uid,observed_at,size FROM verification_events
             WHERE folder=?1 AND level='full' AND result='ok' ORDER BY rowid",
        )?;
        let rows = stmt.query_map([folder], |r| {
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?;
        for row in rows {
            let (v, u, at, size) = row?;
            let size = size.and_then(|s| u64::try_from(s).ok());
            // A later event without a size (legacy path) must not erase a size learned earlier.
            let known = map.get(&(v, u)).and_then(|f: &FullVerification| f.size);
            map.insert(
                (v, u),
                FullVerification {
                    observed_at: at,
                    size: size.or(known),
                },
            );
        }
        Ok(map)
    }

    /// Records of one folder that are currently `confirmed` and have a destination identity.
    pub fn confirmed_records(&self, folder: &str, validity: u32) -> Result<Vec<Record>> {
        let mut stmt = self.0.prepare("SELECT folder,uid_validity,uid,fingerprint,state,destination_validity,destination_uid,date,flags,omitted,baseline_validity,baseline_next FROM transfers WHERE folder=?1 AND uid_validity=?2 AND state='confirmed' AND destination_uid IS NOT NULL ORDER BY uid")?;
        let rows = stmt.query_map(params![folder, validity], read_record)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Summarise one lightweight pass (counts and times only; per-message rows are written solely
    /// for problems). Nothing here can change a transfer state.
    pub fn record_history_run(&mut self, run: &HistoryRun<'_>) -> Result<()> {
        if !self.evidence_ready()? {
            return Ok(());
        }
        let tx = self.0.transaction()?;
        tx.execute(
            "INSERT INTO verification_runs (level,started_at,finished_at,checked,drift,problems) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                run.level,
                run.started_at,
                chrono::Utc::now().to_rfc3339(),
                run.checked as i64,
                run.drift as i64,
                run.problems as i64
            ],
        )?;
        crate::fault::point("history_run_before_commit");
        tx.commit()?;
        crate::fault::point("history_run_after_commit");
        Ok(())
    }

    pub fn summary(&self) -> Result<Summary> {
        let mut result = Summary {
            report_version: 1,
            scope: "historical journal content evidence; no live or metadata verification",
            planned: 0,
            uncertain: 0,
            accepted: 0,
            confirmed: 0,
            skipped: 0,
        };
        let mut stmt = self
            .0
            .prepare("SELECT state, count(*) FROM transfers GROUP BY state")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (state, count) = row?;
            let count = u64::try_from(count).context("invalid negative transfer count")?;
            match state.as_str() {
                "planned" => result.planned = count,
                "uncertain" => result.uncertain = count,
                "accepted" => result.accepted = count,
                "confirmed" => result.confirmed = count,
                _ => bail!("unknown journal state"),
            }
        }
        // Read-only status opens journals older than schema 4 without upgrading them.
        let has_events: bool = self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='operator_skip_events')",
            [],
            |r| r.get(0),
        )?;
        if has_events {
            let skipped: i64 = self.0.query_row(
                "SELECT count(*) FROM transfers t WHERE t.state='planned' AND t.destination_uid IS NULL AND (SELECT action FROM operator_skip_events e WHERE e.folder=t.folder AND e.validity=t.uid_validity AND e.uid=t.uid ORDER BY e.rowid DESC LIMIT 1)='skip'",
                [],
                |r| r.get(0),
            )?;
            result.skipped = u64::try_from(skipped).context("invalid skip count")?;
        }
        Ok(result)
    }

    /// The operator's reason when this message is currently skipped, else None.
    /// A skip only has force while the record is still an unattributed planned
    /// transfer; it can never make any other state look skipped.
    pub fn active_skip(&self, key: &MessageKey) -> Result<Option<String>> {
        Ok(self
            .0
            .query_row(
                "SELECT e.reason FROM operator_skip_events e WHERE e.folder=?1 AND e.validity=?2 AND e.uid=?3 AND e.action='skip' AND e.rowid=(SELECT max(rowid) FROM operator_skip_events WHERE folder=?1 AND validity=?2 AND uid=?3) AND EXISTS(SELECT 1 FROM transfers t WHERE t.folder=?1 AND t.uid_validity=?2 AND t.uid=?3 AND t.state='planned' AND t.destination_uid IS NULL)",
                params![key.folder, key.uid_validity, key.uid],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Record an operator decision NOT to migrate a permanently rejected message.
    /// Refuses unless the transfer is a planned, unattributed record (a state only
    /// reachable when no APPEND is outstanding) with at least one durable tagged
    /// rejection. The message stays planned: a skip is evidence of intent, never
    /// of delivery, and it changes no transfer state.
    pub fn skip_rejected(&mut self, key: &MessageKey, reason: &str) -> Result<()> {
        let reason = checked_reason(reason)?;
        let tx = self.0.transaction()?;
        let fingerprint: String = tx
            .query_row(
                "SELECT fingerprint FROM transfers WHERE folder=?1 AND uid_validity=?2 AND uid=?3 AND state='planned' AND destination_uid IS NULL",
                params![key.folder, key.uid_validity, key.uid],
                |r| r.get(0),
            )
            .optional()?
            .context("skip refused: only a planned, never-attributed transfer (not uncertain, accepted or confirmed) can be skipped")?;
        let evidence: String = tx
            .query_row(
                "SELECT evidence FROM append_rejections WHERE folder=?1 AND validity=?2 AND uid=?3 ORDER BY rowid DESC LIMIT 1",
                params![key.folder, key.uid_validity, key.uid],
                |r| r.get(0),
            )
            .optional()?
            .context("skip refused: no durable tagged APPEND rejection exists for this message")?;
        let latest: Option<String> = tx
            .query_row(
                "SELECT action FROM operator_skip_events WHERE folder=?1 AND validity=?2 AND uid=?3 ORDER BY rowid DESC LIMIT 1",
                params![key.folder, key.uid_validity, key.uid],
                |r| r.get(0),
            )
            .optional()?;
        if latest.as_deref() == Some("skip") {
            bail!("message is already skipped");
        }
        tx.execute(
            "INSERT INTO operator_skip_events VALUES (?1,?2,?3,'skip',?4,?5,?6,?7)",
            params![
                key.folder,
                key.uid_validity,
                key.uid,
                chrono::Utc::now().to_rfc3339(),
                reason,
                fingerprint,
                evidence
            ],
        )?;
        crate::fault::point("skip_before_commit");
        tx.commit()?;
        crate::fault::point("after_skip");
        Ok(())
    }

    /// Reverse a skip so the message follows the normal path again. Audited.
    pub fn unskip(&mut self, key: &MessageKey, reason: &str) -> Result<()> {
        let reason = checked_reason(reason)?;
        let tx = self.0.transaction()?;
        let (action, fingerprint, evidence): (String, String, String) = tx
            .query_row(
                "SELECT action, fingerprint, rejection_evidence FROM operator_skip_events WHERE folder=?1 AND validity=?2 AND uid=?3 ORDER BY rowid DESC LIMIT 1",
                params![key.folder, key.uid_validity, key.uid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .context("message has no operator skip to reverse")?;
        if action != "skip" {
            bail!("message is not currently skipped");
        }
        tx.execute(
            "INSERT INTO operator_skip_events VALUES (?1,?2,?3,'unskip',?4,?5,?6,?7)",
            params![
                key.folder,
                key.uid_validity,
                key.uid,
                chrono::Utc::now().to_rfc3339(),
                reason,
                fingerprint,
                evidence
            ],
        )?;
        crate::fault::point("unskip_before_commit");
        tx.commit()?;
        crate::fault::point("after_unskip");
        Ok(())
    }
}

/// Operator text is echoed in reports: bounded, non-empty, and free of control
/// characters so it cannot forge terminal output or log lines.
fn checked_reason(reason: &str) -> Result<&str> {
    let reason = reason.trim();
    if reason.is_empty() {
        bail!("a non-empty --reason is required");
    }
    if reason.chars().count() > 500 || reason.chars().any(char::is_control) {
        bail!("reason must be at most 500 characters with no control characters");
    }
    Ok(reason)
}

/// SQLite online backup includes committed WAL pages. Publish without clobbering
/// even symlinks; failures stop migration before any schema change.
fn backup_before_upgrade(conn: &Connection, path: &Path, version: i64) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut destination = Connection::open(temporary.path())?;
    {
        let backup = rusqlite::backup::Backup::new(conn, &mut destination)?;
        backup.run_to_completion(128, std::time::Duration::from_millis(10), None)?;
    }
    let integrity: String = destination.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if integrity != "ok" {
        bail!("pre-upgrade backup failed integrity check");
    }
    drop(destination);
    temporary.as_file().sync_all()?;
    let stem = path
        .file_name()
        .context("journal has no filename")?
        .to_string_lossy();
    let mut temporary = temporary;
    for suffix in 0..10000 {
        let name = if suffix == 0 {
            format!("{stem}.v{version}.bak")
        } else {
            format!("{stem}.v{version}.bak.{suffix}")
        };
        match temporary.persist_noclobber(parent.join(name)) {
            Ok(_) => {
                std::fs::File::open(parent)?.sync_all()?;
                return Ok(());
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                temporary = error.file;
            }
            Err(error) => return Err(error.error.into()),
        }
    }
    bail!("too many pre-upgrade backups; refusing upgrade")
}

/// Union of the plan (snapshot and scans) and every transfer row for one folder and validity.
fn insert_event(
    conn: &Connection,
    key: &MessageKey,
    level: &str,
    result: &str,
    size: Option<u64>,
    detail: &str,
    observed_at: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO verification_events (folder,validity,uid,level,result,size,observed_at,detail) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            key.folder,
            key.uid_validity,
            key.uid,
            level,
            result,
            size.map(|s| s as i64),
            observed_at,
            detail
        ],
    )?;
    Ok(())
}

impl Drop for Journal {
    fn drop(&mut self) {
        // Best effort only; a failure here loses renewal evidence, never state.
        let _ = self.flush_evidence();
    }
}

fn known_in(
    conn: &Connection,
    folder: &str,
    validity: u32,
) -> Result<std::collections::BTreeSet<u32>> {
    let mut known = std::collections::BTreeSet::new();
    let mut lists: Vec<String> = Vec::new();
    let snapshot: Option<(u32, String)> = conn
        .query_row(
            "SELECT validity,uids FROM snapshots WHERE folder=?1",
            [folder],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((v, json)) = snapshot {
        if v != validity {
            bail!("source UIDVALIDITY differs from the recorded plan");
        }
        lists.push(json);
    }
    let has_scans: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans')",
        [],
        |r| r.get(0),
    )?;
    if has_scans {
        let mut stmt = conn.prepare("SELECT uids FROM scans WHERE folder=?1 AND validity=?2")?;
        for row in stmt.query_map(params![folder, validity], |r| r.get::<_, String>(0))? {
            lists.push(row?);
        }
    }
    for json in lists {
        known.extend(serde_json::from_str::<Vec<u32>>(&json)?);
    }
    let mut stmt = conn.prepare("SELECT uid FROM transfers WHERE folder=?1 AND uid_validity=?2")?;
    for row in stmt.query_map(params![folder, validity], |r| r.get::<_, u32>(0))? {
        known.insert(row?);
    }
    Ok(known)
}

pub fn fingerprint(body: &[u8]) -> String {
    format!("{:x}", Sha256::digest(body))
}

fn require_one(count: usize) -> Result<()> {
    if count != 1 {
        bail!("transfer transition rejected: missing record, wrong state or mismatching evidence");
    }
    Ok(())
}

fn read_record(r: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    fn list(r: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<Vec<String>>> {
        let value: Option<String> = r.get(index)?;
        value
            .map(|s| {
                serde_json::from_str(&s).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        index,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })
            .transpose()
    }
    let dv: Option<u32> = r.get(5)?;
    let du: Option<u32> = r.get(6)?;
    let bv: Option<u32> = r.get(10)?;
    let bn: Option<u32> = r.get(11)?;
    Ok(Record {
        key: MessageKey {
            folder: r.get(0)?,
            uid_validity: r.get(1)?,
            uid: r.get(2)?,
        },
        hash: r.get(3)?,
        state: r.get(4)?,
        destination: dv.zip(du),
        date: r.get(7)?,
        flags: list(r, 8)?,
        omitted: list(r, 9)?.unwrap_or_default(),
        baseline: bv.zip(bn),
    })
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    fn prepared() -> (tempfile::TempDir, Journal, MessageKey) {
        let directory = tempfile::tempdir().unwrap();
        let mut journal =
            Journal::create(&directory.path().join("journal.sqlite3"), "binding").unwrap();
        let key = MessageKey {
            folder: "INBOX".into(),
            uid_validity: 7,
            uid: 1,
        };
        journal.plan(&key, b"body").unwrap();
        journal.metadata(&key, 100, &[], &[], (11, 1)).unwrap();
        journal.begin_append(&key).unwrap();
        (directory, journal, key)
    }
    #[test]
    fn recovery_requires_pre_literal_evidence_and_matching_destination_epoch() {
        let (_directory, mut journal, key) = prepared();
        assert!(journal.recover_not_sent(&key, 12).is_err());
        assert_eq!(journal.record(&key).unwrap().unwrap().state, "uncertain");
        journal.recover_not_sent(&key, 11).unwrap();
        assert_eq!(journal.record(&key).unwrap().unwrap().state, "planned");
        assert!(journal.recover_not_sent(&key, 11).is_err());
        journal.begin_append(&key).unwrap();
        journal.authorize_literal(&key).unwrap();
        assert!(journal.recover_not_sent(&key, 11).is_err());
        assert_eq!(journal.record(&key).unwrap().unwrap().state, "uncertain");
        assert_eq!(
            journal
                .0
                .query_row("SELECT count(*) FROM recovery_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn v2_upgrade_does_not_invent_unsent_evidence() {
        let (directory, journal, key) = prepared();
        journal
            .0
            .execute_batch(
                "DROP TABLE append_attempts; DROP TABLE recovery_events; PRAGMA user_version=2;",
            )
            .unwrap();
        drop(journal);
        let mut journal = Journal::open(&directory.path().join("journal.sqlite3")).unwrap();
        assert!(journal.recover_not_sent(&key, 11).is_err());
        assert_eq!(journal.record(&key).unwrap().unwrap().state, "uncertain");
        assert_eq!(
            journal
                .0
                .query_row("SELECT count(*) FROM append_attempts", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn failed_authorization_transaction_preserves_prepared_evidence() {
        let (_directory, mut journal, key) = prepared();
        journal.0.execute_batch("CREATE TRIGGER reject_authorization BEFORE UPDATE ON append_attempts BEGIN SELECT RAISE(ABORT, 'simulated journal write failure'); END;").unwrap();
        assert!(journal.authorize_literal(&key).is_err());
        assert_eq!(
            journal
                .0
                .query_row("SELECT phase FROM append_attempts", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "prepared"
        );
        journal.recover_not_sent(&key, 11).unwrap();
    }
}

#[cfg(test)]
mod upgrade_backup_tests {
    use super::*;
    #[test]
    fn backup_includes_committed_pages_still_in_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.sqlite3");
        let mut journal = Journal::create(&path, "binding").unwrap();
        journal.0.execute_batch("DROP TABLE append_attempts; DROP TABLE recovery_events; PRAGMA user_version=2; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;").unwrap();
        let key = MessageKey {
            folder: "INBOX".into(),
            uid_validity: 7,
            uid: 9,
        };
        journal.plan(&key, b"committed only in WAL").unwrap();
        let upgraded = Journal::open(&path).unwrap();
        assert_eq!(
            upgraded.record(&key).unwrap().unwrap().hash,
            fingerprint(b"committed only in WAL")
        );
        let backup = Connection::open(dir.path().join("journal.sqlite3.v2.bak")).unwrap();
        assert_eq!(
            backup
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            backup
                .query_row("SELECT fingerprint FROM transfers", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            fingerprint(b"committed only in WAL")
        );
    }
    #[test]
    fn backup_is_consistent_private_and_never_overwrites_previous_evidence() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.sqlite3");
        let mut journal = Journal::create(&path, "binding").unwrap();
        let key = MessageKey {
            folder: "INBOX".into(),
            uid_validity: 7,
            uid: 1,
        };
        journal.plan(&key, b"preserved").unwrap();
        journal
            .0
            .execute_batch(
                "DROP TABLE append_attempts; DROP TABLE recovery_events; PRAGMA user_version=2;",
            )
            .unwrap();
        drop(journal);
        let first = dir.path().join("journal.sqlite3.v2.bak");
        std::fs::write(&first, b"existing backup must survive").unwrap();
        let journal = Journal::open(&path).unwrap();
        assert_eq!(
            journal.record(&key).unwrap().unwrap().hash,
            fingerprint(b"preserved")
        );
        assert_eq!(
            std::fs::read(first).unwrap(),
            b"existing backup must survive"
        );
        let saved = dir.path().join("journal.sqlite3.v2.bak.1");
        assert_eq!(
            std::fs::metadata(&saved).unwrap().permissions().mode() & 0o077,
            0
        );
        let backup = Connection::open(saved).unwrap();
        assert_eq!(
            backup
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            backup
                .query_row("SELECT fingerprint FROM transfers", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            fingerprint(b"preserved")
        );
        assert_eq!(
            backup
                .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }
}

#[cfg(test)]
mod preparation_tests {
    use super::*;
    #[test]
    fn combined_preparation_freezes_metadata_and_never_resets_uncertainty() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::create(&dir.path().join("journal.sqlite3"), "binding").unwrap();
        let key = MessageKey {
            folder: "INBOX".into(),
            uid_validity: 5,
            uid: 1,
        };
        let metadata = || AppendMetadata {
            date: 123,
            flags: &[],
            omitted: &[],
            baseline: (8, 10),
        };
        let record = journal.prepare_append(&key, b"body", metadata()).unwrap();
        assert_eq!(record.state, "uncertain");
        assert_eq!(record.date, Some(123));
        assert_eq!(record.baseline, Some((8, 10)));
        assert_eq!(
            journal
                .0
                .pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert!(journal.prepare_append(&key, b"body", metadata()).is_err());
        journal.authorize_literal(&key).unwrap();
        assert!(
            journal
                .prepare_append(&key, b"different", metadata())
                .is_err()
        );
        assert_eq!(
            journal.record(&key).unwrap().unwrap().hash,
            fingerprint(b"body")
        );
    }
}

#[cfg(test)]
mod skip_tests {
    use super::*;
    use crate::transport::AppendRejection;

    fn fixture() -> (tempfile::TempDir, Journal, MessageKey) {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::create(&dir.path().join("journal.sqlite3"), "b").unwrap();
        let key = MessageKey {
            folder: "INBOX".into(),
            uid_validity: 7,
            uid: 3,
        };
        journal.plan(&key, b"body").unwrap();
        (dir, journal, key)
    }
    fn prepare(journal: &mut Journal, key: &MessageKey) {
        journal
            .prepare_append(
                key,
                b"body",
                AppendMetadata {
                    date: 1,
                    flags: &[],
                    omitted: &[],
                    baseline: (9, 1),
                },
            )
            .unwrap();
    }
    fn reject(journal: &mut Journal, key: &MessageKey) {
        prepare(journal, key);
        journal
            .reject_append(
                key,
                &AppendRejection {
                    code: "CANNOT",
                    status: "NO",
                },
            )
            .unwrap();
    }

    #[test]
    fn skip_requires_prior_rejection_evidence_and_a_clean_reason() {
        let (_dir, mut journal, key) = fixture();
        assert!(journal.skip_rejected(&key, "why").is_err());
        reject(&mut journal, &key);
        for bad in ["", "   ", "line\nbreak", "esc\u{1b}[31m", &"x".repeat(501)] {
            assert!(journal.skip_rejected(&key, bad).is_err(), "{bad:?}");
        }
        assert_eq!(journal.active_skip(&key).unwrap(), None);
        journal.skip_rejected(&key, "ticket 7").unwrap();
        assert_eq!(
            journal.active_skip(&key).unwrap().as_deref(),
            Some("ticket 7")
        );
        assert!(journal.skip_rejected(&key, "again").is_err(), "double skip");
        let summary = journal.summary().unwrap();
        assert_eq!(
            (summary.skipped, summary.planned, summary.confirmed),
            (1, 1, 0)
        );
    }

    #[test]
    fn skip_never_applies_to_uncertain_or_attributed_transfers() {
        let (_dir, mut journal, key) = fixture();
        reject(&mut journal, &key);
        // A later attempt makes the record uncertain: a skip must be refused.
        prepare(&mut journal, &key);
        assert!(journal.skip_rejected(&key, "no").is_err());
        journal.authorize_literal(&key).unwrap();
        assert!(journal.skip_rejected(&key, "no").is_err());
        journal.acknowledge(&key, 9, 5).unwrap();
        assert!(journal.skip_rejected(&key, "no").is_err());
        assert_eq!(journal.summary().unwrap().skipped, 0);
    }

    #[test]
    fn a_skip_loses_force_if_the_transfer_leaves_planned_and_unskip_is_audited() {
        let (_dir, mut journal, key) = fixture();
        reject(&mut journal, &key);
        journal.skip_rejected(&key, "first").unwrap();
        journal.unskip(&key, "provider fixed").unwrap();
        assert_eq!(journal.active_skip(&key).unwrap(), None);
        assert!(journal.unskip(&key, "twice").is_err());
        journal.skip_rejected(&key, "second").unwrap();
        // Defense in depth: even a stale skip cannot hide an uncertain transfer.
        journal
            .0
            .execute("UPDATE transfers SET state='uncertain'", [])
            .unwrap();
        assert_eq!(journal.active_skip(&key).unwrap(), None);
        let actions: Vec<String> = journal
            .0
            .prepare("SELECT action FROM operator_skip_events ORDER BY rowid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(actions, ["skip", "unskip", "skip"]);
    }

    #[test]
    fn schema_three_upgrades_additively_to_four_with_a_backup_and_status_reads_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.sqlite3");
        let mut journal = Journal::create(&path, "b").unwrap();
        let key = MessageKey {
            folder: "INBOX".into(),
            uid_validity: 7,
            uid: 3,
        };
        journal.plan(&key, b"body").unwrap();
        journal
            .0
            .execute_batch("DROP TABLE operator_skip_events; PRAGMA user_version=3;")
            .unwrap();
        drop(journal);
        // Offline status must read a schema-3 journal without upgrading it.
        let old = Journal::open_read_only(&path).unwrap();
        assert_eq!(old.summary().unwrap().skipped, 0);
        drop(old);
        let version = |p: &Path| -> i64 {
            Connection::open(p)
                .unwrap()
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap()
        };
        assert_eq!(version(&path), 3);
        let upgraded = Journal::open(&path).unwrap();
        assert_eq!(version(&path), 4);
        assert_eq!(version(&dir.path().join("journal.sqlite3.v3.bak")), 3);
        assert_eq!(
            upgraded.record(&key).unwrap().unwrap().hash,
            fingerprint(b"body")
        );
    }

    const JSON_BINDING: &str = r#"{"source":["h","993","u"],"destination":["h","993","u"],"folders":[{"source":"INBOX","destination":"INBOX"}]}"#;

    fn key_for(uid: u32) -> MessageKey {
        MessageKey {
            folder: "INBOX".into(),
            uid_validity: 7,
            uid,
        }
    }

    /// A schema-5 journal whose folder holds a message in every historical state.
    fn every_state() -> (tempfile::TempDir, std::path::PathBuf, Journal) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.sqlite3");
        drop(Journal::create(&path, JSON_BINDING).unwrap());
        let mut j = Journal::open(&path).unwrap();
        j.snapshot("INBOX", 7, &[1, 2, 3, 4, 5, 6, 8]).unwrap();
        // 1: planned, never attempted
        j.plan(&key_for(1), b"body").unwrap();
        // 2: rejected and operator-skipped (still 'planned')
        j.plan(&key_for(2), b"body").unwrap();
        reject(&mut j, &key_for(2));
        j.skip_rejected(&key_for(2), "ticket").unwrap();
        // 3: rejected, not skipped (still 'planned')
        j.plan(&key_for(3), b"body").unwrap();
        reject(&mut j, &key_for(3));
        // 4: uncertain
        j.plan(&key_for(4), b"body").unwrap();
        prepare(&mut j, &key_for(4));
        // 5: accepted
        j.plan(&key_for(5), b"body").unwrap();
        prepare(&mut j, &key_for(5));
        j.acknowledge(&key_for(5), 9, 105).unwrap();
        // 6: confirmed
        j.plan(&key_for(6), b"body").unwrap();
        prepare(&mut j, &key_for(6));
        j.acknowledge(&key_for(6), 9, 106).unwrap();
        j.confirm_content(&key_for(6), 9, 106, b"body").unwrap();
        // 8 is only in the snapshot (no transfer row). UID 7 was never in anything.
        assert!(j.upgrade_to_v5(&path).unwrap());
        (dir, path, j)
    }

    #[test]
    fn known_uids_covers_every_state_so_nothing_is_rediscovered() {
        let (_dir, _path, mut j) = every_state();
        let states: Vec<String> = [1, 2, 3, 4, 5, 6]
            .iter()
            .map(|u| j.record(&key_for(*u)).unwrap().unwrap().state)
            .collect();
        assert_eq!(
            states,
            [
                "planned",
                "planned",
                "planned",
                "uncertain",
                "accepted",
                "confirmed"
            ]
        );
        assert!(j.active_skip(&key_for(2)).unwrap().is_some());
        let expected: std::collections::BTreeSet<u32> = [1, 2, 3, 4, 5, 6, 8].into();
        assert_eq!(j.known_uids("INBOX", 7).unwrap(), expected);
        // 7 is genuinely new; every known UID, in every state, is refused as a "new" UID.
        for known in [1, 2, 3, 4, 5, 6, 8] {
            assert!(
                j.record_scan("INBOX", 7, 20, &[known]).is_err(),
                "UID {known}"
            );
        }
        assert_eq!(j.record_scan("INBOX", 7, 20, &[7, 10]).unwrap(), 1);
        assert_eq!(j.record_scan("INBOX", 7, 25, &[21]).unwrap(), 2);
        let all: std::collections::BTreeSet<u32> = [1, 2, 3, 4, 5, 6, 7, 8, 10, 21].into();
        assert_eq!(j.known_uids("INBOX", 7).unwrap(), all);
        // The original snapshot is untouched and the plan is snapshot first, then scans in order.
        assert_eq!(j.snapshots().unwrap()[0].2, vec![1, 2, 3, 4, 5, 6, 8]);
        assert_eq!(
            j.work_list().unwrap()[0].2,
            vec![1, 2, 3, 4, 5, 6, 8, 7, 10, 21]
        );
    }

    #[test]
    fn a_scan_is_validated_and_all_or_nothing() {
        let (_dir, _path, mut j) = every_state();
        let before = j.work_list().unwrap();
        for (validity, next, uids) in [
            (7, 20, vec![]),       // nothing to record
            (7, 20, vec![12, 11]), // not ascending
            (7, 20, vec![11, 11]), // repeated
            (7, 20, vec![0]),      // UID zero
            (7, 20, vec![20]),     // at the horizon
            (7, 20, vec![9, 25]),  // one inside, one beyond: all-or-nothing
            (8, 20, vec![9]),      // another UIDVALIDITY
        ] {
            assert!(
                j.record_scan("INBOX", validity, next, &uids).is_err(),
                "{validity} {next} {uids:?}"
            );
        }
        assert!(
            j.record_scan("OTHER", 7, 20, &[9]).is_err(),
            "no recorded plan for the folder"
        );
        // UIDNEXT below a known UID, and below an earlier observation, is refused.
        assert!(j.record_scan("INBOX", 7, 8, &[7]).is_err());
        j.record_scan("INBOX", 7, 30, &[11]).unwrap();
        assert!(j.record_scan("INBOX", 7, 29, &[12]).is_err());
        assert_eq!(j.last_scan_uidnext("INBOX", 7).unwrap(), Some(30));
        let mut expected = before;
        expected[0].2.push(11);
        assert_eq!(
            j.work_list().unwrap(),
            expected,
            "only the one valid scan exists"
        );
        // A schema-4 journal cannot record scans.
        let dir = tempfile::tempdir().unwrap();
        let p4 = dir.path().join("journal.sqlite3");
        drop(Journal::create(&p4, JSON_BINDING).unwrap());
        let mut v4 = Journal::open(&p4).unwrap();
        v4.snapshot("INBOX", 7, &[1]).unwrap();
        assert!(v4.record_scan("INBOX", 7, 9, &[2]).is_err());
        assert_eq!(v4.last_scan_uidnext("INBOX", 7).unwrap(), None);
    }

    #[test]
    fn a_scan_only_folder_never_gets_an_original_snapshot() {
        let (_dir, path, mut j) = every_state();
        // Simulate what a later phase will create: a folder known only through scans.
        let conn = Connection::open(&path).unwrap();
        conn.execute("INSERT INTO scans VALUES ('ADDED',3,1,5,'[1,2]','t')", [])
            .unwrap();
        assert!(j.snapshot("ADDED", 3, &[1, 2, 3]).is_err());
        assert!(j.snapshot("ADDED", 4, &[9]).is_err());
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM snapshots WHERE folder='ADDED'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "no snapshot may have been created");
        // An ordinary folder is unaffected.
        assert_eq!(j.snapshot("INBOX", 7, &[99]).unwrap()[0], 1);
    }

    #[test]
    fn uncertain_uids_and_destination_epochs_are_reported_per_folder() {
        let (_dir, _path, j) = every_state();
        assert_eq!(j.uncertain_uids("INBOX").unwrap(), vec![4]);
        assert!(j.uncertain_uids("OTHER").unwrap().is_empty());
        assert_eq!(j.destination_validities("INBOX").unwrap(), [9].into());
        assert!(j.destination_validities("OTHER").unwrap().is_empty());
    }
}
