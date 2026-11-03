//! Conservative, durable transfer state. No message content or credentials stored.
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const SCHEMA_VERSION: i64 = 4;
const SUPPORTED_SCHEMAS: [i64; 4] = [1, 2, 3, SCHEMA_VERSION];

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

pub struct Journal(Connection);

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
        Ok(Self(conn))
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
        } else if !(2..=SCHEMA_VERSION).contains(&version) {
            bail!("unsupported journal schema {version}; expected {SCHEMA_VERSION}");
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
        Ok(Self(conn))
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

    pub fn check_binding(&self, expected: &str) -> Result<()> {
        let actual: String = self
            .0
            .query_row("SELECT binding FROM job WHERE id=1", [], |r| r.get(0))?;
        if actual != expected {
            bail!("journal belongs to a different migration");
        }
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
        crate::fault::point("before_confirm");
        let count = self.0.execute(
            "UPDATE transfers SET state='confirmed' WHERE folder=?1 AND uid_validity=?2 AND uid=?3
             AND state='accepted' AND destination_validity=?4 AND destination_uid=?5 AND fingerprint=?6",
            params![key.folder, key.uid_validity, key.uid, validity, uid, fingerprint],
        ).context("persist content verification")?;
        require_one(count)?;
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
}
