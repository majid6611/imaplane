use crate::{
    config::Config,
    job::Job,
    journal::{AppendMetadata, Journal, MessageKey, Record},
    transport::{
        Destination, Message, Selected, Source, SpoolConfig, SpooledMessage, Transfer, valid_flag,
    },
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Debug, Serialize)]
pub struct Entry {
    pub source_folder: String,
    pub source_uid: u32,
    pub destination_uid: Option<u32>,
    pub result: String,
    pub detail: String,
    pub omitted_flags: Vec<String>,
    pub candidate_uids: Vec<u32>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub report_version: u32,
    pub observed_at: String,
    pub scope: String,
    pub complete: bool,
    pub interrupted: bool,
    pub halt_reason: Option<String>,
    /// Present only for `migrate --incremental`: what each folder's discovery scan found.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub discovery: Vec<Discovery>,
    pub entries: Vec<Entry>,
}
/// Outcome of discovery for one folder in an incremental run.
#[derive(Debug, Serialize, Clone)]
pub struct Discovery {
    pub folder: String,
    pub uid_validity: u32,
    /// UIDs the source listed, UIDs the journal already knew, and UIDs found new.
    pub listed: usize,
    pub known: usize,
    pub new_uids: Vec<u32>,
    /// Generation of the scan recorded for the new UIDs; absent when nothing was new.
    pub scan_generation: Option<u32>,
    pub observed_uidnext: u32,
}
impl Report {
    fn new(scope: &str) -> Self {
        Self {
            report_version: 1,
            observed_at: chrono::Utc::now().to_rfc3339(),
            scope: scope.into(),
            complete: false,
            interrupted: false,
            halt_reason: None,
            discovery: Vec::new(),
            entries: Vec::new(),
        }
    }
    fn finish(&mut self) {
        self.complete = !self.interrupted && self.entries.iter().all(|e| e.result == "confirmed");
    }
}
fn entry(
    key: &MessageKey,
    record: Option<&Record>,
    result: &str,
    detail: impl Into<String>,
) -> Entry {
    Entry {
        source_folder: key.folder.clone(),
        source_uid: key.uid,
        destination_uid: record.and_then(|r| r.destination.map(|(_, u)| u)),
        result: result.into(),
        detail: detail.into(),
        omitted_flags: record.map(|r| r.omitted.clone()).unwrap_or_default(),
        candidate_uids: Vec::new(),
    }
}
fn skipped_entry(key: &MessageKey, record: &Record, reason: &str) -> Entry {
    entry(
        key,
        Some(record),
        "skipped_by_operator",
        format!("NOT migrated: operator skipped this rejected message ({reason})"),
    )
}
fn transient(e: &anyhow::Error) -> bool {
    crate::transport::is_transient(e) || e.is::<SnapshotChanged>()
}
fn retry<T>(attempts: u32, mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    let started = std::time::Instant::now();
    for attempt in 0..attempts {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if transient(&error) && attempt + 1 < attempts => {
                let seconds = (1u64 << attempt.min(7)).min(120);
                if started.elapsed() + Duration::from_secs(seconds) >= Duration::from_secs(600) {
                    return Err(error);
                }
                let jitter = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_millis() as u64
                    % 250;
                let until =
                    std::time::Instant::now() + Duration::from_millis(seconds * 1000 + jitter);
                while std::time::Instant::now() < until {
                    if crate::interrupted() {
                        bail!("operation interrupted");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}

#[derive(Default)]
struct RejectionCircuit {
    previous: Option<(&'static str, &'static str)>,
    consecutive: u32,
}
impl RejectionCircuit {
    fn reject(&mut self, rejection: &crate::transport::AppendRejection) -> u32 {
        let signature = (rejection.status, rejection.code);
        self.consecutive = if self.previous == Some(signature) {
            self.consecutive + 1
        } else {
            1
        };
        self.previous = Some(signature);
        self.consecutive
    }
    fn success(&mut self) {
        *self = Self::default();
    }
}
fn rejection_pause(consecutive: u32, stop: &AtomicBool) -> bool {
    let until = std::time::Instant::now()
        + Duration::from_secs((1u64 << (consecutive - 1).min(7)).min(120));
    while std::time::Instant::now() < until {
        if stop.load(Ordering::Relaxed) || crate::interrupted() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

struct SourceReader<'a> {
    config: &'a Config,
    password: &'a str,
    source: Source,
    selected: Option<(String, u32)>,
}
impl<'a> SourceReader<'a> {
    fn new(config: &'a Config, password: &'a str) -> Result<Self> {
        Ok(Self {
            source: retry(config.read_attempts, || {
                Source::connect(
                    &config.source,
                    password,
                    Duration::from_secs(config.timeout_seconds),
                    config.max_message_bytes,
                )
            })?,
            config,
            password,
            selected: None,
        })
    }
    fn read<T>(&mut self, mut f: impl FnMut(&mut Source) -> Result<T>) -> Result<T> {
        let mut reconnect = false;
        retry(self.config.read_attempts, || {
            if reconnect {
                self.source = Source::connect(
                    &self.config.source,
                    self.password,
                    Duration::from_secs(self.config.timeout_seconds),
                    self.config.max_message_bytes,
                )?;

                if let Some((folder, validity)) = &self.selected {
                    let selected = self.source.examine(folder)?;
                    crate::fault::point("after_source_reconnect");
                    if selected.validity != *validity {
                        bail!("source UIDVALIDITY changed during reconnect");
                    }
                }
            }
            reconnect = true;
            f(&mut self.source)
        })
    }

    fn snapshot(&mut self, name: &str) -> Result<(Selected, Vec<u32>)> {
        self.selected = None;
        let result = self.read(|source| {
            let selected = source.examine(name)?;
            let next = selected
                .next
                .context("source omitted UIDNEXT; cannot bound snapshot")?;
            let uids = if selected.exists == 0 {
                Vec::new()
            } else {
                source.snapshot_uids(next)?
            };
            check_inventory(selected.exists, &uids)?;
            let after = source.examine(name)?;
            if after.validity != selected.validity {
                bail!("source UIDVALIDITY changed during snapshot");
            }
            Ok((selected, uids))
        })?;
        self.selected = Some((name.into(), result.0.validity));
        Ok(result)
    }
    fn select(&mut self, name: &str) -> Result<Selected> {
        // A failed selection must not restore a previously selected folder on retry.
        self.selected = None;
        let s = self.read(|s| s.examine(name))?;
        self.selected = Some((name.into(), s.validity));
        Ok(s)
    }
}
/// A successful APPENDUID proves the next allocated UID must be larger.
/// Reconnect SELECT may already have observed an even higher lower bound.
fn append_lower_bound(previous: Option<u32>, acknowledged_uid: u32) -> Option<u32> {
    acknowledged_uid
        .checked_add(1)
        .map(|next| previous.unwrap_or(next).max(next))
}
struct DestinationReader<'a> {
    config: &'a Config,
    password: &'a str,
    destination: Destination,
    selected: Option<(String, u32, bool)>,
    cached: Option<Selected>,
    last_activity: std::time::Instant,
}
/// A destination left idle this long (e.g. while a large or slow source message
/// is read) is probed before an APPEND is prepared. A successful probe cannot
/// promise the connection survives the APPEND itself; that residual risk keeps
/// the existing uncertain-and-never-replayed handling.
const PROBE_AFTER_IDLE: Duration = Duration::from_secs(2);
impl<'a> DestinationReader<'a> {
    fn new(config: &'a Config, password: &'a str) -> Result<Self> {
        Ok(Self {
            destination: retry(config.read_attempts, || {
                Destination::connect(
                    &config.destination,
                    password,
                    Duration::from_secs(config.timeout_seconds),
                    config.max_message_bytes,
                )
            })?,
            config,
            password,
            selected: None,
            cached: None,
            last_activity: std::time::Instant::now(),
        })
    }
    fn touch(&mut self) {
        self.last_activity = std::time::Instant::now();
    }
    /// Digest of one destination message. Larger than `stream_threshold_bytes` it is
    /// streamed through a hasher and never held in memory; otherwise it is read whole as
    /// before. `chunk_point` names the crash-test hook that fires per streamed chunk.
    fn digest(
        &mut self,
        uid: u32,
        chunk_point: &'static str,
    ) -> Result<Option<crate::transport::MessageDigest>> {
        let threshold = self.config.stream_threshold_bytes;
        self.read(|d| d.message_digest(uid, threshold, chunk_point))
    }
    /// Detect an idle-dropped destination BEFORE any journal transition for the
    /// next APPEND. A dead connection is replaced through the normal read path,
    /// which re-selects the original mode and rechecks UIDVALIDITY; the caller
    /// then takes its baseline from that fresh selection.
    fn ensure_live(&mut self) -> Result<()> {
        if self.last_activity.elapsed() < PROBE_AFTER_IDLE {
            return Ok(());
        }
        self.read(|d| d.noop())
    }
    fn read<T>(&mut self, mut f: impl FnMut(&mut Destination) -> Result<T>) -> Result<T> {
        let mut reconnect = false;
        let value = retry(self.config.read_attempts, || {
            if reconnect {
                self.destination = Destination::connect(
                    &self.config.destination,
                    self.password,
                    Duration::from_secs(self.config.timeout_seconds),
                    self.config.max_message_bytes,
                )?;

                if let Some((folder, validity, writable)) = self.selected.clone() {
                    let selected = if writable {
                        self.destination.select(&folder)?
                    } else {
                        self.destination.examine(&folder)?
                    };
                    if selected.validity != validity {
                        bail!("destination UIDVALIDITY changed during reconnect");
                    }
                    if writable && !selected.writable {
                        bail!("destination became read-only during reconnect");
                    }
                    self.cached = Some(selected);
                    crate::fault::point("after_destination_reconnect");
                }
            }
            reconnect = true;
            f(&mut self.destination)
        })?;
        self.touch();
        Ok(value)
    }

    fn select(&mut self, name: &str, writable: bool) -> Result<Selected> {
        self.selected = None;
        self.cached = None;
        let s = self.read(|d| {
            if writable {
                d.select(name)
            } else {
                d.examine(name)
            }
        })?;
        if writable && !s.writable {
            bail!("destination folder is read-only");
        }
        self.selected = Some((name.into(), s.validity, writable));
        self.cached = Some(s.clone());
        Ok(s)
    }
    fn writable_selection(&mut self, name: &str) -> Result<Selected> {
        if self
            .selected
            .as_ref()
            .is_some_and(|(folder, _, writable)| folder == name && *writable)
        {
            if let Some(selected) = &self.cached {
                return Ok(selected.clone());
            }
        }
        self.select(name, true)
    }
    fn advance_baseline(&mut self, acknowledged_uid: u32) {
        if let Some(selected) = &mut self.cached {
            selected.next = append_lower_bound(selected.next, acknowledged_uid);
        }
    }
}

pub fn inspect(c: &Config) -> Result<serde_json::Value> {
    let source_password = c.source.password("Source")?;
    let destination_password = c.destination.password("Destination")?;
    let mut source = SourceReader::new(c, &source_password)?;
    let mut destination = DestinationReader::new(c, &destination_password)?;
    Ok(
        serde_json::json!({ "source":source.read(|s| s.folders())?,"destination":destination.read(|d| d.folders())? }),
    )
}

/// One folder's read-only discovery result, before anything is recorded.
struct Listing {
    folder: String,
    validity: u32,
    next: u32,
    listed: usize,
    known: usize,
    new: Vec<u32>,
}

/// Read-only half of incremental discovery, shared by real runs and `--dry-run`: a consistent
/// complete UID listing per folder compared with every UID the journal knows, plus the source and
/// destination UIDVALIDITY refusals. Writes nothing anywhere.
fn plan_discovery(
    c: &Config,
    journal: &Journal,
    source: &mut SourceReader<'_>,
    dest: &mut DestinationReader<'_>,
) -> Result<Vec<Listing>> {
    let plan = journal.work_list()?;
    let mut listings = Vec::new();
    for f in &c.folders {
        let Some((_, recorded, _)) = plan.iter().find(|(name, _, _)| *name == f.source) else {
            bail!(
                "job has no recorded plan for folder {:?}; run an ordinary migrate first",
                f.source
            );
        };
        // The inventory check inside snapshot() makes this listing consistent: a message that
        // arrived or was expunged while it was read is retried, never recorded half-seen.
        let (selected, listed) = source.snapshot(&f.source)?;
        if selected.validity != *recorded {
            bail!(
                "source UIDVALIDITY of folder {:?} changed ({} recorded, {} now); incremental migration refuses and nothing was transferred",
                f.source,
                recorded,
                selected.validity
            );
        }
        let next = selected
            .next
            .context("source omitted UIDNEXT; cannot bound discovery")?;
        let known = journal.known_uids(&f.source, *recorded)?;
        if known.last().is_some_and(|k| *k >= next)
            || journal
                .last_scan_uidnext(&f.source, *recorded)?
                .is_some_and(|p| next < p)
        {
            bail!(
                "source UIDNEXT of folder {:?} is lower than earlier evidence; refusing to discover",
                f.source
            );
        }
        let mut new: Vec<u32> = listed
            .iter()
            .copied()
            .filter(|u| !known.contains(u))
            .collect();
        new.sort_unstable();
        new.dedup();
        listings.push(Listing {
            folder: f.source.clone(),
            validity: *recorded,
            next,
            listed: listed.len(),
            known: known.len(),
            new,
        });
    }
    // Destination: a folder that holds our transfers must still be the same UIDVALIDITY epoch.
    let existing = dest.read(|d| d.folders())?;
    for f in &c.folders {
        let recorded = journal.destination_validities(&f.source)?;
        if recorded.is_empty() {
            continue;
        }
        if !existing
            .iter()
            .any(|d| same_folder(&d.name, &f.destination) && d.selectable)
        {
            bail!(
                "destination folder {:?} no longer exists but the journal holds transfers into it; refusing",
                f.destination
            );
        }
        let now = dest.select(&f.destination, false)?.validity;
        if recorded.len() != 1 || !recorded.contains(&now) {
            bail!(
                "destination UIDVALIDITY of folder {:?} changed ({recorded:?} recorded, {now} now); incremental migration refuses and nothing was transferred",
                f.destination
            );
        }
    }
    Ok(listings)
}

/// Real incremental discovery: plan read-only, then upgrade to schema 5 if needed, then record
/// one atomic scan per folder that has new messages. Every scan is durable before any transfer.
fn discover(
    c: &Config,
    job: &mut Job,
    source: &mut SourceReader<'_>,
    dest: &mut DestinationReader<'_>,
) -> Result<Vec<Discovery>> {
    let listings = plan_discovery(c, &job.journal, source, dest)?;
    crate::fault::point("scan_listed");
    if job.journal.schema_version()? < 5 {
        job.journal
            .upgrade_to_v5(&c.state_dir.join("journal.sqlite3"))?;
    }
    let mut found = Vec::new();
    for l in listings {
        let generation = if l.new.is_empty() {
            None
        } else {
            Some(
                job.journal
                    .record_scan(&l.folder, l.validity, l.next, &l.new)?,
            )
        };
        eprintln!(
            "Folder {:?}: {} listed, {} already known, {} new",
            l.folder,
            l.listed,
            l.known,
            l.new.len()
        );
        found.push(Discovery {
            folder: l.folder,
            uid_validity: l.validity,
            listed: l.listed,
            known: l.known,
            new_uids: l.new,
            scan_generation: generation,
            observed_uidnext: l.next,
        });
    }
    Ok(found)
}

/// `migrate --incremental --dry-run`: reports what discovery would find. The journal is opened
/// read-only (no lock file, no upgrade, no scan, no backup) and nothing is sent to the destination.
pub fn dry_run_incremental(c: &Config) -> Result<serde_json::Value> {
    require_mappings(c)?;
    let path = c.state_dir.join("journal.sqlite3");
    let journal =
        Journal::open_read_only(&path).context("incremental dry run needs an existing job")?;
    let version = journal.schema_version()?;
    if version < 4 {
        bail!(
            "journal schema {version} predates incremental migration; run an ordinary migrate once to bring it to schema 4"
        );
    }
    journal.check_binding(&c.binding()?)?;
    let sp = c.source.password("Source")?;
    let dp = c.destination.password("Destination")?;
    let mut source = SourceReader::new(c, &sp)?;
    let mut dest = DestinationReader::new(c, &dp)?;
    let listings = plan_discovery(c, &journal, &mut source, &mut dest)?;
    let folders: Vec<_> = listings
        .iter()
        .map(|l| serde_json::json!({"source":l.folder,"uid_validity":l.validity,"listed":l.listed,"known":l.known,"new_uids":l.new,"observed_uidnext":l.next}))
        .collect();
    Ok(serde_json::json!({
        "dry_run":true,
        "incremental":true,
        "scope":"read-only discovery; the journal was not upgraded or written and nothing was sent to the destination",
        "journal_schema":version,
        "would_upgrade_to_schema_5":version < 5,
        "folders":folders
    }))
}

pub fn dry_run(c: &Config) -> Result<serde_json::Value> {
    require_mappings(c)?;
    let sp = c.source.password("Source")?;
    let dp = c.destination.password("Destination")?;
    let mut source = SourceReader::new(c, &sp)?;
    let mut destination = DestinationReader::new(c, &dp)?;
    preflight(c, &mut source, &mut destination)?;
    let folders = destination.read(|d| d.folders())?;
    let mut plans = Vec::new();
    for f in &c.folders {
        let (s, uids) = source.snapshot(&f.source)?;
        plans.push(serde_json::json!({"source":f.source,"destination":f.destination,"uid_validity":s.validity,"message_count":uids.len(),"create_destination":!folders.iter().any(|d| same_folder(&d.name,&f.destination))}));
    }
    Ok(
        serde_json::json!({"dry_run":true,"scope":"read-only preflight; no journal or destination writes","folders":plans}),
    )
}
#[derive(Debug)]
struct SnapshotChanged;
impl std::fmt::Display for SnapshotChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "source UID inventory differs from EXISTS; retry snapshot without discarding state",
        )
    }
}
impl std::error::Error for SnapshotChanged {}
fn check_inventory(exists: u32, uids: &[u32]) -> Result<()> {
    if uids.len() != exists as usize {
        return Err(SnapshotChanged.into());
    }
    Ok(())
}
fn require_mappings(c: &Config) -> Result<()> {
    if c.folders.is_empty() {
        bail!(
            "at least one explicit [[folders]] mapping is required; use inspect to discover names"
        );
    }
    Ok(())
}
fn same_folder(a: &str, b: &str) -> bool {
    a == b || (a.eq_ignore_ascii_case("INBOX") && b.eq_ignore_ascii_case("INBOX"))
}
fn preflight(c: &Config, s: &mut SourceReader<'_>, d: &mut DestinationReader<'_>) -> Result<()> {
    let sf = s.read(|s| s.folders())?;
    let df = d.read(|d| d.folders())?;
    for f in &c.folders {
        if !sf
            .iter()
            .any(|n| same_folder(&n.name, &f.source) && n.selectable)
        {
            bail!("source folder {:?} was not listed as selectable", f.source);
        }
        if df
            .iter()
            .any(|n| same_folder(&n.name, &f.destination) && !n.selectable)
        {
            bail!("destination folder {:?} is not selectable", f.destination);
        }
    }
    Ok(())
}

/// A source message being transferred: small ones live in memory, large ones in a verified spool.
enum Payload {
    Buffered(Message),
    Spooled(SpooledMessage),
}
impl Payload {
    fn date(&self) -> chrono::DateTime<chrono::FixedOffset> {
        match self {
            Payload::Buffered(m) => m.date,
            Payload::Spooled(s) => s.date,
        }
    }
    fn flags(&self) -> &[String] {
        match self {
            Payload::Buffered(m) => &m.flags,
            Payload::Spooled(s) => &s.flags,
        }
    }
    /// Only a buffered message can be empty: a spooled one is, by definition, above the threshold.
    fn is_empty_body(&self) -> bool {
        matches!(self, Payload::Buffered(m) if m.body.is_empty())
    }
}

pub fn migrate(c: &Config, stop: Arc<AtomicBool>) -> Result<Report> {
    migrate_with(c, stop, false)
}

/// `migrate --incremental`: discover messages that arrived after the job was planned, record the
/// discovery durably, then run the ordinary transfer sequence over the extended plan.
pub fn migrate_incremental(c: &Config, stop: Arc<AtomicBool>) -> Result<Report> {
    migrate_with(c, stop, true)
}

fn migrate_with(c: &Config, stop: Arc<AtomicBool>, incremental: bool) -> Result<Report> {
    require_mappings(c)?;
    // An incremental run extends an existing job; it never creates one.
    let mut job = Job::open(c, !incremental)?;
    let sp = c.source.password("Source")?;
    let dp = c.destination.password("Destination")?;
    let mut source = SourceReader::new(c, &sp)?;
    let mut dest = DestinationReader::new(c, &dp)?;
    preflight(c, &mut source, &mut dest)?;
    let mut report = Report::new(
        "live destination content, INTERNALDATE and supported flags against the durable source UID snapshot",
    );
    if incremental {
        report.discovery = discover(c, &mut job, &mut source, &mut dest)?;
    } else {
        // Snapshot ALL configured source folders before any destination writes.
        for f in &c.folders {
            let (s, uids) = source.snapshot(&f.source)?;
            job.journal.snapshot(&f.source, s.validity, &uids)?;
        }
    }
    let mut circuit = RejectionCircuit::default();
    let spool_config = SpoolConfig {
        dir: c.spool_dir.clone().unwrap_or_else(|| c.state_dir.clone()),
        allow_memory_backed: c.spool_allow_memory_backed,
    };
    let mut known = dest.read(|d| d.folders())?;
    for (folder, validity, uids) in job.journal.work_list()? {
        let mapping = c
            .folders
            .iter()
            .find(|f| f.source == folder)
            .context("snapshot folder absent from config")?;
        let source_selection = source.select(&folder)?;
        if source_selection.validity != validity {
            bail!("source UIDVALIDITY changed after snapshot");
        }
        if stop.load(Ordering::Relaxed) {
            report.interrupted = true;
            break;
        }
        if !known
            .iter()
            .any(|f| same_folder(&f.name, &mapping.destination))
        {
            dest.destination.create(&mapping.destination)?;
            known = dest.read(|d| d.folders())?;
            if !known
                .iter()
                .any(|f| same_folder(&f.name, &mapping.destination) && f.selectable)
            {
                bail!("destination did not create the exact requested folder name");
            }
        }
        let selected = dest.select(&mapping.destination, true)?;
        if !selected.writable {
            bail!("destination folder is read-only");
        }
        // Incremental runs add no APPEND to a folder that has an unresolved uncertain transfer:
        // every further append would add reconciliation candidates for it. Other folders go on.
        let blocked = if incremental {
            job.journal.uncertain_uids(&folder)?
        } else {
            Vec::new()
        };
        if !blocked.is_empty() {
            eprintln!(
                "Folder {:?}: {} unresolved uncertain transfer(s) (UIDs {:?}); no new APPEND will be made in this folder",
                folder,
                blocked.len(),
                blocked
            );
        }
        for (index, uid) in uids.iter().enumerate() {
            let key = MessageKey {
                folder: folder.clone(),
                uid_validity: validity,
                uid: *uid,
            };
            if stop.load(Ordering::Relaxed) {
                report.interrupted = true;
                break;
            }
            eprintln!(
                "Folder {:?}: {}/{} (UID {})",
                folder,
                index + 1,
                uids.len(),
                uid
            );
            if let Some(r) = job.journal.record(&key)? {
                if r.state == "uncertain" {
                    report
                        .entries
                        .push(reconcile(&r, &mut dest, selected.validity)?);
                    continue;
                }
                if r.destination.is_some() {
                    report.entries.push(verify_record(
                        &mut job.journal,
                        &r,
                        &mut dest,
                        selected.validity,
                    )?);
                    if report.entries.last().is_some_and(|e| e.result == "failed") {
                        report.interrupted |= stop.load(Ordering::Relaxed);
                        report.finish();
                        return Ok(report);
                    }
                    continue;
                }
                if let Some(reason) = job.journal.active_skip(&key)? {
                    // Operator decision: nothing is fetched or sent. NOT migrated.
                    report.entries.push(skipped_entry(&key, &r, &reason));
                    continue;
                }
            }
            if !blocked.is_empty() {
                report.entries.push(entry(
                    &key,
                    job.journal.record(&key)?.as_ref(),
                    "blocked_by_uncertain",
                    format!(
                        "NOT transferred: folder has unresolved uncertain transfer(s) at source UID(s) {blocked:?}; resolve, recover or skip them (see the operator guide), then rerun. Other folders are not affected"
                    ),
                ));
                continue;
            }
            let threshold = c.stream_threshold_bytes;
            let mut payload = match source
                .read(|s| s.read_for_transfer(*uid, threshold, &spool_config))
            {
                Ok(Some(Transfer::Buffered(m))) => Payload::Buffered(m),
                Ok(Some(Transfer::Spooled(m))) => Payload::Spooled(m),
                Ok(None) => {
                    report.entries.push(entry(
                        &key,
                        None,
                        "source_changed",
                        "snapshot UID is no longer available",
                    ));
                    continue;
                }
                Err(e) if crate::transport::is_permanent_message(&e) => {
                    report.entries.push(entry(
                        &key,
                        None,
                        "skipped_permanent",
                        format!("source read failed: {e:#}"),
                    ));
                    continue;
                }
                // A stop request arrived while the message was still being downloaded into the
                // spool. Nothing durable exists yet, so the run simply stops here.
                Err(e) if e.is::<crate::transport::StopRequested>() => {
                    report.interrupted = true;
                    break;
                }
                // The spool could not be created, filled or verified. This happens before any
                // journal write or destination byte, so nothing is uncertain: the run stops and
                // the operator fixes the spool directory (space, filesystem, permissions).
                Err(e) if e.is::<crate::spool::SpoolError>() => {
                    report.entries.push(entry(
                        &key,
                        None,
                        "failed",
                        format!(
                            "source spool unavailable: {e:#}; nothing was written to the journal or the destination"
                        ),
                    ));
                    report.interrupted |= stop.load(Ordering::Relaxed);
                    report.finish();
                    return Ok(report);
                }
                Err(e) => {
                    report.entries.push(entry(
                        &key,
                        None,
                        "failed",
                        format!("source read failed: {e:#}"),
                    ));
                    report.interrupted |= stop.load(Ordering::Relaxed);
                    report.finish();
                    return Ok(report);
                }
            };
            let old = job.journal.record(&key)?;
            if old
                .as_ref()
                .and_then(|r| r.date)
                .is_some_and(|date| date != payload.date().timestamp())
            {
                report.entries.push(entry(
                    &key,
                    old.as_ref(),
                    "source_changed",
                    "source INTERNALDATE changed since planning",
                ));
                continue;
            }
            dest.ensure_live()?;
            let current = dest.writable_selection(&mapping.destination)?;
            if current.validity != selected.validity {
                bail!("destination UIDVALIDITY changed before APPEND");
            }
            let baseline = (
                current.validity,
                current
                    .next
                    .context("destination omitted UIDNEXT; cannot track append baseline")?,
            );
            let (flags, omitted) = transfer_flags(payload.flags(), &current.flags);
            if stop.load(Ordering::Relaxed) {
                report.interrupted = true;
                break;
            }
            let metadata = AppendMetadata {
                date: payload.date().timestamp(),
                flags: &flags,
                omitted: &omitted,
                baseline,
            };
            // The same single FULL preparation commit either way; a spooled message was fully
            // read, verified and hashed before this point, so its fingerprint is already known.
            let r = match &payload {
                Payload::Buffered(m) => job.journal.prepare_append(&key, &m.body, metadata)?,
                Payload::Spooled(s) => {
                    job.journal
                        .prepare_append_fingerprint(&key, s.sha256(), metadata)?
                }
            };
            // Empty literals could be committed without any body bytes; authorize
            // those BEFORE sending even the APPEND command prefix.
            let empty_body = payload.is_empty_body();
            if empty_body {
                job.journal.authorize_literal(&key)?;
            }
            crate::fault::point("before_append");
            // NEVER retry this operation. Its state is durable before sending bytes.
            let planned_flags = r.flags.as_ref().context("missing planned flags")?;
            // Durable authorization after the continuation and before the first body byte; the
            // same guard for both paths.
            let guard = || {
                crate::fault::point("after_append_continuation");
                if !empty_body {
                    job.journal.authorize_literal(&key).map_err(|_| {
                        std::io::Error::other("cannot durably authorize APPEND literal")
                    })?;
                }
                crate::fault::point("before_literal_send");
                Ok(())
            };
            let mut streamed_phase = None;
            let appended = match &mut payload {
                Payload::Buffered(message) => {
                    dest.destination
                        .append(&mapping.destination, message, planned_flags, guard)
                }
                Payload::Spooled(spooled) => {
                    let out = dest.destination.append_spooled(
                        &mapping.destination,
                        spooled,
                        planned_flags,
                        guard,
                    );
                    streamed_phase = Some(out.phase);
                    out.result
                }
            };
            dest.touch();
            match appended {
                Ok((dv, du)) => {
                    crate::fault::point("after_append_reply");
                    if dv != selected.validity || du < baseline.1 {
                        bail!(
                            "APPENDUID differs from destination epoch or precedes the saved UID baseline; transfer remains uncertain"
                        );
                    }
                    circuit.success();
                    drop(payload); // Release source content (and any spool) before verification.
                    job.journal.acknowledge(&key, dv, du)?;
                    dest.advance_baseline(du);
                    let r = job.journal.record(&key)?.unwrap();
                    report.entries.push(verify_record(
                        &mut job.journal,
                        &r,
                        &mut dest,
                        selected.validity,
                    )?);
                }
                Err(e) if crate::transport::append_rejection(&e).is_some() => {
                    let proof = crate::transport::append_rejection(&e).unwrap();
                    job.journal.reject_append(&key, &proof)?;
                    use crate::transport::RejectionScope as Scope;
                    let scope = proof.scope();
                    match scope {
                        // This message alone (or its size against quota) is the
                        // reason; later messages are independent. Never replayed.
                        Scope::Message | Scope::SizeDependent => {
                            circuit.success();
                            report.entries.push(entry(&key, Some(&r), "rejected", format!("APPEND {} [{}]; {} rejection, retained as planned; continuing to later messages", proof.status, proof.code, scope.name())));
                            continue;
                        }
                        Scope::Transient => {}
                        Scope::Mailbox | Scope::Account | Scope::Ambiguous => {
                            report.entries.push(entry(&key, Some(&r), "rejected", format!("APPEND {} [{}]; {} rejection, retained as planned; no automatic replay", proof.status, proof.code, scope.name())));
                            report.halt_reason = Some(match scope {
                                Scope::Mailbox => format!(
                                    "destination mailbox rejected APPEND [{}]; no further messages attempted; fix the destination folder (existence, permissions) and rerun",
                                    proof.code
                                ),
                                Scope::Account => format!(
                                    "destination account or session rejected APPEND [{}]; no further messages attempted; restore account access and rerun",
                                    proof.code
                                ),
                                _ => format!(
                                    "unclassified destination rejection [{}]; operator review required; if this message can never be migrated, record that decision with the skip command, otherwise resolve the destination and rerun",
                                    proof.code
                                ),
                            });
                            report.finish();
                            return Ok(report);
                        }
                    }
                    let consecutive = circuit.reject(&proof);
                    report.entries.push(entry(&key, Some(&r), "rejected", format!("APPEND {} [{}]; retained as planned; consecutive identical rejections: {consecutive}", proof.status, proof.code)));
                    if consecutive >= c.append_rejection_limit {
                        report.halt_reason = Some(format!(
                            "destination rejection circuit open after {consecutive} consecutive {} [{}] responses; no further messages attempted; resolve destination limits before rerunning",
                            proof.status, proof.code
                        ));
                        report.interrupted |= stop.load(Ordering::Relaxed);
                        report.finish();
                        return Ok(report);
                    }
                    if !rejection_pause(consecutive, &stop) {
                        report.interrupted = true;
                        report.finish();
                        return Ok(report);
                    }
                    continue;
                }
                Err(e) => {
                    // The streaming phase is information for the operator only; every unsettled
                    // APPEND stays uncertain and manual, exactly as before.
                    let phase = streamed_phase
                        .map(|p| {
                            format!(
                                " (streamed APPEND reached: {})",
                                crate::transport::phase_name(p)
                            )
                        })
                        .unwrap_or_default();
                    report.entries.push(entry(
                        &key,
                        Some(&r),
                        "uncertain",
                        format!(
                            "{e:#}{phase}; rerun to inspect destination candidates, do not blindly retry"
                        ),
                    ));
                    // The connection may be out of sync, and no further writes are safe.
                    report.interrupted |= stop.load(Ordering::Relaxed);
                    report.finish();
                    return Ok(report);
                }
            }
            if report.entries.last().is_some_and(|e| e.result == "failed") {
                report.interrupted |= stop.load(Ordering::Relaxed);
                report.finish();
                return Ok(report);
            }
        }
        if report.interrupted {
            break;
        }
    }
    report.interrupted |= stop.load(Ordering::Relaxed);
    report.finish();
    Ok(report)
}

fn transfer_flags(flags: &[String], supported: &[String]) -> (Vec<String>, Vec<String>) {
    let mut kept = BTreeSet::new();
    let mut omitted = BTreeSet::new();
    for f in flags {
        if f.eq_ignore_ascii_case("\\Recent") {
            continue;
        }
        let system = f.starts_with('\\');
        let accepted = supported.iter().any(|p| p.eq_ignore_ascii_case(f))
            || (!system && supported.iter().any(|p| p == "\\*"));
        if f.eq_ignore_ascii_case("\\Deleted") || !valid_flag(f) || !accepted {
            omitted.insert(f.clone());
        } else {
            kept.insert(f.clone());
        }
    }
    (kept.into_iter().collect(), omitted.into_iter().collect())
}
/// The one comparison of journal evidence against a destination message: content hash,
/// INTERNALDATE and supported persistent flags.
fn matches_digest(r: &Record, m: &crate::transport::MessageDigest) -> Result<()> {
    if m.sha256 != r.hash {
        bail!("content hash mismatch");
    }
    if Some(m.date.timestamp()) != r.date {
        bail!("INTERNALDATE mismatch");
    }
    let actual: BTreeSet<_> = m
        .flags
        .iter()
        .filter(|f| !f.eq_ignore_ascii_case("\\Recent"))
        .map(|f| f.to_ascii_lowercase())
        .collect();
    let expected: BTreeSet<_> = r
        .flags
        .as_ref()
        .context("journal lacks metadata")?
        .iter()
        .map(|f| f.to_ascii_lowercase())
        .collect();
    if actual != expected {
        bail!("persistent flags mismatch");
    }
    Ok(())
}
fn verification_failure(
    j: &mut Journal,
    r: &Record,
    result: &str,
    detail: impl Into<String>,
) -> Result<Entry> {
    // Persist observed failure; do not erase historical confirmation merely
    // because a new check started and could be interrupted.
    j.invalidate(&r.key)?;
    Ok(entry(&r.key, Some(r), result, detail))
}
fn verify_record(
    j: &mut Journal,
    r: &Record,
    d: &mut DestinationReader<'_>,
    validity: u32,
) -> Result<Entry> {
    let (dv, du) = r
        .destination
        .context("record has no destination identity")?;
    if dv != validity {
        return verification_failure(
            j,
            r,
            "destination_changed",
            "destination UIDVALIDITY differs from APPENDUID",
        );
    }
    crate::fault::point("before_verification_fetch");
    let m = match d.digest(du, "verification_stream_chunk") {
        Ok(Some(m)) => m,
        Ok(None) => {
            return verification_failure(j, r, "missing", "destination UID no longer exists");
        }
        Err(e) => {
            return verification_failure(
                j,
                r,
                if crate::transport::is_permanent_message(&e) {
                    "verification_failed_permanent"
                } else {
                    "failed"
                },
                format!("destination read failed: {e:#}"),
            );
        }
    };
    crate::fault::point("after_verification_fetch");
    if let Err(e) = matches_digest(r, &m) {
        return verification_failure(j, r, "mismatch", e.to_string());
    }
    if r.state == "confirmed" {
        // Exact read-back above is still mandatory for this run. Its historical
        // confirmation already exists durably, so no new transition is needed.
        crate::fault::point("before_confirm");
        crate::fault::point("after_confirm");
    } else {
        j.confirm_content_fingerprint(&r.key, dv, du, &m.sha256)?;
    }
    Ok(entry(
        &r.key,
        Some(r),
        "confirmed",
        "exact content, INTERNALDATE and supported persistent flags match",
    ))
}
fn reconcile(r: &Record, d: &mut DestinationReader<'_>, validity: u32) -> Result<Entry> {
    let mut result = entry(
        &r.key,
        Some(r),
        "uncertain",
        "no upload retry: destination attribution requires operator resolution",
    );
    let Some((bv, next)) = r.baseline else {
        return Ok(result);
    };
    if bv != validity {
        result.detail = "destination UIDVALIDITY changed; previous baseline cannot be used".into();
        return Ok(result);
    }
    let uids = d.read(|d| d.uids())?;
    let candidates: Vec<_> = uids.into_iter().filter(|u| *u >= next).collect();
    if candidates.len() > 1000 {
        result.detail = "candidate search incomplete: more than 1000 post-baseline UIDs; no automatic attribution or retry".into();
        return Ok(result);
    }
    for uid in candidates {
        if let Some(m) = d.digest(uid, "candidate_stream_chunk")? {
            if matches_digest(r, &m).is_ok() {
                result.candidate_uids.push(uid);
            }
        }
    }
    result.detail = "matching candidates are evidence only, not confirmed attribution; at most 1000 post-baseline UIDs examined".into();
    Ok(result)
}

pub fn verify(c: &Config, stop: Arc<AtomicBool>) -> Result<Report> {
    require_mappings(c)?;
    let mut job = Job::open(c, false)?;
    let dp = c.destination.password("Destination")?;
    let mut dest = DestinationReader::new(c, &dp)?;
    let mut report = Report::new(
        "live destination content, INTERNALDATE and supported flags against the durable source UID snapshot; source not contacted",
    );
    let snapshots = job.journal.work_list()?;
    if snapshots.len() != c.folders.len() {
        bail!("job snapshot is incomplete; resume migrate first");
    }
    for (folder, validity, uids) in snapshots {
        if stop.load(Ordering::Relaxed) {
            report.interrupted = true;
            break;
        }
        let mapping = c
            .folders
            .iter()
            .find(|f| f.source == folder)
            .context("snapshot mapping missing")?;
        let selected = dest.select(&mapping.destination, false)?;
        for uid in uids {
            if stop.load(Ordering::Relaxed) {
                report.interrupted = true;
                break;
            }
            let key = MessageKey {
                folder: folder.clone(),
                uid_validity: validity,
                uid,
            };
            let Some(r) = job.journal.record(&key)? else {
                report.entries.push(entry(
                    &key,
                    None,
                    "not_transferred",
                    "snapshot message has no transfer record",
                ));
                continue;
            };
            if r.state == "uncertain" {
                report
                    .entries
                    .push(reconcile(&r, &mut dest, selected.validity)?);
            } else if r.destination.is_none() {
                if let Some(reason) = job.journal.active_skip(&key)? {
                    report.entries.push(skipped_entry(&key, &r, &reason));
                } else {
                    report.entries.push(entry(
                        &key,
                        Some(&r),
                        "not_transferred",
                        "message was planned but not uploaded",
                    ));
                }
            } else {
                report.entries.push(verify_record(
                    &mut job.journal,
                    &r,
                    &mut dest,
                    selected.validity,
                )?);
            }
            if report.entries.last().is_some_and(|e| e.result == "failed") {
                report.finish();
                return Ok(report);
            }
        }
    }
    report.finish();
    Ok(report)
}

/// Recovery is evidence-based, never inferred from an empty search alone.
pub fn recover_not_sent(c: &Config, folder: &str, uid: u32) -> Result<Report> {
    require_mappings(c)?;
    let mapping = c
        .folders
        .iter()
        .find(|f| f.source == folder)
        .context("folder is not configured")?;
    let mut job = Job::open(c, false)?;
    let record = job
        .journal
        .records()?
        .into_iter()
        .find(|r| r.key.folder == folder && r.key.uid == uid && r.state == "uncertain")
        .context("no uncertain source record with this folder and UID")?;
    let dp = c.destination.password("Destination")?;
    let mut dest = DestinationReader::new(c, &dp)?;
    let selected = dest.select(&mapping.destination, false)?;
    let (validity, next) = record
        .baseline
        .context("record lacks baseline; manual review required")?;
    if validity != selected.validity {
        bail!("destination UIDVALIDITY changed; recovery refused");
    }
    let post_baseline: Vec<_> = dest
        .read(|d| d.uids())?
        .into_iter()
        .filter(|uid| *uid >= next)
        .collect();
    if post_baseline.len() > 1000 {
        bail!("candidate search exceeds recovery safety limit; manual review required");
    }
    for candidate in post_baseline {
        let message = dest
            .digest(candidate, "candidate_stream_chunk")?
            .context("destination changed during candidate inspection; retry review")?;
        if matches_digest(&record, &message).is_ok() {
            bail!("matching candidate exists; use manual attribution");
        }
    }
    job.journal
        .recover_not_sent(&record.key, selected.validity)?;
    let mut report = Report::new(
        "audited pre-literal recovery; no upload; rerun migrate to attempt this planned transfer",
    );
    report.entries.push(entry(
        &record.key,
        Some(&record),
        "retry_authorized",
        "durable attempt fence proves literal was never authorized; zero matching candidates",
    ));
    Ok(report)
}

/// Record an explicit operator decision not to migrate a permanently rejected
/// message. Contacts no server, changes no transfer state, uploads nothing, and
/// can never make a run complete: the message remains reported as not migrated.
pub fn skip(c: &Config, folder: &str, uid: u32, reason: &str) -> Result<Report> {
    skip_or_unskip(c, folder, uid, reason, true)
}
/// Reverse `skip` so the message follows the normal migrate path again.
pub fn unskip(c: &Config, folder: &str, uid: u32, reason: &str) -> Result<Report> {
    skip_or_unskip(c, folder, uid, reason, false)
}
fn skip_or_unskip(c: &Config, folder: &str, uid: u32, reason: &str, skip: bool) -> Result<Report> {
    require_mappings(c)?;
    c.folders
        .iter()
        .find(|f| f.source == folder)
        .context("folder is not configured")?;
    let mut job = Job::open(c, false)?;
    let record = job
        .journal
        .records()?
        .into_iter()
        .find(|r| r.key.folder == folder && r.key.uid == uid)
        .context("no transfer record with this folder and UID")?;
    let mut report = Report::new(if skip {
        "audited operator skip; no server contacted; the message is NOT migrated"
    } else {
        "audited operator unskip; no server contacted; rerun migrate to transfer the message"
    });
    if skip {
        job.journal.skip_rejected(&record.key, reason)?;
        report
            .entries
            .push(skipped_entry(&record.key, &record, reason));
    } else {
        job.journal.unskip(&record.key, reason)?;
        report.entries.push(entry(
            &record.key,
            Some(&record),
            "unskipped",
            "skip reversed; the message will be attempted again by migrate",
        ));
    }
    report.finish();
    Ok(report)
}

/// This command represents explicit operator attribution, not automatic inference.
pub fn resolve(c: &Config, folder: &str, uid: u32, destination_uid: u32) -> Result<Report> {
    require_mappings(c)?;
    let mapping = c
        .folders
        .iter()
        .find(|f| f.source == folder)
        .context("folder is not configured")?;
    let mut job = Job::open(c, false)?;
    let record = job
        .journal
        .records()?
        .into_iter()
        .find(|r| r.key.folder == folder && r.key.uid == uid && r.state == "uncertain")
        .context("no uncertain source record with this folder and UID")?;
    let dp = c.destination.password("Destination")?;
    let mut dest = DestinationReader::new(c, &dp)?;
    let selected = dest.select(&mapping.destination, false)?;
    let (validity, next) = record
        .baseline
        .context("record lacks a pre-append baseline")?;
    if selected.validity != validity || destination_uid < next {
        bail!("destination UID is outside the recorded append baseline");
    }
    let message = dest
        .digest(destination_uid, "candidate_stream_chunk")?
        .context("destination UID does not exist")?;
    matches_digest(&record, &message).context("refusing attribution: candidate does not match")?;
    job.journal
        .resolve_attribution(&record.key, validity, destination_uid)?;
    let r = job.journal.record(&record.key)?.unwrap();
    let mut report = Report::new(
        "operator-attributed uncertain transfer; exact content, date and flags verified; this is not a full-job verification",
    );
    report
        .entries
        .push(verify_record(&mut job.journal, &r, &mut dest, validity)?);
    // Resolution is deliberately not a declaration of whole-job completion.
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn append_baseline_is_monotone_and_does_not_wrap_uids() {
        assert_eq!(append_lower_bound(Some(1), 7), Some(8));
        assert_eq!(append_lower_bound(Some(50), 40), Some(50));
        assert_eq!(append_lower_bound(None, 3), Some(4));
        assert_eq!(append_lower_bound(Some(u32::MAX), u32::MAX), None);
    }
    #[test]
    fn transfer_flags_enforce_safe_supported_flags_without_deleted_or_recent() {
        let source = [
            "\\Seen",
            "\\Deleted",
            "\\Recent",
            "custom",
            "unsupported",
            "bad)\r\nEXPUNGE",
        ]
        .map(str::to_owned);
        let supported = ["\\Seen", "\\Deleted", "custom"].map(str::to_owned);
        let (kept, omitted) = transfer_flags(&source, &supported);
        assert_eq!(kept, vec!["\\Seen", "custom"]);
        assert!(omitted.contains(&"\\Deleted".to_owned()));
        assert!(omitted.contains(&"unsupported".to_owned()));
        assert!(!omitted.contains(&"\\Recent".to_owned()));
        let (kept, _) = transfer_flags(&source, &["\\*".into()]);
        assert_eq!(kept, vec!["custom", "unsupported"]);
    }
}
