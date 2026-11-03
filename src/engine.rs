use crate::{
    config::Config,
    job::Job,
    journal::{Journal, MessageKey, Record, fingerprint},
    transport::{Destination, Message, Selected, Source, valid_flag},
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
    pub entries: Vec<Entry>,
}
impl Report {
    fn new(scope: &str) -> Self {
        Self {
            report_version: 1,
            observed_at: chrono::Utc::now().to_rfc3339(),
            scope: scope.into(),
            complete: false,
            interrupted: false,
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
fn transient(e: &anyhow::Error) -> bool {
    crate::transport::is_transient(e)
}
fn backoff(attempt: u32) {
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis() as u64
        % 100;
    std::thread::sleep(Duration::from_millis((100u64 << attempt.min(5)) + jitter));
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
            source: Source::connect(
                &config.source,
                password,
                Duration::from_secs(config.timeout_seconds),
                config.max_message_bytes,
            )?,
            config,
            password,
            selected: None,
        })
    }
    fn read<T>(&mut self, mut f: impl FnMut(&mut Source) -> Result<T>) -> Result<T> {
        for attempt in 0..self.config.read_attempts {
            match f(&mut self.source) {
                Ok(value) => return Ok(value),
                Err(e) if transient(&e) && attempt + 1 < self.config.read_attempts => {
                    backoff(attempt);
                    self.source = Source::connect(
                        &self.config.source,
                        self.password,
                        Duration::from_secs(self.config.timeout_seconds),
                        self.config.max_message_bytes,
                    )?;
                    if let Some((folder, validity)) = &self.selected {
                        let s = self.source.examine(folder)?;
                        if s.validity != *validity {
                            bail!("source UIDVALIDITY changed during reconnect");
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }
    fn select(&mut self, name: &str) -> Result<Selected> {
        // A failed selection must not restore a previously selected folder on retry.
        self.selected = None;
        let s = self.read(|s| s.examine(name))?;
        self.selected = Some((name.into(), s.validity));
        Ok(s)
    }
}
struct DestinationReader<'a> {
    config: &'a Config,
    password: &'a str,
    destination: Destination,
    selected: Option<(String, u32)>,
}
impl<'a> DestinationReader<'a> {
    fn new(config: &'a Config, password: &'a str) -> Result<Self> {
        Ok(Self {
            destination: Destination::connect(
                &config.destination,
                password,
                Duration::from_secs(config.timeout_seconds),
                config.max_message_bytes,
            )?,
            config,
            password,
            selected: None,
        })
    }
    fn read<T>(&mut self, mut f: impl FnMut(&mut Destination) -> Result<T>) -> Result<T> {
        for attempt in 0..self.config.read_attempts {
            match f(&mut self.destination) {
                Ok(v) => return Ok(v),
                Err(e) if transient(&e) && attempt + 1 < self.config.read_attempts => {
                    backoff(attempt);
                    self.destination = Destination::connect(
                        &self.config.destination,
                        self.password,
                        Duration::from_secs(self.config.timeout_seconds),
                        self.config.max_message_bytes,
                    )?;
                    if let Some((folder, validity)) = &self.selected {
                        let s = self.destination.examine(folder)?;
                        if s.validity != *validity {
                            bail!("destination UIDVALIDITY changed during reconnect");
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }
    fn select(&mut self, name: &str, writable: bool) -> Result<Selected> {
        self.selected = None;
        let s = self.read(|d| {
            if writable {
                d.select(name)
            } else {
                d.examine(name)
            }
        })?;
        self.selected = Some((name.into(), s.validity));
        Ok(s)
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
        let s = source.select(&f.source)?;
        let uids = source.read(|s| s.uids())?;
        check_inventory(s.exists, &uids)?;
        plans.push(serde_json::json!({"source":f.source,"destination":f.destination,"uid_validity":s.validity,"message_count":uids.len(),"create_destination":!folders.iter().any(|d| same_folder(&d.name,&f.destination))}));
    }
    Ok(
        serde_json::json!({"dry_run":true,"scope":"read-only preflight; no journal or destination writes","folders":plans}),
    )
}
fn check_inventory(exists: u32, uids: &[u32]) -> Result<()> {
    if uids.len() != exists as usize {
        bail!(
            "source UID inventory differs from EXISTS; source changed during snapshot or server omitted UIDs; retry without discarding state"
        );
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

pub fn migrate(c: &Config, stop: Arc<AtomicBool>) -> Result<Report> {
    require_mappings(c)?;
    let mut job = Job::open(c, true)?;
    let sp = c.source.password("Source")?;
    let dp = c.destination.password("Destination")?;
    let mut source = SourceReader::new(c, &sp)?;
    let mut dest = DestinationReader::new(c, &dp)?;
    preflight(c, &mut source, &mut dest)?;
    // Snapshot ALL configured source folders before any destination writes.
    for f in &c.folders {
        let s = source.select(&f.source)?;
        let uids = source.read(|s| s.uids())?;
        check_inventory(s.exists, &uids)?;
        job.journal.snapshot(&f.source, s.validity, &uids)?;
    }
    let mut report = Report::new(
        "live destination content, INTERNALDATE and supported flags against the durable source UID snapshot",
    );
    let mut known = dest.read(|d| d.folders())?;
    for (folder, validity, uids) in job.journal.snapshots()? {
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
                        report.finish();
                        return Ok(report);
                    }
                    continue;
                }
            }
            let message = match source.read(|s| s.message(*uid)) {
                Ok(Some(m)) => m,
                Ok(None) => {
                    report.entries.push(entry(
                        &key,
                        None,
                        "source_changed",
                        "snapshot UID is no longer available",
                    ));
                    continue;
                }
                Err(e) => {
                    report.entries.push(entry(
                        &key,
                        None,
                        "failed",
                        format!("source read failed: {e:#}"),
                    ));
                    report.finish();
                    return Ok(report);
                }
            };
            job.journal.plan(&key, &message.body)?;
            let mut r = job
                .journal
                .record(&key)?
                .context("planned record missing")?;
            let current = dest.select(&mapping.destination, true)?;
            if current.validity != selected.validity {
                bail!("destination UIDVALIDITY changed before APPEND");
            }
            let baseline = (
                current.validity,
                current
                    .next
                    .context("destination omitted UIDNEXT; cannot track append baseline")?,
            );
            if r.date.is_none() {
                let (flags, omitted) = transfer_flags(&message.flags, &current.flags);
                job.journal
                    .metadata(&key, message.date.timestamp(), &flags, &omitted, baseline)?;
            } else if r.date != Some(message.date.timestamp()) {
                report.entries.push(entry(
                    &key,
                    Some(&r),
                    "source_changed",
                    "source INTERNALDATE changed since planning",
                ));
                continue;
            }
            job.journal.refresh_baseline(&key, baseline)?;
            r = job.journal.record(&key)?.unwrap();
            if stop.load(Ordering::Relaxed) {
                report.interrupted = true;
                break;
            }
            job.journal.begin_append(&key)?;
            // NEVER retry this operation. Its state is durable before sending bytes.
            match dest.destination.append(
                &mapping.destination,
                &message,
                r.flags.as_ref().context("missing planned flags")?,
            ) {
                Ok((dv, du)) => {
                    drop(message); // Release source content before destination verification.
                    job.journal.acknowledge(&key, dv, du)?;
                    let r = job.journal.record(&key)?.unwrap();
                    report.entries.push(verify_record(
                        &mut job.journal,
                        &r,
                        &mut dest,
                        selected.validity,
                    )?);
                }
                Err(e) => {
                    report.entries.push(entry(
                        &key,
                        Some(&r),
                        "uncertain",
                        format!(
                            "{e:#}; rerun to inspect destination candidates, do not blindly retry"
                        ),
                    ));
                    // The connection may be out of sync, and no further writes are safe.
                    report.finish();
                    return Ok(report);
                }
            }
            if report.entries.last().is_some_and(|e| e.result == "failed") {
                report.finish();
                return Ok(report);
            }
        }
        if report.interrupted {
            break;
        }
    }
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
fn matches_record(r: &Record, m: &Message) -> Result<()> {
    if fingerprint(&m.body) != r.hash {
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
fn verify_record(
    j: &mut Journal,
    r: &Record,
    d: &mut DestinationReader<'_>,
    validity: u32,
) -> Result<Entry> {
    let (dv, du) = r
        .destination
        .context("record has no destination identity")?;
    j.invalidate(&r.key)?;
    if dv != validity {
        return Ok(entry(
            &r.key,
            Some(r),
            "destination_changed",
            "destination UIDVALIDITY differs from APPENDUID",
        ));
    }
    let m = match d.read(|d| d.message(du)) {
        Ok(Some(m)) => m,
        Ok(None) => {
            return Ok(entry(
                &r.key,
                Some(r),
                "missing",
                "destination UID no longer exists",
            ));
        }
        Err(e) => {
            return Ok(entry(
                &r.key,
                Some(r),
                "failed",
                format!("destination read failed: {e:#}"),
            ));
        }
    };
    if let Err(e) = matches_record(r, &m) {
        return Ok(entry(&r.key, Some(r), "mismatch", e.to_string()));
    }
    j.confirm_content(&r.key, dv, du, &m.body)?;
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
    for uid in uids.into_iter().filter(|u| *u >= next).take(1000) {
        if let Some(m) = d.read(|d| d.message(uid))? {
            if matches_record(r, &m).is_ok() {
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
    let snapshots = job.journal.snapshots()?;
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
                report.entries.push(entry(
                    &key,
                    Some(&r),
                    "not_transferred",
                    "message was planned but not uploaded",
                ));
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
        .read(|d| d.message(destination_uid))?
        .context("destination UID does not exist")?;
    matches_record(&record, &message).context("refusing attribution: candidate does not match")?;
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
