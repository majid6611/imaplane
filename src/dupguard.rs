//! Client-side duplicate check for Gmail-style destinations (see docs/GMAIL_DUPLICATE_MERGE_DESIGN.md).
//!
//! Some providers merge an APPEND into an existing message with the same content and, in one observed case,
//! silently discard the appended bytes while reporting success. Before a message is prepared for APPEND this
//! check looks (READ-ONLY) for a sibling: an earlier copy in this job's journal, a message appended earlier in
//! this run, or an existing message in the destination account found by a batched Message-ID search. A
//! positive finding holds the message back: nothing durable but one evidence row is written and nothing is sent.
//!
//! This is risk reduction, never proof of delivery: the exact SHA-256 read-back after every APPEND stays
//! mandatory and unchanged. A failure of the check itself is never recorded as evidence and never lets the
//! message through: the caller stops the run (fail closed).
use crate::{
    dedup::{self, Keys},
    journal::{Journal, MessageKey},
    transport::{Destination, SEARCH_BATCH, Source, searchable_id},
};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};

/// Messages looked up per window (source header pass and destination search).
pub const WINDOW: usize = 1000;
const SEARCH_RETRIES: u32 = 2;

/// A message that already exists in the destination account.
#[derive(Debug, Clone)]
struct Existing {
    uid: u32,
    body_sha256: String,
    content_sha256: String,
    size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Clear,
    Hold {
        reason: &'static str,
        detail: String,
    },
}

/// What the check needs to know about the message being transferred.
pub struct Subject {
    pub keys: Keys,
    /// SHA-256 of the whole message (the journal fingerprint).
    pub fingerprint: String,
}

pub struct DupGuard {
    reader: Destination,
    all_mail: String,
    endpoint: crate::config::Endpoint,
    password: String,
    timeout: std::time::Duration,
    max_message: usize,
    /// Message-IDs already searched in the destination, and what the hits were.
    searched: HashSet<String>,
    existing: HashMap<String, Vec<Existing>>,
    /// (message id, body hash) of every message appended in this run, with its source UID.
    in_run: HashMap<(String, String), String>,
    pub searches: u64,
}

impl DupGuard {
    /// Opens the second, read-only destination connection and selects the `\All` mailbox read-only.
    pub fn start(
        endpoint: &crate::config::Endpoint,
        password: &str,
        timeout: std::time::Duration,
        max_message: usize,
    ) -> Result<Self> {
        let mut reader = Destination::connect(endpoint, password, timeout, max_message)?;
        let all_mail = match reader.all_mail_folder()? {
            Some(name) => name,
            None => bail!(
                "the destination offers X-GM-EXT-1 but lists no \\All mailbox, so duplicates cannot be checked; enable \"Show in IMAP\" for All Mail in the account's Gmail settings, or set gmail_duplicate_protection = \"off\" to accept Gmail's silent duplicate merging"
            ),
        };
        let selected = reader.examine(&all_mail)?;
        if selected.writable {
            bail!("duplicate-check connection unexpectedly opened {all_mail:?} writable");
        }
        Ok(Self {
            reader,
            all_mail,
            endpoint: endpoint.clone(),
            password: password.to_owned(),
            timeout,
            max_message,
            searched: HashSet::new(),
            existing: HashMap::new(),
            in_run: HashMap::new(),
            searches: 0,
        })
    }

    pub fn all_mail(&self) -> &str {
        &self.all_mail
    }

    fn reconnect(&mut self) -> Result<()> {
        let mut reader = Destination::connect(
            &self.endpoint,
            &self.password,
            self.timeout,
            self.max_message,
        )?;
        reader.examine(&self.all_mail)?;
        self.reader = reader;
        Ok(())
    }

    /// Bounded retry of a read-only lookup: at most SEARCH_RETRIES retries with 1 s and 2 s backoff and a
    /// reconnect before each. Permanent errors are returned at once.
    fn read<T>(&mut self, mut f: impl FnMut(&mut Destination) -> Result<T>) -> Result<T> {
        let mut attempt = 0;
        loop {
            match f(&mut self.reader) {
                Ok(v) => return Ok(v),
                Err(e) if crate::transport::is_transient(&e) && attempt < SEARCH_RETRIES => {
                    attempt += 1;
                    let until = std::time::Instant::now()
                        + std::time::Duration::from_secs(u64::from(attempt));
                    while std::time::Instant::now() < until {
                        if crate::interrupted() {
                            bail!("operation interrupted");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    self.reconnect()?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Reads the Message-IDs of `uids` (source headers, BODY.PEEK) and searches the destination for them in
    /// batches. Afterwards `check` needs no per-message round trip for any of these messages.
    pub fn prescan(&mut self, source: &mut Source, uids: &[u32]) -> Result<()> {
        let mut wanted: Vec<String> = Vec::new();
        for chunk in uids.chunks(WINDOW) {
            let blocks = source.header_blocks(chunk)?;
            for uid in chunk {
                if let Some(id) = blocks
                    .get(uid)
                    .and_then(|b| dedup::message_id(dedup::split(b).0))
                {
                    if searchable_id(&id) && !self.searched.contains(&id) && !wanted.contains(&id) {
                        wanted.push(id);
                    }
                }
            }
        }
        self.search(&wanted)
    }

    fn search(&mut self, ids: &[String]) -> Result<()> {
        for batch in ids.chunks(SEARCH_BATCH) {
            self.searches += 1;
            let hits = self.read(|d| d.search_message_ids(batch))?;
            for uid in hits {
                let max = self.max_message;
                let found = self.read(|d| d.message_keys(uid))?;
                let Some((keys, content, size)) = found else {
                    continue; // vanished between search and fetch: nothing to compare
                };
                if size as usize > max {
                    bail!(
                        "an existing destination message (All Mail UID {uid}) exceeds max_message_bytes and cannot be compared"
                    );
                }
                if let Some(id) = keys.message_id {
                    let list = self.existing.entry(id).or_default();
                    if !list.iter().any(|e| e.uid == uid) {
                        list.push(Existing {
                            uid,
                            body_sha256: keys.body_sha256,
                            content_sha256: content,
                            size,
                        });
                    }
                }
            }
            self.searched.extend(batch.iter().cloned());
        }
        Ok(())
    }

    /// Decides whether this message may go on to `prepare_append`. Read-only; writes nothing anywhere.
    pub fn check(
        &mut self,
        journal: &Journal,
        key: &MessageKey,
        subject: &Subject,
    ) -> Result<Verdict> {
        // 1. This job's journal: an earlier copy of identical content that is (or may be) in the destination.
        if let Some((sibling, state)) =
            journal.sibling_with_fingerprint(&subject.fingerprint, key)?
        {
            let reason = if state == "uncertain" {
                "SIBLING_UNCERTAIN"
            } else {
                "SAME_CONTENT_THIS_JOB"
            };
            return Ok(Verdict::Hold {
                reason,
                detail: format!(
                    "identical content already {state} for source {:?} UID {}",
                    sibling.folder, sibling.uid
                ),
            });
        }
        let Some(id) = subject.keys.message_id.as_deref() else {
            return Ok(Verdict::Clear); // no usable identifier: nothing to compare (never a hold)
        };
        // 2. Appended earlier in this run (covers the seconds in which search cannot see it yet).
        if let Some(earlier) = self
            .in_run
            .get(&(id.to_owned(), subject.keys.body_sha256.clone()))
        {
            return Ok(Verdict::Hold {
                reason: "SAME_CONTENT_THIS_JOB",
                detail: format!(
                    "same Message-ID and body as {earlier}, appended earlier in this run"
                ),
            });
        }
        // 3. Existing destination mail.
        if !self.searched.contains(id) && searchable_id(id) {
            self.search(&[id.to_owned()])?;
        }
        if let Some(found) = self.existing.get(id).and_then(|list| {
            list.iter()
                .find(|e| e.body_sha256 == subject.keys.body_sha256)
        }) {
            let reason = if found.content_sha256 == subject.fingerprint {
                "SAME_CONTENT_EXISTING"
            } else {
                "SAME_ID_AND_BODY_EXISTING"
            };
            return Ok(Verdict::Hold {
                reason,
                detail: format!(
                    "{:?} UID {} ({} bytes) has the same Message-ID and body",
                    self.all_mail, found.uid, found.size
                ),
            });
        }
        Ok(Verdict::Clear)
    }

    /// Remember a message this run appended (or left in doubt), for later siblings.
    pub fn note_appended(&mut self, key: &MessageKey, subject: &Subject) {
        if let Some(id) = &subject.keys.message_id {
            self.in_run.insert(
                (id.clone(), subject.keys.body_sha256.clone()),
                format!("source {:?} UID {}", key.folder, key.uid),
            );
        }
    }
}
