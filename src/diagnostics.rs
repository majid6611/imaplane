//! Opt-in, sanitized protocol diagnostics for provider compatibility work.
//!
//! Off unless `--diagnostics-file PATH` is given. When on, one JSON object per line
//! records WHAT happened on the wire, never the content of it:
//! role, operation class, tagged status (OK/NO/BAD/BYE/IO), response-code name,
//! the failure scope IMAPLANE assigned, elapsed milliseconds and a few counts.
//!
//! Never recorded: passwords, tokens, usernames, folder names, message content,
//! headers, UIDs, or any free-form server text. A response code is recorded only as
//! a fixed IMAPLANE name or, for an unlisted vendor code, as a strictly validated
//! `[A-Z0-9-]{1,32}` atom (a protocol identifier, never a sentence). Capability
//! names are recorded only from a fixed allowlist plus a count of the rest.
//!
//! The sink is write-only and best effort: it cannot change control flow, and a write
//! failure silently disables it. The file is created mode 0600, never followed through
//! a symlink, and appended to.
use anyhow::{Result, bail};
use serde_json::{Map, Value};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

static SINK: OnceLock<Mutex<File>> = OnceLock::new();
static ALIVE: AtomicBool = AtomicBool::new(true);
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Open the sink. Explicit opt-in: failure to open is an error, not a silent no-op.
pub fn enable(path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: getuid has no preconditions.
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::getuid() } {
        bail!("diagnostics file must be a regular file owned by you with mode 0600");
    }
    if SINK.set(Mutex::new(file)).is_err() {
        bail!("diagnostics already enabled");
    }
    event(
        "start",
        Map::from_iter([
            ("version".into(), env!("CARGO_PKG_VERSION").into()),
            ("pid".into(), std::process::id().into()),
        ]),
    );
    Ok(())
}

pub(crate) fn enabled() -> bool {
    SINK.get().is_some() && ALIVE.load(Ordering::Relaxed)
}

/// Append one line. Callers pass only already-sanitized scalar fields.
pub(crate) fn event(kind: &str, mut fields: Map<String, Value>) {
    let Some(sink) = SINK.get().filter(|_| ALIVE.load(Ordering::Relaxed)) else {
        return;
    };
    fields.insert("event".into(), kind.into());
    fields.insert("seq".into(), SEQ.fetch_add(1, Ordering::Relaxed).into());
    fields.insert(
        "t".into(),
        chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            .into(),
    );
    let Ok(mut line) = serde_json::to_vec(&Value::Object(fields)) else {
        return;
    };
    line.push(b'\n');
    let ok = sink
        .lock()
        .map(|mut file| file.write_all(&line).is_ok())
        .unwrap_or(false);
    if !ok {
        ALIVE.store(false, Ordering::Relaxed);
    }
}
