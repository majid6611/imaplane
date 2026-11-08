use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    #[serde(default = "port")]
    pub port: u16,
    pub username: String,
    pub password_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub security: Security,
    pub access_token_file: Option<PathBuf>,
    #[serde(default)]
    pub auth: Auth,
}
#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    #[default]
    Tls,
    Starttls,
}
fn port() -> u16 {
    993
}
#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    #[default]
    Auto,
    Plain,
    Login,
    #[serde(alias = "oauth2")]
    Xoauth2,
}
/// Client-side duplicate protection for Gmail-style destinations (those advertising X-GM-EXT-1).
/// `auto` (default) checks every message before it is appended and holds back probable duplicates, because
/// Gmail merges duplicates and can silently discard the appended bytes. `off` accepts that risk.
#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum GmailProtection {
    #[default]
    Auto,
    Off,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FolderMap {
    pub source: String,
    pub destination: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub state_dir: PathBuf,
    #[serde(default)]
    pub folders: Vec<FolderMap>,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "max_message")]
    pub max_message_bytes: usize,
    #[serde(default = "attempts")]
    pub read_attempts: u32,
    #[serde(default = "rejection_limit")]
    pub append_rejection_limit: u32,
    /// Destination reads of messages larger than this many bytes stream through a hasher
    /// instead of being held in memory. Absent (the default) means never; 0 means always.
    /// Not part of the job binding, so it can be changed between runs.
    #[serde(default)]
    pub stream_threshold_bytes: Option<usize>,
    /// Directory for spooled large source messages (those above `stream_threshold_bytes`).
    /// Default: `state_dir`. It must be a private (mode 0700) directory you own on a local
    /// filesystem that supports O_TMPFILE. Spooled mail is PLAINTEXT on that storage until
    /// the kernel reclaims it; O_TMPFILE does not encrypt. Not part of the job binding.
    #[serde(default)]
    pub spool_dir: Option<PathBuf>,
    /// Accept a tmpfs/ramfs `spool_dir`, which keeps spooled mail in RAM. Default false.
    #[serde(default)]
    pub spool_allow_memory_backed: bool,
    /// Journal file storage: `auto` (default) uses a write-ahead log with full synchronous commits when it can be
    /// done safely, `rollback` keeps (or restores) the rollback journal. Not part of the job binding.
    #[serde(default)]
    pub journal_mode: crate::journal::JournalPref,
    /// Gmail duplicate protection (`auto` or `off`). Not part of the job binding.
    #[serde(default)]
    pub gmail_duplicate_protection: GmailProtection,
}
fn rejection_limit() -> u32 {
    3
}
fn timeout() -> u64 {
    60
}
fn max_message() -> usize {
    64 * 1024 * 1024
}
fn attempts() -> u32 {
    6
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        // Never include TOML parser errors, which can quote secrets accidentally put in config.
        let text = fs::read_to_string(path).context("read configuration")?;
        let mut c: Self = toml::from_str(&text).map_err(|_| anyhow::anyhow!("invalid configuration; check field names and types (inline passwords are not supported)"))?;
        let base = path.parent().unwrap_or(Path::new("."));
        for e in [&mut c.source, &mut c.destination] {
            if e.host.is_empty()
                || e.host.chars().any(char::is_control)
                || e.username.is_empty()
                || e.username.chars().any(char::is_control)
                || e.port == 0
            {
                bail!("invalid endpoint host, port or username");
            }
            if matches!(e.auth, Auth::Xoauth2) {
                if e.access_token_file.is_none() || e.password_file.is_some() {
                    bail!("XOAUTH2 requires access_token_file and forbids password_file");
                }
            } else if e.access_token_file.is_some() {
                bail!("access_token_file requires auth = xoauth2");
            }
            for p in [
                &mut e.password_file,
                &mut e.ca_file,
                &mut e.access_token_file,
            ]
            .into_iter()
            .flatten()
            {
                if p.is_relative() {
                    *p = base.join(&*p);
                }
            }
        }
        if let Some(dir) = &mut c.spool_dir {
            if dir.is_relative() {
                *dir = base.join(&*dir);
            }
        }
        if c.state_dir.is_relative() {
            c.state_dir = base.join(&c.state_dir);
        }
        if c.source.host.eq_ignore_ascii_case(&c.destination.host)
            && c.source.port == c.destination.port
            && c.source.username == c.destination.username
        {
            bail!("source and destination must be different accounts");
        }
        if !(1..=3600).contains(&c.timeout_seconds)
            || !(1..=10).contains(&c.read_attempts)
            || !(1..=100).contains(&c.append_rejection_limit)
            || c.max_message_bytes == 0
            || c.max_message_bytes > 1024 * 1024 * 1024
            || c.stream_threshold_bytes
                .is_some_and(|t| t > 1024 * 1024 * 1024)
        {
            bail!(
                "invalid limits: timeout 1..3600, attempts 1..10, rejection limit 1..100, message bytes 1..1073741824, stream threshold 0..1073741824"
            );
        }
        let mut sources = std::collections::HashSet::new();
        let mut destinations = std::collections::HashSet::new();
        for f in &c.folders {
            crate::folders::FolderEncoding::Utf8.encode(&f.source)?;
            crate::folders::FolderEncoding::Utf8.encode(&f.destination)?;
            let canonical = |s: &str| {
                if s.eq_ignore_ascii_case("INBOX") {
                    "INBOX".to_owned()
                } else {
                    s.to_owned()
                }
            };
            if !sources.insert(canonical(&f.source))
                || !destinations.insert(canonical(&f.destination))
            {
                bail!("folder mappings must be one-to-one, without INBOX aliases");
            }
        }
        Ok(c)
    }
    pub fn binding(&self) -> Result<String> {
        // Credentials, CA paths, operational limits and password-file paths are not identity.
        Ok(serde_json::to_string(&serde_json::json!({
            "source": [self.source.host.to_ascii_lowercase(), self.source.port.to_string(), self.source.username.clone()],
            "destination": [self.destination.host.to_ascii_lowercase(), self.destination.port.to_string(), self.destination.username.clone()],
            "folders": self.folders
        }))?)
    }
}
impl Endpoint {
    pub fn password(&self, label: &str) -> Result<Zeroizing<String>> {
        let oauth = matches!(self.auth, Auth::Xoauth2);
        let secret_file = if oauth {
            &self.access_token_file
        } else {
            &self.password_file
        };
        let mut value = if let Some(path) = secret_file {
            use std::{
                io::Read,
                os::unix::fs::{MetadataExt, OpenOptionsExt},
            };
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
                .context("open credential file")?;
            let meta = file.metadata()?;
            // SAFETY: getuid has no preconditions.
            if !meta.is_file()
                || meta.mode() & 0o077 != 0
                || meta.uid() != unsafe { libc::getuid() }
            {
                bail!(
                    "credential file must be a regular file owned by this user with mode 0600 or 0400"
                );
            }
            let mut s = Zeroizing::new(String::new());
            file.take(16385).read_to_string(&mut s)?;
            if s.len() > 16384 {
                bail!("credential file exceeds 16 KiB");
            }
            if s.ends_with('\n') {
                s.pop();
                if s.ends_with('\r') {
                    s.pop();
                }
            }
            s
        } else {
            if oauth {
                bail!("XOAUTH2 requires access_token_file");
            }
            Zeroizing::new(rpassword::prompt_password(format!("{label} password: "))?)
        };
        if value.is_empty() || value.chars().any(|c| matches!(c, '\0' | '\r' | '\n')) {
            value.clear();
            bail!("credential must be nonempty and contain no NUL or line breaks");
        }
        if value.len() > 16384 {
            bail!("credential exceeds 16 KiB");
        }
        if oauth
            && !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            bail!("access token contains invalid bearer-token characters");
        }
        Ok(value)
    }
}
