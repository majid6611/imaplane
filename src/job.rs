use crate::{config::Config, journal::Journal};
use anyhow::{Context, Result, bail};
use fs2::FileExt;
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

pub struct Job {
    pub journal: Journal,
    /// Configured folder mappings the job does not record yet (only with `allow_new`).
    pub new_folders: Vec<(String, String)>,
    _lock: File,
}
impl Job {
    pub fn open(c: &Config, create: bool) -> Result<Self> {
        Self::open_with(c, create, false)
    }

    /// `allow_new` admits configured folders the job does not record (only `migrate --incremental
    /// --add-new-folders`); they are listed in `new_folders` and added by the engine.
    pub fn open_with(c: &Config, create: bool, allow_new: bool) -> Result<Self> {
        if create {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&c.state_dir)?;
        }
        let meta = fs::symlink_metadata(&c.state_dir).context("open private state directory")?;
        // SAFETY: getuid has no preconditions.
        if !meta.is_dir() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::getuid() } {
            bail!("state_dir must be owned by this user, not a symlink, and mode 0700");
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(c.state_dir.join("job.lock"))?;
        lock.try_lock_exclusive()
            .context("another process holds this migration job lock")?;
        let path = c.state_dir.join("journal.sqlite3");
        let binding = c.binding()?;
        let journal = if path.try_exists()? {
            check_private_file(&path)?;
            Journal::open(&path)?
        } else if create {
            Journal::create(&path, &binding)?
        } else {
            bail!("no migration journal exists");
        };
        let new_folders = journal.check_binding_mode(&binding, allow_new)?;
        // A development-era schema-5 journal is refused here, before any network use or write.
        journal.require_compatible_evidence()?;
        Ok(Self {
            journal,
            new_folders,
            _lock: lock,
        })
    }
}
fn check_private_file(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    // SAFETY: getuid has no preconditions.
    if !m.is_file() || m.mode() & 0o077 != 0 || m.uid() != unsafe { libc::getuid() } {
        bail!("journal must be a private regular file owned by this user");
    }
    Ok(())
}
