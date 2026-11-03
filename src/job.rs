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
    _lock: File,
}
impl Job {
    pub fn open(c: &Config, create: bool) -> Result<Self> {
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
        journal.check_binding(&binding)?;
        Ok(Self {
            journal,
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
