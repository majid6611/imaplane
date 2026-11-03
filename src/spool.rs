//! Temporary spool for large source messages (phase 4 of docs/STREAMING_DESIGN.md).
//!
//! A message above the streaming threshold is written here while it is read from the source,
//! hashed and counted, verified, and only then sent to the destination. Guarantees:
//!
//! * **Anonymous.** The file is created with `O_TMPFILE | O_EXCL` in a private directory: it
//!   has no directory entry, can never be linked into the filesystem, is mode 0600, and the
//!   kernel reclaims it when the descriptor closes, including when the process is killed.
//!   There is deliberately **no named-file fallback**: it could not offer the same cleanup
//!   guarantee (a crash between create and unlink would leave plaintext on disk), so an
//!   unsupported filesystem fails closed and the operator picks another `spool_dir`.
//! * **Never silently RAM.** A tmpfs or ramfs spool directory is refused unless explicitly
//!   allowed, because that would put the "disk" spool back in memory.
//! * **Not encrypted.** `O_TMPFILE` hides and cleans up the file; it does NOT encrypt it. Spooled
//!   mail is plaintext on the underlying storage until the kernel reclaims it. Disk or volume
//!   encryption, quotas and a private `spool_dir` are the operator's responsibility.
//! * **Bounded and checked.** Free space is checked before the transfer and every write error
//!   (`ENOSPC`, `EDQUOT`, `EFBIG`) is a clean, typed failure that happens before any journal
//!   write or destination byte. The content is hashed on the way in, re-read and re-hashed
//!   before it can be authorized, and hashed again on the way out so a changed byte can never
//!   complete a literal.
//!
//! Error values are fixed variants with fixed text; they never carry message content, server
//! text or file paths.
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

/// Space kept free beyond the message itself when checking before a transfer.
pub const SPACE_MARGIN: u64 = 1 << 20;
const COPY_BUFFER: usize = 128 * 1024;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const RAMFS_MAGIC: i64 = 0x8584_58f6_u32 as i64;

#[derive(Debug)]
pub enum SpoolError {
    /// The directory's filesystem cannot create anonymous temporary files.
    Unsupported,
    /// The directory is memory-backed (tmpfs/ramfs) and that was not explicitly allowed.
    MemoryBacked,
    /// Not enough free space, quota exhausted, or the file-size limit was reached.
    NoSpace,
    /// The spool directory is not an acceptable private directory.
    BadDirectory(&'static str),
    /// The spooled bytes do not match the hash taken when they were written.
    Corrupt,
    /// Any other I/O failure.
    Io(io::ErrorKind),
}
impl std::fmt::Display for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str(
                "spool directory's filesystem does not support anonymous temporary files (O_TMPFILE); set spool_dir to a local filesystem that does",
            ),
            Self::MemoryBacked => f.write_str(
                "spool directory is memory-backed (tmpfs/ramfs); choose a disk-backed spool_dir or set spool_allow_memory_backed = true to accept RAM use",
            ),
            Self::NoSpace => f.write_str("not enough space for the spool (disk full, quota or file-size limit)"),
            Self::BadDirectory(why) => write!(f, "spool directory is not acceptable: {why}"),
            Self::Corrupt => f.write_str("spooled message content changed after it was verified"),
            Self::Io(kind) => write!(f, "spool I/O failure ({kind})"),
        }
    }
}
impl std::error::Error for SpoolError {}

/// Map an I/O error to the typed failure. Disk-full style errors are one class.
pub fn classify(e: &io::Error) -> SpoolError {
    match e.raw_os_error() {
        Some(libc::ENOSPC) | Some(libc::EDQUOT) | Some(libc::EFBIG) => SpoolError::NoSpace,
        Some(libc::EOPNOTSUPP) | Some(libc::EISDIR) | Some(libc::EINVAL) => SpoolError::Unsupported,
        _ => SpoolError::Io(e.kind()),
    }
}
impl From<io::Error> for SpoolError {
    fn from(e: io::Error) -> Self {
        classify(&e)
    }
}

fn check_directory(dir: &Path) -> Result<(), SpoolError> {
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|_| SpoolError::BadDirectory("cannot be inspected"))?;
    if meta.file_type().is_symlink() {
        return Err(SpoolError::BadDirectory("is a symlink"));
    }
    if !meta.is_dir() {
        return Err(SpoolError::BadDirectory("is not a directory"));
    }
    // SAFETY: getuid has no preconditions.
    if meta.uid() != unsafe { libc::getuid() } {
        return Err(SpoolError::BadDirectory("is not owned by this user"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(SpoolError::BadDirectory(
            "is accessible by group or others (needs mode 0700)",
        ));
    }
    Ok(())
}

fn cstring(dir: &Path) -> Result<std::ffi::CString, SpoolError> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| SpoolError::BadDirectory("contains a NUL byte"))
}

// The statvfs/statfs field widths differ by Linux target; the casts are no-ops on x86-64 only.
#[allow(clippy::unnecessary_cast)]
fn available_bytes(dir: &Path) -> Result<u64, SpoolError> {
    let path = cstring(dir)?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a valid C string and `st` is a valid out-pointer.
    if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
        return Err(SpoolError::Io(io::Error::last_os_error().kind()));
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[allow(clippy::unnecessary_cast)]
fn memory_backed(dir: &Path) -> Result<bool, SpoolError> {
    let path = cstring(dir)?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a valid C string and `st` is a valid out-pointer.
    if unsafe { libc::statfs(path.as_ptr(), &mut st) } != 0 {
        return Err(SpoolError::Io(io::Error::last_os_error().kind()));
    }
    let kind = st.f_type as i64;
    Ok(kind == TMPFS_MAGIC || kind == RAMFS_MAGIC)
}

/// A spool being written. Hashes and counts every byte as it is written.
pub struct Spool {
    file: File,
    written: u64,
    hasher: Sha256,
}
impl Spool {
    /// Create an anonymous spool in `dir` for a message of `needed` bytes.
    /// All checks happen before anything is written: directory, filesystem kind, free space.
    pub fn create(dir: &Path, needed: u64, allow_memory_backed: bool) -> Result<Spool, SpoolError> {
        check_directory(dir)?;
        if !allow_memory_backed && memory_backed(dir)? {
            return Err(SpoolError::MemoryBacked);
        }
        if available_bytes(dir)? < needed.saturating_add(SPACE_MARGIN) {
            return Err(SpoolError::NoSpace);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            // O_EXCL on an O_TMPFILE means it can never be linked into the filesystem.
            .custom_flags(libc::O_TMPFILE | libc::O_EXCL)
            .mode(0o600)
            .open(dir)
            .map_err(|e| classify(&e))?;
        Ok(Spool {
            file,
            written: 0,
            hasher: Sha256::new(),
        })
    }

    /// Append bytes, hashing them first. A failure leaves the spool unusable.
    pub fn write_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.write_all(data)?;
        self.hasher.update(data);
        self.written += data.len() as u64;
        Ok(())
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Finish writing and verify by re-reading the file against the hash taken on the way in.
    /// Only a verified spool can be sealed; nothing from it may be sent before this succeeds.
    pub fn seal(self) -> Result<SealedSpool, SpoolError> {
        let Spool {
            mut file,
            written,
            hasher,
        } = self;
        let sha256 = format!("{:x}", hasher.finalize());
        file.seek(SeekFrom::Start(0))?;
        let mut check = Sha256::new();
        let mut buf = vec![0u8; COPY_BUFFER];
        let mut left = written;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let n = file.read(&mut buf[..want])?;
            if n == 0 {
                return Err(SpoolError::Corrupt); // shorter than what was written
            }
            check.update(&buf[..n]);
            left -= n as u64;
        }
        if format!("{:x}", check.finalize()) != sha256 {
            return Err(SpoolError::Corrupt);
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(SealedSpool {
            file,
            sha256,
            size: written,
        })
    }
}

/// A completed, verified spool. Dropping it closes the descriptor, which frees the storage.
pub struct SealedSpool {
    file: File,
    /// Lowercase hex SHA-256 of the content, identical to `journal::fingerprint` of the bytes.
    pub sha256: String,
    pub size: u64,
}
impl SealedSpool {
    /// A reader over the whole content from the start. `chunk_point` is the crash-test hook
    /// fired for every read. If the content differs from the sealed hash, the final chunk is
    /// withheld, so a changed byte can never complete a literal.
    pub fn reader(&mut self, chunk_point: &'static str) -> io::Result<SpoolReader<'_>> {
        self.file.seek(SeekFrom::Start(0))?;
        Ok(SpoolReader {
            file: &mut self.file,
            remaining: self.size,
            hasher: Sha256::new(),
            expected: &self.sha256,
            chunk_point,
        })
    }

    #[cfg(test)]
    pub(crate) fn file_for_test(&mut self) -> &mut File {
        &mut self.file
    }
}

pub struct SpoolReader<'a> {
    file: &'a mut File,
    remaining: u64,
    hasher: Sha256,
    expected: &'a str,
    chunk_point: &'static str,
}
impl Read for SpoolReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        // Crash-test hook (absent in default builds): die part-way through the literal.
        crate::fault::point(self.chunk_point);
        let want = self.remaining.min(buf.len() as u64) as usize;
        let n = loop {
            match self.file.read(&mut buf[..want]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other?,
            }
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "spool ended early",
            ));
        }
        self.hasher.update(&buf[..n]);
        self.remaining -= n as u64;
        if self.remaining == 0 {
            let actual = format!("{:x}", self.hasher.clone().finalize());
            if actual != self.expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "spool content changed",
                ));
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    fn data(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8)
            .collect()
    }
    /// Does any open descriptor of this process still refer to that file? Per-file, so it is
    /// not disturbed by other tests running in parallel threads.
    fn fd_refers_to(dev: u64, ino: u64) -> bool {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| std::fs::metadata(e.path()).is_ok_and(|m| m.dev() == dev && m.ino() == ino))
    }

    #[test]
    fn spool_is_anonymous_private_and_unlinkable() {
        let dir = private_dir();
        let mut spool = Spool::create(dir.path(), 1000, true).unwrap();
        spool.write_chunk(b"secret mail").unwrap();
        // No directory entry exists while the file is open and in use.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let meta = spool.file.metadata().unwrap();
        let (dev, ino) = (meta.dev(), meta.ino());
        assert!(fd_refers_to(dev, ino));
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.nlink(), 0, "an O_TMPFILE has no link");
        // O_EXCL: it can never be given a name, so it cannot be left behind.
        let target = dir.path().join("named");
        let linked = unsafe {
            let src = std::ffi::CString::new(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&spool.file)
            ))
            .unwrap();
            let dst = std::ffi::CString::new(target.to_str().unwrap()).unwrap();
            libc::linkat(
                libc::AT_FDCWD,
                src.as_ptr(),
                libc::AT_FDCWD,
                dst.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        assert_ne!(
            linked, 0,
            "O_EXCL must forbid linking the spool into the filesystem"
        );
        assert!(!target.exists());
        drop(spool);
        assert!(
            !fd_refers_to(dev, ino),
            "closing the spool releases the file"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn seal_hashes_what_was_written_and_reader_returns_exactly_it() {
        let dir = private_dir();
        for len in [
            0usize,
            1,
            4095,
            COPY_BUFFER - 1,
            COPY_BUFFER,
            COPY_BUFFER + 1,
            700_000,
        ] {
            let bytes = data(len);
            let mut spool = Spool::create(dir.path(), len as u64, true).unwrap();
            for chunk in bytes.chunks(10_007) {
                spool.write_chunk(chunk).unwrap();
            }
            assert_eq!(spool.written(), len as u64);
            let mut sealed = spool.seal().unwrap();
            assert_eq!(
                sealed.sha256,
                crate::journal::fingerprint(&bytes),
                "len {len}"
            );
            assert_eq!(sealed.size, len as u64);
            let mut out = Vec::new();
            let mut reader = sealed.reader("").unwrap();
            let mut buf = vec![0u8; 5000];
            loop {
                let n = reader.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            assert_eq!(out, bytes, "len {len}");
        }
    }

    #[test]
    fn a_changed_byte_is_caught_and_the_final_chunk_is_withheld() {
        let dir = private_dir();
        let bytes = data(300_000);
        let mut spool = Spool::create(dir.path(), 300_000, true).unwrap();
        spool.write_chunk(&bytes).unwrap();
        let mut sealed = spool.seal().unwrap();
        // Corrupt the very last byte on disk after sealing.
        {
            let f = sealed.file_for_test();
            f.seek(SeekFrom::Start(299_999)).unwrap();
            f.write_all(&[bytes[299_999] ^ 1]).unwrap();
        }
        let mut reader = sealed.reader("").unwrap();
        let mut got = 0usize;
        let mut buf = vec![0u8; 128 * 1024];
        let error = loop {
            match reader.read(&mut buf) {
                Ok(0) => panic!("a corrupted spool must not read to a clean end"),
                Ok(n) => got += n,
                Err(e) => break e,
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            got < 300_000,
            "the chunk containing the changed byte must not be returned ({got})"
        );
    }

    #[test]
    fn seal_detects_corruption_before_anything_can_be_sent() {
        let dir = private_dir();
        let mut spool = Spool::create(dir.path(), 10, true).unwrap();
        spool.write_chunk(b"0123456789").unwrap();
        // Simulate storage returning different bytes between write and the verification read.
        spool.file.seek(SeekFrom::Start(3)).unwrap();
        spool.file.write_all(b"X").unwrap();
        assert!(matches!(spool.seal(), Err(SpoolError::Corrupt)));
        // A file that lost its tail is also corrupt.
        let mut spool = Spool::create(dir.path(), 10, true).unwrap();
        spool.write_chunk(b"0123456789").unwrap();
        spool.file.set_len(4).unwrap();
        assert!(matches!(spool.seal(), Err(SpoolError::Corrupt)));
    }

    #[test]
    fn directory_must_be_a_private_owned_real_directory() {
        let base = private_dir();
        let missing = base.path().join("missing");
        assert!(matches!(
            Spool::create(&missing, 1, true),
            Err(SpoolError::BadDirectory(_))
        ));
        let file = base.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            Spool::create(&file, 1, true),
            Err(SpoolError::BadDirectory("is not a directory"))
        ));
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            Spool::create(&link, 1, true),
            Err(SpoolError::BadDirectory("is a symlink"))
        ));
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            Spool::create(&real, 1, true),
            Err(SpoolError::BadDirectory(_))
        ));
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Spool::create(&real, 1, true).is_ok());
    }

    #[test]
    fn free_space_is_checked_before_any_write() {
        let dir = private_dir();
        assert!(matches!(
            Spool::create(dir.path(), u64::MAX / 2, true),
            Err(SpoolError::NoSpace)
        ));
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "a refused spool leaves nothing"
        );
    }

    #[test]
    fn memory_backed_directories_are_refused_unless_explicitly_allowed() {
        let shm = Path::new("/dev/shm");
        if !shm.is_dir() || !memory_backed(shm).unwrap_or(false) {
            return; // nothing memory-backed to test with on this host
        }
        let dir = tempfile::tempdir_in(shm).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            Spool::create(dir.path(), 10, false),
            Err(SpoolError::MemoryBacked)
        ));
        assert!(
            Spool::create(dir.path(), 10, true).is_ok(),
            "explicit opt-in must work"
        );
    }

    #[test]
    fn io_errors_map_to_typed_failures_with_no_embedded_text() {
        for (errno, want) in [
            (libc::ENOSPC, "NoSpace"),
            (libc::EDQUOT, "NoSpace"),
            (libc::EFBIG, "NoSpace"),
            (libc::EOPNOTSUPP, "Unsupported"),
            (libc::EISDIR, "Unsupported"),
            (libc::EIO, "Io"),
        ] {
            let e = classify(&io::Error::from_raw_os_error(errno));
            assert!(format!("{e:?}").starts_with(want), "{errno}: {e:?}");
            let text = e.to_string().replace("I/O", "").replace("tmpfs/ramfs", "");
            assert!(!text.contains('/'), "messages must not carry paths: {text}");
        }
    }
}
