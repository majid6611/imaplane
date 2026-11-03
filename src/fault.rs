//! Test-only abrupt process death. Default/release builds contain no env hook.
#[inline]
pub(crate) fn point(name: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("IMAPLANE_FAULT_POINT").as_deref() == Ok(name) {
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        unreachable!("SIGKILL returned");
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = name;
}
