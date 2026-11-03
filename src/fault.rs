//! Crash injection is absent from default builds; counts only the selected point.
#[inline]
pub(crate) fn point(name: &str) {
    #[cfg(feature = "fault-injection")]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static HITS: AtomicU64 = AtomicU64::new(0);
        if std::env::var("IMAPLANE_FAULT_POINT").as_deref() == Ok(name) {
            let nth = std::env::var("IMAPLANE_FAULT_NTH")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(1);
            if HITS.fetch_add(1, Ordering::SeqCst) + 1 == nth {
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
                unreachable!("SIGKILL returned");
            }
        }
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = name;
}
