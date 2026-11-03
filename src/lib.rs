//! Migration foundations. Network migration is not exposed until recovery is tested.
pub mod config;
pub mod diagnostics;
pub mod engine;
pub mod folders;
pub mod job;
pub mod journal;
pub mod spool;
pub mod transport;

static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn interrupt() {
    INTERRUPTED.store(true, std::sync::atomic::Ordering::Relaxed);
}
pub fn interrupted() -> bool {
    INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed)
}

mod fault;
