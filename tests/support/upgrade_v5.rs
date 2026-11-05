//! Test-only helper (never packaged): explicitly upgrade a journal file to schema 5.
//! Phase I0 has no user-facing command for this; the incremental run will perform it in I1.
//! Usage: cargo run --example upgrade_v5 -- JOURNAL_PATH
fn main() -> anyhow::Result<()> {
    let path = std::path::PathBuf::from(std::env::args().nth(1).expect("journal path"));
    let mut journal = imaplane::journal::Journal::open(&path)?;
    println!(
        "{}",
        if journal.upgrade_to_v5(&path)? {
            "upgraded"
        } else {
            "already schema 5"
        }
    );
    Ok(())
}
