use clap::{Parser, Subcommand};
use imaplane::{config::Config, engine, journal::Journal};
use std::{
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Parser)]
#[command(
    version,
    about = "Additive, resumable IMAP-to-IMAP migration with read-only source access"
)]
struct Cli {
    /// Opt in to sanitized protocol diagnostics (status, response-code names, timings,
    /// counts) appended to this private file. Never records credentials, tokens,
    /// usernames, folder names, message content or server text. Off by default.
    #[arg(long, global = true, value_name = "PATH")]
    diagnostics_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Discover selectable folders on both servers (no writes).
    Inspect {
        #[arg(long)]
        config: PathBuf,
    },
    /// Copy configured folders, or safely resume an existing job.
    Migrate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        dry_run: bool,
        /// Also discover and transfer messages that arrived after the job was planned. Upgrades
        /// the journal to schema 5 (after a verified backup) on the first real run.
        #[arg(long)]
        incremental: bool,
        /// With --incremental: how much of the already-confirmed history to re-check. `metadata`
        /// (default) and `existence` read no message bodies and never create or renew a content
        /// confirmation; `full` re-reads every body like `verify`.
        #[arg(long, value_enum, default_value = "metadata", requires = "incremental")]
        verify_history: engine::HistoryLevel,
        /// With --incremental: add configured folders the job does not record yet (their baseline is
        /// recorded atomically, then their messages are copied). Recorded folders can never be
        /// removed, renamed or remapped.
        #[arg(long, requires = "incremental")]
        add_new_folders: bool,
        #[arg(long)]
        json: bool,
    },
    /// Re-read destination messages against journal evidence; source is not contacted.
    Verify {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Attribute an uncertain transfer to a verified destination UID; audited, no upload.
    Resolve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        folder: String,
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        destination_uid: u32,
        #[arg(long)]
        json: bool,
    },
    /// Return an uncertain transfer to planned only with durable proof no literal was authorized.
    Recover {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        folder: String,
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        json: bool,
    },
    /// Record an audited operator decision NOT to migrate a permanently rejected message.
    Skip {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        folder: String,
        #[arg(long)]
        uid: u32,
        /// Why this message cannot be migrated (recorded in the journal and reports).
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// Reverse an operator skip so migrate attempts the message again.
    Unskip {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        folder: String,
        #[arg(long)]
        uid: u32,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    /// Inspect historical journal evidence. Does not connect to an IMAP server.
    Status {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        json: bool,
    },
}
fn print_report(report: &engine::Report, json: bool) -> anyhow::Result<ExitCode> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("{}", report.scope);
        let confirmed = report
            .entries
            .iter()
            .filter(|e| e.result == "confirmed")
            .count();
        let drift = report
            .entries
            .iter()
            .filter(|e| e.result == "drift")
            .count();
        println!(
            "Confirmed: {confirmed}; flag drift: {drift}; unresolved: {}; interrupted: {}",
            report.entries.len() - confirmed - drift,
            report.interrupted
        );
        if let Some(h) = &report.history_check {
            println!(
                "History re-checked at the {} level only (content NOT re-read): {} checked, {} passed, {} drift, {} problems",
                h.level, h.checked, h.passed, h.drift, h.problems
            );
        }
        for e in &report.entries {
            if e.result != "confirmed" || !e.omitted_flags.is_empty() {
                println!(
                    "{:?} UID {}: {} — {:?}; omitted flags: {:?}; candidates: {:?}",
                    e.source_folder,
                    e.source_uid,
                    e.result,
                    e.detail,
                    e.omitted_flags,
                    e.candidate_uids
                );
            }
        }
        if let Some(reason) = &report.halt_reason {
            println!("Stopped: {reason}");
        }
        println!("Complete for recorded snapshot: {}", report.complete);
    }
    Ok(ExitCode::from(if report.complete { 0 } else { 2 }))
}
fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    if let Some(path) = &cli.diagnostics_file {
        imaplane::diagnostics::enable(path)?;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::Relaxed);
        imaplane::interrupt();
    })?;
    match cli.command {
        Command::Inspect { config } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&engine::inspect(&Config::load(&config)?)?)?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Migrate {
            config,
            dry_run,
            incremental,
            verify_history,
            add_new_folders,
            json,
        } => {
            let c = Config::load(&config)?;
            if dry_run {
                let plan = if incremental {
                    engine::dry_run_incremental(&c, verify_history, add_new_folders)?
                } else {
                    engine::dry_run(&c)?
                };
                println!("{}", serde_json::to_string_pretty(&plan)?);
                return Ok(ExitCode::SUCCESS);
            }
            if incremental {
                return print_report(
                    &engine::migrate_incremental(&c, stop, verify_history, add_new_folders)?,
                    json,
                );
            }
            print_report(&engine::migrate(&c, stop)?, json)
        }
        Command::Verify { config, json } => {
            print_report(&engine::verify(&Config::load(&config)?, stop)?, json)
        }
        Command::Resolve {
            config,
            folder,
            uid,
            destination_uid,
            json,
        } => print_report(
            &engine::resolve(&Config::load(&config)?, &folder, uid, destination_uid)?,
            json,
        ),
        Command::Recover {
            config,
            folder,
            uid,
            json,
        } => print_report(
            &engine::recover_not_sent(&Config::load(&config)?, &folder, uid)?,
            json,
        ),
        Command::Skip {
            config,
            folder,
            uid,
            reason,
            json,
        } => print_report(
            &engine::skip(&Config::load(&config)?, &folder, uid, &reason)?,
            json,
        ),
        Command::Unskip {
            config,
            folder,
            uid,
            reason,
            json,
        } => print_report(
            &engine::unskip(&Config::load(&config)?, &folder, uid, &reason)?,
            json,
        ),
        Command::Status { state, json } => {
            let summary = Journal::open_read_only(&state)?.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "Scope: {}\nPlanned: {}\nUncertain: {}\nAccepted: {}\nContent confirmed: {}\nSkipped by operator (not migrated): {}",
                    summary.scope,
                    summary.planned,
                    summary.uncertain,
                    summary.accepted,
                    summary.confirmed,
                    summary.skipped
                );
            }
            Ok(ExitCode::from(2))
        }
    }
}
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("imaplane: {:?}", format!("{error:#}"));
            if imaplane::interrupted() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
