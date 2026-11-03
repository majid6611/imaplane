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
        println!(
            "Confirmed: {confirmed}; unresolved: {}; interrupted: {}",
            report.entries.len() - confirmed,
            report.interrupted
        );
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
            json,
        } => {
            let c = Config::load(&config)?;
            if dry_run {
                println!("{}", serde_json::to_string_pretty(&engine::dry_run(&c)?)?);
                return Ok(ExitCode::SUCCESS);
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
        Command::Status { state, json } => {
            let summary = Journal::open_read_only(&state)?.summary()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "Scope: {}\nPlanned: {}\nUncertain: {}\nAccepted: {}\nContent confirmed: {}",
                    summary.scope,
                    summary.planned,
                    summary.uncertain,
                    summary.accepted,
                    summary.confirmed
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
