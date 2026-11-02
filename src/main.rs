//! rustmon - realtime resource and network monitor with suspicious-activity detection.
//! Runs on Windows and Linux. Interactive TUI by default; `--once` prints a report.

mod app;
mod collector;
mod detect;
mod model;
mod platform;
mod ui;

use anyhow::{Context, Result};
use clap::Parser;
use detect::Thresholds;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "rustmon",
    version,
    about = "Realtime resource & network monitor with suspicious-activity detection (Windows/Linux)"
)]
struct Cli {
    /// Refresh interval in milliseconds (200..=60000)
    #[arg(short, long, default_value_t = 1000, value_name = "MS")]
    interval: u64,

    /// Append every new alert as a JSON line to this file
    #[arg(long, value_name = "FILE")]
    log: Option<PathBuf>,

    /// Sustained upload threshold per interface, in MiB/s, that raises an upload-spike alert
    #[arg(long, default_value_t = 5.0, value_name = "MIB_PER_S")]
    upload_threshold: f64,

    /// Print a one-shot text report (3 samples, ~3s) and exit; no TUI.
    /// Exit code 2 if a High/Critical alert is active.
    #[arg(long)]
    once: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let log: Option<File> = match &cli.log {
        Some(path) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("cannot open log file {}", path.display()))?,
        ),
        None => None,
    };

    let th = Thresholds {
        upload_bps: cli.upload_threshold.max(0.0) * 1024.0 * 1024.0,
        ..Thresholds::default()
    };

    if cli.once {
        let code = app::run_once(th, log)?;
        std::process::exit(code);
    }

    let interval = Duration::from_millis(cli.interval.clamp(200, 60_000));
    let mut app = app::App::new(th, interval, log);
    app::run_tui(&mut app)
}
