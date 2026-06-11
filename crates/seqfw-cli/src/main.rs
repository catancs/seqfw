use std::io;
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use seqfw_core::{check_path, check_reader, Options, Report, Severity};

#[derive(Parser)]
#[command(name = "seqfw", version, about = "A firewall for genomic data")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a genomic file. Exit 0 = clean, 1 = rejected, 2 = tool error.
    Check {
        /// Path to the file, or '-' to read stdin.
        path: String,
        /// Emit findings as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check { path, json } => run_check(&path, json),
    }
}

fn run_check(path: &str, json: bool) -> ExitCode {
    let opts = Options::default();

    let report = if path == "-" {
        check_reader(Box::new(io::stdin().lock()), &opts)
    } else {
        match check_path(Path::new(path), &opts) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("seqfw: cannot open {path}: {e}");
                return ExitCode::from(2);
            }
        }
    };

    if json {
        render_json(&report);
    } else {
        render_human(&report, path);
    }

    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn render_human(report: &Report, path: &str) {
    if report.ok() && report.findings.is_empty() {
        println!("OK   {path}");
        return;
    }
    let verdict = if report.ok() { "OK*" } else { "REJECT" };
    println!("{verdict} {path}");
    for f in &report.findings {
        let sev = match f.severity {
            Severity::Error => "error",
            Severity::Warn => "warn",
        };
        let loc = match &f.location {
            Some(l) => match l.record {
                Some(r) => format!(" [record {r}]"),
                None => String::new(),
            },
            None => String::new(),
        };
        println!("  {sev:<5} {}{loc}: {}", f.rule, f.message);
    }
}

fn render_json(report: &Report) {
    let out = serde_json::json!({
        "ok": report.ok(),
        "findings": report.findings,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
