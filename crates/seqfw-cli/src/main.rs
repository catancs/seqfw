use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use seqfw_core::{
    check_pair_reader, check_path, check_reader, Options, Report, SeqAlphabet, Severity,
};

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
        /// Validate as paired-end: PATH is R1, this file is R2.
        #[arg(long, value_name = "PATH")]
        mate: Option<String>,
        /// Enforce strict DNA (ACGTN) instead of the default IUPAC alphabet.
        #[arg(long)]
        strict_dna: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check {
            path,
            json,
            mate,
            strict_dna,
        } => run_check(&path, mate.as_deref(), json, strict_dna),
    }
}

fn run_check(path: &str, mate: Option<&str>, json: bool, strict_dna: bool) -> ExitCode {
    let opts = Options {
        seq_alphabet: if strict_dna {
            SeqAlphabet::Dna
        } else {
            SeqAlphabet::Iupac
        },
        ..Options::default()
    };

    let report = match mate {
        Some(mate_path) => {
            let r1 = match open_input(path) {
                Ok(r) => r,
                Err(code) => return code,
            };
            let r2: Box<dyn Read> = match File::open(mate_path) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    eprintln!("seqfw: cannot open {mate_path}: {e}");
                    return ExitCode::from(2);
                }
            };
            check_pair_reader(r1, r2, &opts)
        }
        None => {
            if path == "-" {
                check_reader(Box::new(io::stdin().lock()), &opts)
            } else {
                match check_path(Path::new(path), &opts) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("seqfw: cannot open {path}: {e}");
                        return ExitCode::from(2);
                    }
                }
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

/// Open a path (or stdin for "-") as a boxed reader, mapping open failures to
/// the tool-error exit code.
fn open_input(path: &str) -> Result<Box<dyn Read>, ExitCode> {
    if path == "-" {
        Ok(Box::new(io::stdin().lock()))
    } else {
        match File::open(path) {
            Ok(f) => Ok(Box::new(f)),
            Err(e) => {
                eprintln!("seqfw: cannot open {path}: {e}");
                Err(ExitCode::from(2))
            }
        }
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
