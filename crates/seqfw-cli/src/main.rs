use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use seqfw_core::{
    check_index_reader, check_pair_reader, check_path, check_reader, Format, IndexKind, Options,
    Report, SeqAlphabet, Severity,
};

#[derive(Clone, Copy, clap::ValueEnum)]
enum FormatArg {
    Fastq,
    Fasta,
    Vcf,
}

impl From<FormatArg> for Format {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Fastq => Format::Fastq,
            FormatArg::Fasta => Format::Fasta,
            FormatArg::Vcf => Format::Vcf,
        }
    }
}

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
        /// Force the input format instead of auto-detecting it.
        #[arg(long, value_enum)]
        format: Option<FormatArg>,
        /// For an index file (.fai/.gzi/.tbi/.csi), the data file it indexes,
        /// enabling offset-in-bounds checks.
        #[arg(long, value_name = "PATH")]
        data: Option<String>,
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
            format,
            data,
        } => run_check(
            &path,
            mate.as_deref(),
            json,
            strict_dna,
            format.map(Into::into),
            data.as_deref(),
        ),
    }
}

fn run_check(
    path: &str,
    mate: Option<&str>,
    json: bool,
    strict_dna: bool,
    format: Option<Format>,
    data: Option<&str>,
) -> ExitCode {
    let opts = Options {
        seq_alphabet: if strict_dna {
            SeqAlphabet::Dna
        } else {
            SeqAlphabet::Iupac
        },
        forced_format: format,
        ..Options::default()
    };

    if let Some(kind) = index_kind_from_path(path) {
        let data_len = match data {
            Some(d) => match std::fs::metadata(d) {
                Ok(m) => Some(m.len()),
                Err(e) => {
                    eprintln!("seqfw: cannot stat {d}: {e}");
                    return ExitCode::from(2);
                }
            },
            None => None,
        };
        let reader = match open_input(path) {
            Ok(r) => r,
            Err(code) => return code,
        };
        let report = check_index_reader(kind, reader, data_len, &opts);
        return finish(&report, path, json);
    }

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

    finish(&report, path, json)
}

/// Render a report and map it to the process exit code.
fn finish(report: &Report, path: &str, json: bool) -> ExitCode {
    if json {
        render_json(report);
    } else {
        render_human(report, path);
    }
    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Map a path's extension to an index kind, if it names a known index file.
fn index_kind_from_path(path: &str) -> Option<IndexKind> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".fai") {
        Some(IndexKind::Fai)
    } else if lower.ends_with(".gzi") {
        Some(IndexKind::Gzi)
    } else if lower.ends_with(".tbi") {
        Some(IndexKind::Tbi)
    } else if lower.ends_with(".csi") {
        Some(IndexKind::Csi)
    } else {
        None
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
