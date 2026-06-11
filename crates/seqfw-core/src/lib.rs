//! seqfw-core: streaming validation of genomic files at the trust boundary.

/// Library version, surfaced by the CLI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod finding;
pub use finding::{Finding, Location, Report, Severity};

// Internal: resource-exhaustion defense. Consumed within this crate by
// `source.rs` and the format checks via `crate::bomb::…`; intentionally not
// part of the public API.
mod bomb;

mod checks;
mod detect;
mod source;

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Which nucleotide alphabet the FASTQ sequence check enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqAlphabet {
    /// Strict DNA: A, C, G, T, N (either case).
    Dna,
    /// Full IUPAC nucleotide codes: A,C,G,T,U plus ambiguity R,Y,S,W,K,M,B,D,H,V,N
    /// (either case). The generous default.
    Iupac,
}

impl SeqAlphabet {
    /// True if `b` (a non-control byte) is a member of this alphabet.
    pub(crate) fn accepts(self, b: u8) -> bool {
        let u = b.to_ascii_uppercase();
        match self {
            SeqAlphabet::Dna => matches!(u, b'A' | b'C' | b'G' | b'T' | b'N'),
            SeqAlphabet::Iupac => matches!(
                u,
                b'A' | b'C'
                    | b'G'
                    | b'T'
                    | b'U'
                    | b'R'
                    | b'Y'
                    | b'S'
                    | b'W'
                    | b'K'
                    | b'M'
                    | b'B'
                    | b'D'
                    | b'H'
                    | b'V'
                    | b'N'
            ),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            SeqAlphabet::Dna => "strict DNA (ACGTN)",
            SeqAlphabet::Iupac => "IUPAC nucleotide",
        }
    }
}

/// A genomic file format `seqfw` can validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Fastq,
    Fasta,
}

/// Validation thresholds. Defaults are deliberately generous so real data
/// passes while pathological inputs are still bounded.
#[derive(Debug, Clone)]
pub struct Options {
    /// Absolute cap on decompressed bytes before declaring a bomb.
    pub max_decompress_bytes: u64,
    /// Max decompressed/compressed expansion ratio.
    pub max_decompress_ratio: u64,
    /// Max length of any single line, in bytes (including the line terminator).
    pub max_line_len: usize,
    /// Nucleotide alphabet enforced on FASTQ sequence lines.
    pub seq_alphabet: SeqAlphabet,
    /// Force a specific input format instead of auto-detecting. `None` = sniff.
    pub forced_format: Option<Format>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_decompress_bytes: 50 * 1024 * 1024 * 1024, // 50 GiB
            max_decompress_ratio: 200,
            max_line_len: 1024 * 1024, // 1 MiB
            seq_alphabet: SeqAlphabet::Iupac,
            forced_format: None,
        }
    }
}

/// Validate the file at `path`. Returns an io::Error only if the file cannot be
/// opened; all *content* problems are reported as `Finding`s in the `Report`.
pub fn check_path(path: &Path, opts: &Options) -> std::io::Result<Report> {
    let file = File::open(path)?;
    Ok(check_reader(Box::new(file), opts))
}

/// Validate an arbitrary byte stream (file, stdin, network, in-memory).
pub fn check_reader(reader: Box<dyn Read>, opts: &Options) -> Report {
    let mut report = Report::default();
    let guarded = source::open_guarded(reader, opts);
    let (decision, stream) = detect::sniff(guarded, opts.forced_format);
    match decision {
        detect::Decision::Known(Format::Fastq) => checks::fastq::check(stream, opts, &mut report),
        detect::Decision::Known(Format::Fasta) => checks::fasta::check(stream, opts, &mut report),
        detect::Decision::Empty => {} // nothing to validate; a clean pass
        detect::Decision::Unrecognized(b) => report.push(Finding::error(
            "format.unrecognized",
            format!(
                "could not recognize the file format (first content byte 0x{b:02x}); expected FASTQ ('@')"
            ),
            None,
        )),
    }
    report
}

/// Validate two byte streams as a FASTQ R1/R2 mate pair. Both streams are
/// transparently decompressed and bomb-guarded, exactly like `check_reader`.
pub fn check_pair_reader(r1: Box<dyn Read>, r2: Box<dyn Read>, opts: &Options) -> Report {
    let mut report = Report::default();
    let g1 = source::open_guarded(r1, opts);
    let g2 = source::open_guarded(r2, opts);
    checks::fastq::check_pair(g1, g2, opts, &mut report);
    report
}

#[cfg(test)]
mod smoke {
    #[test]
    fn version_is_set() {
        assert!(!crate::VERSION.is_empty());
    }
}

#[cfg(test)]
mod dispatch {
    use crate::{check_reader, Options};
    use std::io::Cursor;

    fn check(data: &[u8]) -> crate::Report {
        check_reader(Box::new(Cursor::new(data.to_vec())), &Options::default())
    }

    #[test]
    fn fastq_is_routed_and_passes() {
        assert!(check(b"@r1\nACGT\n+\nIIII\n").ok());
    }

    #[test]
    fn unrecognized_input_is_rejected() {
        let r = check(b"hello, not a genomic file\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "format.unrecognized"));
    }

    #[test]
    fn empty_input_is_clean() {
        assert!(check(b"").ok());
    }

    #[test]
    fn leading_blank_lines_are_skipped() {
        assert!(check(b"\n\n@r1\nACGT\n+\nIIII\n").ok());
    }
}
