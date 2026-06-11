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
mod source;

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Validation thresholds. Defaults are deliberately generous so real data
/// passes while pathological inputs are still bounded.
#[derive(Debug, Clone)]
pub struct Options {
    /// Absolute cap on decompressed bytes before declaring a bomb.
    pub max_decompress_bytes: u64,
    /// Max decompressed/compressed expansion ratio.
    pub max_decompress_ratio: u64,
    /// Max length of any single line, in bytes.
    pub max_line_len: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_decompress_bytes: 50 * 1024 * 1024 * 1024, // 50 GiB
            max_decompress_ratio: 200,
            max_line_len: 1024 * 1024, // 1 MiB
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
    checks::fastq::check(guarded, opts, &mut report);
    report
}

#[cfg(test)]
mod smoke {
    #[test]
    fn version_is_set() {
        assert!(!crate::VERSION.is_empty());
    }
}
