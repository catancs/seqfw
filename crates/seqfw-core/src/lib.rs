//! seqfw-core: streaming validation of genomic files at the trust boundary.

/// Library version, surfaced by the CLI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod finding;
pub use finding::{Finding, Location, Report, Severity};

mod bomb;

#[cfg(test)]
mod smoke {
    #[test]
    fn version_is_set() {
        assert!(!crate::VERSION.is_empty());
    }
}
