pub mod fasta;
pub mod fastq;
pub mod safety;

use crate::bomb::BOMB_ERR;
use crate::{Finding, Report};

/// Map a stream read error to a transport finding, shared by all format checks.
/// A bomb-guard trip surfaces here as a read error whose message contains
/// `BOMB_ERR`; everything else is treated as truncation/corruption.
pub(crate) fn push_read_error(report: &mut Report, msg: &str) {
    if msg.contains(BOMB_ERR) {
        report.push(Finding::error(
            "transport.decompression_bomb",
            "input expands too much when decompressed (possible decompression bomb)".to_string(),
            None,
        ));
    } else {
        report.push(Finding::error(
            "transport.read_error",
            format!("error reading input (file may be truncated or corrupt): {msg}"),
            None,
        ));
    }
}
