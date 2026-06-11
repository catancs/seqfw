use std::io::{Cursor, Read};

use crate::Format;

/// How many leading (decompressed) bytes to peek when sniffing the format.
/// Large enough to skip a few blank lines, small enough to stay cheap.
const SNIFF_LEN: usize = 64;

/// The result of sniffing a stream's format.
pub(crate) enum Decision {
    /// A recognized format.
    Known(Format),
    /// No non-whitespace bytes in the peeked window — treat as clean/no-op.
    Empty,
    /// First content byte matched no known format.
    Unrecognized(u8),
}

/// Peek the leading bytes of a (already decompressed) stream to choose a format,
/// then return a reader that still yields the *entire* original stream (the
/// peeked bytes are chained back in front). If `forced` is set, no peeking
/// happens and the stream is returned untouched.
pub(crate) fn sniff(
    mut reader: Box<dyn Read>,
    forced: Option<Format>,
) -> (Decision, Box<dyn Read>) {
    if let Some(f) = forced {
        return (Decision::Known(f), reader);
    }

    let mut peek = [0u8; SNIFF_LEN];
    let n = read_fill(&mut reader, &mut peek);

    let decision = match peek[..n].iter().copied().find(|b| !b.is_ascii_whitespace()) {
        None => Decision::Empty,
        Some(b'@') => Decision::Known(Format::Fastq),
        Some(b'>') => Decision::Known(Format::Fasta),
        Some(other) => Decision::Unrecognized(other),
    };

    let restored: Box<dyn Read> = Box::new(Cursor::new(peek[..n].to_vec()).chain(reader));
    (decision, restored)
}

/// Best-effort fill of `buf`; returns how many bytes were read (0..=buf.len()).
/// Read errors (e.g. a bomb-guard trip) are swallowed here and re-surface on the
/// first real read by the chosen check, where they map to a transport finding.
fn read_fill(r: &mut dyn Read, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(k) => filled += k,
            Err(_) => break,
        }
    }
    filled
}
