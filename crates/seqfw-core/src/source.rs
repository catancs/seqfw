use std::io::{Cursor, Read};
use std::sync::{atomic::AtomicU64, Arc};

use flate2::read::MultiGzDecoder;

use crate::bomb::{BombGuard, CountingReader};
use crate::Options;

/// Wrap a raw reader so the returned reader yields *decompressed* bytes (if the
/// input is gzip/bgzf) and is protected by the decompression-bomb guard.
///
/// bgzf is a series of concatenated gzip members, which `MultiGzDecoder` handles.
pub fn open_guarded(mut reader: Box<dyn Read>, opts: &Options) -> Box<dyn Read> {
    // Peek the first two bytes to detect the gzip magic number (0x1f 0x8b),
    // then put them back by chaining a cursor in front of the rest of the stream.
    let mut magic = [0u8; 2];
    let n = read_fill(&mut reader, &mut magic);
    let combined = Cursor::new(magic[..n].to_vec()).chain(reader);

    if n == 2 && magic == [0x1f, 0x8b] {
        let compressed = Arc::new(AtomicU64::new(0));
        let counting = CountingReader::new(combined, compressed.clone());
        let decoded = MultiGzDecoder::new(counting);
        Box::new(BombGuard::new(
            decoded,
            compressed,
            opts.max_decompress_bytes,
            opts.max_decompress_ratio,
        ))
    } else {
        Box::new(combined)
    }
}

/// Best-effort fill of `buf`; returns how many bytes were read (0..=buf.len()).
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

#[cfg(test)]
mod tests {
    use crate::{check_reader, Options};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Cursor, Write};

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::best());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzipped_valid_fastq_passes() {
        let gz = gzip(b"@r1\nACGT\n+\nIIII\n");
        let r = check_reader(Box::new(Cursor::new(gz)), &Options::default());
        assert!(r.ok(), "gzipped valid FASTQ should pass: {:?}", r.findings);
    }

    #[test]
    fn gzip_bomb_is_rejected() {
        // ~8 MiB of zeros compresses to a few KiB; a tiny absolute cap trips it.
        let gz = gzip(&vec![b'A'; 8 * 1024 * 1024]);
        let opts = Options { max_decompress_bytes: 64 * 1024, ..Options::default() };
        let r = check_reader(Box::new(Cursor::new(gz)), &opts);
        assert!(!r.ok());
        assert!(
            r.findings.iter().any(|f| f.rule == "transport.decompression_bomb"),
            "expected a bomb finding, got {:?}",
            r.findings
        );
    }
}
