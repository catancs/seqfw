use std::io::{self, Read};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Error message embedded in the io::Error when a bomb is detected.
/// Downstream code matches on this substring to raise the right finding.
pub const BOMB_ERR: &str = "decompression-bomb-guard";

/// Counts bytes pulled from an underlying (compressed) reader into a shared counter.
pub struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: Read> CountingReader<R> {
    pub fn new(inner: R, count: Arc<AtomicU64>) -> Self {
        CountingReader { inner, count }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Wraps a *decompressed* stream and enforces two caps as bytes flow through:
/// an absolute uncompressed-size cap, and a max expansion ratio relative to the
/// compressed bytes consumed so far. Tripping either yields an io::Error whose
/// message contains `BOMB_ERR`.
pub struct BombGuard<R> {
    inner: R,
    compressed: Arc<AtomicU64>,
    decompressed: u64,
    max_bytes: u64,
    max_ratio: u64,
}

impl<R: Read> BombGuard<R> {
    pub fn new(inner: R, compressed: Arc<AtomicU64>, max_bytes: u64, max_ratio: u64) -> Self {
        BombGuard {
            inner,
            compressed,
            decompressed: 0,
            max_bytes,
            max_ratio,
        }
    }

    fn tripped(&self) -> bool {
        if self.decompressed > self.max_bytes {
            return true;
        }
        // Only apply the ratio test once we've emitted enough that a ratio is
        // meaningful (avoids false positives on tiny inputs).
        let compressed = self.compressed.load(Ordering::Relaxed);
        compressed > 0
            && self.decompressed > 1_000_000
            && self.decompressed / compressed > self.max_ratio
    }
}

impl<R: Read> Read for BombGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.decompressed += n as u64;
        if self.tripped() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, BOMB_ERR));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::{atomic::AtomicU64, Arc};

    /// A reader that yields zeros forever — an idealized decompression bomb.
    struct Zeros;
    impl Read for Zeros {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            for b in buf.iter_mut() {
                *b = 0;
            }
            Ok(buf.len())
        }
    }

    fn read_to_end<R: Read>(r: &mut R, scratch: &mut [u8]) -> std::io::Result<()> {
        loop {
            let n = r.read(scratch)?;
            if n == 0 {
                return Ok(());
            }
        }
    }

    #[test]
    fn bomb_guard_trips_on_absolute_cap() {
        let counter = Arc::new(AtomicU64::new(1)); // pretend 1 compressed byte
                                                   // Absolute cap 1 KiB, ratio cap huge so the absolute cap is what trips.
        let mut guard = BombGuard::new(Zeros, counter, 1024, u64::MAX);
        let mut sink = vec![0u8; 4096];
        let err = read_to_end(&mut guard, &mut sink).unwrap_err();
        assert!(err.to_string().contains(BOMB_ERR), "got: {err}");
    }

    #[test]
    fn bomb_guard_trips_on_ratio_cap() {
        // Absolute cap effectively disabled (u64::MAX); compressed pinned at 1
        // byte so the expansion ratio explodes. Trips once >1 MiB has been
        // emitted (the ratio-test threshold), exercising the ratio path
        // independently of the absolute cap.
        let counter = Arc::new(AtomicU64::new(1));
        let mut guard = BombGuard::new(Zeros, counter, u64::MAX, 10);
        let mut sink = vec![0u8; 8192];
        let err = read_to_end(&mut guard, &mut sink).unwrap_err();
        assert!(err.to_string().contains(BOMB_ERR), "got: {err}");
    }
}
