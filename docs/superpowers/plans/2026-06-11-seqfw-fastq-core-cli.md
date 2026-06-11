# seqfw Plan 1 — FASTQ Core + CLI (walking skeleton) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `seqfw check <file.fastq[.gz]>` — a Rust CLI that rejects malformed FASTQ structure and gzip decompression bombs at the trust boundary, with correct exit codes and `--json` output.

**Architecture:** A Rust workspace with two crates. `seqfw-core` is a streaming, I/O-policy-free validation library: a `Source` that transparently decompresses gzip/bgzf through a byte-counting decompression-bomb guard, feeding independent `Check`s that emit `Finding`s into a `Report`. `seqfw-cli` is a thin `clap` adapter that wires stdin/file into the core and renders human or JSON output with exit codes (`0` clean / `1` rejected / `2` tool error). This plan delivers the skeleton + two real check classes; later plans extend it with more checks and formats without engine surgery.

**Tech Stack:** Rust (edition 2021), `flate2` (gzip/multi-member bgzf decode), `serde`/`serde_json` (JSON output), `clap` (CLI), `assert_cmd`/`predicates` (CLI tests).

**Scope:** This is **Plan 1 of a sequence**. Subsequent plans: Plan 2 (remaining FASTQ checks: seq/qual length, Phred range, control-char/IUPAC, paired-end sync); Plan 3 (FASTA + VCF + index-bounds); Plan 4 (Python bindings via PyO3/maturin); Plan 5 (reproducible ASAN benchmark harness); Plan 6 (packaging: cargo-dist, PyPI, Bioconda). See `docs/superpowers/specs/2026-06-11-seqfw-genomic-firewall-design.md`.

---

## File Structure

```
seqfw/
  Cargo.toml                         # [workspace] manifest
  crates/
    seqfw-core/
      Cargo.toml
      src/
        lib.rs                       # public API: Options, check_path, check_reader; module wiring
        finding.rs                   # Severity, Location, Finding, Report
        bomb.rs                      # CountingReader, BombGuard (decompression-bomb defense)
        source.rs                    # open_guarded(): gzip sniff + decode + bomb guard
        checks/
          mod.rs                     # checks module root
          fastq.rs                   # FASTQ structural checks (record framing)
    seqfw-cli/
      Cargo.toml
      src/
        main.rs                      # clap CLI; renders human/JSON; exit codes
      tests/
        cli.rs                       # assert_cmd end-to-end CLI tests
  corpus/
    fastq/
      pass/good.fastq                # valid 2-record FASTQ
      fail/bad_separator.fastq       # record with a wrong line-3 separator
```

Responsibilities: `finding.rs` owns the result vocabulary (no logic). `bomb.rs` owns resource-exhaustion defense (no format knowledge). `source.rs` owns "turn raw bytes into a safe-to-read decompressed stream." `checks/fastq.rs` owns FASTQ framing rules. `cli` owns argument parsing, rendering, and process exit semantics — nothing else.

---

## Task 1: Scaffold the Rust workspace (walking skeleton compiles)

**Files:**
- Create: `Cargo.toml`
- Create: `crates/seqfw-core/Cargo.toml`
- Create: `crates/seqfw-core/src/lib.rs`
- Create: `crates/seqfw-cli/Cargo.toml`
- Create: `crates/seqfw-cli/src/main.rs`

- [ ] **Step 1: Create the workspace manifest**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/seqfw-core", "crates/seqfw-cli"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/catancs/seqfw"
```

- [ ] **Step 2: Create the core crate manifest**

`crates/seqfw-core/Cargo.toml`:
```toml
[package]
name = "seqfw-core"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
flate2 = "1"
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 3: Create a minimal lib with a smoke test**

`crates/seqfw-core/src/lib.rs`:
```rust
//! seqfw-core: streaming validation of genomic files at the trust boundary.

/// Library version, surfaced by the CLI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod smoke {
    #[test]
    fn version_is_set() {
        assert!(!crate::VERSION.is_empty());
    }
}
```

- [ ] **Step 4: Create the CLI crate manifest**

`crates/seqfw-cli/Cargo.toml`:
```toml
[package]
name = "seqfw-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[[bin]]
name = "seqfw"
path = "src/main.rs"

[dependencies]
seqfw-core = { path = "../seqfw-core" }
clap = { version = "4", features = ["derive"] }
serde_json = "1"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
```

- [ ] **Step 5: Create a minimal CLI main**

`crates/seqfw-cli/src/main.rs`:
```rust
fn main() {
    println!("seqfw {}", seqfw_core::VERSION);
}
```

- [ ] **Step 6: Build and test the skeleton**

Run: `cargo test`
Expected: compiles; `version_is_set` passes (1 passed).

Run: `cargo run -p seqfw-cli`
Expected: prints `seqfw 0.1.0`.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml crates/
git commit -m "feat: scaffold seqfw Rust workspace (core + cli skeleton)"
```

---

## Task 2: Result types (Severity, Location, Finding, Report)

**Files:**
- Create: `crates/seqfw-core/src/finding.rs`
- Modify: `crates/seqfw-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/seqfw-core/src/finding.rs` (created in Step 3, but write the test first conceptually — create the file with this test):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_ok_only_when_no_errors() {
        let mut r = Report::default();
        assert!(r.ok(), "empty report is ok");
        r.push(Finding::warn("x.warn", "heads up".into(), None));
        assert!(r.ok(), "warnings do not fail the report");
        r.push(Finding::error("x.err", "nope".into(), Some(Location::at_record(3))));
        assert!(!r.ok(), "an error fails the report");
        assert_eq!(r.findings.len(), 2);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p seqfw-core finding`
Expected: FAIL to compile (`Report`, `Finding`, etc. not defined).

- [ ] **Step 3: Write the implementation**

At the **top** of `crates/seqfw-core/src/finding.rs`:
```rust
use serde::Serialize;

/// Whether a finding rejects the input (`Error`) or merely flags it (`Warn`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Warn,
    Error,
}

/// Where in the input a finding occurred. All fields optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct Location {
    /// 1-based record index, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<u64>,
    /// Byte offset into the (decompressed) stream, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
}

impl Location {
    pub fn at_record(record: u64) -> Self {
        Location { record: Some(record), byte_offset: None }
    }
}

/// A single validation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine-readable rule id, e.g. "fastq.bad_separator".
    pub rule: String,
    /// Human-readable explanation of what is wrong and why it matters.
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

impl Finding {
    pub fn error(rule: &str, message: String, location: Option<Location>) -> Self {
        Finding { severity: Severity::Error, rule: rule.to_string(), message, location }
    }
    pub fn warn(rule: &str, message: String, location: Option<Location>) -> Self {
        Finding { severity: Severity::Warn, rule: rule.to_string(), message, location }
    }
}

/// The aggregated outcome of validating one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    /// True unless at least one `Error`-severity finding is present.
    pub fn ok(&self) -> bool {
        !self.findings.iter().any(|f| f.severity == Severity::Error)
    }
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }
}
```

- [ ] **Step 4: Wire the module into lib.rs**

In `crates/seqfw-core/src/lib.rs`, add below the `VERSION` const:
```rust
mod finding;
pub use finding::{Finding, Location, Report, Severity};
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p seqfw-core finding`
Expected: PASS (`report_ok_only_when_no_errors`).

- [ ] **Step 6: Commit**

```bash
git add crates/seqfw-core/src/finding.rs crates/seqfw-core/src/lib.rs
git commit -m "feat(core): Finding/Report result vocabulary with severity policy"
```

---

## Task 3: Decompression-bomb guard

**Files:**
- Create: `crates/seqfw-core/src/bomb.rs`
- Modify: `crates/seqfw-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/seqfw-core/src/bomb.rs` with this test at the bottom:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::{atomic::AtomicU64, Arc};

    #[test]
    fn bomb_guard_trips_on_absolute_cap() {
        // A reader that yields zeros forever.
        struct Zeros;
        impl Read for Zeros {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                for b in buf.iter_mut() { *b = 0; }
                Ok(buf.len())
            }
        }
        let counter = Arc::new(AtomicU64::new(1)); // pretend 1 compressed byte
        // absolute cap 1 KiB, ratio cap huge so the absolute cap is what trips.
        let mut guard = BombGuard::new(Zeros, counter, 1024, u64::MAX);
        let mut sink = vec![0u8; 4096];
        let err = read_to_end(&mut guard, &mut sink).unwrap_err();
        assert!(err.to_string().contains(BOMB_ERR), "got: {err}");
    }

    fn read_to_end<R: Read>(r: &mut R, scratch: &mut [u8]) -> std::io::Result<()> {
        loop {
            let n = r.read(scratch)?;
            if n == 0 { return Ok(()); }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p seqfw-core bomb`
Expected: FAIL to compile (`BombGuard`, `BOMB_ERR` not defined).

- [ ] **Step 3: Write the implementation**

At the **top** of `crates/seqfw-core/src/bomb.rs`:
```rust
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
        BombGuard { inner, compressed, decompressed: 0, max_bytes, max_ratio }
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
```

- [ ] **Step 4: Wire the module into lib.rs**

In `crates/seqfw-core/src/lib.rs`, add:
```rust
mod bomb;
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p seqfw-core bomb`
Expected: PASS (`bomb_guard_trips_on_absolute_cap`).

- [ ] **Step 6: Commit**

```bash
git add crates/seqfw-core/src/bomb.rs crates/seqfw-core/src/lib.rs
git commit -m "feat(core): decompression-bomb guard (absolute + ratio caps)"
```

---

## Task 4: FASTQ structural check + public `check_reader` API

**Files:**
- Create: `crates/seqfw-core/src/checks/mod.rs`
- Create: `crates/seqfw-core/src/checks/fastq.rs`
- Modify: `crates/seqfw-core/src/lib.rs`

- [ ] **Step 1: Write the failing test (drives the public API)**

Create `crates/seqfw-core/src/checks/fastq.rs` with this test at the bottom:
```rust
#[cfg(test)]
mod tests {
    use crate::{check_reader, Options};
    use std::io::Cursor;

    fn check_bytes(data: &[u8]) -> crate::Report {
        check_reader(Box::new(Cursor::new(data.to_vec())), &Options::default())
    }

    #[test]
    fn valid_fastq_passes() {
        let r = check_bytes(b"@r1\nACGT\n+\nIIII\n@r2\nTT\n+\n!!\n");
        assert!(r.ok(), "valid FASTQ should pass, got {:?}", r.findings);
    }

    #[test]
    fn bad_separator_is_rejected() {
        // line 3 of record 1 must start with '+', here it's '-'
        let r = check_bytes(b"@r1\nACGT\n-\nIIII\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.bad_separator"));
    }

    #[test]
    fn truncated_record_is_rejected() {
        let r = check_bytes(b"@r1\nACGT\n+\n"); // missing the quality line
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.truncated_record"));
    }
}
```

- [ ] **Step 2: Write the FASTQ check implementation**

At the **top** of `crates/seqfw-core/src/checks/fastq.rs`:
```rust
use std::io::{BufRead, BufReader, Read};

use crate::bomb::BOMB_ERR;
use crate::{Finding, Location, Options, Report};

/// Validate FASTQ record framing on a (already decompressed) stream.
/// Records are 4 lines: `@header`, sequence, `+separator`, quality.
pub fn check(reader: impl Read, opts: &Options, report: &mut Report) {
    let mut buf = BufReader::new(reader);
    let mut record: u64 = 0;

    loop {
        let mut lines: Vec<Vec<u8>> = Vec::with_capacity(4);
        let mut clean_eof = false;

        for i in 0..4 {
            let mut line = Vec::new();
            match buf.read_until(b'\n', &mut line) {
                Ok(0) => {
                    clean_eof = i == 0; // EOF exactly at a record boundary is clean
                    break;
                }
                Ok(_) => {
                    if line.len() > opts.max_line_len {
                        report.push(Finding::error(
                            "fastq.line_too_long",
                            format!(
                                "line in record {} exceeds the {}-byte limit (possible resource-exhaustion input)",
                                record + 1,
                                opts.max_line_len
                            ),
                            Some(Location::at_record(record + 1)),
                        ));
                        return;
                    }
                    while matches!(line.last(), Some(b'\n') | Some(b'\r')) {
                        line.pop();
                    }
                    lines.push(line);
                }
                Err(e) => {
                    push_read_error(report, &e.to_string());
                    return;
                }
            }
        }

        if clean_eof {
            break;
        }
        record += 1;

        if lines.len() < 4 {
            report.push(Finding::error(
                "fastq.truncated_record",
                format!(
                    "record {} is incomplete: expected 4 lines, found {} (file may be truncated)",
                    record,
                    lines.len()
                ),
                Some(Location::at_record(record)),
            ));
            break;
        }

        if lines[0].first() != Some(&b'@') {
            report.push(Finding::error(
                "fastq.bad_header",
                format!("record {} header (line 1) must start with '@'", record),
                Some(Location::at_record(record)),
            ));
        }
        if lines[2].first() != Some(&b'+') {
            report.push(Finding::error(
                "fastq.bad_separator",
                format!("record {} separator (line 3) must start with '+'", record),
                Some(Location::at_record(record)),
            ));
        }
    }
}

fn push_read_error(report: &mut Report, msg: &str) {
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
```

- [ ] **Step 3: Create the checks module root**

`crates/seqfw-core/src/checks/mod.rs`:
```rust
pub mod fastq;
```

- [ ] **Step 4: Add `Options`, `check_reader`, `check_path` to lib.rs**

In `crates/seqfw-core/src/lib.rs`, add below the existing module declarations:
```rust
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
```

> NOTE: this references `source::open_guarded`, implemented in Task 5. The crate will not compile until Task 5 is done — that is expected; run this task's tests after Task 5.

- [ ] **Step 5: Commit (compile happens after Task 5)**

```bash
git add crates/seqfw-core/src/checks crates/seqfw-core/src/lib.rs
git commit -m "feat(core): FASTQ structural framing check + public check API"
```

---

## Task 5: Source — transparent gzip/bgzf decode behind the bomb guard

**Files:**
- Create: `crates/seqfw-core/src/source.rs`

- [ ] **Step 1: Write the implementation**

`crates/seqfw-core/src/source.rs`:
```rust
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
```

- [ ] **Step 2: Run the FASTQ + core tests (now everything compiles)**

Run: `cargo test -p seqfw-core`
Expected: PASS — `valid_fastq_passes`, `bad_separator_is_rejected`, `truncated_record_is_rejected`, plus the earlier finding/bomb/smoke tests.

- [ ] **Step 3: Add a gzip round-trip + bomb integration test**

Append to `crates/seqfw-core/src/source.rs`:
```rust
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
```

- [ ] **Step 4: Run the integration tests**

Run: `cargo test -p seqfw-core source`
Expected: PASS (`gzipped_valid_fastq_passes`, `gzip_bomb_is_rejected`).

- [ ] **Step 5: Commit**

```bash
git add crates/seqfw-core/src/source.rs
git commit -m "feat(core): transparent gzip/bgzf decode behind the bomb guard"
```

---

## Task 6: CLI `check` verb — human output + exit codes

**Files:**
- Modify: `crates/seqfw-cli/src/main.rs`
- Create: `corpus/fastq/pass/good.fastq`
- Create: `corpus/fastq/fail/bad_separator.fastq`
- Create: `crates/seqfw-cli/tests/cli.rs`

- [ ] **Step 1: Create corpus fixtures**

`corpus/fastq/pass/good.fastq`:
```
@read1
ACGTACGT
+
IIIIIIII
@read2
TTGGCCAA
+
########
```

`corpus/fastq/fail/bad_separator.fastq`:
```
@read1
ACGTACGT
-
IIIIIIII
```

- [ ] **Step 2: Write the failing CLI test**

`crates/seqfw-cli/tests/cli.rs`:
```rust
use assert_cmd::Command;
use predicates::prelude::*;

fn seqfw() -> Command {
    Command::cargo_bin("seqfw").unwrap()
}

#[test]
fn check_clean_file_exits_zero() {
    seqfw()
        .args(["check", "../../corpus/fastq/pass/good.fastq"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn check_bad_file_exits_one() {
    seqfw()
        .args(["check", "../../corpus/fastq/fail/bad_separator.fastq"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fastq.bad_separator"));
}

#[test]
fn check_missing_file_exits_two() {
    seqfw()
        .args(["check", "../../corpus/does-not-exist.fastq"])
        .assert()
        .code(2);
}
```

> Note: `assert_cmd` runs the binary with the crate dir as CWD, so the corpus path is relative to `crates/seqfw-cli/`. Hence `../../corpus/...`.

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p seqfw-cli`
Expected: FAIL (current `main` only prints the version; no `check` subcommand).

- [ ] **Step 4: Implement the CLI**

Replace `crates/seqfw-cli/src/main.rs` entirely:
```rust
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p seqfw-cli`
Expected: PASS (`check_clean_file_exits_zero`, `check_bad_file_exits_one`, `check_missing_file_exits_two`).

- [ ] **Step 6: Manual smoke check**

Run: `cargo run -p seqfw-cli -- check corpus/fastq/fail/bad_separator.fastq`
Expected: prints `REJECT ...` with a `fastq.bad_separator` line; shell `echo $?` is `1`.

- [ ] **Step 7: Commit**

```bash
git add crates/seqfw-cli/src/main.rs crates/seqfw-cli/tests/cli.rs corpus/
git commit -m "feat(cli): seqfw check verb with human output + exit codes"
```

---

## Task 7: CLI `--json` output (golden assertion)

**Files:**
- Modify: `crates/seqfw-cli/tests/cli.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/seqfw-cli/tests/cli.rs`:
```rust
#[test]
fn check_json_reports_findings() {
    seqfw()
        .args(["check", "--json", "../../corpus/fastq/fail/bad_separator.fastq"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"ok\": false"))
        .stdout(predicate::str::contains("\"rule\": \"fastq.bad_separator\""))
        .stdout(predicate::str::contains("\"severity\": \"error\""));
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test -p seqfw-cli check_json_reports_findings`
Expected: PASS (the JSON renderer from Task 6 already produces this shape).

> If it fails, the bug is in `render_json`/serde derives, not the test — fix the renderer to match the asserted keys.

- [ ] **Step 3: Commit**

```bash
git add crates/seqfw-cli/tests/cli.rs
git commit -m "test(cli): assert --json output shape"
```

---

## Task 8: Workspace lint gate + README stub + final green run

**Files:**
- Create: `README.md`
- Modify: (none — validation task)

- [ ] **Step 1: Create a minimal README stub**

`README.md`:
```markdown
# seqfw — a firewall for genomic data

`seqfw` validates genomic files at the trust boundary and **rejects malformed,
malicious, or resource-exhausting inputs before they reach memory-unsafe parsers**
(htslib / samtools / BioPython).

> Status: early development. v1 target: FASTQ / FASTA / VCF. This build validates
> FASTQ record framing and blocks gzip/bgzf decompression bombs.

## Install (from source, for now)

```bash
git clone https://github.com/catancs/seqfw && cd seqfw
cargo build --release
./target/release/seqfw check your.fastq.gz
```

## Use

```bash
seqfw check sample.fastq.gz        # exit 0 = clean, 1 = rejected, 2 = tool error
seqfw check - < sample.fastq       # read stdin
seqfw check sample.fastq --json    # machine-readable findings
```

See `docs/superpowers/specs/` for the design and `docs/superpowers/plans/` for the
build plan. Citations for every empirical claim live in the design spec's References.
```

- [ ] **Step 2: Run the whole test suite**

Run: `cargo test`
Expected: all tests pass across both crates (smoke, finding, bomb, fastq, source, cli — ~11 tests).

- [ ] **Step 3: Run clippy + fmt gates**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: no warnings (fix any that appear — they are real).

Run: `cargo fmt --all -- --check`
Expected: clean. If it reports diffs, run `cargo fmt --all` and re-check.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add README stub; lint/fmt clean across workspace"
```

- [ ] **Step 5: Push the branch**

```bash
git push origin main
```

---

## Self-Review (completed by plan author)

**Spec coverage (Plan 1 subset):** the spec's §6 "Transport" decompression-bomb guard → Tasks 3+5; §6 FASTQ "4-line record structure / `@`/`+` markers" and "per-line length caps" → Task 4; §6 "truncated-stream detection" → Task 4 (`transport.read_error` / `fastq.truncated_record`); §6 output/exit-code model (human + `--json`, exit 0/1/2) → Tasks 6+7; §7 architecture (3 bounded units, streaming, bomb meter) → file structure + Tasks 1–5; §5 stdin support → Task 6. **Deliberately deferred to later plans** (not gaps): seq/qual length equality, Phred range, control-char/IUPAC, paired-end sync (Plan 2); FASTA/VCF/index-bounds (Plan 3); Python bindings (Plan 4); ASAN benchmark (Plan 5); packaging/cargo-fuzz (Plans 5–6). These are listed in the Scope section so the omission is intentional and tracked.

**Placeholder scan:** no TBD/TODO; every code step contains complete, compilable code; the one forward-reference (Task 4 → `source::open_guarded`) is explicitly flagged with the resolving task.

**Type consistency:** `Report`/`Finding`/`Severity`/`Location` signatures are defined once in Task 2 and used unchanged in Tasks 3–7. `Options` fields (`max_decompress_bytes`, `max_decompress_ratio`, `max_line_len`) are defined in Task 4 and referenced consistently in Tasks 3/5. `check_reader(Box<dyn Read>, &Options) -> Report` and `check_path(&Path, &Options) -> io::Result<Report>` signatures match across core and CLI. Rule ids (`fastq.bad_separator`, `transport.decompression_bomb`, etc.) are asserted in tests exactly as emitted.
