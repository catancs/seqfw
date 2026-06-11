# seqfw Plan 3 — Format Dispatch + FASTA + Cross-Cutting Header Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `seqfw check` from a FASTQ-only validator into a multi-format gate. Add (1) a **format-detection + dispatch** layer that sniffs FASTQ vs FASTA (or takes `--format`) and rejects unrecognized inputs, (2) a full **FASTA** structural check set, and (3) a reusable **cross-cutting header-safety** check (control-byte / shell-metacharacter / path-traversal / URL-scheme) applied to FASTQ and FASTA identifiers.

**Architecture:** Builds on Plan 1 + Plan 2's `seqfw-core`. Today `check_reader` hardcodes `checks::fastq::check`; this plan inserts a `detect::sniff` step between the bomb-guarded `Source` and the per-format check, selecting the right `Check` (or emitting `format.unrecognized`). FASTA becomes a sibling of `checks::fastq` with the same `check(reader, opts, report)` shape. A new `checks::safety` module owns identifier hygiene and is called from both format checks — the spec's "Cross-cutting" helper. The transport read-error mapping (`push_read_error`) is promoted from `fastq.rs` to `checks/mod.rs` so every format shares one definition. No changes to `Source`, the bomb guard, or the `Finding`/`Report` vocabulary.

**Tech Stack:** Rust (edition 2021). No new dependencies — `clap`'s `derive`/`ValueEnum` (already enabled) covers the `--format` flag.

**Scope:** This is **Plan 3 of a sequence** (Plans 1 and 2 are shipped on `main`). It delivers the format-dispatch foundation, FASTA, and the cross-cutting identifier checks. **Deliberately deferred to Plan 4** (a deliberate split, not a gap): VCF structural + header/tag consistency + FORMAT-field safety, and index-bounds validation (`.fai`/`.gzi`/`.tbi`/`.csi` — the `CVE-2026-31970` class). FASTA sequence-alphabet/content enforcement is intentionally out of scope (FASTA may carry protein), so FASTA validates structure + header safety only. Later: Python bindings (Plan 5), ASAN benchmark (Plan 6), packaging (Plan 7). See `docs/superpowers/specs/2026-06-11-seqfw-genomic-firewall-design.md` §6–§7.

---

## File Structure

```
seqfw/
  crates/
    seqfw-core/
      src/
        lib.rs                       # + Format enum; Options gains forced_format; check_reader dispatches
        detect.rs                    # NEW — sniff(): peek leading bytes → Decision (Known/Empty/Unrecognized)
        source.rs                    # (test only) bomb-test payload gains a leading '@' so it routes to FASTQ
        checks/
          mod.rs                     # + pub mod fasta; pub mod safety; + shared push_read_error
          fastq.rs                   # drop local push_read_error; call header-safety on the read header
          fasta.rs                   # NEW — FASTA structural checks
          safety.rs                  # NEW — cross-cutting identifier hygiene
    seqfw-cli/
      src/
        main.rs                      # + --format flag (FormatArg → Format)
      tests/
        cli.rs                       # + FASTA + format + safety end-to-end tests
  corpus/
    fasta/
      pass/good.fasta                # NEW — valid 2-record FASTA
      fail/duplicate_name.fasta      # NEW
      fail/empty_sequence.fasta      # NEW
    misc/
      unrecognized.txt               # NEW — neither FASTQ nor FASTA
```

**Rule ids introduced by this plan** (stable, asserted in tests): `format.unrecognized`; `fasta.line_too_long`, `fasta.bad_header`, `fasta.empty_name`, `fasta.duplicate_name`, `fasta.empty_sequence`; `safety.control_char` (ERROR), `safety.shell_metachar` (WARN), `safety.path_traversal` (WARN), `safety.url_scheme` (WARN).

---

## Task 1: Format detection + dispatch skeleton (FASTQ routes through a sniffer)

**Files:**
- Create: `crates/seqfw-core/src/detect.rs`
- Modify: `crates/seqfw-core/src/lib.rs`
- Modify: `crates/seqfw-core/src/checks/mod.rs`
- Modify: `crates/seqfw-core/src/checks/fastq.rs`
- Modify: `crates/seqfw-core/src/source.rs` (test only)

- [ ] **Step 1: Promote `push_read_error` to a shared `checks` helper**

In `crates/seqfw-core/src/checks/mod.rs`, replace the contents with:
```rust
pub mod fastq;

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
```

In `crates/seqfw-core/src/checks/fastq.rs`: delete the local `push_read_error` function (the whole `fn push_read_error(...) { ... }` block near the bottom), delete the now-unused `use crate::bomb::BOMB_ERR;` import at the top, and change the one call site inside `Reader::next` from `push_read_error(report, &e.to_string())` to `super::push_read_error(report, &e.to_string())`.

- [ ] **Step 2: Create the detection module**

`crates/seqfw-core/src/detect.rs`:
```rust
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
pub(crate) fn sniff(mut reader: Box<dyn Read>, forced: Option<Format>) -> (Decision, Box<dyn Read>) {
    if let Some(f) = forced {
        return (Decision::Known(f), reader);
    }

    let mut peek = [0u8; SNIFF_LEN];
    let n = read_fill(&mut reader, &mut peek);

    let decision = match peek[..n].iter().copied().find(|b| !b.is_ascii_whitespace()) {
        None => Decision::Empty,
        Some(b'@') => Decision::Known(Format::Fastq),
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
```

- [ ] **Step 3: Add `Format`, `forced_format`, and dispatch to `lib.rs`**

In `crates/seqfw-core/src/lib.rs`:

Add the module declaration alongside the others (near `mod source;`):
```rust
mod detect;
```

Add the `Format` enum above `Options` (e.g. just below the `SeqAlphabet` impl):
```rust
/// A genomic file format `seqfw` can validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Fastq,
}
```

Add a field to `Options` (after `seq_alphabet`):
```rust
    /// Force a specific input format instead of auto-detecting. `None` = sniff.
    pub forced_format: Option<Format>,
```
and to its `Default` impl (after `seq_alphabet: SeqAlphabet::Iupac,`):
```rust
            forced_format: None,
```

Re-place `check_reader` with the dispatching version:
```rust
/// Validate an arbitrary byte stream (file, stdin, network, in-memory).
pub fn check_reader(reader: Box<dyn Read>, opts: &Options) -> Report {
    let mut report = Report::default();
    let guarded = source::open_guarded(reader, opts);
    let (decision, stream) = detect::sniff(guarded, opts.forced_format);
    match decision {
        detect::Decision::Known(Format::Fastq) => checks::fastq::check(stream, opts, &mut report),
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
```
> `Finding` is already re-exported in `lib.rs`; reference it as `Finding` (it is in scope via `pub use finding::...`). If the compiler disagrees about scope, use `finding::Finding` — but the existing `pub use finding::{Finding, ...}` makes the bare name available.

- [ ] **Step 4: Keep the bomb test routable — prepend `@` to its payload**

In `crates/seqfw-core/src/source.rs`, the `gzip_bomb_is_rejected` test currently gzips `&vec![b'A'; 8 * 1024 * 1024]`. With sniffing now in front of the checks, an all-`'A'` stream would be classified `format.unrecognized` and short-circuit *before* the bomb guard reads far enough to trip. Make the payload route through the FASTQ check by giving it a FASTQ-looking first byte:
```rust
    #[test]
    fn gzip_bomb_is_rejected() {
        // Leading '@' routes this through the FASTQ check, where the bomb guard
        // trips mid-read. ~8 MiB of 'A' compresses to a few KiB; a tiny absolute
        // cap trips it before the (single, newline-free) line is fully read.
        let mut payload = vec![b'@'];
        payload.extend(std::iter::repeat(b'A').take(8 * 1024 * 1024));
        let gz = gzip(&payload);
        let opts = Options {
            max_decompress_bytes: 64 * 1024,
            ..Options::default()
        };
        let r = check_reader(Box::new(Cursor::new(gz)), &opts);
        assert!(!r.ok());
        assert!(
            r.findings
                .iter()
                .any(|f| f.rule == "transport.decompression_bomb"),
            "expected a bomb finding, got {:?}",
            r.findings
        );
    }
```
> The 64 KiB absolute cap (`max_decompress_bytes`) is far below the default 1 MiB `max_line_len`, so the bomb guard returns an error from inside `read_until` before the over-long-line check can fire — the finding is `transport.decompression_bomb`, as asserted.

- [ ] **Step 5: Add dispatch tests to `lib.rs`**

In `crates/seqfw-core/src/lib.rs`, add below the existing `mod smoke`:
```rust
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
```

- [ ] **Step 6: Build, test, lint**

Run: `cargo test -p seqfw-core`
Expected: PASS — the four new dispatch tests, the adjusted bomb test, and every Plan 1/2 test (fastq, finding, source, smoke).

Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings`
Expected: clean (no unused `BOMB_ERR` import, etc.).

Run: `cargo fmt -p seqfw-core`

- [ ] **Step 7: Commit**

```bash
git add crates/seqfw-core/src/detect.rs crates/seqfw-core/src/lib.rs crates/seqfw-core/src/checks/mod.rs crates/seqfw-core/src/checks/fastq.rs crates/seqfw-core/src/source.rs
git commit -m "feat(core): format detection + dispatch layer (FASTQ via sniffer)"
```

---

## Task 2: FASTA structural checks

**Files:**
- Create: `crates/seqfw-core/src/checks/fasta.rs`
- Modify: `crates/seqfw-core/src/checks/mod.rs`
- Modify: `crates/seqfw-core/src/lib.rs`
- Modify: `crates/seqfw-core/src/detect.rs`

A FASTA record is a `>`-prefixed header naming a sequence, followed by one or more sequence lines, up to the next header or EOF. We validate framing (`>` present, no data before the first header), naming (non-empty, unique), non-empty sequence, and per-line length. We do **not** enforce a sequence alphabet (FASTA may be protein).

- [ ] **Step 1: Create the FASTA check**

`crates/seqfw-core/src/checks/fasta.rs`:
```rust
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read};

use crate::{Finding, Location, Options, Report};

/// Validate FASTA structure on a (already decompressed) stream.
pub fn check(reader: impl Read, opts: &Options, report: &mut Report) {
    let mut buf = BufReader::new(reader);
    let mut line = Vec::new();
    let mut record: u64 = 0;
    let mut seen_header = false;
    let mut seq_len: u64 = 0;
    let mut names: HashSet<Vec<u8>> = HashSet::new();
    let mut bad_header_reported = false;

    loop {
        line.clear();
        match buf.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.len() > opts.max_line_len {
                    report.push(Finding::error(
                        "fasta.line_too_long",
                        format!(
                            "a line exceeds the {}-byte limit (possible resource-exhaustion input)",
                            opts.max_line_len
                        ),
                        Some(Location::at_record(record.max(1))),
                    ));
                    return;
                }
                while matches!(line.last(), Some(b'\n') | Some(b'\r')) {
                    line.pop();
                }

                if line.first() == Some(&b'>') {
                    // Close the previous record before opening a new one.
                    if seen_header && seq_len == 0 {
                        report.push(Finding::error(
                            "fasta.empty_sequence",
                            format!("record {record} has a header but no sequence"),
                            Some(Location::at_record(record)),
                        ));
                    }
                    record += 1;
                    seen_header = true;
                    seq_len = 0;

                    let name = header_name(&line);
                    if name.is_empty() {
                        report.push(Finding::error(
                            "fasta.empty_name",
                            format!("record {record} header ('>') has no sequence name"),
                            Some(Location::at_record(record)),
                        ));
                    } else if !names.insert(name.to_vec()) {
                        report.push(Finding::error(
                            "fasta.duplicate_name",
                            format!(
                                "record {record}: duplicate sequence name '{}'",
                                String::from_utf8_lossy(name)
                            ),
                            Some(Location::at_record(record)),
                        ));
                    }
                } else if !seen_header {
                    if !bad_header_reported {
                        report.push(Finding::error(
                            "fasta.bad_header",
                            "sequence data appears before the first '>' header".to_string(),
                            Some(Location::at_record(1)),
                        ));
                        bad_header_reported = true;
                    }
                } else {
                    seq_len += line.len() as u64;
                }
            }
            Err(e) => {
                super::push_read_error(report, &e.to_string());
                return;
            }
        }
    }

    if seen_header && seq_len == 0 {
        report.push(Finding::error(
            "fasta.empty_sequence",
            format!("record {record} has a header but no sequence"),
            Some(Location::at_record(record)),
        ));
    }
}

/// The sequence name: bytes after the leading '>' up to the first whitespace.
fn header_name(line: &[u8]) -> &[u8] {
    let s = line.strip_prefix(b">").unwrap_or(line);
    let end = s
        .iter()
        .position(|&c| c == b' ' || c == b'\t')
        .unwrap_or(s.len());
    &s[..end]
}

#[cfg(test)]
mod tests {
    use crate::{check_reader, Options, Report};
    use std::io::Cursor;

    fn fasta_check(data: &[u8]) -> Report {
        let mut report = Report::default();
        super::check(Cursor::new(data.to_vec()), &Options::default(), &mut report);
        report
    }

    #[test]
    fn valid_fasta_passes() {
        let r = fasta_check(b">seq1 first\nACGTACGT\n>seq2\nTTGGCCAA\n");
        assert!(r.ok(), "valid FASTA should pass, got {:?}", r.findings);
    }

    #[test]
    fn empty_name_is_rejected() {
        let r = fasta_check(b">\nACGT\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fasta.empty_name"));
    }

    #[test]
    fn duplicate_name_is_rejected() {
        let r = fasta_check(b">seq1\nACGT\n>seq1\nTTGG\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fasta.duplicate_name"));
    }

    #[test]
    fn empty_sequence_is_rejected() {
        // seq1 has a header but no bases before seq2's header
        let r = fasta_check(b">seq1\n>seq2\nACGT\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fasta.empty_sequence"));
    }

    #[test]
    fn sequence_before_header_is_rejected() {
        let r = fasta_check(b"ACGT\n>seq1\nTTGG\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fasta.bad_header"));
    }

    #[test]
    fn fasta_is_routed_via_sniffer() {
        let r = check_reader(
            Box::new(Cursor::new(b">seq1\nACGT\n".to_vec())),
            &Options::default(),
        );
        assert!(r.ok(), "sniffed FASTA should pass, got {:?}", r.findings);
    }
}
```

- [ ] **Step 2: Register the module + recognize FASTA in the sniffer + dispatch**

In `crates/seqfw-core/src/checks/mod.rs`, add at the top (above `use ...`):
```rust
pub mod fasta;
```

In `crates/seqfw-core/src/lib.rs`, add the `Fasta` variant to `Format`:
```rust
pub enum Format {
    Fastq,
    Fasta,
}
```
and add the dispatch arm in `check_reader`'s match (before the `Empty` arm):
```rust
        detect::Decision::Known(Format::Fasta) => checks::fasta::check(stream, opts, &mut report),
```

In `crates/seqfw-core/src/detect.rs`, recognize `>` in the `sniff` match (between the `b'@'` and the `other` arms):
```rust
        Some(b'>') => Decision::Known(Format::Fasta),
```

- [ ] **Step 3: Build, test, lint**

Run: `cargo test -p seqfw-core`
Expected: PASS — all six FASTA tests plus everything earlier.

Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings` and `cargo fmt -p seqfw-core`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/seqfw-core/src/checks/fasta.rs crates/seqfw-core/src/checks/mod.rs crates/seqfw-core/src/lib.rs crates/seqfw-core/src/detect.rs
git commit -m "feat(core): FASTA structural checks + sniffer/dispatch wiring"
```

---

## Task 3: Cross-cutting identifier-safety helper

**Files:**
- Create: `crates/seqfw-core/src/checks/safety.rs`
- Modify: `crates/seqfw-core/src/checks/mod.rs`

A reusable check for identifiers (read-IDs, sequence names, sample names) that may flow into logs, filesystem paths, or shell commands downstream (spec §6 "Cross-cutting"). Control bytes are an ERROR (unambiguous corruption/injection); shell-metacharacter / path-traversal / URL-scheme are WARN (heuristic — flag but don't reject).

- [ ] **Step 1: Create the safety module with unit tests**

`crates/seqfw-core/src/checks/safety.rs`:
```rust
use crate::{Finding, Location, Report};

fn is_control(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}

/// Bytes that are dangerous if an identifier is interpolated into a shell
/// command without quoting. Deliberately excludes ':' and space (ubiquitous in
/// legitimate Illumina/Casava read headers) to keep the false-positive rate low.
fn is_shell_metachar(b: u8) -> bool {
    matches!(
        b,
        b';' | b'|' | b'&' | b'$' | b'`' | b'(' | b')' | b'<' | b'>' | b'\\' | b'\'' | b'"'
    )
}

/// True if `s` looks like a path with `..` traversal or an absolute/home prefix.
fn looks_like_traversal(s: &[u8]) -> bool {
    s.windows(3).any(|w| w == b"../" || w == b"..\\")
        || matches!(s.first(), Some(b'/') | Some(b'~'))
}

/// The URL scheme (e.g. `http`) if `s` embeds a `scheme://` sequence.
fn url_scheme(s: &[u8]) -> Option<&[u8]> {
    let pos = s.windows(3).position(|w| w == b"://")?;
    let scheme = &s[..pos];
    let ok = !scheme.is_empty()
        && scheme
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    ok.then_some(scheme)
}

/// Validate an identifier that may flow into logs, paths, or shell commands.
/// `context` is a human label (e.g. "FASTQ record 3 header") prefixed onto each
/// message; `location` is attached to every emitted finding.
pub(crate) fn check_identifier(
    id: &[u8],
    context: &str,
    location: Option<Location>,
    report: &mut Report,
) {
    if let Some(b) = id.iter().copied().find(|&b| is_control(b)) {
        report.push(Finding::error(
            "safety.control_char",
            format!(
                "{context} contains a control byte (0x{b:02x}); control characters in identifiers can corrupt logs or downstream commands"
            ),
            location.clone(),
        ));
    }
    if id.iter().copied().any(is_shell_metachar) {
        report.push(Finding::warn(
            "safety.shell_metachar",
            format!(
                "{context} contains a shell metacharacter; unsafe if interpolated into a shell command without quoting"
            ),
            location.clone(),
        ));
    }
    if looks_like_traversal(id) {
        report.push(Finding::warn(
            "safety.path_traversal",
            format!(
                "{context} looks like a path with '..' traversal or an absolute/home prefix; unsafe if used as a filesystem path"
            ),
            location.clone(),
        ));
    }
    if url_scheme(id).is_some() {
        report.push(Finding::warn(
            "safety.url_scheme",
            format!("{context} embeds a URL scheme; unsafe if dereferenced as a location"),
            location,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Report, Severity};

    fn findings(id: &[u8]) -> Report {
        let mut r = Report::default();
        check_identifier(id, "test id", None, &mut r);
        r
    }

    #[test]
    fn clean_identifier_has_no_findings() {
        let r = findings(b"SRR123.45:flowcell:1");
        assert!(r.findings.is_empty(), "got {:?}", r.findings);
    }

    #[test]
    fn control_byte_is_an_error() {
        let r = findings(b"read\x00name");
        assert!(!r.ok());
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "safety.control_char" && f.severity == Severity::Error));
    }

    #[test]
    fn shell_metachar_is_a_warning() {
        let r = findings(b"read;rm -rf");
        assert!(r.ok(), "metachar is warn-only");
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "safety.shell_metachar" && f.severity == Severity::Warn));
    }

    #[test]
    fn path_traversal_is_flagged() {
        let r = findings(b"../../etc/passwd");
        assert!(r.findings.iter().any(|f| f.rule == "safety.path_traversal"));
    }

    #[test]
    fn url_scheme_is_flagged() {
        let r = findings(b"http://evil.example/x");
        assert!(r.findings.iter().any(|f| f.rule == "safety.url_scheme"));
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/seqfw-core/src/checks/mod.rs`, add near the other `pub mod` lines:
```rust
pub mod safety;
```

- [ ] **Step 3: Build, test, lint**

Run: `cargo test -p seqfw-core safety`
Expected: PASS — the five safety unit tests.

Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings` and `cargo fmt -p seqfw-core`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/seqfw-core/src/checks/safety.rs crates/seqfw-core/src/checks/mod.rs
git commit -m "feat(core): cross-cutting identifier-safety check (control/shell/path/url)"
```

---

## Task 4: Wire identifier-safety into FASTQ and FASTA headers

**Files:**
- Modify: `crates/seqfw-core/src/checks/fastq.rs`
- Modify: `crates/seqfw-core/src/checks/fasta.rs`

- [ ] **Step 1: Write the failing tests**

Add to `fastq.rs` `mod tests`:
```rust
    #[test]
    fn header_control_byte_is_rejected() {
        let r = check_bytes(b"@r\x001\nACGT\n+\nIIII\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "safety.control_char"));
    }

    #[test]
    fn header_shell_metachar_warns_but_passes() {
        let r = check_bytes(b"@read;rm\nACGT\n+\nIIII\n");
        assert!(r.ok(), "shell metachar in header is warn-only");
        assert!(r.findings.iter().any(|f| f.rule == "safety.shell_metachar"));
    }
```

Add to `fasta.rs` `mod tests`:
```rust
    #[test]
    fn fasta_header_shell_metachar_warns() {
        let r = fasta_check(b">seq$(whoami)\nACGT\n");
        assert!(r.findings.iter().any(|f| f.rule == "safety.shell_metachar"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p seqfw-core header_ fasta_header`
Expected: FAIL (no safety findings emitted from headers yet).

- [ ] **Step 3: Call the safety check from both format checks**

In `fastq.rs`, in `validate_record`, after the `bad_separator` check (the header byte content is now scanned regardless of the `@` prefix), add:
```rust
    let id = header.strip_prefix(b"@").unwrap_or(header);
    super::safety::check_identifier(id, &format!("FASTQ record {n} header"), Some(Location::at_record(n)), report);
```

In `fasta.rs`, inside the `if line.first() == Some(&b'>')` branch, after the name uniqueness check, add:
```rust
                    super::safety::check_identifier(
                        &line[1..],
                        &format!("FASTA record {record} header"),
                        Some(Location::at_record(record)),
                        report,
                    );
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p seqfw-core`
Expected: PASS — the three new header tests plus every earlier test. (The existing FASTQ/FASTA fixtures use clean identifiers — `@r1`, `@read1/1`, `>seq1` — which the safety set does not flag, so nothing regresses.)

Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings` and `cargo fmt -p seqfw-core`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/seqfw-core/src/checks/fastq.rs crates/seqfw-core/src/checks/fasta.rs
git commit -m "feat(core): scan FASTQ/FASTA headers with the identifier-safety check"
```

---

## Task 5: CLI `--format` flag + corpus + end-to-end tests

**Files:**
- Modify: `crates/seqfw-cli/src/main.rs`
- Create: `corpus/fasta/pass/good.fasta`
- Create: `corpus/fasta/fail/duplicate_name.fasta`
- Create: `corpus/fasta/fail/empty_sequence.fasta`
- Create: `corpus/misc/unrecognized.txt`
- Modify: `crates/seqfw-cli/tests/cli.rs`

- [ ] **Step 1: Create corpus fixtures**

`corpus/fasta/pass/good.fasta`:
```
>seq1 first sequence
ACGTACGTACGT
>seq2 second sequence
TTGGCCAATTGG
```

`corpus/fasta/fail/duplicate_name.fasta`:
```
>seq1
ACGTACGT
>seq1
TTGGCCAA
```

`corpus/fasta/fail/empty_sequence.fasta`:
```
>seq1
>seq2
ACGTACGT
```

`corpus/misc/unrecognized.txt`:
```
this is not a genomic file
```

- [ ] **Step 2: Add the `--format` flag**

In `crates/seqfw-cli/src/main.rs`:

Extend the import to include `Format`:
```rust
use seqfw_core::{
    check_pair_reader, check_path, check_reader, Format, Options, Report, SeqAlphabet, Severity,
};
```

Add a clap value-enum that maps to the core `Format` (place it above `struct Cli`):
```rust
#[derive(Clone, Copy, clap::ValueEnum)]
enum FormatArg {
    Fastq,
    Fasta,
}

impl From<FormatArg> for Format {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Fastq => Format::Fastq,
            FormatArg::Fasta => Format::Fasta,
        }
    }
}
```

Add the flag to the `Check` variant (after `strict_dna`):
```rust
        /// Force the input format instead of auto-detecting it.
        #[arg(long, value_enum)]
        format: Option<FormatArg>,
```

Thread it through `main` and `run_check`:
```rust
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check {
            path,
            json,
            mate,
            strict_dna,
            format,
        } => run_check(&path, mate.as_deref(), json, strict_dna, format.map(Into::into)),
    }
}

fn run_check(
    path: &str,
    mate: Option<&str>,
    json: bool,
    strict_dna: bool,
    format: Option<Format>,
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
    // ... the rest of run_check is unchanged ...
```
> Only the signature, the `opts` initializer, and the `main` call site change. The `mate`/stdin/file dispatch body below is unchanged. (Paired-end mode is FASTQ-only; `forced_format` simply rides along in `opts` and is ignored by `check_pair_reader`.)

- [ ] **Step 3: Write the failing end-to-end tests**

Append to `crates/seqfw-cli/tests/cli.rs`:
```rust
#[test]
fn check_good_fasta_exits_zero() {
    seqfw()
        .args(["check", "../../corpus/fasta/pass/good.fasta"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn check_duplicate_fasta_name_exits_one() {
    seqfw()
        .args(["check", "../../corpus/fasta/fail/duplicate_name.fasta"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fasta.duplicate_name"));
}

#[test]
fn check_unrecognized_format_exits_one() {
    seqfw()
        .args(["check", "../../corpus/misc/unrecognized.txt"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("format.unrecognized"));
}

#[test]
fn forcing_fastq_on_a_fasta_file_rejects() {
    // A FASTA file forced through the FASTQ check fails framing.
    seqfw()
        .args([
            "check",
            "--format",
            "fastq",
            "../../corpus/fasta/pass/good.fasta",
        ])
        .assert()
        .code(1);
}

#[test]
fn header_shell_metachar_warns_but_passes() {
    seqfw()
        .args(["check", "-"])
        .write_stdin("@read;rm\nACGT\n+\nIIII\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("safety.shell_metachar"));
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p seqfw-cli`
Expected: PASS — the five new tests plus every Plan 1/2 CLI test.

- [ ] **Step 5: Manual smoke check**

Run: `cargo run -p seqfw-cli -- check corpus/fasta/fail/empty_sequence.fasta`
Expected: `REJECT ...` with a `fasta.empty_sequence` line; `echo $?` is `1`.

- [ ] **Step 6: Commit**

```bash
git add crates/seqfw-cli/src/main.rs crates/seqfw-cli/tests/cli.rs corpus/
git commit -m "feat(cli): --format flag; FASTA + unrecognized + safety e2e tests"
```

---

## Task 6: Final gate + README refresh + push

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Refresh the README**

In `README.md`, update the status blurb to mention FASTA + format detection + header safety, and add usage lines. Replace the status line:
```markdown
> Status: early development. v1 target: FASTQ / FASTA / VCF. This build validates
> FASTQ (framing + content + paired-end) and FASTA (structure + naming) files,
> auto-detects format, screens identifiers for unsafe characters, and blocks
> gzip/bgzf decompression bombs.
```
and add to the "Use" block:
```bash
seqfw check sample.fasta                      # FASTA structural validation
seqfw check input --format fastq              # force a format instead of sniffing
```

- [ ] **Step 2: Run the whole suite**

Run: `cargo test`
Expected: all tests pass across both crates (Plan 1/2 + this plan's core + CLI tests).

- [ ] **Step 3: Run clippy + fmt gates**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: no warnings.

Run: `cargo fmt --all -- --check`
Expected: clean. If diffs, run `cargo fmt --all` and add a `style:` commit.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document FASTA + format detection + identifier safety"
```

- [ ] **Step 5: Push directly to main**

Per the project's current solo direct-to-main flow (no PR for this plan):
```bash
git push origin main
```

---

## Self-Review (completed by plan author)

**Spec coverage (Plan 3 subset of §6–§7):** §7 "`Format`: sniffer (or explicit `--format`)" → Task 1 (`detect::sniff`) + Task 5 (`--format`); §6 "Corrupt / non-... detection" extended with `format.unrecognized` for inputs that are neither FASTQ nor FASTA → Task 1; §6 FASTA "Header sanity; reject duplicate / empty sequence names" + "Line-length caps" → Task 2 (`fasta.bad_header`, `fasta.empty_name`, `fasta.duplicate_name`, `fasta.empty_sequence`, `fasta.line_too_long`); §6 Cross-cutting "Read-ID / header / sample-name shell-metacharacter sanitization helper" + "Path-traversal / URL-scheme rejection in any embedded path-like field" → Tasks 3–4 (`safety.*`). **Deliberately deferred** (tracked, not gaps): FASTA `.fai` offset-within-bounds — part of the Plan 4 index-bounds work since it shares the index-parsing machinery; VCF (all of §6 VCF) → Plan 4; FASTA sequence-alphabet enforcement → intentionally omitted (FASTA may be protein), noted in Scope.

**Routing/regression safety:** the one behavior change to an existing test is documented and justified in Task 1 Step 4 — inserting the sniffer ahead of the checks means the bomb-test payload (previously all-`'A'`) must begin with `@` to reach the FASTQ check where the guard trips; without this the stream would short-circuit as `format.unrecognized`. All other Plan 1/2 fixtures begin with `@` and route unchanged. The identifier-safety wiring (Task 4) was checked against every existing fixture header (`@r1`, `@r2`, `@read1/1`, `@readX/2`, `>seq1`, `>seq2`) — none contain control bytes, the restricted shell-metachar set, `..`/absolute prefixes, or `://`, so no existing test gains a finding.

**Type/contract consistency:** `Format` is defined in `lib.rs` (crate root, already public); `Options.forced_format: Option<Format>` defaults to `None` (sniff). `detect::sniff(Box<dyn Read>, Option<Format>) -> (Decision, Box<dyn Read>)` and the `Decision` enum are `pub(crate)`. Each format check keeps the established `check(reader, opts, report)` shape, so dispatch is a uniform match. `push_read_error` moves to `checks/mod.rs` as `pub(crate)` and both `fastq`/`fasta` call it via `super::`. The CLI `FormatArg` is a thin `clap::ValueEnum` mapping to the core `Format` (keeps `clap` out of core). Rule ids are asserted in tests exactly as emitted.

**False-positive analysis (identifier safety):** the shell-metachar set excludes `:` and space (ubiquitous in Casava/Illumina headers) and only WARNs, so real read headers exit 0; control bytes are the only ERROR and are unambiguous corruption. The `://` and `..`/absolute heuristics are WARN-only, so even a sequence description that legitimately contains a URL informs without rejecting.

**Placeholder scan:** no TBD/TODO; every code step is complete and compilable at the point its task ends. Cross-task evolutions are explicit: `Format` gains its `Fasta` variant in Task 2 (exactly when the dispatch arm + module exist), and `checks/mod.rs` accretes `pub mod` lines across Tasks 1–3.
