# seqfw Plan 2 — FASTQ Content Checks + Paired-End Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `seqfw check` from FASTQ *framing* validation to FASTQ *content* validation — per-record sequence/quality length equality, Phred byte-range sanity (with an ambiguous +33/+64 encoding flag), embedded NUL/control-char rejection, and IUPAC alphabet enforcement — plus **paired-end sync** (`--mate`) that rejects R1/R2 files whose record counts or read IDs don't correspond.

**Architecture:** Builds directly on Plan 1's `seqfw-core`. Plan 1's monolithic `checks::fastq::check` loop is first refactored (no behavior change) into a `Reader` that yields one record at a time plus a `validate_record` function that owns all per-record rules. Every new content check is then a focused addition to `validate_record`. Paired-end sync reuses the same `Reader` to walk two streams in lockstep through a new `check_pair` core function, surfaced by a thin `--mate` CLI flag. No engine surgery: the `Source` (bomb guard + gzip decode) and `Finding`/`Report` vocabulary are unchanged.

**Tech Stack:** Rust (edition 2021). No new dependencies — reuses `flate2`, `serde`, `clap`, `assert_cmd`, `predicates` from Plan 1.

**Scope:** This is **Plan 2 of a sequence** (see `docs/superpowers/plans/2026-06-11-seqfw-fastq-core-cli.md` for Plan 1, already shipped). It completes the spec's §6 "FASTQ" check list. Out of scope here and tracked to later plans: FASTA/VCF/index-bounds (Plan 3); read-ID/sample-name shell-metacharacter sanitization and path-traversal rejection — the spec's "Cross-cutting" checks (Plan 3); Python bindings (Plan 4); ASAN benchmark (Plan 5); packaging (Plan 6). See `docs/superpowers/specs/2026-06-11-seqfw-genomic-firewall-design.md` §6.

---

## File Structure

```
seqfw/
  crates/
    seqfw-core/
      src/
        lib.rs                       # + SeqAlphabet enum; + check_pair_reader; Options gains seq_alphabet
        checks/
          fastq.rs                   # refactor → Reader + validate_record; + content checks; + check_pair
    seqfw-cli/
      src/
        main.rs                      # + --mate / --strict-dna flags on `check`
      tests/
        cli.rs                       # + content + pairing end-to-end tests
  corpus/
    fastq/
      pass/
        good.fastq                   # (exists)
        pair_R1.fastq                # NEW — valid R1 mate
        pair_R2.fastq                # NEW — valid R2 mate
      fail/
        bad_separator.fastq          # (exists)
        length_mismatch.fastq        # NEW — seq/qual length differ
        pair_mismatch_R1.fastq       # NEW — R1 whose IDs don't match its R2
        pair_mismatch_R2.fastq       # NEW
```

Responsibilities (unchanged boundaries): `checks/fastq.rs` owns all FASTQ rules — framing (Plan 1), content (this plan), and pair correspondence (this plan). `lib.rs` owns the public API surface and config (`Options`, `SeqAlphabet`, `check_reader`, `check_pair_reader`). `cli` owns flag parsing and rendering only.

**Rule ids introduced by this plan** (stable, asserted in tests): `fastq.length_mismatch`, `fastq.phred_out_of_range`, `fastq.ambiguous_encoding` (WARN), `fastq.control_char`, `fastq.invalid_base`, `fastq.pair_count_mismatch`, `fastq.pair_id_mismatch`.

---

## Task 1: Refactor `fastq::check` into `Reader` + `validate_record` (no behavior change)

**Files:**
- Modify: `crates/seqfw-core/src/checks/fastq.rs`

This is a pure restructure: it introduces the per-record iteration point that content checks (Tasks 2–4) and pairing (Task 5) build on, while emitting the exact same findings as Plan 1. The existing tests (`valid_fastq_passes`, `bad_separator_is_rejected`, `bad_header_is_rejected`, `truncated_record_is_rejected`) are the regression guard and must stay green unchanged.

- [ ] **Step 1: Replace the body of `fastq.rs` above the `#[cfg(test)]` module**

Replace everything from the top of the file down to (but **not** including) the `#[cfg(test)] mod tests {` line with:
```rust
use std::io::{BufRead, BufReader, Read};

use crate::bomb::BOMB_ERR;
use crate::{Finding, Location, Options, Report};

/// One parsed FASTQ record with line terminators stripped. `index` is 1-based.
struct RawRecord {
    index: u64,
    lines: [Vec<u8>; 4],
}

/// Outcome of pulling one record from the stream.
enum Next {
    /// A complete 4-line record.
    Record(RawRecord),
    /// Clean EOF exactly at a record boundary — no more records.
    Eof,
    /// A fatal stream problem was already reported; stop reading.
    Fatal,
}

/// Streams 4-line FASTQ records off a buffered reader, reporting framing-level
/// stream faults (truncation, over-long lines, read errors) as it goes.
struct Reader<R: BufRead> {
    buf: R,
    record: u64,
}

impl<R: BufRead> Reader<R> {
    fn new(buf: R) -> Self {
        Reader { buf, record: 0 }
    }

    fn next(&mut self, opts: &Options, report: &mut Report) -> Next {
        let mut lines: Vec<Vec<u8>> = Vec::with_capacity(4);

        for i in 0..4 {
            let mut line = Vec::new();
            match self.buf.read_until(b'\n', &mut line) {
                Ok(0) => {
                    if i == 0 {
                        return Next::Eof; // EOF at a record boundary is clean
                    }
                    self.record += 1;
                    report.push(Finding::error(
                        "fastq.truncated_record",
                        format!(
                            "record {} is incomplete: expected 4 lines, found {} (file may be truncated)",
                            self.record, i
                        ),
                        Some(Location::at_record(self.record)),
                    ));
                    return Next::Fatal;
                }
                Ok(_) => {
                    if line.len() > opts.max_line_len {
                        report.push(Finding::error(
                            "fastq.line_too_long",
                            format!(
                                "line in record {} exceeds the {}-byte limit (possible resource-exhaustion input)",
                                self.record + 1,
                                opts.max_line_len
                            ),
                            Some(Location::at_record(self.record + 1)),
                        ));
                        return Next::Fatal;
                    }
                    while matches!(line.last(), Some(b'\n') | Some(b'\r')) {
                        line.pop();
                    }
                    lines.push(line);
                }
                Err(e) => {
                    push_read_error(report, &e.to_string());
                    return Next::Fatal;
                }
            }
        }

        self.record += 1;
        let lines: [Vec<u8>; 4] = lines.try_into().expect("loop collected exactly 4 lines");
        Next::Record(RawRecord {
            index: self.record,
            lines,
        })
    }
}

/// Validate FASTQ record framing on a (already decompressed) stream.
/// Records are 4 lines: `@header`, sequence, `+separator`, quality.
pub fn check(reader: impl Read, opts: &Options, report: &mut Report) {
    let mut rdr = Reader::new(BufReader::new(reader));
    loop {
        match rdr.next(opts, report) {
            Next::Record(rec) => validate_record(&rec, opts, report),
            Next::Eof => break,
            Next::Fatal => return,
        }
    }
}

/// Run every per-record rule against one record.
fn validate_record(rec: &RawRecord, _opts: &Options, report: &mut Report) {
    let n = rec.index;
    let header = &rec.lines[0];
    let sep = &rec.lines[2];

    if header.first() != Some(&b'@') {
        report.push(Finding::error(
            "fastq.bad_header",
            format!("record {n} header (line 1) must start with '@'"),
            Some(Location::at_record(n)),
        ));
    }
    if sep.first() != Some(&b'+') {
        report.push(Finding::error(
            "fastq.bad_separator",
            format!("record {n} separator (line 3) must start with '+'"),
            Some(Location::at_record(n)),
        ));
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

> The `_opts` parameter on `validate_record` is unused this task; Tasks 2–4 use it. The leading underscore keeps clippy quiet until then.

- [ ] **Step 2: Run the existing tests to confirm no behavior change**

Run: `cargo test -p seqfw-core fastq`
Expected: PASS — `valid_fastq_passes`, `bad_separator_is_rejected`, `bad_header_is_rejected`, `truncated_record_is_rejected` (unchanged from Plan 1).

Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/seqfw-core/src/checks/fastq.rs
git commit -m "refactor(core): extract FASTQ Reader + validate_record (no behavior change)"
```

---

## Task 2: Sequence/quality length-equality check

**Files:**
- Modify: `crates/seqfw-core/src/checks/fastq.rs`

A quality line that doesn't match its sequence length is both a corruption signal and the canonical "length field that lies about its payload" exploit primitive (spec §1).

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `fastq.rs`:
```rust
    #[test]
    fn length_mismatch_is_rejected() {
        // seq is 4 bases, qual is 3 bytes
        let r = check_bytes(b"@r1\nACGT\n+\nIII\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.length_mismatch"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p seqfw-core length_mismatch`
Expected: FAIL (`r.ok()` is true — no such rule emitted yet).

- [ ] **Step 3: Add the check to `validate_record`**

In `validate_record`, add `seq`/`qual` bindings and the length comparison after the separator check:
```rust
    let seq = &rec.lines[1];
    let qual = &rec.lines[3];

    if seq.len() != qual.len() {
        report.push(Finding::error(
            "fastq.length_mismatch",
            format!(
                "record {n}: sequence is {} bases but quality is {} bytes (lengths must match)",
                seq.len(),
                qual.len()
            ),
            Some(Location::at_record(n)),
        ));
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p seqfw-core fastq`
Expected: PASS — new test plus all Plan 1 framing tests still green.

- [ ] **Step 5: Commit**

```bash
git add crates/seqfw-core/src/checks/fastq.rs
git commit -m "feat(core): FASTQ sequence/quality length-equality check"
```

---

## Task 3: Phred byte-range sanity + ambiguous-encoding flag

**Files:**
- Modify: `crates/seqfw-core/src/checks/fastq.rs`

Quality bytes must fall in the union Phred range `33..=126`. Separately, if **every** observed quality byte is `>= 64`, the data is consistent with both Phred+33 and legacy Phred+64 — genuinely ambiguous — so we emit a WARN (does not fail the file). A single byte `< 64` proves Phred+33 and suppresses the warning. This is a deliberately conservative cutoff (the offset itself), so real Sanger/Illumina-1.8+ data — which routinely contains bytes well below 64 — never trips it.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`:
```rust
    #[test]
    fn phred_out_of_range_is_rejected() {
        // 0x1f is below the printable Phred floor (33). Use a control-free
        // out-of-range byte by making qual one byte too high: 0x7f handled in
        // Task 4 as a control char, so here use byte 127+1 territory via space.
        // Space (0x20 = 32) is < 33 and is NOT a control char.
        let r = check_bytes(b"@r1\nAC\n+\n  \n"); // two spaces as quality
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.phred_out_of_range"));
    }

    #[test]
    fn all_high_quality_flags_ambiguous_encoding() {
        // every qual byte >= 64 ('h' = 104) → cannot tell +33 from +64
        let r = check_bytes(b"@r1\nACGT\n+\nhhhh\n");
        assert!(r.ok(), "ambiguous encoding is a warning, not an error");
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "fastq.ambiguous_encoding"
                && f.severity == crate::Severity::Warn));
    }

    #[test]
    fn low_quality_byte_suppresses_ambiguous_flag() {
        // '!' = 33 is < 64 → unambiguously Phred+33, no warning
        let r = check_bytes(b"@r1\nACGT\n+\nhhh!\n");
        assert!(r.ok());
        assert!(!r
            .findings
            .iter()
            .any(|f| f.rule == "fastq.ambiguous_encoding"));
    }
```

> Note: `check_bytes` and `Severity` need importing in the test module — the test `use` line becomes `use crate::{check_reader, Options, Severity};` if not already; `check_bytes` is the existing helper.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p seqfw-core phred ambiguous`
Expected: FAIL (no range check, no ambiguous flag yet).

- [ ] **Step 3: Add `is_control`, the qual validator, and ambiguous-encoding finalization**

In `fastq.rs`, add a control-byte helper near the top (below the imports):
```rust
/// C0 control characters and DEL — never valid inside a FASTQ sequence or
/// quality line, and a classic injection/corruption primitive (esp. NUL).
fn is_control(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}
```

Change `validate_record` to thread a running minimum quality byte, and add the quality scan. The signature becomes:
```rust
fn validate_record(rec: &RawRecord, opts: &Options, report: &mut Report, qual_min: &mut u8) {
```
(rename `_opts` → `opts`; it is now used). At the end of `validate_record`, after the length check, add:
```rust
    validate_qual(qual, n, report, qual_min);
```

Add the quality validator:
```rust
/// Scan a quality line for out-of-range bytes and track the file-wide minimum
/// in-range byte (used to decide Phred+33 vs +64 ambiguity). Control bytes are
/// left for `validate_seq`/`validate_qual`'s control path in Task 4; here a
/// byte `< 33` or `> 126` is an out-of-range Phred score.
fn validate_qual(qual: &[u8], n: u64, report: &mut Report, qual_min: &mut u8) {
    let mut range_reported = false;
    for &b in qual {
        if is_control(b) {
            continue; // reported as a control char in Task 4's path
        }
        if !(33..=126).contains(&b) {
            if !range_reported {
                report.push(Finding::error(
                    "fastq.phred_out_of_range",
                    format!(
                        "record {n}: quality byte 0x{b:02x} is outside the valid Phred range (33..=126)"
                    ),
                    Some(Location::at_record(n)),
                ));
                range_reported = true;
            }
        } else if b < *qual_min {
            *qual_min = b;
        }
    }
}

/// Emit a WARN if every in-range quality byte was `>= 64` (ambiguous +33/+64).
fn flag_ambiguous_encoding(qual_min: u8, report: &mut Report) {
    if qual_min != u8::MAX && qual_min >= 64 {
        report.push(Finding::warn(
            "fastq.ambiguous_encoding",
            format!(
                "all quality scores are >= 0x{qual_min:02x}; cannot distinguish Phred+33 from legacy Phred+64 encoding"
            ),
            None,
        ));
    }
}
```

Update `check` to own and finalize `qual_min`:
```rust
pub fn check(reader: impl Read, opts: &Options, report: &mut Report) {
    let mut rdr = Reader::new(BufReader::new(reader));
    let mut qual_min = u8::MAX;
    loop {
        match rdr.next(opts, report) {
            Next::Record(rec) => validate_record(&rec, opts, report, &mut qual_min),
            Next::Eof => break,
            Next::Fatal => return,
        }
    }
    flag_ambiguous_encoding(qual_min, report);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p seqfw-core fastq`
Expected: PASS — the three new tests plus all earlier FASTQ tests. (Plan 1's `valid_fastq_passes` uses `!` = 0x21 = 33 in record 2's quality, so its `qual_min` is 33 < 64 → no ambiguous warning; `.ok()` unaffected regardless.)

- [ ] **Step 5: Commit**

```bash
git add crates/seqfw-core/src/checks/fastq.rs
git commit -m "feat(core): FASTQ Phred range check + ambiguous +33/+64 encoding flag"
```

---

## Task 4: Embedded NUL/control-char rejection + IUPAC alphabet enforcement

**Files:**
- Modify: `crates/seqfw-core/src/lib.rs`
- Modify: `crates/seqfw-core/src/checks/fastq.rs`

Reject control bytes (NUL/C0/DEL) anywhere in a sequence or quality line — the embedded-NUL/control class is a direct injection and parser-corruption primitive (spec §6, §2.3). Enforce a configurable nucleotide alphabet on the sequence: default IUPAC (generous — won't false-positive on legitimate ambiguity codes), with a strict-DNA mode (`ACGTN`).

- [ ] **Step 1: Add the `SeqAlphabet` option to `lib.rs`**

In `crates/seqfw-core/src/lib.rs`, add the enum above `Options`:
```rust
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
                b'A' | b'C' | b'G' | b'T' | b'U' | b'R' | b'Y' | b'S' | b'W' | b'K' | b'M'
                    | b'B' | b'D' | b'H' | b'V' | b'N'
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
```

Add the field to `Options` and its default:
```rust
    /// Nucleotide alphabet enforced on FASTQ sequence lines.
    pub seq_alphabet: SeqAlphabet,
```
and in `impl Default for Options`, add:
```rust
            seq_alphabet: SeqAlphabet::Iupac,
```

Re-export it next to the other public types:
```rust
pub use finding::{Finding, Location, Report, Severity};
// (add)
pub use checks::fastq::; // <-- do NOT add this line; SeqAlphabet lives in lib.rs
```
> `SeqAlphabet` is defined in `lib.rs` itself, so it is already public — no extra `pub use` needed. (The crate root re-exports `finding::*`; `SeqAlphabet` sits directly in the root.)

- [ ] **Step 2: Write the failing tests**

Add to `fastq.rs` `mod tests`:
```rust
    #[test]
    fn embedded_nul_in_sequence_is_rejected() {
        let r = check_bytes(b"@r1\nAC\0T\n+\nIIII\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.control_char"));
    }

    #[test]
    fn invalid_base_is_rejected() {
        // 'Z' is not an IUPAC nucleotide code
        let r = check_bytes(b"@r1\nACZT\n+\nIIII\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.invalid_base"));
    }

    #[test]
    fn iupac_ambiguity_code_passes_by_default() {
        // 'R' (A or G) is valid IUPAC; default alphabet accepts it
        let r = check_bytes(b"@r1\nACRT\n+\nIIII\n");
        assert!(r.ok(), "IUPAC code R should pass, got {:?}", r.findings);
    }

    #[test]
    fn strict_dna_rejects_iupac_code() {
        use crate::SeqAlphabet;
        let opts = Options {
            seq_alphabet: SeqAlphabet::Dna,
            ..Options::default()
        };
        let r = check_reader(Box::new(Cursor::new(b"@r1\nACRT\n+\nIIII\n".to_vec())), &opts);
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.invalid_base"));
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p seqfw-core` (will fail to compile until `seq_alphabet` exists — it does after Step 1; then these four tests FAIL on assertions).
Expected: the four new tests FAIL (no control/alphabet rules emitted yet).

- [ ] **Step 4: Add the sequence validator and the control scan to quality**

In `fastq.rs`, add the sequence validator:
```rust
/// Scan a sequence line: control bytes first (security), then alphabet
/// membership. Emits at most one `control_char` and one `invalid_base` per
/// record to avoid flooding a pathological line with findings.
fn validate_seq(seq: &[u8], n: u64, opts: &Options, report: &mut Report) {
    let mut control_reported = false;
    let mut base_reported = false;
    for &b in seq {
        if is_control(b) {
            if !control_reported {
                report.push(Finding::error(
                    "fastq.control_char",
                    format!(
                        "record {n}: sequence contains a control byte (0x{b:02x}); embedded NUL/control bytes can corrupt or exploit downstream parsers"
                    ),
                    Some(Location::at_record(n)),
                ));
                control_reported = true;
            }
        } else if !opts.seq_alphabet.accepts(b) && !base_reported {
            report.push(Finding::error(
                "fastq.invalid_base",
                format!(
                    "record {n}: sequence byte 0x{b:02x} is outside the {} alphabet",
                    opts.seq_alphabet.name()
                ),
                Some(Location::at_record(n)),
            ));
            base_reported = true;
        }
        if control_reported && base_reported {
            break;
        }
    }
}
```

Wire it into `validate_record` (call before `validate_qual`):
```rust
    validate_seq(seq, n, opts, report);
    validate_qual(qual, n, report, qual_min);
```

Add the control scan to `validate_qual` — replace the `if is_control(b) { continue; }` line with a reporting branch:
```rust
        if is_control(b) {
            if !control_reported {
                report.push(Finding::error(
                    "fastq.control_char",
                    format!("record {n}: quality line contains a control byte (0x{b:02x})"),
                    Some(Location::at_record(n)),
                ));
                control_reported = true;
            }
            continue;
        }
```
and declare `let mut control_reported = false;` at the top of `validate_qual` alongside `range_reported`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p seqfw-core`
Expected: PASS — all four new tests plus every earlier core test (smoke, finding, bomb, source, fastq).

- [ ] **Step 6: Commit**

```bash
git add crates/seqfw-core/src/lib.rs crates/seqfw-core/src/checks/fastq.rs
git commit -m "feat(core): reject control bytes + enforce configurable IUPAC alphabet"
```

---

## Task 5: Paired-end sync — `check_pair` core API

**Files:**
- Modify: `crates/seqfw-core/src/checks/fastq.rs`
- Modify: `crates/seqfw-core/src/lib.rs`

Walk R1 and R2 in lockstep through the same `Reader`. Reject when record counts differ (`fastq.pair_count_mismatch`) or per-record read IDs don't correspond after stripping the mate suffix (`fastq.pair_id_mismatch`). Each record is still fully content-validated via `validate_record`.

- [ ] **Step 1: Write the failing test**

Add to `fastq.rs` `mod tests`:
```rust
    fn check_pair_bytes(r1: &[u8], r2: &[u8]) -> crate::Report {
        let mut report = crate::Report::default();
        super::check_pair(
            Cursor::new(r1.to_vec()),
            Cursor::new(r2.to_vec()),
            &Options::default(),
            &mut report,
        );
        report
    }

    #[test]
    fn matched_pair_passes() {
        let r1 = b"@read1/1\nACGT\n+\nIIII\n@read2/1\nTTGG\n+\nIIII\n";
        let r2 = b"@read1/2\nCCGG\n+\nIIII\n@read2/2\nAATT\n+\nIIII\n";
        let r = check_pair_bytes(r1, r2);
        assert!(r.ok(), "matched pair should pass, got {:?}", r.findings);
    }

    #[test]
    fn pair_id_mismatch_is_rejected() {
        let r1 = b"@read1/1\nACGT\n+\nIIII\n";
        let r2 = b"@readX/2\nCCGG\n+\nIIII\n";
        let r = check_pair_bytes(r1, r2);
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.pair_id_mismatch"));
    }

    #[test]
    fn pair_count_mismatch_is_rejected() {
        let r1 = b"@read1/1\nACGT\n+\nIIII\n@read2/1\nTTGG\n+\nIIII\n";
        let r2 = b"@read1/2\nCCGG\n+\nIIII\n"; // one fewer record
        let r = check_pair_bytes(r1, r2);
        assert!(!r.ok());
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "fastq.pair_count_mismatch"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p seqfw-core pair`
Expected: FAIL to compile (`super::check_pair` not defined).

- [ ] **Step 3: Implement `check_pair`, `read_id`, `compare_ids`**

In `fastq.rs`:
```rust
/// Validate two FASTQ streams as an R1/R2 mate pair: each record is
/// content-validated, and the pair is checked for equal record counts and
/// corresponding read IDs.
pub fn check_pair(r1: impl Read, r2: impl Read, opts: &Options, report: &mut Report) {
    let mut a = Reader::new(BufReader::new(r1));
    let mut b = Reader::new(BufReader::new(r2));
    let mut qual_min = u8::MAX;
    let mut pair: u64 = 0;

    loop {
        match (a.next(opts, report), b.next(opts, report)) {
            (Next::Record(ra), Next::Record(rb)) => {
                pair += 1;
                validate_record(&ra, opts, report, &mut qual_min);
                validate_record(&rb, opts, report, &mut qual_min);
                compare_ids(&ra, &rb, pair, report);
            }
            (Next::Eof, Next::Eof) => break,
            (Next::Fatal, _) | (_, Next::Fatal) => return,
            (Next::Eof, Next::Record(_)) | (Next::Record(_), Next::Eof) => {
                report.push(Finding::error(
                    "fastq.pair_count_mismatch",
                    "R1 and R2 have different record counts (paired files must be in sync)"
                        .to_string(),
                    None,
                ));
                return;
            }
        }
    }
    flag_ambiguous_encoding(qual_min, report);
}

/// The shared read ID: bytes after a leading '@', up to the first whitespace or
/// '/' mate-suffix delimiter. Handles both `@id/1`+`@id/2` and Casava-1.8
/// `@id 1:...`+`@id 2:...` conventions.
fn read_id(header: &[u8]) -> &[u8] {
    let s = header.strip_prefix(b"@").unwrap_or(header);
    let end = s
        .iter()
        .position(|&c| c == b' ' || c == b'\t' || c == b'/')
        .unwrap_or(s.len());
    &s[..end]
}

fn compare_ids(a: &RawRecord, b: &RawRecord, pair: u64, report: &mut Report) {
    if read_id(&a.lines[0]) != read_id(&b.lines[0]) {
        report.push(Finding::error(
            "fastq.pair_id_mismatch",
            format!("record {pair}: R1 and R2 read IDs do not correspond (paired reads must share a base ID)"),
            Some(Location::at_record(pair)),
        ));
    }
}
```

- [ ] **Step 4: Add the public `check_pair_reader` to `lib.rs`**

In `crates/seqfw-core/src/lib.rs`, below `check_reader`:
```rust
/// Validate two byte streams as a FASTQ R1/R2 mate pair. Both streams are
/// transparently decompressed and bomb-guarded, exactly like `check_reader`.
pub fn check_pair_reader(r1: Box<dyn Read>, r2: Box<dyn Read>, opts: &Options) -> Report {
    let mut report = Report::default();
    let g1 = source::open_guarded(r1, opts);
    let g2 = source::open_guarded(r2, opts);
    checks::fastq::check_pair(g1, g2, opts, &mut report);
    report
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p seqfw-core`
Expected: PASS — `matched_pair_passes`, `pair_id_mismatch_is_rejected`, `pair_count_mismatch_is_rejected`, plus all earlier tests.

- [ ] **Step 6: Commit**

```bash
git add crates/seqfw-core/src/checks/fastq.rs crates/seqfw-core/src/lib.rs
git commit -m "feat(core): paired-end sync (record-count + read-ID correspondence)"
```

---

## Task 6: CLI `--mate` / `--strict-dna` + corpus + end-to-end tests

**Files:**
- Modify: `crates/seqfw-cli/src/main.rs`
- Create: `corpus/fastq/pass/pair_R1.fastq`, `corpus/fastq/pass/pair_R2.fastq`
- Create: `corpus/fastq/fail/length_mismatch.fastq`, `corpus/fastq/fail/pair_mismatch_R1.fastq`, `corpus/fastq/fail/pair_mismatch_R2.fastq`
- Modify: `crates/seqfw-cli/tests/cli.rs`

- [ ] **Step 1: Create corpus fixtures**

`corpus/fastq/pass/pair_R1.fastq`:
```
@read1/1
ACGTACGT
+
IIIIIIII
@read2/1
TTGGCCAA
+
IIIIIIII
```

`corpus/fastq/pass/pair_R2.fastq`:
```
@read1/2
TTGGCCAA
+
IIIIIIII
@read2/2
ACGTACGT
+
IIIIIIII
```

`corpus/fastq/fail/length_mismatch.fastq`:
```
@read1
ACGTACGT
+
IIII
```

`corpus/fastq/fail/pair_mismatch_R1.fastq`:
```
@read1/1
ACGTACGT
+
IIIIIIII
```

`corpus/fastq/fail/pair_mismatch_R2.fastq`:
```
@totally_different/2
ACGTACGT
+
IIIIIIII
```

- [ ] **Step 2: Implement the CLI flags**

In `crates/seqfw-cli/src/main.rs`, extend imports:
```rust
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use seqfw_core::{
    check_pair_reader, check_path, check_reader, Options, Report, SeqAlphabet, Severity,
};
```

Extend the `Check` variant:
```rust
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
    },
```

Update `main`'s match arm and `run_check`:
```rust
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check {
            path,
            json,
            mate,
            strict_dna,
        } => run_check(&path, mate.as_deref(), json, strict_dna),
    }
}

fn run_check(path: &str, mate: Option<&str>, json: bool, strict_dna: bool) -> ExitCode {
    let opts = Options {
        seq_alphabet: if strict_dna {
            SeqAlphabet::Dna
        } else {
            SeqAlphabet::Iupac
        },
        ..Options::default()
    };

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
```

> `render_human` and `render_json` are unchanged from Plan 1.

- [ ] **Step 3: Write the failing end-to-end tests**

Append to `crates/seqfw-cli/tests/cli.rs`:
```rust
#[test]
fn check_length_mismatch_exits_one() {
    seqfw()
        .args(["check", "../../corpus/fastq/fail/length_mismatch.fastq"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fastq.length_mismatch"));
}

#[test]
fn check_matched_pair_exits_zero() {
    seqfw()
        .args([
            "check",
            "../../corpus/fastq/pass/pair_R1.fastq",
            "--mate",
            "../../corpus/fastq/pass/pair_R2.fastq",
        ])
        .assert()
        .success();
}

#[test]
fn check_mismatched_pair_exits_one() {
    seqfw()
        .args([
            "check",
            "../../corpus/fastq/fail/pair_mismatch_R1.fastq",
            "--mate",
            "../../corpus/fastq/fail/pair_mismatch_R2.fastq",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fastq.pair_id_mismatch"));
}

#[test]
fn check_strict_dna_rejects_iupac() {
    // good.fastq is pure ACGT, so craft an IUPAC-but-not-DNA case via stdin.
    seqfw()
        .args(["check", "--strict-dna", "-"])
        .write_stdin("@r1\nACRT\n+\nIIII\n")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fastq.invalid_base"));
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p seqfw-cli`
Expected: PASS — the four new tests plus the Plan 1 CLI tests.

- [ ] **Step 5: Manual smoke check**

Run: `cargo run -p seqfw-cli -- check corpus/fastq/pass/pair_R1.fastq --mate corpus/fastq/fail/pair_mismatch_R2.fastq`
Expected: `REJECT ...` with a `fastq.pair_id_mismatch` line; `echo $?` is `1`.

- [ ] **Step 6: Commit**

```bash
git add crates/seqfw-cli/src/main.rs crates/seqfw-cli/tests/cli.rs corpus/
git commit -m "feat(cli): --mate paired-end + --strict-dna alphabet flags"
```

---

## Task 7: Final gate + README refresh + push

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Refresh the README check list**

In `README.md`, update the status blurb to reflect the new checks and document the new flags. Replace the status line:
```markdown
> Status: early development. v1 target: FASTQ / FASTA / VCF. This build validates
> FASTQ record framing + content (sequence/quality length, Phred range, control-byte
> rejection, IUPAC alphabet), paired-end sync, and blocks gzip/bgzf decompression bombs.
```
and add to the "Use" block:
```bash
seqfw check R1.fastq.gz --mate R2.fastq.gz   # paired-end sync check
seqfw check sample.fastq --strict-dna        # enforce ACGTN (default is IUPAC)
```

- [ ] **Step 2: Run the whole suite**

Run: `cargo test`
Expected: all tests pass across both crates (Plan 1's ~14 + this plan's new core and CLI tests).

- [ ] **Step 3: Run clippy + fmt gates**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: no warnings (fix any that appear — they are real).

Run: `cargo fmt --all -- --check`
Expected: clean. If it reports diffs, run `cargo fmt --all`, re-check, and amend the relevant commit or add a `style:` commit.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document FASTQ content checks + paired-end usage"
```

- [ ] **Step 5: Push and open a PR (or update the existing branch's PR)**

```bash
git push origin plan1-fastq-core-cli   # or a new plan2 branch if Plan 1's PR is merged
```
> Coordinate with the human on branch/PR strategy: if Plan 1's PR #1 is still open, these commits can extend it or land on a fresh `plan2-fastq-content` branch off `main`. Confirm before pushing.

---

## Self-Review (completed by plan author)

**Spec coverage (Plan 2 subset of §6 FASTQ):** "len(seq) == len(qual) per record" → Task 2 (`fastq.length_mismatch`); "Phred byte range sanity; flag ambiguous +33 vs +64 encoding" → Task 3 (`fastq.phred_out_of_range` + `fastq.ambiguous_encoding`); "Reject embedded NUL / control chars; IUPAC alphabet enforcement (configurable strictness)" → Task 4 (`fastq.control_char`, `fastq.invalid_base`, `SeqAlphabet` + `--strict-dna`); "Paired-end sync: R1/R2 record counts and read-ID correspondence" → Tasks 5–6 (`fastq.pair_count_mismatch`, `fastq.pair_id_mismatch`, `--mate`). The "Per-line and per-record length caps" item was satisfied in Plan 1 (`fastq.line_too_long`). **Deliberately deferred** (not gaps): the §6 "Cross-cutting" read-ID/sample-name shell-metacharacter sanitization and path-traversal/URL-scheme rejection → Plan 3 (they are format-agnostic and pair naturally with FASTA/VCF); FASTA/VCF/index-bounds → Plan 3; Python bindings → Plan 4.

**Behavior-preservation:** Task 1 is an explicit no-behavior-change refactor guarded by Plan 1's four FASTQ tests, run before any new rule is added. Each subsequent task is TDD (failing test → implementation → green) and re-runs the full `-p seqfw-core` suite so earlier checks never regress.

**Type consistency:** `validate_record`'s signature evolves once (Task 3 adds `&mut u8` for `qual_min`); every call site (`check`, and `check_pair` in Task 5) is updated in the same task that introduces the change, so each task compiles. `SeqAlphabet` is defined in `lib.rs` (crate root → already public, no extra re-export), added to `Options` with an `Iupac` default in Task 4, and consumed by `validate_seq` and the CLI consistently. Rule ids are asserted in tests exactly as emitted. `check_pair_reader(Box<dyn Read>, Box<dyn Read>, &Options) -> Report` mirrors the existing `check_reader` shape.

**Ambiguity-flag false-positive analysis:** the `>= 64` cutoff is the Phred+64 offset itself; any genuine Sanger/Illumina-1.8+ file contains at least one base below Q31 (byte < 64) and so suppresses the warning. The warning is WARN severity, so even a true ambiguous file (all-high-quality) still exits 0 — it informs without rejecting, matching the spec's "pass-but-flag" semantics.

**Placeholder scan:** no TBD/TODO; every code step is complete and compilable at the point its task ends. The one intentional cross-task signature change (`qual_min`) is flagged in Task 3.
