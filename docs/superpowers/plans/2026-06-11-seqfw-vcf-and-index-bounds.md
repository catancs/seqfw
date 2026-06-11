# seqfw Plan 4 — VCF Validation + Index-Bounds Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the third v1 format — **VCF** — and the **index-bounds** check class. `seqfw check x.vcf[.gz]` validates VCF header/record structure, coordinate sanity, INFO/FORMAT header-tag consistency, and the `CVE-2020-36403`-class FORMAT-field-count safety; `seqfw check x.fai --data x.fa` (and `.gzi`/`.tbi`/`.csi`) validates companion **index files** for impossible counts and out-of-bounds offsets (the `CVE-2026-31970` class).

**Architecture:** Builds on Plans 1–3's `seqfw-core`. VCF slots into the existing sniff/dispatch path: a VCF starts `##fileformat=`, so the sniffer recognizes a leading `#` and routes to a new `checks::vcf` module shaped like `fastq`/`fasta`. Index files are a *different* surface — they are validated against an optional companion **data file's byte length**, so they get a new public entry point `check_index_reader(kind, reader, data_len, opts)` and a new `checks::index` module; the CLI selects the index kind by extension and passes `--data` through. `.tbi`/`.csi` are BGZF-compressed binary, so they ride the existing `source::open_guarded` decode+bomb-guard; `.fai` is text and `.gzi` is uncompressed binary (both pass through `open_guarded` untouched). VCF sample names reuse `checks::safety`. No changes to the bomb guard or the `Finding`/`Report` vocabulary.

**Tech Stack:** Rust (edition 2021). No new dependencies — binary index parsing uses `u64::from_le_bytes`/`i32::from_le_bytes` from std.

**Scope:** This is **Plan 4 of a sequence** (Plans 1–3 shipped on `main`). It completes the spec's §6 VCF check list and the §6 transport "index sanity" item. **Deliberately bounded:** `.tbi`/`.csi` validation is a *header-level* magic + impossible-count guard (the security-relevant `CVE-2026-31970` integer-overflow class), **not** a full structural walk of every bin/chunk/interval — that depth is roadmap. Later plans: Python bindings (Plan 5), reproducible ASAN benchmark (Plan 6), packaging (Plan 7). See `docs/superpowers/specs/2026-06-11-seqfw-genomic-firewall-design.md` §6–§8.

---

## File Structure

```
seqfw/
  crates/
    seqfw-core/
      src/
        lib.rs                       # + Format::Vcf; + IndexKind + check_index_reader; dispatch arm
        detect.rs                    # sniff '#' → Format::Vcf
        checks/
          mod.rs                     # + pub mod vcf; pub mod index;
          vcf.rs                     # NEW — VCF header/record/tag/FORMAT-field checks
          index.rs                   # NEW — .fai / .gzi / .tbi / .csi bounds checks
    seqfw-cli/
      src/
        main.rs                      # + Vcf in FormatArg; + --data flag; route index files by extension
      tests/
        cli.rs                       # + VCF + .fai end-to-end tests
  corpus/
    vcf/
      pass/good.vcf                  # NEW — valid minimal VCF
      fail/bad_pos.vcf               # NEW — non-numeric POS
      fail/format_mismatch.vcf       # NEW — sample has more subfields than FORMAT keys
    fai/
      pass/ref.fa                    # NEW — tiny FASTA (the data file)
      pass/ref.fa.fai                # NEW — its valid .fai index
      fail/oob.fa.fai                # NEW — offset past end of ref.fa
```

**Rule ids introduced by this plan** (stable, asserted in tests):
- VCF: `vcf.line_too_long`, `vcf.missing_fileformat`, `vcf.missing_header`, `vcf.too_few_columns`, `vcf.column_count_mismatch`, `vcf.bad_pos`, `vcf.undeclared_info` (WARN), `vcf.undeclared_format` (WARN), `vcf.format_field_mismatch` (ERROR).
- Index: `fai.bad_columns`, `fai.bad_number`, `fai.bad_linewidth`, `fai.offset_out_of_bounds`; `gzi.truncated`, `gzi.bad_entry_count`, `gzi.non_monotonic`, `gzi.offset_out_of_bounds`; `tabix.bad_magic`, `tabix.truncated`, `tabix.impossible_count`.

---

## Task 1: VCF dispatch + parser skeleton + header-presence checks

**Files:**
- Create: `crates/seqfw-core/src/checks/vcf.rs`
- Modify: `crates/seqfw-core/src/checks/mod.rs`
- Modify: `crates/seqfw-core/src/lib.rs`
- Modify: `crates/seqfw-core/src/detect.rs`

- [ ] **Step 1: Create the VCF module with the line loop + header-presence rules**

`crates/seqfw-core/src/checks/vcf.rs`:
```rust
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read};

use crate::{Finding, Location, Options, Report};

/// Validate VCF structure on a (already decompressed) stream.
pub fn check(reader: impl Read, opts: &Options, report: &mut Report) {
    let mut buf = BufReader::new(reader);
    let mut line = Vec::new();
    let mut line_no: u64 = 0;
    let mut seen_fileformat = false;
    let mut seen_chrom_header = false;
    let mut header_missing_reported = false;
    let mut header_cols: usize = 0;
    let mut data_record: u64 = 0;

    // Header-declared INFO/FORMAT IDs (populated in Task 3).
    let mut info_ids: HashSet<Vec<u8>> = HashSet::new();
    let mut format_ids: HashSet<Vec<u8>> = HashSet::new();

    loop {
        line.clear();
        match buf.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
                line_no += 1;
                if line.len() > opts.max_line_len {
                    report.push(Finding::error(
                        "vcf.line_too_long",
                        format!(
                            "line {line_no} exceeds the {}-byte limit (possible resource-exhaustion input)",
                            opts.max_line_len
                        ),
                        None,
                    ));
                    return;
                }
                while matches!(line.last(), Some(b'\n') | Some(b'\r')) {
                    line.pop();
                }
                if line.is_empty() {
                    continue;
                }

                if line.starts_with(b"##") {
                    if line.starts_with(b"##fileformat=") {
                        seen_fileformat = true;
                    }
                    // Task 3 parses ##INFO/##FORMAT IDs here.
                    let _ = (&info_ids, &format_ids);
                    continue;
                }

                if line.starts_with(b"#CHROM") {
                    seen_chrom_header = true;
                    header_cols = split_tabs(&line).len();
                    // Task 4 scans sample names here.
                    continue;
                }

                // A data line.
                if !seen_chrom_header {
                    if !header_missing_reported {
                        report.push(Finding::error(
                            "vcf.missing_header",
                            "data record appears before the '#CHROM' column-header line".to_string(),
                            None,
                        ));
                        header_missing_reported = true;
                    }
                    continue;
                }
                data_record += 1;
                validate_data_line(
                    &line,
                    header_cols,
                    &info_ids,
                    &format_ids,
                    data_record,
                    report,
                );
            }
            Err(e) => {
                super::push_read_error(report, &e.to_string());
                return;
            }
        }
    }

    if !seen_fileformat {
        report.push(Finding::error(
            "vcf.missing_fileformat",
            "missing the mandatory '##fileformat=' meta line".to_string(),
            None,
        ));
    }
    if !seen_chrom_header && !header_missing_reported {
        report.push(Finding::error(
            "vcf.missing_header",
            "missing the '#CHROM' column-header line".to_string(),
            None,
        ));
    }
}

/// Per-data-record checks. Task 1 leaves this empty; Tasks 2–4 fill it in.
fn validate_data_line(
    _line: &[u8],
    _header_cols: usize,
    _info_ids: &HashSet<Vec<u8>>,
    _format_ids: &HashSet<Vec<u8>>,
    _record: u64,
    _report: &mut Report,
) {
}

/// Split a line into tab-separated columns.
fn split_tabs(line: &[u8]) -> Vec<&[u8]> {
    line.split(|&c| c == b'\t').collect()
}

#[cfg(test)]
mod tests {
    use crate::{check_reader, Options, Report};
    use std::io::Cursor;

    fn vcf_check(data: &[u8]) -> Report {
        let mut report = Report::default();
        super::check(Cursor::new(data.to_vec()), &Options::default(), &mut report);
        report
    }

    const MINIMAL_HEADER: &[u8] =
        b"##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

    #[test]
    fn minimal_valid_vcf_passes() {
        let r = vcf_check(MINIMAL_HEADER);
        assert!(r.ok(), "minimal VCF should pass, got {:?}", r.findings);
    }

    #[test]
    fn missing_fileformat_is_rejected() {
        let r = vcf_check(b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "vcf.missing_fileformat"));
    }

    #[test]
    fn data_before_header_is_rejected() {
        let r = vcf_check(b"##fileformat=VCFv4.2\nchr1\t100\t.\tA\tG\t.\t.\t.\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "vcf.missing_header"));
    }

    #[test]
    fn vcf_is_routed_via_sniffer() {
        let r = check_reader(Box::new(Cursor::new(MINIMAL_HEADER.to_vec())), &Options::default());
        assert!(r.ok(), "sniffed VCF should pass, got {:?}", r.findings);
    }
}
```

- [ ] **Step 2: Register the module, add the `Vcf` format, wire dispatch + sniffer**

In `crates/seqfw-core/src/checks/mod.rs`, add near the other `pub mod` lines:
```rust
pub mod vcf;
```

In `crates/seqfw-core/src/lib.rs`, add `Vcf` to `Format`:
```rust
pub enum Format {
    Fastq,
    Fasta,
    Vcf,
}
```
and add the dispatch arm in `check_reader` (after the `Fasta` arm):
```rust
        detect::Decision::Known(Format::Vcf) => checks::vcf::check(stream, opts, &mut report),
```
Also extend the `Unrecognized` message so it lists all three (cosmetic, keeps the help honest):
```rust
        detect::Decision::Unrecognized(b) => report.push(Finding::error(
            "format.unrecognized",
            format!(
                "could not recognize the file format (first content byte 0x{b:02x}); expected FASTQ ('@'), FASTA ('>'), or VCF ('#')"
            ),
            None,
        )),
```

In `crates/seqfw-core/src/detect.rs`, recognize `#` (between the `b'>'` and `other` arms):
```rust
        Some(b'#') => Decision::Known(Format::Vcf),
```

- [ ] **Step 3: Build, test, lint**

Run: `cargo test -p seqfw-core vcf`
Expected: PASS — `minimal_valid_vcf_passes`, `missing_fileformat_is_rejected`, `data_before_header_is_rejected`, `vcf_is_routed_via_sniffer`.

Run: `cargo test -p seqfw-core` — everything still green.
Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings` and `cargo fmt -p seqfw-core` — clean.
> The `validate_data_line` params are `_`-prefixed this task to keep clippy quiet; Tasks 2–4 use them. The `let _ = (&info_ids, &format_ids);` line keeps those bindings live until Task 3.

- [ ] **Step 4: Commit**

```bash
git add crates/seqfw-core/src/checks/vcf.rs crates/seqfw-core/src/checks/mod.rs crates/seqfw-core/src/lib.rs crates/seqfw-core/src/detect.rs
git commit -m "feat(core): VCF dispatch + header-presence checks"
```

---

## Task 2: VCF column structure + coordinate sanity

**Files:**
- Modify: `crates/seqfw-core/src/checks/vcf.rs`

VCF data records are tab-separated with ≥8 mandatory columns (CHROM POS ID REF ALT QUAL FILTER INFO), and every data row must match the `#CHROM` header's column count. POS must be a non-negative integer (VCF is 1-based; 0 is the telomere convention).

- [ ] **Step 1: Write the failing tests**

Add to `vcf.rs` `mod tests`:
```rust
    #[test]
    fn too_few_columns_is_rejected() {
        let r = vcf_check(b"##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\nchr1\t100\t.\tA\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "vcf.too_few_columns"));
    }

    #[test]
    fn column_count_mismatch_is_rejected() {
        // header has 8 columns; data row has 9
        let r = vcf_check(b"##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\nchr1\t100\t.\tA\tG\t.\t.\t.\tEXTRA\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "vcf.column_count_mismatch"));
    }

    #[test]
    fn non_numeric_pos_is_rejected() {
        let r = vcf_check(b"##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\nchr1\tABC\t.\tA\tG\t.\t.\t.\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "vcf.bad_pos"));
    }

    #[test]
    fn well_formed_record_passes() {
        let r = vcf_check(b"##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\nchr1\t100\t.\tA\tG\t.\t.\t.\n");
        assert!(r.ok(), "got {:?}", r.findings);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p seqfw-core vcf`
Expected: the four new tests FAIL (`validate_data_line` is empty).

- [ ] **Step 3: Implement `validate_data_line` (columns + POS)**

Replace the empty `validate_data_line` body with:
```rust
fn validate_data_line(
    line: &[u8],
    header_cols: usize,
    _info_ids: &HashSet<Vec<u8>>,
    _format_ids: &HashSet<Vec<u8>>,
    record: u64,
    report: &mut Report,
) {
    let cols = split_tabs(line);
    if cols.len() < 8 {
        report.push(Finding::error(
            "vcf.too_few_columns",
            format!(
                "record {record} has {} columns; VCF requires at least 8 (CHROM..INFO)",
                cols.len()
            ),
            Some(Location::at_record(record)),
        ));
        return;
    }
    if header_cols >= 8 && cols.len() != header_cols {
        report.push(Finding::error(
            "vcf.column_count_mismatch",
            format!(
                "record {record} has {} columns but the #CHROM header declares {header_cols}",
                cols.len()
            ),
            Some(Location::at_record(record)),
        ));
    }
    if !is_valid_pos(cols[1]) {
        report.push(Finding::error(
            "vcf.bad_pos",
            format!(
                "record {record}: POS '{}' is not a non-negative integer",
                String::from_utf8_lossy(cols[1])
            ),
            Some(Location::at_record(record)),
        ));
    }
}

/// VCF POS is a non-negative integer (0 is the telomere convention).
fn is_valid_pos(field: &[u8]) -> bool {
    !field.is_empty() && field.iter().all(|b| b.is_ascii_digit())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p seqfw-core vcf`
Expected: PASS — the four new tests plus Task 1's. (`_info_ids`/`_format_ids` remain `_`-prefixed until Task 3.)

Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings` and `cargo fmt -p seqfw-core` — clean.

- [ ] **Step 5: Commit**

```bash
git add crates/seqfw-core/src/checks/vcf.rs
git commit -m "feat(core): VCF column-structure + coordinate-sanity checks"
```

---

## Task 3: VCF INFO/FORMAT header-tag consistency

**Files:**
- Modify: `crates/seqfw-core/src/checks/vcf.rs`

Collect `##INFO=<ID=...>` and `##FORMAT=<ID=...>` declarations from the header; flag (WARN) any INFO key or FORMAT key used in a data record that the header never declared. WARN, not ERROR — undeclared tags are common in real-world VCFs and shouldn't reject the file, but surfacing them catches header/record drift.

- [ ] **Step 1: Write the failing tests**

Add to `vcf.rs` `mod tests`:
```rust
    #[test]
    fn declared_info_and_format_pass() {
        let vcf = b"##fileformat=VCFv4.2\n\
##INFO=<ID=DP,Number=1,Type=Integer,Description=\"d\">\n\
##FORMAT=<ID=GT,Number=1,Type=String,Description=\"g\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\ts1\n\
chr1\t100\t.\tA\tG\t.\t.\tDP=5\tGT\t0/1\n";
        let r = vcf_check(vcf);
        assert!(r.ok(), "got {:?}", r.findings);
    }

    #[test]
    fn undeclared_info_warns() {
        let vcf = b"##fileformat=VCFv4.2\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
chr1\t100\t.\tA\tG\t.\t.\tXX=1\n";
        let r = vcf_check(vcf);
        assert!(r.ok(), "undeclared INFO is warn-only");
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "vcf.undeclared_info" && f.severity == crate::Severity::Warn));
    }

    #[test]
    fn undeclared_format_warns() {
        let vcf = b"##fileformat=VCFv4.2\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\ts1\n\
chr1\t100\t.\tA\tG\t.\t.\t.\tZZ\t1\n";
        let r = vcf_check(vcf);
        assert!(r.findings.iter().any(|f| f.rule == "vcf.undeclared_format"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p seqfw-core vcf`
Expected: `undeclared_info_warns` / `undeclared_format_warns` FAIL (no such findings yet); `declared_info_and_format_pass` may pass trivially for now.

- [ ] **Step 3: Parse declarations and check usage**

In `check`, replace the `##` handling block (the `if line.starts_with(b"##")` body) with:
```rust
                if line.starts_with(b"##") {
                    if line.starts_with(b"##fileformat=") {
                        seen_fileformat = true;
                    }
                    if let Some(id) = parse_meta_id(&line, b"##INFO=<") {
                        info_ids.insert(id);
                    }
                    if let Some(id) = parse_meta_id(&line, b"##FORMAT=<") {
                        format_ids.insert(id);
                    }
                    continue;
                }
```

Add the parser helpers near `split_tabs`:
```rust
/// Extract the `ID=` value from a structured meta line beginning with `prefix`,
/// e.g. `##INFO=<ID=DP,...>` → `DP`.
fn parse_meta_id(line: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    if !line.starts_with(prefix) {
        return None;
    }
    let rest = &line[prefix.len()..];
    let id_at = find_subslice(rest, b"ID=")?;
    let after = &rest[id_at + 3..];
    let end = after
        .iter()
        .position(|&c| c == b',' || c == b'>')
        .unwrap_or(after.len());
    Some(after[..end].to_vec())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
```

Extend `validate_data_line` (un-underscore `info_ids`/`format_ids`) — append, after the POS check:
```rust
    // INFO keys (column 8) must be header-declared. "." means no INFO.
    let info = cols[7];
    if info != b"." {
        for entry in info.split(|&c| c == b';') {
            let key = entry.split(|&c| c == b'=').next().unwrap_or(entry);
            if !key.is_empty() && !info_ids.contains(key) {
                report.push(Finding::warn(
                    "vcf.undeclared_info",
                    format!(
                        "record {record}: INFO key '{}' is not declared in the header",
                        String::from_utf8_lossy(key)
                    ),
                    Some(Location::at_record(record)),
                ));
                break; // one warning per record
            }
        }
    }

    // FORMAT keys (column 9, when present) must be header-declared.
    if cols.len() >= 9 {
        for key in cols[8].split(|&c| c == b':') {
            if !key.is_empty() && key != b"." && !format_ids.contains(key) {
                report.push(Finding::warn(
                    "vcf.undeclared_format",
                    format!(
                        "record {record}: FORMAT key '{}' is not declared in the header",
                        String::from_utf8_lossy(key)
                    ),
                    Some(Location::at_record(record)),
                ));
                break; // one warning per record
            }
        }
    }
```
Update the `validate_data_line` signature so `info_ids`/`format_ids` are no longer `_`-prefixed:
```rust
fn validate_data_line(
    line: &[u8],
    header_cols: usize,
    info_ids: &HashSet<Vec<u8>>,
    format_ids: &HashSet<Vec<u8>>,
    record: u64,
    report: &mut Report,
) {
```
Also remove the now-obsolete `let _ = (&info_ids, &format_ids);` line in `check`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p seqfw-core vcf`
Expected: PASS — all Task 3 tests plus Tasks 1–2. Run clippy + fmt; clean.

- [ ] **Step 5: Commit**

```bash
git add crates/seqfw-core/src/checks/vcf.rs
git commit -m "feat(core): VCF INFO/FORMAT header-tag consistency (warn on undeclared)"
```

---

## Task 4: VCF FORMAT-field-count safety + sample-name header safety

**Files:**
- Modify: `crates/seqfw-core/src/checks/vcf.rs`

The `CVE-2020-36403` class is a per-sample/FORMAT mismatch in `vcf_parse_format`: a sample column carrying **more** `:`-separated subfields than the FORMAT column declares keys is the out-of-bounds-write primitive (VCF permits *fewer* — trailing fields may be dropped — but never more). And sample names on the `#CHROM` line flow into downstream filenames/commands, so they get the cross-cutting identifier-safety scan.

- [ ] **Step 1: Write the failing tests**

Add to `vcf.rs` `mod tests`:
```rust
    #[test]
    fn extra_sample_subfields_is_rejected() {
        // FORMAT declares 1 key (GT) but the sample has 2 subfields
        let vcf = b"##fileformat=VCFv4.2\n\
##FORMAT=<ID=GT,Number=1,Type=String,Description=\"g\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\ts1\n\
chr1\t100\t.\tA\tG\t.\t.\t.\tGT\t0/1:99\n";
        let r = vcf_check(vcf);
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "vcf.format_field_mismatch"));
    }

    #[test]
    fn fewer_sample_subfields_is_allowed() {
        // FORMAT declares 2 keys; sample provides 1 (trailing dropped) — legal
        let vcf = b"##fileformat=VCFv4.2\n\
##FORMAT=<ID=GT,Number=1,Type=String,Description=\"g\">\n\
##FORMAT=<ID=DP,Number=1,Type=Integer,Description=\"d\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\ts1\n\
chr1\t100\t.\tA\tG\t.\t.\t.\tGT:DP\t0/1\n";
        let r = vcf_check(vcf);
        assert!(r.ok(), "got {:?}", r.findings);
    }

    #[test]
    fn unsafe_sample_name_is_flagged() {
        let vcf = b"##fileformat=VCFv4.2\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tsample;rm\n";
        let r = vcf_check(vcf);
        assert!(r.findings.iter().any(|f| f.rule == "safety.shell_metachar"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p seqfw-core vcf`
Expected: `extra_sample_subfields_is_rejected` and `unsafe_sample_name_is_flagged` FAIL.

- [ ] **Step 3: Implement the FORMAT-field count check + sample-name scan**

In `validate_data_line`, inside the `if cols.len() >= 9 {` block, after the undeclared-FORMAT loop, add:
```rust
        let n_keys = cols[8].split(|&c| c == b':').count();
        for sample in &cols[9..] {
            let n_sub = sample.split(|&c| c == b':').count();
            if n_sub > n_keys {
                report.push(Finding::error(
                    "vcf.format_field_mismatch",
                    format!(
                        "record {record}: a sample has {n_sub} subfields but FORMAT declares only {n_keys} keys (CVE-2020-36403-class field-count overflow)"
                    ),
                    Some(Location::at_record(record)),
                ));
                break; // one error per record
            }
        }
```

In `check`, replace the `#CHROM` handling block with one that scans sample names:
```rust
                if line.starts_with(b"#CHROM") {
                    seen_chrom_header = true;
                    let cols = split_tabs(&line);
                    header_cols = cols.len();
                    // Columns 10+ (index 9+) are sample names.
                    for (i, name) in cols.iter().enumerate().skip(9) {
                        super::safety::check_identifier(
                            name,
                            &format!("VCF sample name (column {})", i + 1),
                            None,
                            report,
                        );
                    }
                    continue;
                }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p seqfw-core vcf`
Expected: PASS — all VCF tests across Tasks 1–4.

Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings` and `cargo fmt -p seqfw-core` — clean.

- [ ] **Step 5: Commit**

```bash
git add crates/seqfw-core/src/checks/vcf.rs
git commit -m "feat(core): VCF FORMAT-field-count safety + sample-name screening"
```

---

## Task 5: Index module + `.fai` bounds checks + public `check_index_reader`

**Files:**
- Create: `crates/seqfw-core/src/checks/index.rs`
- Modify: `crates/seqfw-core/src/checks/mod.rs`
- Modify: `crates/seqfw-core/src/lib.rs`

A `.fai` FASTA index has one line per sequence with five tab-separated fields: `NAME LENGTH OFFSET LINEBASES LINEWIDTH`. We validate the column count, that the four numeric fields parse, that `LINEBASES <= LINEWIDTH <= LINEBASES + 2` (the newline width), and — when the companion data file's length is known — that `OFFSET + LENGTH <= data_len` (a conservative lower bound: the on-disk bytes are at least `LENGTH`).

- [ ] **Step 1: Create the index module with `.fai` + the binary read helpers**

`crates/seqfw-core/src/checks/index.rs`:
```rust
use std::io::{BufRead, BufReader, Read};

use crate::{Finding, Location, Report};

/// Validate a `.fai` FASTA index. `data_len` is the byte length of the indexed
/// `.fa`/`.fasta`, when known, enabling offset-in-bounds checks.
pub fn check_fai(reader: impl Read, data_len: Option<u64>, report: &mut Report) {
    let mut buf = BufReader::new(reader);
    let mut line = Vec::new();
    let mut record: u64 = 0;

    loop {
        line.clear();
        match buf.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
                while matches!(line.last(), Some(b'\n') | Some(b'\r')) {
                    line.pop();
                }
                if line.is_empty() {
                    continue;
                }
                record += 1;

                let cols: Vec<&[u8]> = line.split(|&c| c == b'\t').collect();
                if cols.len() != 5 {
                    report.push(Finding::error(
                        "fai.bad_columns",
                        format!(
                            "record {record}: expected 5 tab-separated columns, found {}",
                            cols.len()
                        ),
                        Some(Location::at_record(record)),
                    ));
                    continue;
                }

                let (length, offset, linebases, linewidth) =
                    match (num(cols[1]), num(cols[2]), num(cols[3]), num(cols[4])) {
                        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                        _ => {
                            report.push(Finding::error(
                                "fai.bad_number",
                                format!("record {record}: a numeric column is not a valid integer"),
                                Some(Location::at_record(record)),
                            ));
                            continue;
                        }
                    };

                if linewidth < linebases || linewidth > linebases + 2 {
                    report.push(Finding::error(
                        "fai.bad_linewidth",
                        format!(
                            "record {record}: LINEWIDTH ({linewidth}) must be LINEBASES ({linebases}) plus a 0–2 byte line terminator"
                        ),
                        Some(Location::at_record(record)),
                    ));
                }

                if let Some(data_len) = data_len {
                    if offset > data_len || offset.saturating_add(length) > data_len {
                        report.push(Finding::error(
                            "fai.offset_out_of_bounds",
                            format!(
                                "record {record}: OFFSET {offset} + LENGTH {length} exceeds the data file size ({data_len} bytes)"
                            ),
                            Some(Location::at_record(record)),
                        ));
                    }
                }
            }
            Err(e) => {
                super::push_read_error(report, &e.to_string());
                return;
            }
        }
    }
}

/// Parse an ASCII unsigned integer field.
fn num(field: &[u8]) -> Option<u64> {
    if field.is_empty() || !field.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(field).ok()?.parse().ok()
}

/// Read a little-endian u64 at `pos`, if in bounds.
pub(crate) fn read_u64_le(buf: &[u8], pos: usize) -> Option<u64> {
    buf.get(pos..pos + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// Read a little-endian i32 at `pos`, if in bounds.
pub(crate) fn read_i32_le(buf: &[u8], pos: usize) -> Option<i32> {
    buf.get(pos..pos + 4)
        .map(|s| i32::from_le_bytes(s.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use crate::Report;
    use std::io::Cursor;

    fn fai(data: &[u8], data_len: Option<u64>) -> Report {
        let mut report = Report::default();
        super::check_fai(Cursor::new(data.to_vec()), data_len, &mut report);
        report
    }

    #[test]
    fn valid_fai_passes() {
        // one sequence, length 12, offset 6 ('>seq1\n'), 60 bases/line, 61 width
        let r = fai(b"seq1\t12\t6\t60\t61\n", Some(100));
        assert!(r.ok(), "got {:?}", r.findings);
    }

    #[test]
    fn wrong_column_count_is_rejected() {
        let r = fai(b"seq1\t12\t6\t60\n", None);
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fai.bad_columns"));
    }

    #[test]
    fn non_numeric_field_is_rejected() {
        let r = fai(b"seq1\tXX\t6\t60\t61\n", None);
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fai.bad_number"));
    }

    #[test]
    fn offset_past_end_is_rejected() {
        let r = fai(b"seq1\t12\t6\t60\t61\n", Some(10));
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fai.offset_out_of_bounds"));
    }
}
```

- [ ] **Step 2: Register the module + add `IndexKind` and `check_index_reader`**

In `crates/seqfw-core/src/checks/mod.rs`, add near the other `pub mod` lines:
```rust
pub mod index;
```

In `crates/seqfw-core/src/lib.rs`, add the `IndexKind` enum (below `Format`):
```rust
/// A companion index file kind, selected by extension by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexKind {
    /// `.fai` — FASTA index (text).
    Fai,
    /// `.gzi` — bgzip index (uncompressed binary).
    Gzi,
    /// `.tbi` — tabix index (BGZF-compressed binary).
    Tbi,
    /// `.csi` — coordinate-sorted index (BGZF-compressed binary).
    Csi,
}
```
and add the public entry point (below `check_pair_reader`):
```rust
/// Validate a companion index file. `data_len` is the byte length of the data
/// file the index points into, when available, enabling offset-in-bounds checks.
/// `.tbi`/`.csi` are BGZF-compressed and ride the same decode+bomb guard as data
/// streams; `.fai` (text) and `.gzi` (binary) pass through `open_guarded`.
pub fn check_index_reader(
    kind: IndexKind,
    reader: Box<dyn Read>,
    data_len: Option<u64>,
    opts: &Options,
) -> Report {
    let mut report = Report::default();
    let stream = source::open_guarded(reader, opts);
    match kind {
        IndexKind::Fai => checks::index::check_fai(stream, data_len, &mut report),
        IndexKind::Gzi => checks::index::check_gzi(stream, data_len, &mut report),
        IndexKind::Tbi | IndexKind::Csi => checks::index::check_tabix(kind, stream, &mut report),
    }
    report
}
```
> This references `check_gzi` (Task 6) and `check_tabix` (Task 7), which do not exist yet — the crate will not compile until those are added. Implement them next; run this task's `.fai` tests after Task 7. (To keep Task 5 independently green, you may temporarily stub the two arms with `_ => {}` and the missing kinds; but the cleaner path is to land Tasks 5–7 together before running the full suite. Either way, the `.fai` unit tests in Step 1 can be run in isolation with `cargo test -p seqfw-core check_fai`-scoped names once the module compiles.)

- [ ] **Step 3: Commit (compiles after Task 7)**

```bash
git add crates/seqfw-core/src/checks/index.rs crates/seqfw-core/src/checks/mod.rs crates/seqfw-core/src/lib.rs
git commit -m "feat(core): index module + .fai bounds checks + check_index_reader API"
```

---

## Task 6: `.gzi` binary index validation

**Files:**
- Modify: `crates/seqfw-core/src/checks/index.rs`

A `.gzi` (bgzip index) is uncompressed little-endian binary: a `u64` entry count, then that many `(u64 compressed_offset, u64 uncompressed_offset)` pairs. The file must be exactly `8 + 16*count` bytes — a mismatch (especially a wildly large declared count) is the integer-overflow class. Offsets must be monotonic non-decreasing, and compressed offsets must lie within the data file when its length is known.

- [ ] **Step 1: Write the implementation**

Append to `crates/seqfw-core/src/checks/index.rs` (above the `#[cfg(test)]` module):
```rust
/// Validate a `.gzi` bgzip index (uncompressed little-endian binary).
pub fn check_gzi(mut reader: impl Read, data_len: Option<u64>, report: &mut Report) {
    let mut buf = Vec::new();
    if let Err(e) = reader.read_to_end(&mut buf) {
        super::push_read_error(report, &e.to_string());
        return;
    }
    let len = buf.len() as u64;
    if len < 8 {
        report.push(Finding::error(
            "gzi.truncated",
            "file is too short to contain the entry count (need at least 8 bytes)".to_string(),
            None,
        ));
        return;
    }

    let count = read_u64_le(&buf, 0).unwrap();
    // Body must be exactly count * 16 bytes; reject overflow / size mismatch.
    let expected = count.checked_mul(16).and_then(|b| b.checked_add(8));
    if expected != Some(len) {
        report.push(Finding::error(
            "gzi.bad_entry_count",
            format!(
                "declared {count} entries implies {} bytes but the file is {len} (impossible / corrupt count)",
                expected.map_or("an overflowing number of".to_string(), |e| e.to_string())
            ),
            None,
        ));
        return;
    }

    let mut prev = (0u64, 0u64);
    for i in 0..count as usize {
        let base = 8 + i * 16;
        let comp = read_u64_le(&buf, base).unwrap();
        let uncomp = read_u64_le(&buf, base + 8).unwrap();
        if comp < prev.0 || uncomp < prev.1 {
            report.push(Finding::error(
                "gzi.non_monotonic",
                format!("entry {} offsets decrease (index must be monotonic)", i + 1),
                Some(Location::at_record((i + 1) as u64)),
            ));
            return;
        }
        if let Some(data_len) = data_len {
            if comp > data_len {
                report.push(Finding::error(
                    "gzi.offset_out_of_bounds",
                    format!(
                        "entry {}: compressed offset {comp} exceeds the data file size ({data_len} bytes)",
                        i + 1
                    ),
                    Some(Location::at_record((i + 1) as u64)),
                ));
                return;
            }
        }
        prev = (comp, uncomp);
    }
}
```

- [ ] **Step 2: Add tests**

Add to the `#[cfg(test)] mod tests` in `index.rs`:
```rust
    fn gzi_bytes(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut v = (entries.len() as u64).to_le_bytes().to_vec();
        for (c, u) in entries {
            v.extend_from_slice(&c.to_le_bytes());
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn gzi(bytes: &[u8], data_len: Option<u64>) -> Report {
        let mut report = Report::default();
        super::check_gzi(Cursor::new(bytes.to_vec()), data_len, &mut report);
        report
    }

    #[test]
    fn valid_gzi_passes() {
        let r = gzi(&gzi_bytes(&[(0, 0), (1000, 65280)]), Some(100_000));
        assert!(r.ok(), "got {:?}", r.findings);
    }

    #[test]
    fn impossible_gzi_count_is_rejected() {
        // claim u64::MAX entries with an empty body
        let bytes = u64::MAX.to_le_bytes().to_vec();
        let r = gzi(&bytes, None);
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "gzi.bad_entry_count"));
    }

    #[test]
    fn non_monotonic_gzi_is_rejected() {
        let r = gzi(&gzi_bytes(&[(1000, 1000), (500, 2000)]), None);
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "gzi.non_monotonic"));
    }

    #[test]
    fn gzi_offset_past_data_end_is_rejected() {
        let r = gzi(&gzi_bytes(&[(0, 0), (999_999, 0)]), Some(1000));
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "gzi.offset_out_of_bounds"));
    }
```

- [ ] **Step 3: Commit (compiles after Task 7)**

```bash
git add crates/seqfw-core/src/checks/index.rs
git commit -m "feat(core): .gzi index bounds + impossible-count guard"
```

---

## Task 7: `.tbi` / `.csi` BGZF index validation (magic + impossible-count guard)

**Files:**
- Modify: `crates/seqfw-core/src/checks/index.rs`

`.tbi` and `.csi` are BGZF-compressed binary (already decompressed by `open_guarded` before reaching here). This task validates the **magic number** and that the leading **count/length header fields fit within the decompressed payload** — the `CVE-2026-31970` impossible-count class. It is intentionally a header-level guard, not a full bin/chunk/interval walk.

- [ ] **Step 1: Write the implementation**

Append to `index.rs` (above the test module):
```rust
use crate::IndexKind;

/// Per-format sanity cap on reference-sequence counts (more than this is absurd).
const MAX_REFS: i32 = 1_000_000;

/// Validate a `.tbi`/`.csi` index header after BGZF decompression.
pub fn check_tabix(kind: IndexKind, mut reader: impl Read, report: &mut Report) {
    let mut buf = Vec::new();
    if let Err(e) = reader.read_to_end(&mut buf) {
        super::push_read_error(report, &e.to_string());
        return;
    }

    let magic: &[u8] = match kind {
        IndexKind::Tbi => b"TBI\x01",
        IndexKind::Csi => b"CSI\x01",
        _ => return, // never reached: lib routes only Tbi/Csi here
    };
    if buf.len() < 4 || &buf[0..4] != magic {
        report.push(Finding::error(
            "tabix.bad_magic",
            "missing the expected tabix/CSI magic number".to_string(),
            None,
        ));
        return;
    }

    match kind {
        IndexKind::Tbi => {
            // magic[4] + 8 int32 fields (n_ref, format, col_seq, col_beg,
            // col_end, meta, skip, l_nm) = 36 bytes.
            let (n_ref, l_nm) = match (read_i32_le(&buf, 4), read_i32_le(&buf, 4 + 7 * 4)) {
                (Some(a), Some(b)) => (a, b),
                _ => {
                    report.push(Finding::error(
                        "tabix.truncated",
                        "header ends before the mandatory tabix fields".to_string(),
                        None,
                    ));
                    return;
                }
            };
            check_counts(n_ref, l_nm, 36, buf.len(), report);
        }
        IndexKind::Csi => {
            // magic[4] + min_shift(4) + depth(4) + l_aux(4) = 16 bytes, then
            // aux[l_aux], then n_ref(4).
            let l_aux = match read_i32_le(&buf, 4 + 2 * 4) {
                Some(v) => v,
                None => {
                    report.push(Finding::error(
                        "tabix.truncated",
                        "header ends before the CSI aux-length field".to_string(),
                        None,
                    ));
                    return;
                }
            };
            if l_aux < 0 || (16i64 + l_aux as i64 + 4) > buf.len() as i64 {
                report.push(Finding::error(
                    "tabix.impossible_count",
                    format!("CSI l_aux ({l_aux}) is negative or exceeds the payload"),
                    None,
                ));
                return;
            }
            let n_ref = match read_i32_le(&buf, 16 + l_aux as usize) {
                Some(v) => v,
                None => {
                    report.push(Finding::error(
                        "tabix.truncated",
                        "header ends before the CSI n_ref field".to_string(),
                        None,
                    ));
                    return;
                }
            };
            check_counts(n_ref, 0, 16 + l_aux as usize + 4, buf.len(), report);
        }
        _ => {}
    }
}

/// Reject negative or impossibly large header counts (the integer-overflow
/// class): `n_ref` must be in `0..=MAX_REFS`, and `l_nm` (name-block length)
/// must be non-negative and fit in the bytes after `header_end`.
fn check_counts(n_ref: i32, l_nm: i32, header_end: usize, total: usize, report: &mut Report) {
    if !(0..=MAX_REFS).contains(&n_ref) {
        report.push(Finding::error(
            "tabix.impossible_count",
            format!("n_ref ({n_ref}) is negative or implausibly large (> {MAX_REFS})"),
            None,
        ));
        return;
    }
    if l_nm < 0 || header_end as i64 + l_nm as i64 > total as i64 {
        report.push(Finding::error(
            "tabix.impossible_count",
            format!("name-block length ({l_nm}) is negative or exceeds the payload"),
            None,
        ));
    }
}
```
> Move the `use crate::IndexKind;` to the top of the file with the other `use` lines if the implementer prefers; placing it mid-file is valid Rust but `cargo fmt` will leave it — group it with the top imports for cleanliness.

- [ ] **Step 2: Add tests**

Add to `index.rs` `mod tests`:
```rust
    use crate::IndexKind;

    fn tabix(kind: IndexKind, bytes: &[u8]) -> Report {
        let mut report = Report::default();
        super::check_tabix(kind, Cursor::new(bytes.to_vec()), &mut report);
        report
    }

    fn tbi_header(n_ref: i32, l_nm: i32, name_bytes: usize) -> Vec<u8> {
        let mut v = b"TBI\x01".to_vec();
        for f in [n_ref, 0, 1, 2, 3, 0, 0, l_nm] {
            v.extend_from_slice(&f.to_le_bytes());
        }
        v.extend(std::iter::repeat_n(0u8, name_bytes));
        v
    }

    #[test]
    fn valid_tbi_header_passes() {
        let r = tabix(IndexKind::Tbi, &tbi_header(2, 8, 8));
        assert!(r.ok(), "got {:?}", r.findings);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let r = tabix(IndexKind::Tbi, b"NOPE\x00\x00\x00\x00");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "tabix.bad_magic"));
    }

    #[test]
    fn impossible_n_ref_is_rejected() {
        let r = tabix(IndexKind::Tbi, &tbi_header(i32::MAX, 0, 0));
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "tabix.impossible_count"));
    }

    #[test]
    fn impossible_name_block_is_rejected() {
        // claims an 8000-byte name block but ships none
        let r = tabix(IndexKind::Tbi, &tbi_header(1, 8000, 0));
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "tabix.impossible_count"));
    }
```

- [ ] **Step 3: Build the whole core crate + test + lint**

Run: `cargo test -p seqfw-core`
Expected: PASS — all `.fai`/`.gzi`/`.tbi` index tests (the crate now compiles, resolving Task 5's forward references) plus every VCF and Plan 1–3 test.

Run: `cargo clippy -p seqfw-core --all-targets -- -D warnings` and `cargo fmt -p seqfw-core` — clean.

- [ ] **Step 4: Commit**

```bash
git add crates/seqfw-core/src/checks/index.rs
git commit -m "feat(core): .tbi/.csi magic + impossible-count guard (CVE-2026-31970 class)"
```

---

## Task 8: CLI — `--data` flag, index-by-extension routing, VCF/`.fai` corpus + e2e tests

**Files:**
- Modify: `crates/seqfw-cli/src/main.rs`
- Create: `corpus/vcf/pass/good.vcf`, `corpus/vcf/fail/bad_pos.vcf`, `corpus/vcf/fail/format_mismatch.vcf`
- Create: `corpus/fai/pass/ref.fa`, `corpus/fai/pass/ref.fa.fai`, `corpus/fai/fail/oob.fa.fai`
- Modify: `crates/seqfw-cli/tests/cli.rs`

- [ ] **Step 1: Create corpus fixtures**

`corpus/vcf/pass/good.vcf`:
```
##fileformat=VCFv4.2
##INFO=<ID=DP,Number=1,Type=Integer,Description="Total Depth">
##FORMAT=<ID=GT,Number=1,Type=String,Description="Genotype">
#CHROM	POS	ID	REF	ALT	QUAL	FILTER	INFO	FORMAT	sample1
chr1	100	.	A	G	50	PASS	DP=20	GT	0/1
chr1	200	rs1	C	T	99	PASS	DP=35	GT	1/1
```
> The columns above are separated by **single tab characters**, not spaces — ensure the fixture uses literal tabs.

`corpus/vcf/fail/bad_pos.vcf`:
```
##fileformat=VCFv4.2
#CHROM	POS	ID	REF	ALT	QUAL	FILTER	INFO
chr1	NOTANUMBER	.	A	G	.	.	.
```

`corpus/vcf/fail/format_mismatch.vcf`:
```
##fileformat=VCFv4.2
##FORMAT=<ID=GT,Number=1,Type=String,Description="Genotype">
#CHROM	POS	ID	REF	ALT	QUAL	FILTER	INFO	FORMAT	sample1
chr1	100	.	A	G	.	.	.	GT	0/1:99
```

`corpus/fai/pass/ref.fa` (12 bases, so the matching `.fai` below is in-bounds):
```
>seq1
ACGTACGTACGT
```

`corpus/fai/pass/ref.fa.fai` (NAME LENGTH OFFSET LINEBASES LINEWIDTH, tab-separated; `>seq1\n` is 6 bytes so OFFSET=6):
```
seq1	12	6	12	13
```

`corpus/fai/fail/oob.fa.fai` (offset far past the 19-byte `ref.fa`):
```
seq1	12	9000	12	13
```

- [ ] **Step 2: Add `Vcf` to `FormatArg`, the `--data` flag, and index routing**

In `crates/seqfw-cli/src/main.rs`:

Extend the import:
```rust
use seqfw_core::{
    check_index_reader, check_pair_reader, check_path, check_reader, Format, IndexKind, Options,
    Report, SeqAlphabet, Severity,
};
```

Add `Vcf` to the value-enum + mapping:
```rust
#[derive(Clone, Copy, clap::ValueEnum)]
enum FormatArg {
    Fastq,
    Fasta,
    Vcf,
}

impl From<FormatArg> for Format {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Fastq => Format::Fastq,
            FormatArg::Fasta => Format::Fasta,
            FormatArg::Vcf => Format::Vcf,
        }
    }
}
```

Add the `--data` flag to the `Check` variant (after `format`):
```rust
        /// For an index file (.fai/.gzi/.tbi/.csi), the data file it indexes,
        /// enabling offset-in-bounds checks.
        #[arg(long, value_name = "PATH")]
        data: Option<String>,
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
            data,
        } => run_check(
            &path,
            mate.as_deref(),
            json,
            strict_dna,
            format.map(Into::into),
            data.as_deref(),
        ),
    }
}
```

Add the signature param and an index branch at the top of `run_check`'s report selection. Change the signature to:
```rust
fn run_check(
    path: &str,
    mate: Option<&str>,
    json: bool,
    strict_dna: bool,
    format: Option<Format>,
    data: Option<&str>,
) -> ExitCode {
```
Then, immediately after building `opts` and before the `let report = match mate {` block, insert an index short-circuit:
```rust
    if let Some(kind) = index_kind_from_path(path) {
        let data_len = match data {
            Some(d) => match std::fs::metadata(d) {
                Ok(m) => Some(m.len()),
                Err(e) => {
                    eprintln!("seqfw: cannot stat {d}: {e}");
                    return ExitCode::from(2);
                }
            },
            None => None,
        };
        let reader = match open_input(path) {
            Ok(r) => r,
            Err(code) => return code,
        };
        let report = check_index_reader(kind, reader, data_len, &opts);
        return finish(&report, path, json);
    }
```
Refactor the tail of `run_check` (the `if json { ... } else { ... }` + exit-code block) into a shared `finish` helper so both paths use it:
```rust
/// Render a report and map it to the process exit code.
fn finish(report: &Report, path: &str, json: bool) -> ExitCode {
    if json {
        render_json(report);
    } else {
        render_human(report, path);
    }
    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
```
and replace the existing tail of `run_check` (everything after the `let report = match mate { ... };`) with:
```rust
    finish(&report, path, json)
}

/// Map a path's extension to an index kind, if it names a known index file.
fn index_kind_from_path(path: &str) -> Option<IndexKind> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".fai") {
        Some(IndexKind::Fai)
    } else if lower.ends_with(".gzi") {
        Some(IndexKind::Gzi)
    } else if lower.ends_with(".tbi") {
        Some(IndexKind::Tbi)
    } else if lower.ends_with(".csi") {
        Some(IndexKind::Csi)
    } else {
        None
    }
}
```
> Net effect: `run_check` first checks for an index extension (routing to `check_index_reader`), otherwise falls through to the unchanged mate/stdin/file dispatch, and both render via `finish`.

- [ ] **Step 3: Write the failing end-to-end tests**

Append to `crates/seqfw-cli/tests/cli.rs`:
```rust
#[test]
fn check_good_vcf_exits_zero() {
    seqfw()
        .args(["check", "../../corpus/vcf/pass/good.vcf"])
        .assert()
        .success();
}

#[test]
fn check_bad_pos_vcf_exits_one() {
    seqfw()
        .args(["check", "../../corpus/vcf/fail/bad_pos.vcf"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("vcf.bad_pos"));
}

#[test]
fn check_format_mismatch_vcf_exits_one() {
    seqfw()
        .args(["check", "../../corpus/vcf/fail/format_mismatch.vcf"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("vcf.format_field_mismatch"));
}

#[test]
fn check_valid_fai_with_data_exits_zero() {
    seqfw()
        .args([
            "check",
            "../../corpus/fai/pass/ref.fa.fai",
            "--data",
            "../../corpus/fai/pass/ref.fa",
        ])
        .assert()
        .success();
}

#[test]
fn check_out_of_bounds_fai_exits_one() {
    seqfw()
        .args([
            "check",
            "../../corpus/fai/fail/oob.fa.fai",
            "--data",
            "../../corpus/fai/pass/ref.fa",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fai.offset_out_of_bounds"));
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p seqfw-cli`
Expected: PASS — the five new tests plus every Plan 1–3 CLI test.

- [ ] **Step 5: Manual smoke check**

Run: `cargo run -p seqfw-cli -- check corpus/fai/fail/oob.fa.fai --data corpus/fai/pass/ref.fa`
Expected: `REJECT ...` with a `fai.offset_out_of_bounds` line; `echo $?` is `1`.

- [ ] **Step 6: Commit**

```bash
git add crates/seqfw-cli/src/main.rs crates/seqfw-cli/tests/cli.rs corpus/
git commit -m "feat(cli): --data flag + index-by-extension routing; VCF + .fai e2e tests"
```

---

## Task 9: Final gate + README refresh + push

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Refresh the README**

Update the status blurb to mention VCF + index validation, and add usage lines. Replace the status line:
```markdown
> Status: early development. v1 target: FASTQ / FASTA / VCF. This build validates
> FASTQ (framing + content + paired-end), FASTA (structure + naming), and VCF
> (header/record/tag + CVE-2020-36403-class FORMAT-field safety) files, checks
> companion index files (.fai/.gzi/.tbi/.csi) for impossible counts and
> out-of-bounds offsets, auto-detects format, screens identifiers for unsafe
> characters, and blocks gzip/bgzf decompression bombs.
```
and add to the "Use" block:
```bash
seqfw check cohort.vcf.gz                     # VCF structural + tag validation
seqfw check ref.fa.fai --data ref.fa          # index-bounds vs the indexed file
```

- [ ] **Step 2: Run the whole suite**

Run: `cargo test`
Expected: all tests pass across both crates (Plans 1–3 + this plan's VCF, index, and CLI tests).

- [ ] **Step 3: Run clippy + fmt gates**

Run: `cargo clippy --all-targets -- -D warnings` — no warnings.
Run: `cargo fmt --all -- --check` — clean (else `cargo fmt --all` and add a `style:` commit).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document VCF validation + index-bounds checks"
```

- [ ] **Step 5: Push directly to main**

Per the project's solo direct-to-main flow (no PR):
```bash
git push origin main
```

---

## Self-Review (completed by plan author)

**Spec coverage (Plan 4 subset of §6):** VCF "Record/column structural validation" → Tasks 1–2 (`vcf.missing_fileformat`, `vcf.missing_header`, `vcf.too_few_columns`, `vcf.column_count_mismatch`, `vcf.line_too_long`); "Coordinate sanity" → Task 2 (`vcf.bad_pos`); "INFO/FORMAT tags declared in header" → Task 3 (`vcf.undeclared_info`/`vcf.undeclared_format`, WARN); "FORMAT-field parsing safety (the CVE-2020-36403 class)" → Task 4 (`vcf.format_field_mismatch`, ERROR); cross-cutting sample-name screening → Task 4 (reuses `checks::safety`). Transport "Index sanity for `.gzi`/`.tbi`/`.csi`/`.fai`: offsets and item-counts within bounds; reject impossibly large counts (the CVE-2026-31970 class)" → Tasks 5–7. **Deliberately bounded** (tracked, not gaps): `.tbi`/`.csi` are validated at the header/count level (the security-relevant integer-overflow surface), not via a full bin/chunk/interval traversal — noted in Scope and Task 7; "numeric fields within type bounds" for VCF INFO/FORMAT *values* (vs the field-count safety we do enforce) is deferred as lower-value parsing depth.

**Compile-order honesty:** Task 5 adds `check_index_reader` referencing `check_gzi` (Task 6) and `check_tabix` (Task 7); the crate does not compile until Task 7. This is called out explicitly in Task 5 Step 2 and Step 3, mirroring Plan 1's Task 4→5 forward reference. Tasks 5–7 should land together before running the full suite; each adds only its own additive code so the final state is clean.

**Routing/regression safety:** the sniffer gains a `#` → `Vcf` arm; no existing fixture begins with `#` (FASTQ `@`, FASTA `>`), so nothing reroutes. Index files are selected by **extension** in the CLI and never reach the content sniffer, so they don't collide with format detection. `.fai`/`.gzi`/`.tbi`/`.csi` all pass through `open_guarded`, which is a no-op on non-gzip inputs (`.fai` text, `.gzi` binary) and the existing decode path on BGZF (`.tbi`/`.csi`) — reusing the bomb guard for free.

**Type/contract consistency:** `Format` gains `Vcf` in Task 1 (exactly when the module + dispatch arm exist); `IndexKind` is defined in `lib.rs` (crate root, public). `check_index_reader(IndexKind, Box<dyn Read>, Option<u64>, &Options) -> Report` mirrors the existing `check_reader` shape with the data-length cross-check parameter. Binary reads use bounds-checked `read_u64_le`/`read_i32_le` helpers (never indexing slices unchecked), and `checked_mul`/`saturating_add` guard every count arithmetic — the integer-overflow defense applies to *our* parser too, per the spec's §9 "we hold ourselves to the standard we demand of htslib." The CLI `FormatArg` stays a thin `clap::ValueEnum`; `clap` does not leak into core.

**False-positive analysis:** VCF `vcf.undeclared_info`/`vcf.undeclared_format` are WARN (real VCFs omit declarations), so a header-light-but-structurally-valid file still exits 0; only structural/coordinate/field-count faults are ERROR. The `.fai` offset check uses the conservative `OFFSET + LENGTH <= data_len` lower bound (on-disk bytes are at least `LENGTH`), so a valid index never trips it. `MAX_REFS = 1_000_000` is orders of magnitude above any real reference (GRCh38 has ~25 primary + a few thousand contigs), so legitimate indexes pass while overflow-class counts are rejected.

**Placeholder scan:** no TBD/TODO. `validate_data_line` is intentionally empty in Task 1 and fully implemented across Tasks 2–4 (each task un-`_`-prefixes the params it begins using); this is described at each step, not a hidden stub. Every code block is complete and compiles at the point its task (or, for Tasks 5–7, its task group) ends.

---

## Addendum (apply during Tasks 5–7): index memory-safety hardening + `.csi` test

**Why:** the binary index checks buffer the whole file (`read_to_end`), and `.fai`'s `read_until` has no per-line cap — so an uncompressed `.gzi`/`.csi`/`.tbi` or a newline-free `.fai` could allocate unbounded memory. The decompression-bomb guard only engages on *gzip* inputs, so uncompressed index files bypass it. This addendum bounds every index read. It also adds the missing `.csi` unit test. Apply these deltas as part of the relevant tasks; they introduce two rule ids: `fai.line_too_long` and `index.too_large`.

- [ ] **A. `Options` gains an index-size cap (in Task 5 Step 2, `lib.rs`)**

Add to `Options` (after `forced_format`):
```rust
    /// Absolute cap on bytes buffered when validating a binary index file.
    pub max_index_bytes: u64,
```
and to `Default` (after `forced_format: None,`):
```rust
            max_index_bytes: 256 * 1024 * 1024, // 256 MiB
```

- [ ] **B. Thread `opts` into all three index checkers (Task 5 `check_index_reader`)**

```rust
    match kind {
        IndexKind::Fai => checks::index::check_fai(stream, data_len, opts, &mut report),
        IndexKind::Gzi => checks::index::check_gzi(stream, data_len, opts, &mut report),
        IndexKind::Tbi | IndexKind::Csi => checks::index::check_tabix(kind, stream, opts, &mut report),
    }
```

- [ ] **C. `check_fai`: take `opts`, add a per-line cap (Task 5 Step 1, `index.rs`)**

Change the imports to add `Options`:
```rust
use crate::{Finding, Location, Options, Report};
```
Change the signature to `pub fn check_fai(reader: impl Read, data_len: Option<u64>, opts: &Options, report: &mut Report)`, and as the first statement inside the `Ok(_) =>` arm (before stripping terminators) add:
```rust
                if line.len() > opts.max_line_len {
                    report.push(Finding::error(
                        "fai.line_too_long",
                        format!(
                            "record {}: line exceeds the {}-byte limit (possible resource-exhaustion input)",
                            record + 1,
                            opts.max_line_len
                        ),
                        Some(Location::at_record(record + 1)),
                    ));
                    return;
                }
```
> `check_fai` does not accumulate lines, so with the per-line cap it validates an arbitrarily long `.fai` in bounded memory.

- [ ] **D. `check_gzi`: take `opts`, cap the buffered read (Task 6)**

Signature → `pub fn check_gzi(reader: impl Read, data_len: Option<u64>, opts: &Options, report: &mut Report)`. Replace the `read_to_end` preamble with:
```rust
    let cap = opts.max_index_bytes;
    let mut buf = Vec::new();
    if let Err(e) = reader.take(cap + 1).read_to_end(&mut buf) {
        super::push_read_error(report, &e.to_string());
        return;
    }
    if buf.len() as u64 > cap {
        report.push(Finding::error(
            "index.too_large",
            format!("index exceeds the {cap}-byte sanity cap (possible resource-exhaustion input)"),
            None,
        ));
        return;
    }
```

- [ ] **E. `check_tabix`: take `opts`, cap the buffered read (Task 7)**

Signature → `pub fn check_tabix(kind: IndexKind, reader: impl Read, opts: &Options, report: &mut Report)`. Replace its `read_to_end` preamble with the same `cap`/`take`/`index.too_large` block as in D (placed before the magic check).

- [ ] **F. Update test helpers + add coverage (Tasks 5–7 `mod tests`)**

Thread `opts` through the helpers (default except the cap test):
```rust
    fn fai(data: &[u8], data_len: Option<u64>) -> Report {
        let mut report = Report::default();
        super::check_fai(Cursor::new(data.to_vec()), data_len, &Options::default(), &mut report);
        report
    }
    fn gzi(bytes: &[u8], data_len: Option<u64>) -> Report {
        let mut report = Report::default();
        super::check_gzi(Cursor::new(bytes.to_vec()), data_len, &Options::default(), &mut report);
        report
    }
    fn tabix(kind: IndexKind, bytes: &[u8]) -> Report {
        let mut report = Report::default();
        super::check_tabix(kind, Cursor::new(bytes.to_vec()), &Options::default(), &mut report);
        report
    }
```
Add `use crate::Options;` to the `index.rs` test module. Then add:
```rust
    #[test]
    fn oversized_gzi_is_rejected() {
        let opts = Options { max_index_bytes: 64, ..Options::default() };
        let mut report = Report::default();
        super::check_gzi(Cursor::new(vec![0u8; 256]), None, &opts, &mut report);
        assert!(!report.ok());
        assert!(report.findings.iter().any(|f| f.rule == "index.too_large"));
    }

    fn csi_header(l_aux: i32, n_ref: i32) -> Vec<u8> {
        let mut v = b"CSI\x01".to_vec();
        for f in [14, 5, l_aux] {
            v.extend_from_slice(&(f as i32).to_le_bytes());
        }
        v.extend(std::iter::repeat_n(0u8, l_aux.max(0) as usize));
        v.extend_from_slice(&n_ref.to_le_bytes());
        v
    }

    #[test]
    fn valid_csi_header_passes() {
        let r = tabix(IndexKind::Csi, &csi_header(0, 2));
        assert!(r.ok(), "got {:?}", r.findings);
    }

    #[test]
    fn impossible_csi_n_ref_is_rejected() {
        let r = tabix(IndexKind::Csi, &csi_header(0, i32::MAX));
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "tabix.impossible_count"));
    }
```

This addendum updates the **Rule ids** list with `fai.line_too_long` and `index.too_large`, and resolves the self-review's "`.csi` implemented but untested" gap.
