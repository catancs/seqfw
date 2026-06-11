use std::io::{BufRead, BufReader, Read};

use crate::{Finding, IndexKind, Location, Options, Report};

/// Validate a `.fai` FASTA index. `data_len` is the byte length of the indexed
/// `.fa`/`.fasta`, when known, enabling offset-in-bounds checks. The check
/// streams line by line (bounded by `max_line_len`), so it uses constant memory.
pub fn check_fai(reader: impl Read, data_len: Option<u64>, opts: &Options, report: &mut Report) {
    let mut buf = BufReader::new(reader);
    let mut line = Vec::new();
    let mut record: u64 = 0;

    loop {
        line.clear();
        match buf.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
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
                            "record {record}: LINEWIDTH ({linewidth}) must be LINEBASES ({linebases}) plus a 0-2 byte line terminator"
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

/// Buffer a binary index with a hard size cap; returns `None` (after reporting)
/// on a read error or when the cap is exceeded.
fn read_capped(mut reader: impl Read, cap: u64, report: &mut Report) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    if let Err(e) = reader.by_ref().take(cap + 1).read_to_end(&mut buf) {
        super::push_read_error(report, &e.to_string());
        return None;
    }
    if buf.len() as u64 > cap {
        report.push(Finding::error(
            "index.too_large",
            format!("index exceeds the {cap}-byte sanity cap (possible resource-exhaustion input)"),
            None,
        ));
        return None;
    }
    Some(buf)
}

/// Validate a `.gzi` bgzip index (uncompressed little-endian binary): a `u64`
/// entry count followed by that many `(compressed, uncompressed)` u64 offset
/// pairs. The file must be exactly `8 + 16*count` bytes.
pub fn check_gzi(reader: impl Read, data_len: Option<u64>, opts: &Options, report: &mut Report) {
    let buf = match read_capped(reader, opts.max_index_bytes, report) {
        Some(b) => b,
        None => return,
    };
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

/// Per-format sanity cap on reference-sequence counts (more than this is absurd).
const MAX_REFS: i32 = 1_000_000;

/// Validate a `.tbi`/`.csi` index header after BGZF decompression: the magic
/// number and that the leading count/length fields fit within the payload (the
/// `CVE-2026-31970` impossible-count class). Header-level guard, not a full walk.
pub fn check_tabix(kind: IndexKind, reader: impl Read, opts: &Options, report: &mut Report) {
    let buf = match read_capped(reader, opts.max_index_bytes, report) {
        Some(b) => b,
        None => return,
    };

    let magic: &[u8] = match kind {
        IndexKind::Tbi => b"TBI\x01",
        IndexKind::Csi => b"CSI\x01",
        _ => return, // lib routes only Tbi/Csi here
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

#[cfg(test)]
mod tests {
    use crate::{IndexKind, Options, Report};
    use std::io::Cursor;

    fn fai(data: &[u8], data_len: Option<u64>) -> Report {
        let mut report = Report::default();
        super::check_fai(
            Cursor::new(data.to_vec()),
            data_len,
            &Options::default(),
            &mut report,
        );
        report
    }

    #[test]
    fn valid_fai_passes() {
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
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "fai.offset_out_of_bounds"));
    }

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
        super::check_gzi(
            Cursor::new(bytes.to_vec()),
            data_len,
            &Options::default(),
            &mut report,
        );
        report
    }

    #[test]
    fn valid_gzi_passes() {
        let r = gzi(&gzi_bytes(&[(0, 0), (1000, 65280)]), Some(100_000));
        assert!(r.ok(), "got {:?}", r.findings);
    }

    #[test]
    fn impossible_gzi_count_is_rejected() {
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
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "gzi.offset_out_of_bounds"));
    }

    #[test]
    fn oversized_gzi_is_rejected() {
        let opts = Options {
            max_index_bytes: 64,
            ..Options::default()
        };
        let mut report = Report::default();
        super::check_gzi(Cursor::new(vec![0u8; 256]), None, &opts, &mut report);
        assert!(!report.ok());
        assert!(report.findings.iter().any(|f| f.rule == "index.too_large"));
    }

    fn tabix(kind: IndexKind, bytes: &[u8]) -> Report {
        let mut report = Report::default();
        super::check_tabix(
            kind,
            Cursor::new(bytes.to_vec()),
            &Options::default(),
            &mut report,
        );
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
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "tabix.impossible_count"));
    }

    #[test]
    fn impossible_name_block_is_rejected() {
        let r = tabix(IndexKind::Tbi, &tbi_header(1, 8000, 0));
        assert!(!r.ok());
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "tabix.impossible_count"));
    }

    fn csi_header(l_aux: i32, n_ref: i32) -> Vec<u8> {
        let mut v = b"CSI\x01".to_vec();
        for f in [14, 5, l_aux] {
            v.extend_from_slice(&f.to_le_bytes());
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
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "tabix.impossible_count"));
    }
}
