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
                    if let Some(id) = parse_meta_id(&line, b"##INFO=<") {
                        info_ids.insert(id);
                    }
                    if let Some(id) = parse_meta_id(&line, b"##FORMAT=<") {
                        format_ids.insert(id);
                    }
                    continue;
                }

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

                // A data line.
                if !seen_chrom_header {
                    if !header_missing_reported {
                        report.push(Finding::error(
                            "vcf.missing_header",
                            "data record appears before the '#CHROM' column-header line"
                                .to_string(),
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

/// Per-data-record checks.
fn validate_data_line(
    line: &[u8],
    header_cols: usize,
    info_ids: &HashSet<Vec<u8>>,
    format_ids: &HashSet<Vec<u8>>,
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
    }
}

/// VCF POS is a non-negative integer (0 is the telomere convention).
fn is_valid_pos(field: &[u8]) -> bool {
    !field.is_empty() && field.iter().all(|b| b.is_ascii_digit())
}

/// Split a line into tab-separated columns.
fn split_tabs(line: &[u8]) -> Vec<&[u8]> {
    line.split(|&c| c == b'\t').collect()
}

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
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "vcf.missing_fileformat"));
    }

    #[test]
    fn data_before_header_is_rejected() {
        let r = vcf_check(b"##fileformat=VCFv4.2\nchr1\t100\t.\tA\tG\t.\t.\t.\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "vcf.missing_header"));
    }

    #[test]
    fn vcf_is_routed_via_sniffer() {
        let r = check_reader(
            Box::new(Cursor::new(MINIMAL_HEADER.to_vec())),
            &Options::default(),
        );
        assert!(r.ok(), "sniffed VCF should pass, got {:?}", r.findings);
    }

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
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "vcf.column_count_mismatch"));
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

    #[test]
    fn extra_sample_subfields_is_rejected() {
        // FORMAT declares 1 key (GT) but the sample has 2 subfields
        let vcf = b"##fileformat=VCFv4.2\n\
##FORMAT=<ID=GT,Number=1,Type=String,Description=\"g\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\ts1\n\
chr1\t100\t.\tA\tG\t.\t.\t.\tGT\t0/1:99\n";
        let r = vcf_check(vcf);
        assert!(!r.ok());
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "vcf.format_field_mismatch"));
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
}
