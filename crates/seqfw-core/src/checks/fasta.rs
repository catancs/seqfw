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
                    super::safety::check_identifier(
                        &line[1..],
                        &format!("FASTA record {record} header"),
                        Some(Location::at_record(record)),
                        report,
                    );
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
    fn fasta_header_shell_metachar_warns() {
        let r = fasta_check(b">seq$(whoami)\nACGT\n");
        assert!(r.findings.iter().any(|f| f.rule == "safety.shell_metachar"));
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
