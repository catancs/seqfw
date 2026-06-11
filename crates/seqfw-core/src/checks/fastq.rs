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
