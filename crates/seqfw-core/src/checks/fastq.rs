use std::io::{BufRead, BufReader, Read};

use crate::bomb::BOMB_ERR;
use crate::{Finding, Location, Options, Report};

/// C0 control characters and DEL — never valid inside a FASTQ sequence or
/// quality line, and a classic injection/corruption primitive (esp. NUL).
fn is_control(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}

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

/// Run every per-record rule against one record.
fn validate_record(rec: &RawRecord, opts: &Options, report: &mut Report, qual_min: &mut u8) {
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

    validate_seq(seq, n, opts, report);
    validate_qual(qual, n, report, qual_min);
}

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

/// Scan a quality line for out-of-range bytes and track the file-wide minimum
/// in-range byte (used to decide Phred+33 vs +64 ambiguity). Control bytes are
/// left for `validate_seq`/`validate_qual`'s control path in Task 4; here a
/// byte `< 33` or `> 126` is an out-of-range Phred score.
fn validate_qual(qual: &[u8], n: u64, report: &mut Report, qual_min: &mut u8) {
    let mut range_reported = false;
    let mut control_reported = false;
    for &b in qual {
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
    fn bad_header_is_rejected() {
        // line 1 of record 1 must start with '@', here it's '!'
        let r = check_bytes(b"!r1\nACGT\n+\nIIII\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.bad_header"));
    }

    #[test]
    fn truncated_record_is_rejected() {
        let r = check_bytes(b"@r1\nACGT\n+\n"); // missing the quality line
        assert!(!r.ok());
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "fastq.truncated_record"));
    }

    #[test]
    fn length_mismatch_is_rejected() {
        // seq is 4 bases, qual is 3 bytes
        let r = check_bytes(b"@r1\nACGT\n+\nIII\n");
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.length_mismatch"));
    }

    #[test]
    fn phred_out_of_range_is_rejected() {
        // 0x1f is below the printable Phred floor (33). Use a control-free
        // out-of-range byte by making qual one byte too high: 0x7f handled in
        // Task 4 as a control char, so here use byte 127+1 territory via space.
        // Space (0x20 = 32) is < 33 and is NOT a control char.
        let r = check_bytes(b"@r1\nAC\n+\n  \n"); // two spaces as quality
        assert!(!r.ok());
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "fastq.phred_out_of_range"));
    }

    #[test]
    fn all_high_quality_flags_ambiguous_encoding() {
        // every qual byte >= 64 ('h' = 104) → cannot tell +33 from +64
        let r = check_bytes(b"@r1\nACGT\n+\nhhhh\n");
        assert!(r.ok(), "ambiguous encoding is a warning, not an error");
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "fastq.ambiguous_encoding" && f.severity == crate::Severity::Warn));
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
        let r = check_reader(
            Box::new(Cursor::new(b"@r1\nACRT\n+\nIIII\n".to_vec())),
            &opts,
        );
        assert!(!r.ok());
        assert!(r.findings.iter().any(|f| f.rule == "fastq.invalid_base"));
    }

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
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == "fastq.pair_id_mismatch"));
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
}
