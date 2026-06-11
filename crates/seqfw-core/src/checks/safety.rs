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
