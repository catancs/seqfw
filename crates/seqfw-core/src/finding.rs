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
        Location {
            record: Some(record),
            byte_offset: None,
        }
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
        Finding {
            severity: Severity::Error,
            rule: rule.to_string(),
            message,
            location,
        }
    }
    pub fn warn(rule: &str, message: String, location: Option<Location>) -> Self {
        Finding {
            severity: Severity::Warn,
            rule: rule.to_string(),
            message,
            location,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_ok_only_when_no_errors() {
        let mut r = Report::default();
        assert!(r.ok(), "empty report is ok");
        r.push(Finding::warn("x.warn", "heads up".into(), None));
        assert!(r.ok(), "warnings do not fail the report");
        r.push(Finding::error(
            "x.err",
            "nope".into(),
            Some(Location::at_record(3)),
        ));
        assert!(!r.ok(), "an error fails the report");
        assert_eq!(r.findings.len(), 2);
    }
}
