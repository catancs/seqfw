use std::io::Cursor;
use std::path::Path;

use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;

use seqfw_core::{check_path, check_reader, Format, Options, SeqAlphabet, Severity};

/// A single validation finding (mirrors `seqfw_core::Finding`).
#[pyclass(frozen)]
#[derive(Clone)]
struct Finding {
    #[pyo3(get)]
    severity: String,
    #[pyo3(get)]
    rule: String,
    #[pyo3(get)]
    message: String,
    #[pyo3(get)]
    record: Option<u64>,
    #[pyo3(get)]
    byte_offset: Option<u64>,
}

#[pymethods]
impl Finding {
    fn __repr__(&self) -> String {
        format!(
            "Finding(severity={:?}, rule={:?}, message={:?})",
            self.severity, self.rule, self.message
        )
    }
}

/// The aggregated outcome of validating one input (mirrors `seqfw_core::Report`).
#[pyclass(frozen)]
struct Report {
    #[pyo3(get)]
    ok: bool,
    #[pyo3(get)]
    findings: Vec<Finding>,
}

#[pymethods]
impl Report {
    /// Newline-joined `rule: message` for every error finding; empty when clean.
    #[getter]
    fn reason(&self) -> String {
        self.findings
            .iter()
            .filter(|f| f.severity == "error")
            .map(|f| format!("{}: {}", f.rule, f.message))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn __bool__(&self) -> bool {
        self.ok
    }

    fn __repr__(&self) -> String {
        format!("Report(ok={}, findings={})", self.ok, self.findings.len())
    }
}

/// Convert a core report into the Python-facing object.
fn convert(report: seqfw_core::Report) -> Report {
    let findings = report
        .findings
        .iter()
        .map(|f| Finding {
            severity: match f.severity {
                Severity::Error => "error",
                Severity::Warn => "warn",
            }
            .to_string(),
            rule: f.rule.clone(),
            message: f.message.clone(),
            record: f.location.as_ref().and_then(|l| l.record),
            byte_offset: f.location.as_ref().and_then(|l| l.byte_offset),
        })
        .collect();
    Report {
        ok: report.ok(),
        findings,
    }
}

/// Build core `Options` from the Python keyword arguments.
fn build_options(format: Option<&str>, strict_dna: bool) -> PyResult<Options> {
    let mut opts = Options::default();
    if strict_dna {
        opts.seq_alphabet = SeqAlphabet::Dna;
    }
    if let Some(f) = format {
        opts.forced_format = Some(match f.to_ascii_lowercase().as_str() {
            "fastq" => Format::Fastq,
            "fasta" => Format::Fasta,
            "vcf" => Format::Vcf,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown format {other:?}; expected 'fastq', 'fasta', or 'vcf'"
                )))
            }
        });
    }
    Ok(opts)
}

/// Validate a file. Raises `OSError` if the file cannot be opened.
#[pyfunction]
#[pyo3(signature = (path, *, format=None, strict_dna=false))]
fn check(path: &str, format: Option<&str>, strict_dna: bool) -> PyResult<Report> {
    let opts = build_options(format, strict_dna)?;
    let report = check_path(Path::new(path), &opts)
        .map_err(|e| PyIOError::new_err(format!("cannot open {path}: {e}")))?;
    Ok(convert(report))
}

/// Validate an in-memory byte buffer.
#[pyfunction]
#[pyo3(signature = (data, *, format=None, strict_dna=false))]
fn check_bytes(data: &[u8], format: Option<&str>, strict_dna: bool) -> PyResult<Report> {
    let opts = build_options(format, strict_dna)?;
    let report = check_reader(Box::new(Cursor::new(data.to_vec())), &opts);
    Ok(convert(report))
}

/// The `seqfw` Python module.
#[pymodule]
fn seqfw(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Report>()?;
    m.add_class::<Finding>()?;
    m.add_function(wrap_pyfunction!(check, m)?)?;
    m.add_function(wrap_pyfunction!(check_bytes, m)?)?;
    m.add("__version__", seqfw_core::VERSION)?;
    Ok(())
}
