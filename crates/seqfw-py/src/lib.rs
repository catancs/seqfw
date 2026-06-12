use std::fs::File;
use std::io::Cursor;
use std::path::Path;

use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;

use seqfw_core::{
    check_index_reader, check_pair_reader, check_path, check_reader, Format, IndexKind, Options,
    SeqAlphabet, Severity,
};

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

/// Validate a paired-end FASTQ R1/R2 set on disk. Both files are transparently
/// decompressed and bomb-guarded; the check enforces per-read sync between mates.
/// Raises `OSError` if either file cannot be opened.
#[pyfunction]
#[pyo3(signature = (r1, r2, *, strict_dna=false))]
fn check_pair(r1: &str, r2: &str, strict_dna: bool) -> PyResult<Report> {
    let opts = build_options(None, strict_dna)?;
    let f1 = File::open(r1).map_err(|e| PyIOError::new_err(format!("cannot open {r1}: {e}")))?;
    let f2 = File::open(r2).map_err(|e| PyIOError::new_err(format!("cannot open {r2}: {e}")))?;
    let report = check_pair_reader(Box::new(f1), Box::new(f2), &opts);
    Ok(convert(report))
}

/// Validate a paired-end FASTQ R1/R2 set from in-memory byte buffers.
#[pyfunction]
#[pyo3(signature = (r1, r2, *, strict_dna=false))]
fn check_pair_bytes(r1: &[u8], r2: &[u8], strict_dna: bool) -> PyResult<Report> {
    let opts = build_options(None, strict_dna)?;
    let report = check_pair_reader(
        Box::new(Cursor::new(r1.to_vec())),
        Box::new(Cursor::new(r2.to_vec())),
        &opts,
    );
    Ok(convert(report))
}

/// Map an index path's extension to its kind, mirroring the CLI.
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

/// Validate a companion index file (`.fai`/`.gzi`/`.tbi`/`.csi`), routed by
/// extension. Pass `data=` (the path to the data file the index points into) to
/// enable offset-in-bounds checks. Raises `ValueError` if the extension is not a
/// known index kind, or `OSError` if a file cannot be opened.
#[pyfunction]
#[pyo3(signature = (path, *, data=None))]
fn check_index(path: &str, data: Option<&str>) -> PyResult<Report> {
    let kind = index_kind_from_path(path).ok_or_else(|| {
        PyValueError::new_err(format!(
            "{path:?} is not a known index file; expected a .fai/.gzi/.tbi/.csi extension"
        ))
    })?;
    let data_len = match data {
        Some(d) => Some(
            std::fs::metadata(d)
                .map_err(|e| PyIOError::new_err(format!("cannot stat {d}: {e}")))?
                .len(),
        ),
        None => None,
    };
    let opts = Options::default();
    let file =
        File::open(path).map_err(|e| PyIOError::new_err(format!("cannot open {path}: {e}")))?;
    let report = check_index_reader(kind, Box::new(file), data_len, &opts);
    Ok(convert(report))
}

/// The `seqfw` Python module.
#[pymodule]
fn seqfw(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Report>()?;
    m.add_class::<Finding>()?;
    m.add_function(wrap_pyfunction!(check, m)?)?;
    m.add_function(wrap_pyfunction!(check_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(check_pair, m)?)?;
    m.add_function(wrap_pyfunction!(check_pair_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(check_index, m)?)?;
    m.add("__version__", seqfw_core::VERSION)?;
    Ok(())
}
