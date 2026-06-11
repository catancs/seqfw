# seqfw Plan 5 — Python Bindings (PyO3 / maturin) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `import seqfw; report = seqfw.check("upload.fastq.gz")` — a first-class Python library, built from the same Rust core as the CLI, that returns a `Report` object mirroring the Rust one (`.ok`, `.findings`, `.reason`), so a platform upload handler can reject malformed/malicious genomic files in one call.

**Architecture:** A new `crates/seqfw-py` crate compiles to a CPython extension module (`cdylib`) via **PyO3** with the **abi3-py38** stable ABI, packaged by **maturin**. It is a *thin* binding: it path-depends on `seqfw-core`, calls the existing `check_path`/`check_reader`, and converts `seqfw_core::Report`/`Finding` into two small `#[pyclass]` types. No core logic is duplicated or moved. The crate joins the workspace as a member, but `default-members` is set to `seqfw-core` + `seqfw-cli` so the existing `cargo test`/`cargo clippy` gate is unaffected (the Python extension is built/tested via maturin + pytest, and clippy'd explicitly). The Python surface mirrors the CLI's options: an optional `format` override and `strict_dna`.

**Tech Stack:** Rust (edition 2021); `pyo3` (`extension-module`, `abi3-py38`); `maturin` (build backend); `pytest` (Python tests). Local Python is 3.9.6; abi3-py38 wheels run on 3.8+.

**Scope:** This is **Plan 5 of a sequence** (Plans 1–4 shipped on `main`: FASTQ/FASTA/VCF + index-bounds). It delivers the Python `check`/`check_bytes` entry points plus the `Report`/`Finding` object model — the spec's §5 "Python library, first-class" surface. **Deliberately deferred** (cheap follow-ups, kept out to stay focused): Python wrappers for `check_pair_reader` (paired-end) and `check_index_reader` (index files); a `.pyi` type stub; and wheel-building CI — all roadmap for the packaging plan. Later: ASAN benchmark harness (Plan 6), packaging — PyPI/crates.io/Homebrew/Bioconda (Plan 7). See `docs/superpowers/specs/2026-06-11-seqfw-genomic-firewall-design.md` §5, §7, §10.

---

## File Structure

```
seqfw/
  Cargo.toml                         # + seqfw-py member; + default-members (core+cli)
  .gitignore                         # + .venv/, __pycache__/, *.so
  crates/
    seqfw-py/
      Cargo.toml                     # NEW — cdylib, pyo3, path dep on seqfw-core
      pyproject.toml                 # NEW — maturin build backend + project metadata
      src/
        lib.rs                       # NEW — #[pymodule] seqfw: Report/Finding + check/check_bytes
      tests/
        test_seqfw.py                # NEW — pytest against the built module
```

**Python API delivered:**
- `seqfw.check(path: str, *, format: str | None = None, strict_dna: bool = False) -> Report` — validate a file (raises `OSError` if it can't be opened).
- `seqfw.check_bytes(data: bytes, *, format=None, strict_dna=False) -> Report` — validate an in-memory buffer.
- `seqfw.Report` — `.ok: bool`, `.findings: list[Finding]`, `.reason: str` (newline-joined error findings; empty when clean), `bool(report) == report.ok`, `repr`.
- `seqfw.Finding` — `.severity: str` (`"error"`/`"warn"`), `.rule: str`, `.message: str`, `.record: int | None`, `.byte_offset: int | None`, `repr`.
- `seqfw.__version__` — mirrors `seqfw_core::VERSION`.

---

## Task 1: Scaffold the `seqfw-py` crate and prove the module imports

**Files:**
- Modify: `Cargo.toml` (workspace)
- Modify: `.gitignore`
- Create: `crates/seqfw-py/Cargo.toml`
- Create: `crates/seqfw-py/pyproject.toml`
- Create: `crates/seqfw-py/src/lib.rs`

- [ ] **Step 1: Add the crate to the workspace, keep the gate on core+cli**

Replace `Cargo.toml` (workspace) with:
```toml
[workspace]
resolver = "2"
members = ["crates/seqfw-core", "crates/seqfw-cli", "crates/seqfw-py"]
# The Python extension links against CPython config and is built via maturin;
# keep the default cargo gate (test/clippy without -p) on the pure-Rust crates.
default-members = ["crates/seqfw-core", "crates/seqfw-cli"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/catancs/seqfw"
```

- [ ] **Step 2: Ignore Python build artifacts**

Append to `.gitignore`:
```
# Python
.venv/
__pycache__/
*.so
*.pyd
```

- [ ] **Step 3: Create the crate manifest**

`crates/seqfw-py/Cargo.toml`:
```toml
[package]
name = "seqfw-py"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[lib]
# The importable Python module is `seqfw`.
name = "seqfw"
crate-type = ["cdylib"]

[dependencies]
seqfw-core = { path = "../seqfw-core" }
pyo3 = { version = "0.23", features = ["extension-module", "abi3-py38"] }
```
> If `cargo`/`maturin` reports a PyO3 API mismatch at build time, the binding code below targets the PyO3 0.22/0.23 `Bound` API; adjust the dependency to the matching 0.2x and keep the same code shape. Do not downgrade below 0.22 (the `#[pymodule]` signature differs).

- [ ] **Step 4: Create the maturin project file**

`crates/seqfw-py/pyproject.toml`:
```toml
[build-system]
requires = ["maturin>=1.7,<2.0"]
build-backend = "maturin"

[project]
name = "seqfw"
description = "A firewall for genomic data — validate FASTQ/FASTA/VCF and index files at the trust boundary"
requires-python = ">=3.8"
license = { text = "Apache-2.0" }
readme = "../../README.md"
dynamic = ["version"]
classifiers = [
  "Programming Language :: Rust",
  "Programming Language :: Python :: 3",
  "Topic :: Scientific/Engineering :: Bio-Informatics",
]

[tool.maturin]
features = ["pyo3/extension-module"]
```

- [ ] **Step 5: Create a minimal module that imports**

`crates/seqfw-py/src/lib.rs`:
```rust
use pyo3::prelude::*;

/// The `seqfw` Python module.
#[pymodule]
fn seqfw(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", seqfw_core::VERSION)?;
    Ok(())
}
```

- [ ] **Step 6: Build the extension in a venv and prove it imports**

```bash
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip maturin pytest
( cd crates/seqfw-py && ../../.venv/bin/maturin develop )
.venv/bin/python -c "import seqfw; print(seqfw.__version__)"
```
Expected: prints `0.1.0`. (`maturin develop` builds the cdylib and installs it into the active venv.)

> If `maturin develop` fails to find an interpreter, run it with the venv active (`source .venv/bin/activate` then `maturin develop` from `crates/seqfw-py`). On macOS, abi3 + `extension-module` builds with dynamic-lookup linkage — no extra flags needed.

- [ ] **Step 7: Confirm the Rust gate is unaffected**

Run: `cargo test`
Expected: builds only `seqfw-core` + `seqfw-cli` (default-members) — all Plan 1–4 tests still pass; the Python crate is not built by this command.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml .gitignore crates/seqfw-py/
git commit -m "feat(py): scaffold seqfw-py PyO3/maturin crate (module imports)"
```

---

## Task 2: `Report` / `Finding` objects + `check` / `check_bytes`

**Files:**
- Modify: `crates/seqfw-py/src/lib.rs`
- Create: `crates/seqfw-py/tests/test_seqfw.py`

- [ ] **Step 1: Implement the full binding**

Replace `crates/seqfw-py/src/lib.rs` with:
```rust
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
```

- [ ] **Step 2: Write the Python tests**

`crates/seqfw-py/tests/test_seqfw.py`:
```python
import pytest
import seqfw


def test_version_is_set():
    assert seqfw.__version__


def test_valid_fastq_bytes_is_ok():
    r = seqfw.check_bytes(b"@r1\nACGT\n+\nIIII\n")
    assert r.ok
    assert bool(r) is True
    assert r.reason == ""
    assert all(f.severity == "warn" for f in r.findings)


def test_bad_separator_is_rejected():
    r = seqfw.check_bytes(b"@r1\nACGT\n-\nIIII\n")
    assert not r.ok
    assert not bool(r)
    rules = [f.rule for f in r.findings]
    assert "fastq.bad_separator" in rules
    assert r.reason  # non-empty rejection reason
    bad = next(f for f in r.findings if f.rule == "fastq.bad_separator")
    assert bad.severity == "error"
    assert bad.record == 1


def test_vcf_is_routed_and_validated():
    r = seqfw.check_bytes(
        b"##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"
    )
    assert r.ok


def test_format_override_forces_fastq_on_fasta():
    r = seqfw.check_bytes(b">seq1\nACGT\n", format="fastq")
    assert not r.ok  # a FASTA stream forced through the FASTQ check fails framing


def test_unknown_format_raises_value_error():
    with pytest.raises(ValueError):
        seqfw.check_bytes(b"@r1\nACGT\n+\nIIII\n", format="bam")


def test_strict_dna_rejects_iupac():
    r = seqfw.check_bytes(b"@r1\nACRT\n+\nIIII\n", strict_dna=True)
    assert not r.ok
    assert any(f.rule == "fastq.invalid_base" for f in r.findings)


def test_check_path_ok(tmp_path):
    p = tmp_path / "x.fastq"
    p.write_bytes(b"@r1\nACGT\n+\nIIII\n")
    assert seqfw.check(str(p)).ok


def test_check_missing_file_raises_oserror():
    with pytest.raises(OSError):
        seqfw.check("/no/such/file.fastq")


def test_repr_is_readable():
    r = seqfw.check_bytes(b"@r1\nACGT\n+\nIIII\n")
    assert "Report(ok=true" in repr(r) or "Report(ok=True" in repr(r)
```
> Note on `repr`: PyO3 formats a Rust `bool` via `{}` as `true`/`false`, so `Report(ok=true, findings=0)` is expected. The test accepts either casing to be robust to a future tweak.

- [ ] **Step 3: Rebuild and run the Python tests**

```bash
( cd crates/seqfw-py && ../../.venv/bin/maturin develop )
.venv/bin/python -m pytest crates/seqfw-py/tests/ -q
```
Expected: all tests pass.

- [ ] **Step 4: Clippy the Python crate**

Run: `cargo clippy -p seqfw-py --all-targets -- -D warnings`
Expected: clean. Run `cargo fmt -p seqfw-py`.
> `cargo clippy -p seqfw-py` builds the cdylib against the local interpreter; this works because `python3` is on PATH. If clippy cannot find Python, run it with the venv active.

- [ ] **Step 5: Commit**

```bash
git add crates/seqfw-py/src/lib.rs crates/seqfw-py/tests/test_seqfw.py
git commit -m "feat(py): Report/Finding objects + check/check_bytes with options"
```

---

## Task 3: README "Python" section + final gate + push

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the Python API**

In `README.md`, add a "Python" section after the CLI "Use" block:
```markdown
## Python

```bash
pip install maturin            # build from source for now
maturin develop                # from crates/seqfw-py, into a venv
```

```python
import seqfw

report = seqfw.check("user_upload.fastq.gz")   # also: check_bytes(b"...")
if not report.ok:
    raise ValueError(report.reason)            # newline-joined error findings

for f in report.findings:
    print(f.severity, f.rule, f.message, f.record)

seqfw.check("sample.fasta", format="fasta")    # force a format
seqfw.check("reads.fastq", strict_dna=True)    # enforce ACGTN
```
```

- [ ] **Step 2: Full gate (Rust + Python)**

Run: `cargo test`
Expected: all `seqfw-core` + `seqfw-cli` tests pass (Plans 1–4 unaffected).

Run: `cargo clippy --all-targets -- -D warnings` (core + cli) and `cargo clippy -p seqfw-py --all-targets -- -D warnings` (py).
Expected: clean.

Run: `cargo fmt --all -- --check`
Expected: clean (else `cargo fmt --all`).

Run: `( cd crates/seqfw-py && ../../.venv/bin/maturin develop ) && .venv/bin/python -m pytest crates/seqfw-py/tests/ -q`
Expected: all Python tests pass.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document the seqfw Python API"
```

- [ ] **Step 4: Push directly to main**

Per the project's solo direct-to-main flow (push as the `catancs` GitHub account):
```bash
git push origin main
```

---

## Self-Review (completed by plan author)

**Spec coverage (Plan 5 subset of §5/§7):** §5 "Python library — `import seqfw; report = seqfw.check(...)`; `if not report.ok: reject(report.reason)`" → Task 2 (`check`, `Report.ok`, `Report.reason`); §7 "`seqfw-py` (PyO3 / maturin): thin binding exposing `check()` returning a Python object mirroring `Report`" → the whole plan (thin: no logic in the binding, only conversion); §10 "PyPI via maturin … abi3-py38" → the `abi3-py38` feature + maturin backend established here (actual wheel CI is Plan 7). **Deliberately deferred** (tracked, not gaps): Python wrappers for paired-end (`check_pair_reader`) and index files (`check_index_reader`) — both already in core, exposed in a later increment to keep this plan thin; a `.pyi` type stub and `py.typed` marker; and `maturin-action` wheel-building CI (Plan 7 packaging).

**Workspace-impact safety:** the existing Rust gate is preserved by `default-members = ["crates/seqfw-core", "crates/seqfw-cli"]`, so `cargo test` / `cargo clippy --all-targets` keep building exactly the two pure-Rust crates they do today — the PyO3 cdylib (which needs CPython link config) is built only by maturin and clippy'd via an explicit `-p seqfw-py`. Task 1 Step 7 verifies the Plan 1–4 suite is untouched before any binding code exists.

**Thin-binding / type consistency:** the binding calls only the public `check_path`/`check_reader` and reads the public `Report`/`Finding`/`Severity`/`Location` fields — no core type is moved or reshaped. `Severity` collapses to the same `"error"`/`"warn"` strings the CLI `--json` already emits, so the Python and JSON vocabularies agree. The `format=`/`strict_dna=` keywords map 1:1 onto the CLI's `--format`/`--strict-dna`, and an unknown `format` raises `ValueError` (not a silent default). File-open failure maps to `OSError`/`PyIOError`, matching the CLI's exit-2 "tool error" semantics.

**Build-environment notes (honest):** local Python is 3.9.6 and `maturin` is not yet installed — Task 1 Step 6 creates a `.venv` and `pip install`s `maturin`+`pytest`, so the plan is self-contained. PyO3 0.23 targets the `Bound` API used in the code; the manifest note flags that a 0.2x minor bump may be needed and the code shape stays the same. `cargo clippy -p seqfw-py` and `maturin develop` both require `python3` on PATH (present).

**Placeholder scan:** no TBD/TODO; the Task 1 module is a deliberate minimal-but-complete smoke target (imports + `__version__`), fully replaced in Task 2 — described as such, not a hidden stub. Every code block compiles/loads at the point its task ends.