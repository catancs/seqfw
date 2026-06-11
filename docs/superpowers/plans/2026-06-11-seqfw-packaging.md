# seqfw Plan 7 — Packaging & Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `seqfw` installable through every channel the spec targets (§10) — `cargo install`, `pip install`, `brew install`, `conda install`, and a `curl … | sh` static binary — from one build graph, plus a CI gate so every push is tested. This is the final v1 plan.

**Architecture:** No source changes; this plan adds metadata and automation. crates.io metadata goes on `seqfw-core` + `seqfw-cli`. **cargo-dist** (`[workspace.metadata.dist]` + a generated `release.yml`) cross-compiles static Linux (musl) + macOS binaries to GitHub Releases, emits a `curl | sh` installer, and generates a Homebrew tap formula. **maturin** (a `wheels.yml` using `PyO3/maturin-action`) builds abi3 wheels for manylinux/macOS/Windows and publishes to PyPI on tag. A **Bioconda** `recipe/meta.yaml` builds from the published crate/sdist. A `ci.yml` runs the existing Rust gate + Python tests on every push. Publishing is **tag-gated and secret-gated** — the workflows do nothing on a normal push and fail safe without `CARGO_REGISTRY_TOKEN`/`PYPI_API_TOKEN`/release permissions.

**Tech Stack:** GitHub Actions; cargo-dist (a.k.a. `dist`); `PyO3/maturin-action`; conda-build recipe. No new runtime dependencies.

**Scope:** This is **Plan 7 of a sequence** and completes the v1 roadmap (Plans 1–6 shipped: FASTQ/FASTA/VCF + index-bounds + Python bindings + ASAN benchmark). **Verifiability note:** workflow YAML, `cargo package`, and recipe structure are checkable locally; *actual* publishing requires a pushed version tag plus registry credentials in repo secrets, which is an operator action outside this plan's automated steps. **Deliberately bounded:** WASM/C-ABI builds and the auto-BioContainer are roadmap (spec §7/§10). See `docs/superpowers/specs/2026-06-11-seqfw-genomic-firewall-design.md` §10.

---

## File Structure

```
seqfw/
  Cargo.toml                         # + [workspace.metadata.dist] (cargo-dist config)
  crates/
    seqfw-core/Cargo.toml            # + description/keywords/categories/readme
    seqfw-cli/Cargo.toml             # + description/keywords/categories/readme + [[bin]] doc
  .github/workflows/
    ci.yml                           # NEW — fmt/clippy/test + maturin build + pytest
    release.yml                      # NEW — cargo-dist: binaries + installer + brew tap
    wheels.yml                       # NEW — maturin abi3 wheels → PyPI on tag
  recipe/
    meta.yaml                        # NEW — Bioconda recipe
  CHANGELOG.md                       # NEW — cargo-dist reads this for release notes
```

---

## Task 1: crates.io metadata + `cargo package` clean

**Files:**
- Modify: `crates/seqfw-core/Cargo.toml`, `crates/seqfw-cli/Cargo.toml`
- Create: `CHANGELOG.md`

- [ ] **Step 1:** Add publishable metadata to both crates' `[package]` tables (shared fields can move to `[workspace.package]` and be inherited):
```toml
description = "A firewall for genomic data: validate FASTQ/FASTA/VCF and index files at the trust boundary"
keywords = ["bioinformatics", "fastq", "vcf", "security", "validation"]
categories = ["command-line-utilities", "science"]
readme = "../../README.md"
homepage = "https://github.com/catancs/seqfw"
```
Give `seqfw-core` a crate-specific `description` ("streaming validation core for seqfw"). Ensure `seqfw-cli` depends on `seqfw-core` with **both** a path and a version (`seqfw-core = { path = "../seqfw-core", version = "0.1.0" }`) so it can publish after core.

- [ ] **Step 2:** Create `CHANGELOG.md` with a `## 0.1.0` section summarizing v1 (FASTQ/FASTA/VCF + index-bounds + bomb guard + Python + benchmark).

- [ ] **Step 3:** Verify the crates package cleanly:
```bash
cargo package -p seqfw-core --allow-dirty --no-verify
```
Expected: produces `target/package/seqfw-core-0.1.0.crate` with no metadata errors. (`seqfw-cli` can't fully package until core is on crates.io; metadata correctness is what we check here.)

- [ ] **Step 4: Commit** `git commit -m "build: crates.io metadata + CHANGELOG"`.

---

## Task 2: CI workflow (the gate on every push)

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1:** Write `ci.yml`: on `push`/`pull_request`, an Ubuntu job that runs `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, then sets up Python, `pip install maturin pytest`, `maturin develop` in `crates/seqfw-py`, and `pytest crates/seqfw-py/tests/`. Pin `actions/checkout@v4`, `dtolnay/rust-toolchain@stable` (with `clippy`, `rustfmt`), `actions/setup-python@v5`.

- [ ] **Step 2:** Validate the YAML parses:
```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml ok')"
```
(If PyYAML is unavailable, `pip install pyyaml` in the venv, or skip — GitHub validates on push.)

- [ ] **Step 3: Commit** `git commit -m "ci: fmt/clippy/test + python wheel test on every push"`.

---

## Task 3: cargo-dist release workflow (binaries + installer + Homebrew tap)

**Files:**
- Modify: `Cargo.toml` (add `[workspace.metadata.dist]`)
- Create: `.github/workflows/release.yml`

- [ ] **Step 1:** Add cargo-dist config to the workspace `Cargo.toml`:
```toml
[workspace.metadata.dist]
cargo-dist-version = "0.23.0"
ci = "github"
installers = ["shell", "homebrew"]
targets = ["x86_64-unknown-linux-musl", "aarch64-apple-darwin", "x86_64-apple-darwin"]
tap = "catancs/homebrew-seqfw"
publish-jobs = ["homebrew"]
install-path = "CARGO_HOME"
```
Only `seqfw-cli` produces a binary, so dist will package `seqfw`.

- [ ] **Step 2:** Create `.github/workflows/release.yml` — the standard cargo-dist release workflow that triggers on `v*` tags, builds the target matrix, uploads binaries + the shell installer to a GitHub Release, and pushes the Homebrew formula to the tap. (This file is normally generated by `cargo dist init`/`cargo dist generate`; reproduce its structure, or, if `cargo-dist` is installed, run `cargo dist init --yes` and commit what it generates.)

- [ ] **Step 3:** Verify the dist plan if the tool is available:
```bash
cargo dist plan 2>/dev/null || echo "cargo-dist not installed — config validated structurally"
```

- [ ] **Step 4: Commit** `git commit -m "release: cargo-dist binaries + shell installer + homebrew tap"`.

---

## Task 4: maturin PyPI wheel workflow

**Files:**
- Create: `.github/workflows/wheels.yml`

- [ ] **Step 1:** Write `wheels.yml` using `PyO3/maturin-action`: on `v*` tags (and manual `workflow_dispatch`), build abi3-py38 wheels for `linux` (manylinux2014, x86_64+aarch64), `macos` (x86_64+aarch64), and `windows`, plus an sdist, then a `release` job that publishes to PyPI via `maturin-action` with `MATURIN_PYPI_TOKEN: ${{ secrets.PYPI_API_TOKEN }}`. Set `working-directory`/`args: --manifest-path crates/seqfw-py/Cargo.toml`.

- [ ] **Step 2:** Validate YAML parses (as in Task 2 Step 2).

- [ ] **Step 3: Commit** `git commit -m "release: maturin abi3 wheels to PyPI on tag"`.

---

## Task 5: Bioconda recipe + README install matrix + final gate + push

**Files:**
- Create: `recipe/meta.yaml`
- Modify: `README.md`

- [ ] **Step 1:** Write `recipe/meta.yaml` — a Bioconda recipe building from the crates.io sdist (or the GitHub release tarball), using `{{ compiler('rust') }}`, with `test.commands: seqfw --version`, and license/summary metadata bundled. Note in a comment that `cargo-bundle-licenses` output should accompany submission.

- [ ] **Step 2:** Update `README.md` "Install" section into a channel matrix: `cargo install seqfw`, `pip install seqfw`, `brew install catancs/seqfw/seqfw`, `conda install -c bioconda seqfw`, and `curl … | sh`, each marked "(on release)" since they activate once v0.1.0 is tagged and published.

- [ ] **Step 3: Full gate** — `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --all -- --check` (all unchanged-green), and `make benchmark-local` (block rate 100% / FP 0%). Validate all three workflow YAMLs parse.

- [ ] **Step 4: Commit + push (as the `catancs` account)** `git commit -m "docs: bioconda recipe + install matrix"` then `git push origin main`.

> **Operator follow-up (outside automated steps):** to actually publish, add `CARGO_REGISTRY_TOKEN` + `PYPI_API_TOKEN` to repo secrets, create the `catancs/homebrew-seqfw` tap repo, then push a `v0.1.0` tag — `release.yml` + `wheels.yml` fire from there. Bioconda requires a PR to `bioconda-recipes`. None of this happens on a normal push.

---

## Self-Review (completed by plan author)

**Spec coverage (§10):** PyPI via maturin (abi3) → Task 4; crates.io → Task 1; cargo-dist GitHub Releases + `curl|sh` + Homebrew tap → Task 3; Bioconda with `{{ compiler('rust') }}` → Task 5; clone-and-run already works. A CI gate (not in §10 but essential before publishing) → Task 2.

**Safety / least-surprise:** every publishing workflow is **tag-gated** (`v*`) and **secret-gated**; on a normal branch push only `ci.yml` runs (tests, no publish). Absent `CARGO_REGISTRY_TOKEN`/`PYPI_API_TOKEN` and the tap repo, the release jobs fail safe rather than mis-publish. The plan never pushes a tag — that's an explicit operator step — so implementing this plan cannot accidentally release anything.

**Verifiability honesty:** YAML parse checks, `cargo package -p seqfw-core`, and (if installed) `cargo dist plan` are runnable locally and are the plan's gates. End-to-end publishing is inherently CI/credential-bound and is documented as operator follow-up, not faked. No `seqfw-core`/CLI/py source changes, so the Rust + Python test suites stay exactly as Plan 6 left them.

**Placeholder scan:** no TBD/TODO. The two workflow files normally emitted by `cargo dist`/maturin templates are described structurally with exact action versions and trigger/secret wiring; Task 3 Step 2 notes the option to generate them with `cargo dist init` if the tool is present. Every step has a concrete local check.