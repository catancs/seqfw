# seqfw Plan 6 — Reproducible ASAN Security Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the project's headline credibility deliverable (spec §8): a reproducible harness that produces three honest numbers — **block rate** (% of a known-bad set `seqfw` rejects), **harm prevented** (inputs that crash a *real, pinned, unmodified, ASAN-built* vulnerable tool but are rejected by `seqfw` first), and **false positives + overhead** (over a known-good set). `make benchmark` runs it in Docker; the local block-rate/false-positive/overhead portion runs without Docker against the `seqfw` binary.

**Architecture:** A new top-level `benchmark/` tree, not a crate. A `gen_corpus.py` builds a **patch-gated** known-bad corpus (only already-fixed, publicly-disclosed bug classes; spec §11) plus assembles a known-good set from the existing `corpus/*/pass/` fixtures. `run_block_rate.py` shells out to the release `seqfw` binary to compute block rate, false-positive rate, and per-file overhead — fully local and deterministic. A `Dockerfile` builds pinned **htslib 1.10.2** + **samtools** under `-fsanitize=address,undefined -fno-sanitize-recover=all`, copies in `seqfw` + the corpus, and `run_harm_prevented.py` feeds each known-bad input to the sanitizer-built tool, bucketing CLEAN / CRASH / HANG, then reports how many crashes `seqfw` would have blocked. Results are emitted as JSON + a Markdown table. No `seqfw-core`/CLI source changes.

**Tech Stack:** Python 3 (stdlib only) for generators/runners; Docker + a C toolchain (clang/gcc, autoconf, make) inside the image; the existing `seqfw` release binary.

**Scope:** This is **Plan 6 of a sequence** (Plans 1–5 shipped: FASTQ/FASTA/VCF + index-bounds + Python bindings). It delivers the benchmark harness and the local-verifiable numbers; the Dockerized ASAN run is wired and documented but requires a Docker host with a C toolchain to execute end-to-end. **Deliberately bounded** (spec §8/§11): reproducers are **self-built, patch-gated** safe inputs for *documented* bugs — we ship no live crashers for unfixed issues and no weaponized files; the 2026 htslib cluster's deeper CRAM reproducers are roadmap. Next: packaging — cargo-dist/PyPI/Bioconda/Homebrew (Plan 7). See `docs/superpowers/specs/2026-06-11-seqfw-genomic-firewall-design.md` §8, §9, §11.

---

## File Structure

```
seqfw/
  Makefile                           # NEW — `make benchmark` (+ benchmark-local)
  benchmark/
    README.md                        # NEW — what it measures, how to run, ethics
    gen_corpus.py                    # NEW — build patch-gated known-bad + known-good sets
    run_block_rate.py                # NEW — block rate + false positives + overhead (local)
    run_harm_prevented.py            # NEW — feed known-bad to ASAN tools, bucket outcomes
    Dockerfile                       # NEW — pinned htslib/samtools under ASAN+UBSan
    PROVENANCE.md                    # NEW — per-reproducer CVE/issue + fix-commit gating
    corpus/                          # generated (gitignored); manifest committed
      manifest.json                  # NEW — SHA-256 + provenance per file (committed)
```

**Outputs:** `benchmark/results/block_rate.json`, `benchmark/results/harm_prevented.json`, and a printed Markdown summary table.

---

## Task 1: Benchmark scaffold + patch-gated corpus generator

**Files:**
- Create: `benchmark/gen_corpus.py`
- Create: `benchmark/PROVENANCE.md`
- Create: `benchmark/README.md`
- Modify: `.gitignore` (ignore generated `benchmark/corpus/`, keep `manifest.json`)

- [ ] **Step 1: Write the corpus generator**

`benchmark/gen_corpus.py` builds two sets under `benchmark/corpus/`:
- `known-bad/` — one file per documented bug class, each safe to store (no live exploit; the dangerous property is structural, caught by `seqfw`):
  - `vcf_format_overflow.vcf` — a sample with more `:`-subfields than the FORMAT column declares (the `CVE-2020-36403` `vcf_parse_format` OOB-write shape).
  - `gzip_bomb.fastq.gz` — ~64 KiB compressing from a multi-MiB run (decompression-bomb class).
  - `gzi_impossible_count.gzi` — an 8-byte `.gzi` claiming `u64::MAX` entries (the `CVE-2026-31970` integer-overflow class).
  - `csi_impossible_nref.csi` — a CSI header with `n_ref = i32::MAX`.
  - `fastq_truncated.fastq`, `fasta_dupnames.fasta` — corruption-class framing faults.
- `known-good/` — copies of every file under the repo's `corpus/*/pass/` (the false-positive set), plus a few larger synthetic-but-valid FASTQ/VCF files for the overhead measurement.

It writes `benchmark/corpus/manifest.json` with, per file, its relative path, SHA-256, set (`bad`/`good`), the rule `seqfw` is expected to fire (for bad), and a provenance tag. Use only the Python stdlib (`gzip`, `hashlib`, `struct`, `json`, `pathlib`, `shutil`).

Key generator details (so the files match `seqfw`'s rules and the ethics gate):
```python
# vcf_format_overflow.vcf — FORMAT declares 1 key (GT); sample carries 2 subfields
VCF_OVERFLOW = (
    "##fileformat=VCFv4.2\n"
    '##FORMAT=<ID=GT,Number=1,Type=String,Description="g">\n'
    "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\ts1\n"
    "chr1\t100\t.\tA\tG\t.\t.\t.\tGT\t0/1:99\n"
)

# gzi_impossible_count.gzi — 8 bytes: count = u64::MAX, no body
import struct
GZI_IMPOSSIBLE = struct.pack("<Q", (1 << 64) - 1)

# csi_impossible_nref.csi — magic + min_shift,depth,l_aux(=0) + n_ref=i32::MAX
CSI_IMPOSSIBLE = b"CSI\x01" + struct.pack("<iii", 14, 5, 0) + struct.pack("<i", (1 << 31) - 1)

# gzip_bomb.fastq.gz — valid FASTQ first byte so seqfw routes it to the FASTQ
# check where the bomb guard trips; ~8 MiB of 'A' after an '@'.
import gzip
bomb_plain = b"@bomb\n" + b"A" * (8 * 1024 * 1024)
# write with gzip.compress(bomb_plain)
```
Each known-bad entry records the rule it should trigger: `vcf.format_field_mismatch`, `transport.decompression_bomb`, `gzi.bad_entry_count`, `tabix.impossible_count`, `fastq.truncated_record`, `fasta.duplicate_name`.

- [ ] **Step 2: Write the provenance + ethics doc**

`benchmark/PROVENANCE.md` lists each known-bad file with: the bug class, the CVE/advisory it represents, the upstream fix commit/version, and a one-line statement that the file is a **self-built structural reproducer** (no weaponized payload), satisfying spec §11's patch-gate. Include the note that no live crasher is shipped for any unfixed issue.

- [ ] **Step 3: Write the benchmark README**

`benchmark/README.md`: what the three numbers mean, how to run (`make benchmark` for the full ASAN run; `make benchmark-local` / `python3 benchmark/run_block_rate.py` for the local subset), the ethics gate, and that reproducers are regenerated by `gen_corpus.py` (so only the manifest is version-controlled, not the generated bytes).

- [ ] **Step 4: Ignore generated corpus, keep the manifest**

Append to `.gitignore`:
```
# Benchmark generated corpus (regenerate via benchmark/gen_corpus.py)
/benchmark/corpus/*
!/benchmark/corpus/manifest.json
/benchmark/results/
```

- [ ] **Step 5: Generate + sanity check**

```bash
python3 benchmark/gen_corpus.py
python3 -c "import json;m=json.load(open('benchmark/corpus/manifest.json'));print(len(m['files']),'files');print(sorted({f['set'] for f in m['files']}))"
```
Expected: prints a file count and `['bad', 'good']`.

- [ ] **Step 6: Commit**

```bash
git add benchmark/gen_corpus.py benchmark/PROVENANCE.md benchmark/README.md benchmark/corpus/manifest.json .gitignore
git commit -m "feat(bench): patch-gated known-bad/known-good corpus generator"
```

---

## Task 2: Local runner — block rate, false positives, overhead

**Files:**
- Create: `benchmark/run_block_rate.py`
- Create: `Makefile`

This portion runs anywhere `seqfw` is built — no Docker, no vulnerable tools — and is the deterministic, always-verifiable core.

- [ ] **Step 1: Write the runner**

`benchmark/run_block_rate.py` (stdlib only):
- Locate the `seqfw` binary (`target/release/seqfw`, or `$SEQFW_BIN`); if missing, print a clear hint to `cargo build --release -p seqfw-cli`.
- Read `benchmark/corpus/manifest.json`. For each **bad** file: run `seqfw check <path>` (passing `--data` for index files when a sibling data file is recorded), record exit code; "blocked" = exit 1. Confirm the expected rule appears in `--json` output. For each **good** file: run `seqfw check`; "false positive" = exit 1.
- Measure overhead: time `seqfw check` on the larger known-good files; report mean ms.
- Print a Markdown table and write `benchmark/results/block_rate.json` with: `block_rate` (blocked/total bad), `false_positive_rate` (fp/total good), per-file rows (path, expected rule, exit code, matched-rule bool), and overhead stats.
- Exit non-zero if block rate < 100% or false-positive rate > 0% (so it doubles as a regression gate).

- [ ] **Step 2: Write the Makefile**

`Makefile` (repo root):
```make
.PHONY: benchmark benchmark-local seqfw-release

seqfw-release:
	cargo build --release -p seqfw-cli

benchmark-local: seqfw-release
	python3 benchmark/gen_corpus.py
	python3 benchmark/run_block_rate.py

benchmark: seqfw-release
	python3 benchmark/gen_corpus.py
	docker build -f benchmark/Dockerfile -t seqfw-benchmark .
	docker run --rm seqfw-benchmark
```

- [ ] **Step 3: Run the local benchmark**

```bash
make benchmark-local
```
Expected: block rate `100%`, false-positive rate `0%`, an overhead figure, exit 0.

- [ ] **Step 4: Commit**

```bash
git add benchmark/run_block_rate.py Makefile
git commit -m "feat(bench): local block-rate / false-positive / overhead runner"
```

---

## Task 3: Dockerized ASAN harm-prevented run

**Files:**
- Create: `benchmark/Dockerfile`
- Create: `benchmark/run_harm_prevented.py`

This is the "harm prevented" half: feed each known-bad input to a real, pinned, unmodified, sanitizer-built vulnerable tool and record whether it crashes — then show `seqfw` blocked it first. Requires a Docker host with a C toolchain; the image pins exact versions and builds them under ASAN+UBSan.

- [ ] **Step 1: Write the Dockerfile**

`benchmark/Dockerfile`:
- Base `ubuntu:22.04`; install `build-essential clang autoconf automake zlib1g-dev libbz2-dev liblzma-dev curl ca-certificates` and a Rust toolchain (or copy a prebuilt `seqfw`).
- Build **htslib 1.10.2** (the `CVE-2020-36403` window) from the pinned release tarball with `CC=clang CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1"` and matching `LDFLAGS`; build `bcftools`/`htsfile` against it. State the exact version + commit in a label.
- Build `seqfw` release in the image (or `COPY` it in).
- Run `python3 benchmark/gen_corpus.py` then `CMD ["python3", "benchmark/run_harm_prevented.py"]`.
- Set `ASAN_OPTIONS=halt_on_error=1:abort_on_error=1` and a per-invocation timeout for the HANG bucket.

- [ ] **Step 2: Write the harm-prevented runner**

`benchmark/run_harm_prevented.py` (stdlib only):
- For each known-bad file, pick the matching pinned tool (VCF → `bcftools view`; gzip/bgzf → `htsfile`/`bgzip -t`; etc.), run it under a timeout, and bucket the outcome: `CLEAN` (exit 0), `CRASH` (ASAN/UBSan abort — nonzero with sanitizer signature on stderr), or `HANG` (timeout).
- In parallel, run `seqfw check` on the same file and record blocked (exit 1).
- Emit `benchmark/results/harm_prevented.json` and a Markdown table: per input → tool outcome, seqfw verdict; and the headline `harm_prevented` count = inputs where `tool ∈ {CRASH, HANG}` **and** `seqfw blocked`.
- Methodology guardrails (spec §8): real unmodified tool, exact version stated, sanitizer detects the crash (not a bare segfault), CRASH/HANG bucketed separately.

- [ ] **Step 3: Attempt the Docker build/run (host-dependent)**

```bash
make benchmark   # docker build + run
```
Expected on a capable host: prints both tables; `harm_prevented` ≥ 1 (the VCF FORMAT-overflow crashes pinned htslib 1.10.2 yet `seqfw` rejects it). If the Docker build cannot complete in this environment (no toolchain, resource caps), record that the harness is built and the **local** numbers pass, and that the ASAN run requires a Docker host — do **not** fake the numbers.

- [ ] **Step 4: Commit**

```bash
git add benchmark/Dockerfile benchmark/run_harm_prevented.py
git commit -m "feat(bench): Dockerized ASAN harm-prevented runner (pinned htslib 1.10.2)"
```

---

## Task 4: Wire-up docs + README benchmark section + final gate + push

**Files:**
- Modify: `README.md`

- [ ] **Step 1: README benchmark section**

Add a "Benchmark" section summarizing the three numbers, the `make benchmark` / `make benchmark-local` commands, and a one-line ethics statement linking `benchmark/PROVENANCE.md`. Include the latest local block-rate/false-positive result.

- [ ] **Step 2: Full gate**

Run: `cargo test` and `cargo clippy --all-targets -- -D warnings` and `cargo fmt --all -- --check` — the Rust crates are unchanged, so all stay green.
Run: `make benchmark-local` — block rate 100%, false positives 0%.

- [ ] **Step 3: Commit + push (as the `catancs` account)**

```bash
git add README.md
git commit -m "docs: benchmark section + local results"
git push origin main
```

---

## Self-Review (completed by plan author)

**Spec coverage (§8/§9/§11):** §8 three numbers (block rate, harm prevented, false positives + overhead) → Tasks 2 (local) + 3 (ASAN); §8 "real, pinned, unmodified, ASAN+UBSan, no strawman, exact version" → Task 3 Dockerfile (htslib 1.10.2, `-fno-sanitize-recover=all`) + runner guardrails (CRASH/HANG bucketed); §9 "versioned corpus, each file documenting the threat it represents" → Task 1 `manifest.json` + `PROVENANCE.md`; §11 patch-gate / generators-over-weaponized-files / provenance-per-sample → Task 1 (self-built structural reproducers for already-fixed, disclosed bugs only). **Deliberately bounded:** the deeper 2026 CRAM-cluster reproducers and a GIAB/1000G known-good download manifest are roadmap; the false-positive set here reuses the repo's `corpus/*/pass/` fixtures plus a few synthetic valids, which is sufficient to show ~0% FP without shipping large reference data.

**Verifiability honesty:** Tasks 1–2 are fully runnable and deterministic in any environment with the `seqfw` binary (no Docker, no vulnerable tools) and double as a regression gate (exit non-zero on <100% block / >0% FP). Task 3 needs a Docker host with a C toolchain; Step 3 explicitly says to record "harness built, local numbers pass, ASAN run requires a Docker host" rather than fabricate the harm-prevented figure if the build can't complete here. No source in `seqfw-core`/CLI/py changes, so the existing Rust gate is untouched.

**Ethics check:** every known-bad file is a structural reproducer whose hazardous property (a length/count field that lies, an over-long FORMAT row) is exactly what `seqfw` rejects — there is no shellcode, no live exploit, and nothing is shipped for an unfixed bug. `PROVENANCE.md` records the CVE + fix commit per file, satisfying the design's disclosure policy.

**Placeholder scan:** no TBD/TODO; generators and runners are specified with concrete byte layouts and stdlib-only code. The one environment-dependent step (Docker build) is flagged with an explicit honest-fallback instruction, not a hidden stub.