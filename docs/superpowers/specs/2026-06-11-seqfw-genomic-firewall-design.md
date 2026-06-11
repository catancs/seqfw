# seqfw — Genomic Input-Validation Firewall — Design Spec

- **Status:** Draft for review
- **Date:** 2026-06-11
- **Working name:** `seqfw` (provisional — "sequence firewall"; alternatives: `seqguard`, `seqward`, `seqfence`. Rename is cheap; not blocking.)
- **Author:** Catalin + Claude (brainstorming session)

> **Research-integrity note.** Every factual/empirical claim below is tagged with a numbered
> citation `[n]` resolved to a primary source (§15). All citations were verified against
> publisher pages, paper PDFs, NVD/OSV/GHSA records, and source repositories on 2026-06-11.
> Claims that could **not** be verified are stated as such rather than asserted. The point is
> that a reader can check, challenge, or improve any claim here.

---

## 1. Summary

`seqfw` is an open-source **input-validation firewall for genomic data**. It is a fast,
zero-config, streaming gate that sits at the trust boundary and **rejects malformed,
malicious, or resource-exhausting genomic files before they reach memory-unsafe parsers**
(htslib / samtools / BioPython). It ships as **both** a single-binary CLI **and** a Python
library, from one Rust codebase.

One thesis, two reasons to care:

- **Data integrity (daily value):** catch broken/truncated/mismatched files at the door, in
  under a second, *before* an expensive pipeline step — not at hour 8 of a 9-hour run.
- **Security (identity / defense-in-depth):** reject inputs that trigger the buffer-overflow
  and resource-exhaustion classes documented in the 2017 UW "DNA malware" research [1] and the
  2026 htslib CVE cluster [4].

These are the *same code*: a length field that lies about its payload is simultaneously a
corruption bug and an exploit primitive.

---

## 2. Motivation & threat model

### 2.1 The core reframing

To a computer, **a genomic file is untrusted input from an unauthenticated source** —
emailed by a collaborator, pulled from a public archive (SRA/ENA), or sequenced from
synthetic DNA. Bioinformatics never applied the web-security playbook (validate, sanitize,
bound, reject) to this input. `seqfw` does.

### 2.2 What's real vs. what's hype (honesty matters for trust)

The inspiring "virus that is also a cyberattack" framing rests on real research, but with
nuances we represent **accurately** in all materials:

- The 2017 University of Washington paper [1] (Ney et al., USENIX Security 2017) did encode
  an exploit in **176 bases** of synthetic DNA and achieve code execution. **But the working
  exploit ran against a `fqzcomp` v4.6 build the researchers *modified* to insert the
  vulnerability, with stack canaries and ASLR disabled and the stack marked executable**, and
  only **37.4% of reads** carried working exploit code [1]. It proves the *channel* exists —
  not that shipping pipelines are remotely exploitable via DNA today.
- The durable finding was their **survey** [1]: NGS tools use insecure C functions
  (`strcpy`/`sprintf`/…) at an **11× higher density** than comparable internet-facing
  software (2.005 vs 0.185 insecure calls per 1,000 LOC, p=0.027), and they found 3 real
  buffer-overflow bugs — in **fastx-toolkit, samtools, and SOAPdenovo2** (note: **not** `bwa`,
  which they analyzed but did not find vulnerable) [1].
- This is **current, not historical**: a 2026-03-18 coordinated disclosure [4] produced
  **10 htslib + 2 samtools CVEs** (`CVE-2026-31962`…`-31973`) — mostly CRAM-decoder heap
  overflows, plus out-of-bounds reads, a NULL-deref, a samtools use-after-free, and a
  BGZF/GZI index **integer overflow** (`CVE-2026-31970`) [4].

**Why our proof is *more* credible than the original demo:** our benchmark runs against
**real, unmodified, pinned-vulnerable tools under AddressSanitizer.** We never weaken the
victim (the UW demo had to). The sanitizer produces the crash; we show `seqfw` blocked the
input first.

### 2.3 Threat / value taxonomy (what v1 defends)

| Class | Frequency | Example |
|---|---|---|
| Corruption / truncation | **Daily** | interrupted download → truncated FASTQ/VCF; mismatched paired reads |
| Resource exhaustion (DoS) | Common for upload-accepting platforms | decompression bomb (2 KB → 50 GB); pathological line length → OOM |
| Memory corruption | Rare today, real & topical | malformed VCF FORMAT field (`CVE-2020-36403` class [5]); BGZF index overflow (`CVE-2026-31970` [4]) |
| Injection | Real in pipeline glue | shell metacharacters in read-IDs / sample names flowing into downstream commands |

Not every parser bug is memory corruption — e.g. BioPython's `Bio.Entrez` XXE/SSRF
(`CVE-2025-68463`) [6] is an XML-external-entity issue in a memory-safe language — but
file-structure validation at the boundary covers the dominant classes above.

Out of scope (by design): *content* threats — i.e. a sequence whose **bases** are hazardous
or screening-evading. That is the `commec` [12] / SecureDNA [13] domain; `seqfw` validates
file **structure**, not biological meaning. (A future content-screening hook is roadmap.)

---

## 3. Goals & non-goals

**Goals**
- Genuinely easy to install (`pip`/`brew`/`conda`/`cargo`) and to clone-and-run.
- Genuinely useful on day one via the integrity checks (pays for itself the first time it
  catches a broken file before an expensive step).
- Trustworthy, reproducible, quantifiable proof of security improvement (the benchmark, §8).
- Both a flawless CLI and a flawless Python import, from one codebase.

**Non-goals (v1)**
- Not a QC/metrics tool (FastQC's job) — we gate, we don't report GC%.
- Not a pipeline-config linter (a separate possible future tool).
- Not a sequence-content / biosecurity screener (`commec`'s [12] job).
- Not deep BAM/CRAM binary validation (roadmap).

---

## 4. Positioning & differentiation

Adversarial prior-art search concluded the specific niche is **unoccupied (~85% confidence)**.
The honest caveat: **our moat is framing + decompression-bomb defense + the crash benchmark,
not novel algorithms.** Therefore:

- **Lead with** security framing, decompression-bomb / resource-exhaustion defense (the one
  capability *no* genomic tool currently provides), and the "blocks inputs that crash real
  parsers" benchmark.
- **Do not lead with** "streaming validation" or "format checking" — those are table stakes
  (every Rust FASTX parser streams; `fastQValidator`/`vcf-validator`/`quickcheck` already
  validate-and-exit-code).

**Incumbent to out-position: PipeVal [3]** (Patel et al., UCLA, *Bioinformatics* 2024)
validates the same format set (FASTQ/SAM/BAM/CRAM/VCF/ZIP) as a pipeline step, but is framed
around pipeline-I/O **integrity/correctness, not security/adversarial input**, has no
decompression-bomb defense, and ships no security benchmark. We differentiate on exactly
those three axes. Other relatives — `seqkit sana` (salvages, never rejects), `samtools
quickcheck` (header+EOF only), `acidbio` [2] (dev-time test harness, not a runtime gate) —
each miss the security-gate combination.

---

## 5. Users & integration surfaces (both first-class)

```bash
# 1. Shell / CI — exit code gates the next step
seqfw check sample.fastq.gz && bwa mem ref.fa sample.fastq.gz

# 2. Pipe / stdin — gate a download inline
curl -s "$URL" | seqfw check - && echo ok

# 3. Nextflow / Snakemake — a guard step before the expensive one
process GUARD { script: "seqfw check ${reads}" }

# 4. Machine-readable
seqfw check cohort.vcf.gz --json
```

```python
# 5. Python library — e.g. a platform upload handler
import seqfw
report = seqfw.check("user_upload.fastq.gz")
if not report.ok:
    reject(report.reason)
```

**Usability contract (binding requirements):** zero config (sane defaults, no setup file) ·
streaming & bounded memory (validate a 200 GB file in constant RAM) · fast (sub-second on
typical files; it is a gate, not an analysis) · **offline** (zero network, zero telemetry —
a security tool must never phone home) · clear exit codes · reads from stdin.

---

## 6. v1 scope — formats & checks

**Formats:** FASTQ, FASTA, VCF, plus the gzip/bgzf transport layer under them. Verb: `check`.

### Checks

**Transport (gzip/bgzf), all formats**
- Decompression-bomb guard: enforce max compression-ratio **and** absolute uncompressed-size
  cap *as the stream is read*, so a bomb never fully inflates. (Headline security feature.)
- Corrupt / non-gzip / truncated-stream detection (incomplete download).
- Index sanity for `.gzi`/`.tbi`/`.csi`/`.fai`: offsets and item-counts within the data
  file's bounds; reject "impossibly large" counts (the `CVE-2026-31970` class [4]).

**FASTQ**
- 4-line record structure; `@`/`+` markers present.
- `len(seq) == len(qual)` per record.
- Phred byte range sanity; flag ambiguous +33 vs +64 encoding.
- Per-line and per-record length caps (reject pathological single lines).
- Reject embedded NUL / control chars; IUPAC alphabet enforcement (configurable strictness).
- Paired-end sync: R1/R2 record counts and read-ID correspondence.

**FASTA**
- Header sanity; reject duplicate / empty sequence names.
- Line-length caps; `.fai` offset-within-bounds when present.

**VCF**
- Record/column structural validation.
- FORMAT-field parsing safety (the `CVE-2020-36403` out-of-bounds-write class [5]).
- INFO/FORMAT tags declared in header; numeric fields within type bounds.
- Coordinate sanity.

**Cross-cutting**
- Read-ID / header / sample-name shell-metacharacter sanitization helper (downstream-shell
  safety).
- Path-traversal / URL-scheme rejection in any embedded path-like field.

### Output & exit-code model
- **Human (default):** verdict line + per-finding `severity · location (record# / byte
  offset) · what's wrong · why it matters` (with CVE-class tag where apt). Color auto-off
  when not a TTY.
- **`--json`:** structured findings for machines / dashboards.
- **Severity:** `ERROR` (reject) vs `WARN` (pass-but-flag); threshold tunable (`--strict`).
- **Exit codes:** `0` clean · `1` rejected · `2` tool/usage error (so CI distinguishes "bad
  file" from "tool broke").

---

## 7. Architecture

Rust workspace, three small well-bounded units + shared assets:

- **`seqfw-core`** (library): the brain. No I/O policy — it decides *is this stream safe, and
  why*.
  - `Source`: streaming reader; transparently decompresses gz/bgzf through a **byte-counting
    bomb meter** (a wrapping reader enforcing ratio/abs caps mid-stream).
  - `Format`: sniffer (or explicit `--format`).
  - `Check` trait: independent units (`DecompressionGuard`, `IndexBounds`, `FastqStructure`,
    `PairSync`, `PhredRange`, `FastaStructure`, `VcfStructure`, `VcfFormatField`,
    `ControlChars`, `HeaderSafety`) that consume the stream incrementally and emit `Finding`s.
  - `Report { ok, findings }`: aggregator; applies the severity/threshold policy.
- **`seqfw-cli`** (binary): thin adapter — clap args, wires stdin/file → core, renders
  human/JSON, sets exit codes.
- **`seqfw-py`** (PyO3 / maturin): thin binding exposing `check()` returning a Python object
  mirroring `Report`.
- **`corpus/`** + **fuzz harness**: shared test assets (see §9).

**Why these boundaries:** the corpus and core are the durable assets; CLI and Python are
disposable skins. A later WASM build (validate in-browser before an upload leaves the page)
or a C ABI wraps the same core with no rewrite. New format = new `Check`s, no engine surgery.

### Data flow
`input (path/stdin) → Source (decompress + bomb meter) → sniff format → stream records
through ordered Checks → aggregate Findings → Report → adapter renders (CLI exit/text/json or
Python object)`. Nothing loads the whole file into memory.

---

## 8. The proof — reproducible security benchmark (the headline deliverable)

A `make benchmark` Docker harness that produces three honest numbers, re-runnable by anyone.

1. **Block rate (coverage):** % of a curated known-bad set that `seqfw` rejects at the gate.
2. **Harm prevented (the video link):** feed each known-bad input to a **real, pinned,
   unmodified, vulnerable** downstream tool built with **AddressSanitizer + UBSan**, and
   record the outcome (clean / heap-overflow / segfault / OOM / hang). Improvement =
   *"N inputs that provably crash/corrupt the real tool become a clean rejection when `seqfw`
   is in front."*
3. **False positives + overhead:** run over a large **known-good** public corpus (must reject
   ~0%) and measure added latency + bounded memory.

**Materials — and an honesty point that surfaced during citation review:** **no ready-made
public crash file exists for the htslib CVEs we target.** The OSS-Fuzz reproducer for
`CVE-2020-36403` (`OSV-2020-955`) is login-gated, and the 2026 cluster [4] shipped with no
public PoC. This is *appropriate* (responsible disclosure) and it shapes our approach — we
build our own safe reproducers for precisely-documented bugs and lean on genuinely-public
malformed-file corpora for breadth:
- **Primary VCF crash target:** `CVE-2020-36403` [5] — an out-of-bounds write in htslib's
  `vcf_parse_format`, affecting ≤1.10.2 (fixed 1.11). Function, fix commit, and versions are
  public; **the crash file is not** — so we construct a safe reproducer for the documented
  OOB-write against pinned **htslib 1.10.2** (and check the fix PR's regression tests for a
  usable input).
- **Currency:** the 2026 cluster [4] (pin **htslib 1.23.0** vs fixed 1.23.1) — no public PoC,
  so we build safe reproducers from the published source diffs (esp. `CVE-2026-31970`, the
  BGZF/GZI integer overflow, reachable via our index-bounds check).
- **Genuinely-public known-bad (breadth):** the `acidbio` malformed-input corpus [2] (GPLv2)
  and the htslib / htsjdk repository test files. We do **not** rely on OSS-Fuzz reproducer
  artifacts, which are largely access-restricted.
- **Known-good (false-positive set):** GIAB / NIST [9] (HG001 = NA12878, HG002 = NA24385) +
  1000 Genomes [10], with SRA accessions traceable from GIAB indexes (publish manifest with
  SHA-256 per file).

**Methodology (trustworthy; cf. Klees et al. [7], Magma [8]):** detect crashes with
sanitizers, not bare segfaults (`-fno-sanitize-recover=all`, `halt_on_error`); bucket
CRASH / HANG / OOM separately (don't conflate); **no strawman victim** — real unmodified
pinned tools, exact version+commit+flags stated; build the **CLI tools with plain ASAN
*without* `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`** for the actual security claim (the
OSS-Fuzz harness is used only as a convenient corpus dispatcher, never for the headline
number); measure overhead on **non-sanitized release builds**; pin everything; ship the
Docker image and per-input results so the table is independently checkable.

**Citable baselines (verified against primary sources):** UW [1] insecure-function density
**11×** (2.005 vs 0.185 insecure calls per 1k LOC, p=0.027 — *not* "2×"; the static-buffer
metric in the same paper was a null result); 3 real vulns (fastx-toolkit, samtools,
SOAPdenovo2 — not bwa) [1]; `acidbio` [2] found **75/80 packages <70% correct** on malformed
BED (92-case suite).

---

## 9. Testing strategy

- **Versioned corpus** of expected-pass / expected-fail files, each documenting the threat it
  represents (the `acidbio` [2] pattern, security-framed and multi-format). Golden test: each
  file → expected verdict. This corpus is itself a citable public artifact.
- **Fuzzing (`cargo-fuzz`)** on `seqfw-core`: it parses hostile input, so it must **never**
  panic / hang / OOM on arbitrary bytes. (We hold ourselves to the standard we demand of
  htslib.)
- **Property tests:** any spec-valid file passes; any known-good file round-trips a future
  `clean` pass unchanged.

---

## 10. Distribution & install

One build graph, every channel:

- **PyPI via maturin** → `pip install seqfw` (prebuilt `abi3-py38` wheels, manylinux2014
  floor; `maturin-action` GitHub matrix).
- **crates.io** → `cargo install seqfw` (claim the name early; offer `cargo-binstall`).
- **cargo-dist** → GitHub Releases cross-compiled static binaries (musl for Linux) +
  `curl … | sh` installer + a generated **Homebrew tap** formula, all from one config.
  (Note: cargo-dist is renaming to `dist`; track before relying.)
- **Bioconda** → `conda install -c bioconda seqfw` (accepts Rust via
  `{{ compiler('rust') }}`; **auto-builds a BioContainer** on merge — high value for
  genomics; bundle dep licenses with `cargo-bundle-licenses`).
- **Clone & run** → `git clone && cargo run` (cargo auto-fetches deps).

Install-friction (lowest first): PyPI ≈ Homebrew ≈ Bioconda ≈ `curl|sh` → `cargo install`
→ clone & run.

---

## 11. Dual-use & responsible disclosure

Confirmed **low** biosecurity concern: a malformed BAM/VCF that crashes a parser is ordinary
application security — categorically the same as a malformed PNG crashing libpng — and is
**out of scope** of DNA-synthesis screening (which governs ≥200 nt pathogen *sequences*, not
file formats; see the Common Mechanism baseline context [12]). Policy, stated in
`SECURITY.md` + `DISCLOSURE.md`:

1. **Patch-gate:** ship public crashers only for already-fixed, publicly disclosed bugs
   (published CVE / upstream fix commit / already-public OSS-Fuzz issue).
2. **Coordinated disclosure:** if our own fuzzing finds an unknown crash, report upstream
   privately; withhold from the public corpus until fix-or-90-days (+14-day grace).
3. **Generators over raw weaponized files** for the most dangerous samples; gate the
   highest-severity memory-corruption samples behind a build step.
4. **Provenance per sample:** CVE/issue ID + fix commit + disclosure date (auditable gating).
5. **No hazardous biological data:** build malformed files from synthetic / random /
   already-public reference content, never from regulated-agent sequences. State this.
6. **Citable:** license + Zenodo DOI for the corpus.

> The fact that **no public PoCs exist** for our target CVEs (§8) is the disclosure norm
> working as intended — and it is precisely *why* we self-build reproducers rather than
> redistribute crashers.

---

## 12. Roadmap (post-v1)

- BAM / CRAM binary validation + full index-file validation → demo against the 2026 CRAM
  cluster [4].
- `clean` / sanitize verb: emit a cleaned, safe-to-parse stream (firewall "passes good
  traffic").
- Content-screening hook into `commec` [12] (bridge structural validation → biorisk
  screening).
- WASM build for in-browser pre-upload validation; C ABI.
- Possible sibling project: a pipeline-config security linter (separate tool).

---

## 13. Open questions / risks

- **"It's just glue" critique** — mitigated by leading with bomb-defense + benchmark, but
  worth a crisp threat-model section in the README.
- **PipeVal [3] could add a security narrative** — our durable differentiators are the
  benchmark and the bomb defense; keep those strong.
- **No public PoCs exist for `CVE-2020-36403` [5] or the 2026 cluster [4]** — so building
  safe reproducers is real, required work. The documented OOB-write in `vcf_parse_format` on
  pinned htslib 1.10.2 is the most tractable first reproducer.
- **Name** `seqfw` is provisional.

---

## 14. Decision log (locked during brainstorming)

| Decision | Choice |
|---|---|
| Tool shape | Input-validation firewall (not a pipeline linter) |
| v1 formats | FASTQ, FASTA, VCF + gzip/bgzf |
| Value framing | Dual: integrity (daily) + security (identity) |
| Primary surfaces | CLI **and** Python library, both first-class |
| Language | Rust core → static binary (cargo-dist) + Python wheel (maturin/PyO3) |
| Proof | Reproducible ASAN benchmark vs real pinned-vulnerable tools |
| Ethics | Patch-gated corpus + coordinated disclosure |

---

## 15. References

*All entries verified against primary sources on 2026-06-11. Per-claim verification notes
follow the list.*

- **[1]** P. Ney, K. Koscher, L. Organick, L. Ceze, T. Kohno. "Computer Security, Privacy,
  and DNA Sequencing: Compromising Computers with Synthesized DNA, Privacy Leaks, and More."
  *26th USENIX Security Symposium*, 2017, pp. 765–779. (No DOI.)
  https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/ney
- **[2]** Y. N. Niu, E. G. Roberts, D. Denisko, M. M. Hoffman. "Assessing and assuring
  interoperability of a genomics file format." *Bioinformatics* 38(13):3327–3336, 2022.
  https://doi.org/10.1093/bioinformatics/btac327 · repo: https://github.com/hoffmangroup/acidbio
- **[3]** Y. Patel, A. Beshlikyan, M. Jordan, G. Kim, A. Holmes, T. N. Yamaguchi,
  P. C. Boutros. "PipeVal: light-weight extensible tool for file validation."
  *Bioinformatics* 40(2):btae079, 2024.
  https://doi.org/10.1093/bioinformatics/btae079 · repo: https://github.com/uclahs-cds/package-PipeVal
- **[4]** htslib/samtools coordinated disclosure, 2026-03-18 (reporter: Harrison Green):
  `CVE-2026-31962`…`-31973` (10 htslib + 2 samtools); e.g. `CVE-2026-31970` =
  GHSA-p345-84hx-fq6q (BGZF/GZI integer overflow → heap overflow). htslib fixed in
  1.21.1 / 1.22.2 / 1.23.1. https://github.com/samtools/htslib/security/advisories
- **[5]** `CVE-2020-36403` — htslib out-of-bounds write in `vcf_parse_format` (CWE-787),
  affects ≤1.10.2, fixed 1.11.
  https://nvd.nist.gov/vuln/detail/CVE-2020-36403 · https://osv.dev/vulnerability/CVE-2020-36403
- **[6]** `CVE-2025-68463` — BioPython `Bio.Entrez` XML external entity (XXE) / SSRF
  (CWE-611), affects ≤1.86, fixed 1.87, CVSS 4.9.
  https://nvd.nist.gov/vuln/detail/CVE-2025-68463 · https://github.com/biopython/biopython/issues/5109
- **[7]** G. Klees, A. Ruef, B. Cooper, S. Wei, M. Hicks. "Evaluating Fuzz Testing."
  *ACM CCS 2018*, pp. 2123–2138. https://doi.org/10.1145/3243734.3243804
- **[8]** A. Hazimeh, A. Herrera, M. Payer. "Magma: A Ground-Truth Fuzzing Benchmark."
  *Proc. ACM Meas. Anal. Comput. Syst. (POMACS)* 4(3), Art. 49, 2020 (presented at
  SIGMETRICS 2021). https://doi.org/10.1145/3428334 · arXiv:2009.01120
- **[9]** J. M. Zook, D. Catoe, J. McDaniel, … M. Salit, and the Genome in a Bottle
  Consortium. "Extensive sequencing of seven human genomes to characterize benchmark
  reference materials." *Scientific Data* 3:160025, 2016.
  https://doi.org/10.1038/sdata.2016.25 · data: https://ftp-trace.ncbi.nlm.nih.gov/ReferenceSamples/giab/
- **[10]** The 1000 Genomes Project Consortium. "A global reference for human genetic
  variation." *Nature* 526:68–74, 2015.
  https://doi.org/10.1038/nature15393 · portal: https://www.internationalgenome.org/
- **[11]** OSS-Fuzz — htslib project (continuous fuzzing harness).
  https://github.com/google/oss-fuzz/tree/master/projects/htslib
- **[12]** IBBIS Common Mechanism (`commec`), MIT-licensed sequence-screening tool.
  https://github.com/ibbis-bio/common-mechanism — context paper: N. E. Wheeler, S. R. Carter,
  T. Alexanian, C. Isaac, J. Yassif, P. Millet. "Developing a Common Global Baseline for
  Nucleic Acid Synthesis Screening." *Applied Biosafety* 29(2):71–78, 2024.
  https://doi.org/10.1089/apb.2023.0034
- **[13]** C. Baum, J. Berlips, … K. M. Esvelt, … R. L. Rivest, A. Shamir, … A. C. Yao,
  et al. "A system capable of verifiably and privately screening global DNA synthesis."
  arXiv:2403.14023, 2024. https://arxiv.org/abs/2403.14023 · project: https://securedna.org/

### Verification notes (limitations a reviewer should know)
- **[3]** corrected from an earlier draft that mis-attributed authorship/venue; the entry
  above is the verified citation.
- **[4], [5]** — **no public proof-of-concept / crash file is available** for these CVEs;
  the OSS-Fuzz reproducer `OSV-2020-955` referenced for [5] is login-gated. Benchmark inputs
  must be self-built (§8). The 1.21.1/1.22.2/1.23.1 fixed-version triple is scoped to the
  **htslib** CVEs; the two samtools CVEs (`-31972`, `-31973`) have their own fix versions.
- **[6]** fixed-version 1.87 is sourced from the release/PyPI record; the GHSA "patched
  versions" field was unpopulated at verification time.
- **[8]** formal publication year is **2020** (POMACS 4(3)); the "2021" sometimes seen refers
  to SIGMETRICS 2021 presentation.
- **[12]** no dedicated `commec` *software/methods* paper was found; the repo is the primary
  reference and the Applied Biosafety paper is initiative context only.
- **[13]** the arXiv version is the verified primary; a *National Science Review* journal
  version may exist but was **not** primary-verified this pass.
