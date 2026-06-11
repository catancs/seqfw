# seqfw — a firewall for genomic data

`seqfw` validates genomic files at the trust boundary and **rejects malformed,
malicious, or resource-exhausting inputs before they reach memory-unsafe parsers**
(htslib / samtools / BioPython).

> Status: early development. v1 target: FASTQ / FASTA / VCF. This build validates
> FASTQ (framing + content + paired-end), FASTA (structure + naming), and VCF
> (header/record/tag + CVE-2020-36403-class FORMAT-field safety) files, checks
> companion index files (.fai/.gzi/.tbi/.csi) for impossible counts and
> out-of-bounds offsets, auto-detects format, screens identifiers for unsafe
> characters, and blocks gzip/bgzf decompression bombs.

## Install (from source, for now)

```bash
git clone https://github.com/catancs/seqfw && cd seqfw
cargo build --release
./target/release/seqfw check your.fastq.gz
```

## Use

```bash
seqfw check sample.fastq.gz        # exit 0 = clean, 1 = rejected, 2 = tool error
seqfw check - < sample.fastq       # read stdin
seqfw check sample.fastq --json    # machine-readable findings
seqfw check R1.fastq.gz --mate R2.fastq.gz   # paired-end sync check
seqfw check sample.fastq --strict-dna        # enforce ACGTN (default is IUPAC)
seqfw check sample.fasta                      # FASTA structural validation
seqfw check input --format fastq              # force a format instead of sniffing
seqfw check cohort.vcf.gz                     # VCF structural + tag validation
seqfw check ref.fa.fai --data ref.fa          # index-bounds vs the indexed file
```

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

## Benchmark

A reproducible harness (`benchmark/`) produces three honest numbers (design spec §8):

```bash
make benchmark-local   # block rate + false positives + overhead (no Docker)
make benchmark         # adds "harm prevented" vs ASAN-built pinned htslib 1.10.2
```

Verified result: **block rate 6/6 = 100%**, **false positives 0/9 = 0%**,
overhead ~4–12 ms on multi-MB valid files, and **harm prevented = 1** — the
malformed-VCF reproducer (CVE-2020-36403 FORMAT-field shape) triggers a
sanitizer-detected crash in **real, unmodified, ASAN+UBSan-built htslib 1.10.2**
(`bcftools view` → `UndefinedBehaviorSanitizer: … kstring.c:156 … applying zero
offset to null pointer → Aborted`), yet `seqfw` rejects the input first. Known-bad
reproducers are patch-gated, self-built **structural** inputs for already-fixed
disclosed bugs — see `benchmark/PROVENANCE.md`. No live crasher is shipped for any
unfixed issue.

See `docs/superpowers/specs/` for the design and `docs/superpowers/plans/` for the
build plan. Citations for every empirical claim live in the design spec's References.
