# seqfw — a firewall for genomic data

`seqfw` validates genomic files at the trust boundary and **rejects malformed,
malicious, or resource-exhausting inputs before they reach memory-unsafe parsers**
(htslib / samtools / BioPython).

> Status: early development. v1 target: FASTQ / FASTA / VCF. This build validates
> FASTQ record framing + content (sequence/quality length, Phred range, control-byte
> rejection, IUPAC alphabet), paired-end sync, and blocks gzip/bgzf decompression bombs.

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
```

See `docs/superpowers/specs/` for the design and `docs/superpowers/plans/` for the
build plan. Citations for every empirical claim live in the design spec's References.
