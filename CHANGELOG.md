# Changelog

## 0.1.0

First v1 release. `seqfw` validates genomic files at the trust boundary and
rejects malformed, malicious, or resource-exhausting inputs.

- **FASTQ** — record framing, sequence/quality length equality, Phred range +
  ambiguous +33/+64 encoding flag, control-byte rejection, configurable IUPAC
  alphabet, and paired-end (`--mate`) read-ID/count sync.
- **FASTA** — header sanity, empty/duplicate names, empty sequences, line caps.
- **VCF** — header presence, column structure/count, coordinate sanity,
  INFO/FORMAT header-tag consistency, and the CVE-2020-36403-class FORMAT-field
  count safety check.
- **Index files** — `.fai`/`.gzi`/`.tbi`/`.csi` offset-in-bounds and
  impossible-count guards (the CVE-2026-31970 class), all reads bounded.
- **Transport** — transparent gzip/bgzf decode behind a decompression-bomb guard
  (absolute + expansion-ratio caps).
- **Cross-cutting** — identifier safety (control/shell-metachar/path-traversal/
  URL-scheme) on read IDs and sample names.
- **Surfaces** — `seqfw check` CLI (human + `--json`, exit 0/1/2) and a PyO3
  Python module (`seqfw.check` / `check_bytes` / `check_pair` / `check_pair_bytes`
  / `check_index`), reaching parity with the CLI's paired-end and index checks.
- **Proof** — a reproducible ASAN benchmark: 100% block rate / 0% false
  positives, and a verified crash of unmodified htslib 1.10.2 on an input seqfw
  blocks.
