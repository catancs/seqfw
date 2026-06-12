# seqfw rule reference

Every finding `seqfw` emits carries a **stable rule ID** of the form
`area.snake_case` (e.g. `vcf.format_field_mismatch`). These IDs are a public API:
you can branch on them in CI, grep them out of `--json` output, and rely on them
not changing meaning between releases. This file documents every rule the
validator can produce.

## How findings work

Each finding has a **severity**:

| Severity | Effect | Exit code |
|---|---|---|
| `error` | **Rejects** the input — `report.ok` is `false` | `1` |
| `warn`  | Reported for visibility, but does **not** reject on its own | `0` |

A report is "ok" *unless it contains at least one `error`* — warnings never flip
that. (`seqfw` reserves exit code `2` for tool errors: a missing file, an
unreadable path, bad arguments — not a property of the input.)

In `--json`, every finding serializes as `{severity, rule, message, location?}`,
where `location` may carry a 1-based `record` index and/or a `byte_offset`.

```console
$ seqfw check evil.vcf --json | jq '.findings[].rule'
"vcf.format_field_mismatch"
```

### Wildcard families

A few rule names recur across formats because the *defect class* is the same. When
this doc (or the [threat model](../README.md#threat-model--what-v1-defends-against))
writes `*.offset_out_of_bounds`, it means the rule exists under several area
prefixes:

- `*.line_too_long` — `fastq` · `fasta` · `vcf` · `fai`
- `*.offset_out_of_bounds` — `fai` · `gzi`
- `tabix.impossible_count`, `gzi.bad_entry_count`, `index.too_large` — the
  impossible-/oversized-count guards (CVE-2026-31970 class)

---

## `transport.*` — decode layer (gzip / bgzf, all formats)

| Rule | Severity | Triggered when |
|---|---|---|
| `transport.decompression_bomb` | error | Decompressed output exceeds the absolute byte cap or the expansion-ratio cap — a small `.gz`/`.bgzf` that balloons to an enormous size. |
| `transport.read_error` | error | The input stream errored mid-read — a truncated or corrupt file, or a failed decode. |

## `format.*` — dispatch

| Rule | Severity | Triggered when |
|---|---|---|
| `format.unrecognized` | error | The input matches no known format (FASTQ / FASTA / VCF) and none was forced with `--format`. |

## `fastq.*`

| Rule | Severity | Triggered when |
|---|---|---|
| `fastq.bad_header` | error | A record's line 1 does not start with `@`. |
| `fastq.bad_separator` | error | A record's line 3 (the separator) does not start with `+`. |
| `fastq.truncated_record` | error | The input ends before all four lines of a record were read. |
| `fastq.length_mismatch` | error | A record's sequence length differs from its quality length. |
| `fastq.invalid_base` | error | A sequence contains a base outside the active alphabet (full IUPAC by default; `ACGTN` under `--strict-dna`). |
| `fastq.control_char` | error | A control byte appears in a sequence or quality line. |
| `fastq.phred_out_of_range` | error | A quality byte falls outside the valid Phred range. |
| `fastq.line_too_long` | error | A line exceeds the per-line byte cap (memory-exhaustion guard). |
| `fastq.ambiguous_encoding` | warn | Every quality score is `>= 0x49`, so Phred+33 cannot be distinguished from legacy Phred+64. |
| `fastq.pair_count_mismatch` | error | Paired files (`--mate`) have different record counts. |
| `fastq.pair_id_mismatch` | error | Paired reads at the same position do not share a base read ID (`--mate`). |

## `fasta.*`

| Rule | Severity | Triggered when |
|---|---|---|
| `fasta.bad_header` | error | Sequence data appears before the first `>` header. |
| `fasta.empty_name` | error | A `>` header has no sequence name. |
| `fasta.empty_sequence` | error | A header has no sequence body. |
| `fasta.duplicate_name` | error | Two records share the same sequence name. |
| `fasta.line_too_long` | error | A line exceeds the per-line byte cap. |

## `vcf.*`

| Rule | Severity | Triggered when |
|---|---|---|
| `vcf.missing_fileformat` | error | Missing the mandatory `##fileformat=` meta line. |
| `vcf.missing_header` | error | Missing the `#CHROM` column-header line, or a data record appears before it. |
| `vcf.too_few_columns` | error | A record has fewer than the 8 mandatory VCF columns. |
| `vcf.column_count_mismatch` | error | A record's column count differs from the `#CHROM` header's. |
| `vcf.bad_pos` | error | `POS` is not a valid coordinate. |
| `vcf.format_field_mismatch` | error | A sample column has more `:`-subfields than `FORMAT` declares keys (CVE-2020-36403-class field-count overflow). |
| `vcf.undeclared_info` | warn | An `INFO` key is not declared in the header meta lines. |
| `vcf.undeclared_format` | warn | A `FORMAT` key is not declared in the header meta lines. |
| `vcf.line_too_long` | error | A line exceeds the per-line byte cap. |

## `fai.*` — `.fai` FASTA/FASTQ index

| Rule | Severity | Triggered when |
|---|---|---|
| `fai.bad_columns` | error | A line does not have the expected number of `.fai` columns. |
| `fai.bad_number` | error | A numeric column is not a valid integer. |
| `fai.bad_linewidth` | error | The `LINEBASES`/`LINEWIDTH` pair is inconsistent. |
| `fai.offset_out_of_bounds` | error | `OFFSET + LENGTH` exceeds the indexed data file's size (requires `--data`). |
| `fai.line_too_long` | error | A line exceeds the per-line byte cap. |

## `gzi.*` — `.gzi` bgzip index

| Rule | Severity | Triggered when |
|---|---|---|
| `gzi.truncated` | error | The file is too short to hold the declared entry count, or ends mid-entry. |
| `gzi.bad_entry_count` | error | The declared entry count is impossible — it overflows or exceeds the file size. |
| `gzi.non_monotonic` | error | Successive entry offsets decrease (the index must be monotonic). |
| `gzi.offset_out_of_bounds` | error | An entry offset points past the data file (requires `--data`). |

## `tabix.*` — `.tbi` / `.csi` index

| Rule | Severity | Triggered when |
|---|---|---|
| `tabix.bad_magic` | error | Missing the expected tabix/CSI magic number. |
| `tabix.truncated` | error | The header ends before a mandatory field (tabix fields, CSI aux-length, or CSI `n_ref`). |
| `tabix.impossible_count` | error | A declared count/length (`l_aux`, `n_ref`, or name-block length) is negative or implausibly large. |

## `index.*` — generic index guard

| Rule | Severity | Triggered when |
|---|---|---|
| `index.too_large` | error | The index file exceeds the byte sanity cap (resource-exhaustion guard). |

## `safety.*` — identifier hygiene (read IDs & sample names, all formats)

These screen identifiers that often flow into shell commands or filenames
downstream. Most are **warnings**, not errors: real-world IDs legitimately contain
characters like `:` and `|`, so rejecting them outright would violate the
"never reject valid data" contract. A raw control byte is the exception.

| Rule | Severity | Triggered when |
|---|---|---|
| `safety.control_char` | error | An identifier contains a control byte. |
| `safety.shell_metachar` | warn | An identifier contains shell metacharacters. |
| `safety.path_traversal` | warn | An identifier contains a path-traversal sequence (e.g. `../`). |
| `safety.url_scheme` | warn | An identifier embeds a URL scheme — unsafe if dereferenced as a location. |

---

## Adding a rule

New checks must add their rule here. See
[CONTRIBUTING.md → Adding a check](../CONTRIBUTING.md#adding-a-check): add the
`Finding::error(...)` / `Finding::warn(...)` under `crates/seqfw-core/src/checks/`,
a passing **and** failing fixture under `corpus/<format>/{pass,fail}/`, and a row
in the table above. Prefer `warn` over `error` for anything a valid file might
trip.
