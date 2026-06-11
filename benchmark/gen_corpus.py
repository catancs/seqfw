#!/usr/bin/env python3
"""Generate the seqfw benchmark corpus.

Builds two sets under benchmark/corpus/:
  known-bad/  one file per documented, already-fixed bug class. Each file is a
              SELF-BUILT STRUCTURAL reproducer (no weaponized payload); the
              hazardous property — a count/length field that lies, an over-long
              FORMAT row — is exactly what seqfw rejects. Patch-gated per the
              design spec's disclosure policy (see PROVENANCE.md).
  known-good/ the false-positive set: copies of the repo's corpus/*/pass/
              fixtures plus a few larger synthetic-but-valid files for overhead.

Writes corpus/manifest.json (sha256 + set + expected rule + provenance per file).
Stdlib only.
"""
import gzip
import hashlib
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = Path(__file__).resolve().parent / "corpus"
BAD = CORPUS / "known-bad"
GOOD = CORPUS / "known-good"

# --- known-bad payloads -----------------------------------------------------

VCF_FORMAT_OVERFLOW = (
    "##fileformat=VCFv4.2\n"
    '##FORMAT=<ID=GT,Number=1,Type=String,Description="g">\n'
    "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\ts1\n"
    "chr1\t100\t.\tA\tG\t.\t.\t.\tGT\t0/1:99\n"
).encode()

FASTQ_TRUNCATED = b"@r1\nACGT\n+\n"  # missing the quality line
FASTA_DUPNAMES = b">seq1\nACGT\n>seq1\nTTGG\n"

# 8 byte .gzi claiming u64::MAX entries with no body.
GZI_IMPOSSIBLE = struct.pack("<Q", (1 << 64) - 1)

# Raw (uncompressed) CSI header: magic + min_shift, depth, l_aux(=0), n_ref=i32::MAX.
CSI_IMPOSSIBLE = b"CSI\x01" + struct.pack("<iii", 14, 5, 0) + struct.pack("<i", (1 << 31) - 1)


def gzip_bomb() -> bytes:
    # Leading '@' routes through the FASTQ check; ~8 MiB of 'A' compresses to a
    # few KiB, so the expansion ratio trips the bomb guard at default options.
    plain = b"@bomb\n" + b"A" * (8 * 1024 * 1024)
    return gzip.compress(plain, 9)


# (filename, bytes, expected seqfw rule, provenance tag)
KNOWN_BAD = [
    ("vcf_format_overflow.vcf", VCF_FORMAT_OVERFLOW, "vcf.format_field_mismatch", "CVE-2020-36403"),
    ("gzip_bomb.fastq.gz", gzip_bomb(), "transport.decompression_bomb", "decompression-bomb class"),
    ("gzi_impossible_count.gzi", GZI_IMPOSSIBLE, "gzi.bad_entry_count", "CVE-2026-31970 class"),
    ("csi_impossible_nref.csi", CSI_IMPOSSIBLE, "tabix.impossible_count", "CVE-2026-31970 class"),
    ("fastq_truncated.fastq", FASTQ_TRUNCATED, "fastq.truncated_record", "corruption/truncation class"),
    ("fasta_dupnames.fasta", FASTA_DUPNAMES, "fasta.duplicate_name", "corruption/duplicate-name class"),
]


def synth_fastq(n_reads: int) -> bytes:
    rec = b"@read%d\nACGTACGTACGTACGT\n+\nIIIIIIIIIIIIIIII\n"
    return b"".join(rec % i for i in range(n_reads))


def synth_vcf(n_rows: int) -> bytes:
    head = (
        b"##fileformat=VCFv4.2\n"
        b'##INFO=<ID=DP,Number=1,Type=Integer,Description="d">\n'
        b"#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"
    )
    rows = b"".join(b"chr1\t%d\t.\tA\tG\t50\tPASS\tDP=20\n" % (i + 1) for i in range(n_rows))
    return head + rows


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    BAD.mkdir(parents=True)
    GOOD.mkdir(parents=True)

    files = []

    for name, data, rule, prov in KNOWN_BAD:
        (BAD / name).write_bytes(data)
        files.append(
            {
                "path": f"known-bad/{name}",
                "sha256": sha256(data),
                "set": "bad",
                "expected_rule": rule,
                "provenance": prov,
            }
        )

    # Known-good: copy every repo corpus pass fixture.
    for passdir in sorted(ROOT.glob("corpus/*/pass")):
        for src in sorted(passdir.iterdir()):
            if not src.is_file():
                continue
            data = src.read_bytes()
            dst_name = f"{passdir.parent.name}__{src.name}"
            (GOOD / dst_name).write_bytes(data)
            files.append(
                {
                    "path": f"known-good/{dst_name}",
                    "sha256": sha256(data),
                    "set": "good",
                    "expected_rule": None,
                    "provenance": "repo corpus pass fixture",
                }
            )

    # Larger synthetic valids for the overhead measurement.
    for name, data in [
        ("big_valid.fastq", synth_fastq(50_000)),
        ("big_valid.vcf", synth_vcf(50_000)),
    ]:
        (GOOD / name).write_bytes(data)
        files.append(
            {
                "path": f"known-good/{name}",
                "sha256": sha256(data),
                "set": "good",
                "expected_rule": None,
                "provenance": "synthetic valid (overhead)",
                "overhead": True,
            }
        )

    manifest = {
        "description": "seqfw benchmark corpus — see PROVENANCE.md for the ethics gate",
        "files": files,
    }
    (CORPUS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    n_bad = sum(1 for f in files if f["set"] == "bad")
    n_good = sum(1 for f in files if f["set"] == "good")
    print(f"generated {len(files)} files: {n_bad} known-bad, {n_good} known-good")


if __name__ == "__main__":
    main()
