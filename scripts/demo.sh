#!/usr/bin/env bash
#
# demo.sh — the scripted seqfw demo used to record docs/demo.svg.
#
# It runs `seqfw check` against the bundled corpus/ fixtures so the recording is
# fully reproducible and offline: clean inputs pass, malformed ones are rejected
# with a named rule, and exit codes are shown. See docs/DEMO.md for how to record.
#
# Usage:
#   ./scripts/demo.sh            # uses ./target/release/seqfw (build it first)
#   SEQFW=seqfw ./scripts/demo.sh  # use a seqfw already on PATH
#
set -u

SEQFW="${SEQFW:-./target/release/seqfw}"

# --- tiny "typed terminal" helpers -----------------------------------------
# Print a prompt + the command (as if typed), then run it. Pauses make the
# asciinema capture read at human speed; set DEMO_FAST=1 to skip them.
pause() { [ "${DEMO_FAST:-0}" = "1" ] || sleep "${1:-1}"; }

run() {
  printf '\033[1;32m$\033[0m %s\n' "$*"
  pause 0.6
  "$@"
  local rc=$?
  printf '\033[2m# exit %d\033[0m\n\n' "$rc"
  pause 1
  return 0
}

# --- the script ------------------------------------------------------------
clear 2>/dev/null || true
printf '\033[1m# seqfw — a firewall for genomic data\033[0m\n'
printf '\033[2m# one verb, every format; clean input passes, hostile input is rejected\033[0m\n\n'
pause 1.5

# 1. A clean FASTQ passes (exit 0).
run "$SEQFW" check corpus/fastq/pass/good.fastq

# 2. A length-mismatched FASTQ is rejected with a named rule (exit 1).
run "$SEQFW" check corpus/fastq/fail/length_mismatch.fastq

# 3. The CVE-2020-36403-class VCF FORMAT-field defect is rejected.
run "$SEQFW" check corpus/vcf/fail/format_mismatch.vcf

# 4. Duplicate FASTA names are caught.
run "$SEQFW" check corpus/fasta/fail/duplicate_name.fasta

# 5. An out-of-bounds .fai index offset is caught vs the indexed file.
run "$SEQFW" check corpus/fai/fail/oob.fa.fai --data corpus/fai/pass/ref.fa

# 6. Machine-readable findings for CI / platforms.
run "$SEQFW" check corpus/vcf/fail/format_mismatch.vcf --json

printf '\033[1;32m# gate before you compute — exit codes drive your pipeline\033[0m\n'
pause 2
