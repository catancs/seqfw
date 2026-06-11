use assert_cmd::Command;
use predicates::prelude::*;

fn seqfw() -> Command {
    Command::cargo_bin("seqfw").unwrap()
}

#[test]
fn check_clean_file_exits_zero() {
    seqfw()
        .args(["check", "../../corpus/fastq/pass/good.fastq"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn check_bad_file_exits_one() {
    seqfw()
        .args(["check", "../../corpus/fastq/fail/bad_separator.fastq"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fastq.bad_separator"));
}

#[test]
fn check_missing_file_exits_two() {
    seqfw()
        .args(["check", "../../corpus/does-not-exist.fastq"])
        .assert()
        .code(2);
}

#[test]
fn check_json_reports_findings() {
    seqfw()
        .args([
            "check",
            "--json",
            "../../corpus/fastq/fail/bad_separator.fastq",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"ok\": false"))
        .stdout(predicate::str::contains(
            "\"rule\": \"fastq.bad_separator\"",
        ))
        .stdout(predicate::str::contains("\"severity\": \"error\""));
}

#[test]
fn check_length_mismatch_exits_one() {
    seqfw()
        .args(["check", "../../corpus/fastq/fail/length_mismatch.fastq"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fastq.length_mismatch"));
}

#[test]
fn check_matched_pair_exits_zero() {
    seqfw()
        .args([
            "check",
            "../../corpus/fastq/pass/pair_R1.fastq",
            "--mate",
            "../../corpus/fastq/pass/pair_R2.fastq",
        ])
        .assert()
        .success();
}

#[test]
fn check_mismatched_pair_exits_one() {
    seqfw()
        .args([
            "check",
            "../../corpus/fastq/fail/pair_mismatch_R1.fastq",
            "--mate",
            "../../corpus/fastq/fail/pair_mismatch_R2.fastq",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fastq.pair_id_mismatch"));
}

#[test]
fn check_strict_dna_rejects_iupac() {
    // good.fastq is pure ACGT, so craft an IUPAC-but-not-DNA case via stdin.
    seqfw()
        .args(["check", "--strict-dna", "-"])
        .write_stdin("@r1\nACRT\n+\nIIII\n")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fastq.invalid_base"));
}

#[test]
fn check_good_fasta_exits_zero() {
    seqfw()
        .args(["check", "../../corpus/fasta/pass/good.fasta"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn check_duplicate_fasta_name_exits_one() {
    seqfw()
        .args(["check", "../../corpus/fasta/fail/duplicate_name.fasta"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fasta.duplicate_name"));
}

#[test]
fn check_unrecognized_format_exits_one() {
    seqfw()
        .args(["check", "../../corpus/misc/unrecognized.txt"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("format.unrecognized"));
}

#[test]
fn forcing_fastq_on_a_fasta_file_rejects() {
    // A FASTA file forced through the FASTQ check fails framing.
    seqfw()
        .args([
            "check",
            "--format",
            "fastq",
            "../../corpus/fasta/pass/good.fasta",
        ])
        .assert()
        .code(1);
}

#[test]
fn header_shell_metachar_warns_but_passes() {
    seqfw()
        .args(["check", "-"])
        .write_stdin("@read;rm\nACGT\n+\nIIII\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("safety.shell_metachar"));
}

#[test]
fn check_good_vcf_exits_zero() {
    seqfw()
        .args(["check", "../../corpus/vcf/pass/good.vcf"])
        .assert()
        .success();
}

#[test]
fn check_bad_pos_vcf_exits_one() {
    seqfw()
        .args(["check", "../../corpus/vcf/fail/bad_pos.vcf"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("vcf.bad_pos"));
}

#[test]
fn check_format_mismatch_vcf_exits_one() {
    seqfw()
        .args(["check", "../../corpus/vcf/fail/format_mismatch.vcf"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("vcf.format_field_mismatch"));
}

#[test]
fn check_valid_fai_with_data_exits_zero() {
    seqfw()
        .args([
            "check",
            "../../corpus/fai/pass/ref.fa.fai",
            "--data",
            "../../corpus/fai/pass/ref.fa",
        ])
        .assert()
        .success();
}

#[test]
fn check_out_of_bounds_fai_exits_one() {
    seqfw()
        .args([
            "check",
            "../../corpus/fai/fail/oob.fa.fai",
            "--data",
            "../../corpus/fai/pass/ref.fa",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("fai.offset_out_of_bounds"));
}
