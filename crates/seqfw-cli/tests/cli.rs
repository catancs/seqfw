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
