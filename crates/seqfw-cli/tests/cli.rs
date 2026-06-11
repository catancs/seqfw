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
        .args(["check", "--json", "../../corpus/fastq/fail/bad_separator.fastq"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"ok\": false"))
        .stdout(predicate::str::contains("\"rule\": \"fastq.bad_separator\""))
        .stdout(predicate::str::contains("\"severity\": \"error\""));
}
