import pytest
import seqfw


def test_version_is_set():
    assert seqfw.__version__


def test_valid_fastq_bytes_is_ok():
    r = seqfw.check_bytes(b"@r1\nACGT\n+\nIIII\n")
    assert r.ok
    assert bool(r) is True
    assert r.reason == ""
    assert all(f.severity == "warn" for f in r.findings)


def test_bad_separator_is_rejected():
    r = seqfw.check_bytes(b"@r1\nACGT\n-\nIIII\n")
    assert not r.ok
    assert not bool(r)
    rules = [f.rule for f in r.findings]
    assert "fastq.bad_separator" in rules
    assert r.reason  # non-empty rejection reason
    bad = next(f for f in r.findings if f.rule == "fastq.bad_separator")
    assert bad.severity == "error"
    assert bad.record == 1


def test_vcf_is_routed_and_validated():
    r = seqfw.check_bytes(
        b"##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"
    )
    assert r.ok


def test_format_override_forces_fastq_on_fasta():
    r = seqfw.check_bytes(b">seq1\nACGT\n", format="fastq")
    assert not r.ok  # a FASTA stream forced through the FASTQ check fails framing


def test_unknown_format_raises_value_error():
    with pytest.raises(ValueError):
        seqfw.check_bytes(b"@r1\nACGT\n+\nIIII\n", format="bam")


def test_strict_dna_rejects_iupac():
    r = seqfw.check_bytes(b"@r1\nACRT\n+\nIIII\n", strict_dna=True)
    assert not r.ok
    assert any(f.rule == "fastq.invalid_base" for f in r.findings)


def test_check_path_ok(tmp_path):
    p = tmp_path / "x.fastq"
    p.write_bytes(b"@r1\nACGT\n+\nIIII\n")
    assert seqfw.check(str(p)).ok


def test_check_missing_file_raises_oserror():
    with pytest.raises(OSError):
        seqfw.check("/no/such/file.fastq")


def test_repr_is_readable():
    r = seqfw.check_bytes(b"@r1\nACGT\n+\nIIII\n")
    assert "Report(ok=true" in repr(r) or "Report(ok=True" in repr(r)
