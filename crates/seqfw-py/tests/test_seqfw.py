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


def test_check_pair_bytes_in_sync_is_ok():
    r1 = b"@r1/1\nACGT\n+\nIIII\n"
    r2 = b"@r1/2\nTGCA\n+\nIIII\n"
    assert seqfw.check_pair_bytes(r1, r2).ok


def test_check_pair_bytes_out_of_sync_is_rejected():
    r1 = b"@r1/1\nACGT\n+\nIIII\n@r2/1\nACGT\n+\nIIII\n"
    r2 = b"@r1/2\nTGCA\n+\nIIII\n"
    r = seqfw.check_pair_bytes(r1, r2)
    assert not r.ok
    assert any(f.rule.startswith("fastq.pair_") for f in r.findings)


def test_check_pair_paths(tmp_path):
    p1 = tmp_path / "R1.fastq"
    p2 = tmp_path / "R2.fastq"
    p1.write_bytes(b"@r1/1\nACGT\n+\nIIII\n")
    p2.write_bytes(b"@r1/2\nTGCA\n+\nIIII\n")
    assert seqfw.check_pair(str(p1), str(p2)).ok


def test_check_index_rejects_unknown_extension(tmp_path):
    p = tmp_path / "ref.fa"
    p.write_bytes(b">s\nACGT\n")
    with pytest.raises(ValueError):
        seqfw.check_index(str(p))


def test_check_index_fai_ok(tmp_path):
    fa = tmp_path / "ref.fa"
    fa.write_bytes(b">seq1\nACGTACGTAC\n")
    fai = tmp_path / "ref.fa.fai"
    fai.write_bytes(b"seq1\t10\t6\t10\t11\n")
    assert seqfw.check_index(str(fai), data=str(fa)).ok


def test_check_index_fai_offset_out_of_bounds(tmp_path):
    fa = tmp_path / "ref.fa"
    fa.write_bytes(b">seq1\nACGTACGTAC\n")
    fai = tmp_path / "ref.fa.fai"
    fai.write_bytes(b"seq1\t10\t999999\t10\t11\n")
    r = seqfw.check_index(str(fai), data=str(fa))
    assert not r.ok
    assert any(f.rule == "fai.offset_out_of_bounds" for f in r.findings)
