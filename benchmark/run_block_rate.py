#!/usr/bin/env python3
"""Local seqfw benchmark: block rate, false-positive rate, and overhead.

Runs the release `seqfw` binary against the generated corpus. Deterministic and
Docker-free — this is the always-verifiable core of the benchmark, and it
doubles as a regression gate (exits non-zero on <100% block or >0% false
positives). The "harm prevented" half (vs ASAN-built htslib) lives in
run_harm_prevented.py and needs a Docker host.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
CORPUS = BENCH / "corpus"
RESULTS = BENCH / "results"


def find_seqfw() -> str:
    env = os.environ.get("SEQFW_BIN")
    if env and Path(env).exists():
        return env
    cand = ROOT / "target" / "release" / "seqfw"
    if cand.exists():
        return str(cand)
    sys.exit("seqfw binary not found; run `cargo build --release -p seqfw-cli` "
             "or set SEQFW_BIN")


def run_check(seqfw: str, path: Path, json_out: bool):
    args = [seqfw, "check"]
    if json_out:
        args.append("--json")
    args.append(str(path))
    proc = subprocess.run(args, capture_output=True, text=True)
    return proc.returncode, proc.stdout


def main() -> None:
    seqfw = find_seqfw()
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    files = manifest["files"]

    bad_rows, good_rows, overhead = [], [], []
    blocked = matched = n_bad = 0
    false_pos = n_good = 0

    for f in files:
        path = CORPUS / f["path"]
        if f["set"] == "bad":
            n_bad += 1
            code, out = run_check(seqfw, path, json_out=True)
            is_blocked = code == 1
            rule_hit = False
            try:
                rule_hit = any(
                    fi.get("rule") == f["expected_rule"]
                    for fi in json.loads(out).get("findings", [])
                )
            except json.JSONDecodeError:
                pass
            blocked += is_blocked
            matched += rule_hit
            bad_rows.append((f["path"], f["expected_rule"], code, is_blocked, rule_hit))
        else:
            n_good += 1
            code, _ = run_check(seqfw, path, json_out=False)
            fp = code == 1
            false_pos += fp
            good_rows.append((f["path"], code, fp))
            if f.get("overhead"):
                t = []
                for _ in range(5):
                    s = time.perf_counter()
                    run_check(seqfw, path, json_out=False)
                    t.append((time.perf_counter() - s) * 1000)
                overhead.append((f["path"], path.stat().st_size, min(t)))

    block_rate = blocked / n_bad if n_bad else 0.0
    fp_rate = false_pos / n_good if n_good else 0.0

    print("\n## Block rate (known-bad)\n")
    print("| input | expected rule | exit | blocked | rule matched |")
    print("|---|---|---|---|---|")
    for p, rule, code, b, m in bad_rows:
        print(f"| {p} | {rule} | {code} | {'yes' if b else 'NO'} | {'yes' if m else 'NO'} |")
    print(f"\n**block rate: {blocked}/{n_bad} = {block_rate:.0%}**")

    print("\n## False positives (known-good)\n")
    print(f"**false-positive rate: {false_pos}/{n_good} = {fp_rate:.1%}**")
    if false_pos:
        for p, code, fp in good_rows:
            if fp:
                print(f"  - FALSE POSITIVE: {p} (exit {code})")

    if overhead:
        print("\n## Overhead (valid files)\n")
        print("| input | bytes | min ms |")
        print("|---|---|---|")
        for p, size, ms in overhead:
            print(f"| {p} | {size} | {ms:.1f} |")

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "block_rate.json").write_text(
        json.dumps(
            {
                "block_rate": block_rate,
                "false_positive_rate": fp_rate,
                "blocked": blocked,
                "rule_matched": matched,
                "n_bad": n_bad,
                "false_positives": false_pos,
                "n_good": n_good,
                "bad": [
                    {"path": p, "expected_rule": r, "exit": c, "blocked": b, "rule_matched": m}
                    for p, r, c, b, m in bad_rows
                ],
                "overhead_ms": [{"path": p, "bytes": s, "min_ms": ms} for p, s, ms in overhead],
            },
            indent=2,
        )
        + "\n"
    )

    ok = block_rate == 1.0 and fp_rate == 0.0
    print(f"\n{'PASS' if ok else 'FAIL'}: block_rate={block_rate:.0%} false_positive_rate={fp_rate:.1%}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
