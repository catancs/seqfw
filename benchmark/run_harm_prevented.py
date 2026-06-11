#!/usr/bin/env python3
"""Harm-prevented run: feed each known-bad input to a real, pinned, unmodified,
ASAN+UBSan-built vulnerable tool and bucket the outcome, alongside seqfw's
verdict. Intended to run inside benchmark/Dockerfile, where htslib 1.10.2 and
bcftools are built under sanitizers.

Outcome buckets (spec §8 methodology): CLEAN (exit 0), CRASH (sanitizer abort —
nonzero with an ASAN/UBSan signature on stderr), HANG (timeout). The headline
`harm_prevented` count = inputs where the tool CRASHED or HUNG **and** seqfw
blocked the input first.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent
CORPUS = BENCH / "corpus"
RESULTS = BENCH / "results"
TIMEOUT = int(os.environ.get("HARM_TIMEOUT", "20"))

# Map a known-bad file to the vulnerable-tool invocation that exercises it.
# `{path}` is substituted with the absolute corpus path. None = not exercised
# against a downstream tool in this minimal harness.
TOOL_FOR = {
    "vcf_format_overflow.vcf": ["bcftools", "view", "{path}"],
    "gzip_bomb.fastq.gz": ["htsfile", "{path}"],
}

SANITIZER_SIGNS = ("AddressSanitizer", "runtime error:", "UndefinedBehaviorSanitizer", "SUMMARY: ")


def find_seqfw() -> str | None:
    env = os.environ.get("SEQFW_BIN")
    if env and Path(env).exists():
        return env
    cand = BENCH.parent / "target" / "release" / "seqfw"
    return str(cand) if cand.exists() else None


def bucket(argv: list[str]) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return "HANG"
    except FileNotFoundError:
        return "TOOL_MISSING"
    if proc.returncode == 0:
        return "CLEAN"
    if any(s in proc.stderr for s in SANITIZER_SIGNS):
        return "CRASH"
    return f"NONZERO({proc.returncode})"


def seqfw_blocks(seqfw: str | None, path: Path) -> bool | None:
    if not seqfw:
        return None
    return subprocess.run([seqfw, "check", str(path)], capture_output=True).returncode == 1


def main() -> None:
    seqfw = find_seqfw()
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    rows, harm = [], 0

    for f in manifest["files"]:
        if f["set"] != "bad":
            continue
        name = Path(f["path"]).name
        path = (CORPUS / f["path"]).resolve()
        tmpl = TOOL_FOR.get(name)
        if tmpl is None:
            outcome = "not-exercised"
        else:
            outcome = bucket([a.format(path=str(path)) for a in tmpl])
        blocked = seqfw_blocks(seqfw, path)
        if outcome in ("CRASH", "HANG") and blocked:
            harm += 1
        rows.append((f["path"], tmpl[0] if tmpl else "-", outcome, blocked))

    print("\n## Harm prevented (known-bad vs pinned ASAN tool)\n")
    print("| input | tool | tool outcome | seqfw blocked |")
    print("|---|---|---|---|")
    for p, tool, outcome, blocked in rows:
        bl = "yes" if blocked else ("NO" if blocked is False else "?")
        print(f"| {p} | {tool} | {outcome} | {bl} |")
    print(f"\n**harm prevented: {harm} input(s) crash/hang the real tool but are "
          f"blocked by seqfw**")

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "harm_prevented.json").write_text(
        json.dumps(
            {
                "harm_prevented": harm,
                "rows": [
                    {"path": p, "tool": t, "outcome": o, "seqfw_blocked": b}
                    for p, t, o, b in rows
                ],
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
