#!/usr/bin/env python3
"""render_demo_svg.py — generate docs/demo.svg from the real seqfw binary.

This is the *offline, deterministic* way to (re)build the README's terminal
demo. Unlike the asciinema + agg pipeline (see docs/DEMO.md), it needs no extra
tools and no interactive PTY: it runs `seqfw check` against the bundled
corpus/ fixtures and renders the captured output as a static terminal-window
SVG. Because it drives the actual binary, the asset always matches the current
output — clean input passes, hostile input is rejected with a *named* rule.

Usage:
    ./scripts/render_demo_svg.py                 # uses ./target/release/seqfw
    SEQFW=seqfw ./scripts/render_demo_svg.py     # use a seqfw already on PATH

Output: docs/demo.svg
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
SEQFW = os.environ.get("SEQFW", "./target/release/seqfw")

# --- palette (Tokyo Night-ish; matches the asciinema default vibe) ----------
BG        = "#16161e"   # window body
BAR       = "#1f2335"   # title bar
BORDER    = "#2a2e44"
FG        = "#c0caf5"   # default text
DIM       = "#565f89"   # comments, exit codes, paths
GREEN     = "#9ece6a"   # OK, prompt, success
RED       = "#f7768e"   # REJECT, error
YELLOW    = "#e0af68"   # warn
CYAN      = "#7dcfff"   # rule IDs (the "named rule" pitch)
BLUE      = "#7aa2f7"   # command / flags
WHITE     = "#c0caf5"
DOT_R, DOT_Y, DOT_G = "#ff5f56", "#ffbd2e", "#27c93f"

# --- geometry ---------------------------------------------------------------
FONT      = ("ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, "
             "'DejaVu Sans Mono', monospace")
FS        = 15           # font size (px)
CW        = 9.02         # monospace advance width at FS=15
LH        = 22           # line height (px)
PAD_X     = 22           # body left/right padding
BAR_H     = 40           # title bar height
TOP       = 18           # gap below title bar before first line
BOT       = 18           # gap after last line
MAXCOLS   = 84           # soft-wrap width (chars); long output wraps like a tty

# The headline story: a clean pass, then three distinct rejects spanning
# FASTQ / VCF / index — including both CVE classes. Mirrors scripts/demo.sh.
COMMANDS = [
    ["check", "corpus/fastq/pass/good.fastq"],
    ["check", "corpus/fastq/fail/length_mismatch.fastq"],
    ["check", "corpus/vcf/fail/format_mismatch.vcf"],
    ["check", "corpus/fai/fail/oob.fa.fai", "--data", "corpus/fai/pass/ref.fa"],
]


# A rendered line is a list of (text, color, bold) "runs".
def run(text, color=FG, bold=False):
    return (text, color, bold)


def wrap_runs(runs, width, hang):
    """Soft-wrap a sequence of runs to `width` cols, indenting continuations
    by `hang` spaces — exactly how a terminal folds a long line."""
    out, cur, col = [], [], 0
    for text, color, bold in runs:
        for word in _tokenize(text):
            wlen = len(word)
            if col + wlen > width and cur:
                out.append(cur)
                cur, col = [run(" " * hang, DIM)], hang
                if word == " ":
                    continue
            cur.append(run(word, color, bold))
            col += wlen
    if cur:
        out.append(cur)
    return out


def _tokenize(text):
    """Split into words + single spaces so wrapping happens at spaces."""
    toks, word = [], ""
    for ch in text:
        if ch == " ":
            if word:
                toks.append(word)
                word = ""
            toks.append(" ")
        else:
            word += ch
    if word:
        toks.append(word)
    return toks


def style_output(line):
    """Color one line of seqfw output by its semantic prefix."""
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    pad = " " * indent
    if stripped.startswith("OK"):
        rest = stripped[2:]
        return [run("OK", GREEN, True), run(rest, DIM)]
    if stripped.startswith("REJECT"):
        rest = stripped[6:]
        return [run("REJECT", RED, True), run(rest, FG)]
    for kw, color in (("error", RED), ("warn", YELLOW)):
        if stripped.startswith(kw):
            after = stripped[len(kw):].lstrip()
            gap = stripped[len(kw):len(stripped) - len(after)]
            # the token right after the keyword is the rule id (area.rule)
            rule, _, tail = after.partition(" ")
            return [run(pad), run(kw, color, True), run(gap),
                    run(rule, CYAN), run(" " + tail if tail else "", FG)]
    return [run(line, FG)]


def main():
    lines = []  # each entry: list of runs (one logical line, pre-wrap)

    lines.append([run("# seqfw", FG, True),
                  run(" — a firewall for genomic data", DIM)])
    lines.append([run("# clean input passes, hostile input is rejected — "
                      "one verb, every format", DIM)])
    lines.append([])  # blank

    for cmd in COMMANDS:
        shown = "seqfw " + " ".join(cmd)
        prompt = [run("$ ", GREEN, True)]
        # color: program bold, flags dim-blue, paths default
        parts = [run("seqfw", FG, True), run(" check ", FG)]
        for tok in cmd[1:]:
            if tok.startswith("--"):
                parts.append(run(tok + " ", BLUE))
            else:
                parts.append(run(tok + " ", FG))
        lines.append(prompt + parts)

        proc = subprocess.run(
            [SEQFW, *cmd], cwd=ROOT, capture_output=True, text=True,
        )
        body = (proc.stdout + proc.stderr).rstrip("\n")
        for out_line in body.split("\n"):
            lines.append(style_output(out_line))
        lines.append([run(f"# exit {proc.returncode}", DIM)])
        lines.append([])  # blank between commands

    lines.append([run("# gate before you compute — exit codes drive your "
                      "pipeline", GREEN, True)])

    # --- wrap, then lay out -------------------------------------------------
    visual = []
    for runs in lines:
        if not runs:
            visual.append([])
            continue
        first_text = runs[0][0]
        hang = (len(first_text) - len(first_text.lstrip())) + 2
        wrapped = wrap_runs(runs, MAXCOLS, hang) if _line_len(runs) > MAXCOLS \
            else [runs]
        visual.extend(wrapped)

    width = int(PAD_X * 2 + MAXCOLS * CW)
    height = int(BAR_H + TOP + len(visual) * LH + BOT)

    svg = _render(visual, width, height)
    out = ROOT / "docs" / "demo.svg"
    out.write_text(svg, encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}  ({width}x{height}, "
          f"{len(visual)} rows, {out.stat().st_size} bytes)")


def _line_len(runs):
    return sum(len(t) for t, _, _ in runs)


def _render(visual, width, height):
    px = PAD_X
    body_top = BAR_H + TOP
    rows = []
    for i, runs in enumerate(visual):
        y = body_top + i * LH + FS  # baseline
        if not runs:
            continue
        spans, x = [], px
        for text, color, bold in runs:
            if text == "":
                continue
            w = "700" if bold else "400"
            spans.append(
                f'<tspan x="{x:.1f}" fill="{color}" font-weight="{w}">'
                f'{escape(text)}</tspan>'
            )
            x += len(text) * CW
        rows.append(f'<text y="{y}" xml:space="preserve">{"".join(spans)}</text>')

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="{FONT}" font-size="{FS}">
  <rect width="{width}" height="{height}" rx="10" fill="{BG}" stroke="{BORDER}"/>
  <rect width="{width}" height="{BAR_H}" rx="10" fill="{BAR}"/>
  <rect y="{BAR_H - 10}" width="{width}" height="10" fill="{BAR}"/>
  <circle cx="20" cy="{BAR_H // 2}" r="6" fill="{DOT_R}"/>
  <circle cx="40" cy="{BAR_H // 2}" r="6" fill="{DOT_Y}"/>
  <circle cx="60" cy="{BAR_H // 2}" r="6" fill="{DOT_G}"/>
  <text x="{width // 2}" y="{BAR_H // 2 + 5}" fill="{DIM}" text-anchor="middle" font-weight="700">seqfw check</text>
{chr(10).join("  " + r for r in rows)}
</svg>
'''


if __name__ == "__main__":
    sys.exit(main())
