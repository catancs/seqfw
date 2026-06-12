# Contributing to seqfw

Thanks for your interest. `seqfw` is a small, security-focused Rust workspace with
Python bindings. Contributions that sharpen its core promise — *reject hostile
genomic input cheaply, at the trust boundary, with zero false positives on real
data* — are very welcome.

## Ground rules

- **Fail closed, but never on valid data.** A new check must not reject inputs real
  pipelines produce. If in doubt, default to `Warn`, not `Error`, and add a passing
  fixture.
- **Stay offline and streaming.** No network calls, no telemetry, no unbounded
  buffering. Every input is potentially adversarial; bound your memory.
- **Every rule is documented.** A new finding rule (`area.snake_case`) needs an
  entry in [`docs/RULES.md`](docs/RULES.md).
- **Security reports go private.** Don't open a public issue for a vulnerability —
  see [SECURITY.md](SECURITY.md).

## Project layout

```
crates/seqfw-core/   # the streaming validation library (no I/O policy, no CLI)
crates/seqfw-cli/    # the `seqfw` binary (clap; human + --json output, exit codes)
crates/seqfw-py/     # PyO3/maturin bindings → the `seqfw` Python module
benchmark/           # reproducible ASAN security benchmark (patch-gated corpus)
corpus/              # small pass/fail fixtures used by tests and the README
docs/superpowers/    # design spec (the "why") + build plans (the "how")
```

`default-members` excludes `seqfw-py`, so the Rust gate (`cargo …`) skips it; the
Python crate is built and tested via maturin (below).

## Dev setup & the gate

Everything below must be green before a change merges — it's exactly what CI runs:

```bash
# Rust core + CLI
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check

# Python bindings (in a venv)
python -m venv .venv && source .venv/bin/activate
pip install maturin pytest
( cd crates/seqfw-py && maturin develop && python -m pytest tests/ -q )
cargo clippy -p seqfw-py -- -D warnings

# Security benchmark (no Docker needed for the local gate)
make benchmark-local          # must report block_rate=100% false_positive_rate=0.0%
make benchmark                # full run incl. "harm prevented" vs ASAN htslib (needs Docker)
```

## Adding a check

1. Add the logic to the right module under `crates/seqfw-core/src/checks/`, pushing a
   `Finding::error(...)` / `Finding::warn(...)` with a new `area.rule_name`.
2. Add a **passing** fixture (a realistic valid file) and a **failing** fixture under
   `corpus/<format>/{pass,fail}/`, and assert on the rule in a unit test.
3. Document the rule in `docs/RULES.md`.
4. If it defends against a known, *fixed* CVE class, consider a patch-gated
   structural reproducer in `benchmark/gen_corpus.py` (read `benchmark/PROVENANCE.md`
   first — no live crashers, no unfixed bugs).
5. Expose it through the CLI / Python surface only if it needs a new option; most
   checks run automatically by format.

## Commit & PR conventions

- Conventional-commit prefixes (`feat:`, `fix:`, `test:`, `docs:`, `build:`, `style:`).
- Keep PRs scoped; include the fixtures and the doc update in the same change.
- By contributing you agree your work is licensed under the project's
  [Apache-2.0](LICENSE) license.

## Reviewing findings (for AI agents and humans alike)

Treat any automated review finding as a **hypothesis, not a fact**: verify it against
the cited `file:line` and confirm it reproduces before editing; if it doesn't
reproduce, say so with evidence rather than "fixing" a false positive.
