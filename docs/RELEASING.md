# Releasing seqfw

Everything ships from **one trigger: a pushed `v*` git tag.** Two workflows fire
on it; a third channel (Homebrew) is finalized by hand once the binaries exist.

```
git tag v0.1.0 && git push origin v0.1.0
        │
        ├─ release.yml ─→ builds Linux + macOS binaries, uploads them and
        │                 seqfw-installer.sh to a GitHub Release   (no secrets)
        └─ wheels.yml  ─→ builds abi3 wheels + sdist, publishes to PyPI
                          (needs the PYPI_API_TOKEN secret)
```

| Channel | Workflow | Needs from you (once) |
|---|---|---|
| Prebuilt binary + `curl \| sh` installer | `release.yml` | nothing — uses the built-in `GITHUB_TOKEN` |
| `pip install seqfw` | `wheels.yml` | a `PYPI_API_TOKEN` repo secret (below) |
| `brew install catancs/seqfw/seqfw` | manual | a `homebrew-seqfw` tap repo + the generated formula |

---

## Before the first tag

### 1. PyPI (`pip install seqfw`)

The package name `seqfw` must be available/owned by you on PyPI, and the publish
job needs a token.

1. Create the project on [PyPI](https://pypi.org/) (or reserve the name with a
   first manual upload).
2. Generate an API token scoped to the `seqfw` project.
3. Add it to the repo: **Settings → Secrets and variables → Actions → New
   repository secret**, named `PYPI_API_TOKEN`.

`wheels.yml` reads it as `MATURIN_PYPI_TOKEN`. Without the secret the build jobs
still succeed but the **publish** job fails — so set it *before* tagging.

> **More secure alternative — Trusted Publishing (OIDC, no long-lived token).**
> Configure a [PyPI trusted publisher](https://docs.pypi.org/trusted-publishers/)
> for this repo + the `Wheels` workflow, give the `publish` job
> `permissions: id-token: write`, and drop the `MATURIN_PYPI_TOKEN` env. Preferred
> for a security tool, since there's no secret to leak.

### 2. Confirm CI is green on `main`

`cargo test`, clippy/fmt, the Python `maturin develop`/pytest gate, and the
benchmark block-rate gate all pass — see [the CI badge](../README.md). Don't tag a
red tree.

### 3. Version bump

The version is single-sourced from the workspace `Cargo.toml` (`[workspace.package]
version`). The CLI binary, the crate, and the Python wheel all inherit it. Bump it,
update [CHANGELOG.md](../CHANGELOG.md), commit.

---

## Cut the release

```bash
git tag v0.1.0           # tag must match Cargo.toml's version, prefixed with v
git push origin v0.1.0
```

Watch both workflows:

```bash
gh run watch "$(gh run list --workflow Release --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh run watch "$(gh run list --workflow Wheels  --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

When green you'll have a GitHub Release with `seqfw-<target>.tar.gz` + `seqfw-installer.sh`,
and `pip install seqfw` will resolve.

Verify the installer end-to-end:

```bash
curl -LsSf https://github.com/catancs/seqfw/releases/latest/download/seqfw-installer.sh | sh
seqfw --version
```

---

## Finalize Homebrew (after the release exists)

The formula pins each binary by `sha256`, so it can only be built once the release
assets are uploaded.

1. Create a public repo named **`homebrew-seqfw`** under your account (the
   `homebrew-` prefix is what makes `brew tap catancs/seqfw` work).
2. Generate the formula from the published release and commit it to the tap:

   ```bash
   ./scripts/gen_homebrew_formula.sh v0.1.0 > seqfw.rb
   # in the tap repo:
   mkdir -p Formula && mv seqfw.rb Formula/seqfw.rb && git add Formula/seqfw.rb
   git commit -m "seqfw 0.1.0" && git push
   ```
3. Test it: `brew install catancs/seqfw/seqfw && seqfw --version`.

On the next release, re-run the generator with the new tag and update the tap.

---

## What is *not* wired

- **crates.io (`cargo install seqfw`)** — intentionally not set up. The CLI crate
  is `seqfw-cli` and the Python crate has `publish = false`. To add it later,
  publish `seqfw-core` + `seqfw-cli` and add a `cargo publish` step gated on the tag.
- **Bioconda (`conda install -c bioconda seqfw`)** — `recipe/meta.yaml` exists, but
  Bioconda is a separate, externally-reviewed PR against `bioconda-recipes`, not
  part of this tag flow.
