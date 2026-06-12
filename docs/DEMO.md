# Recording the demo

The README shows a terminal demo at `docs/demo.svg`. It is generated from the
bundled `corpus/` fixtures by running the real `seqfw check` binary — so the
asset is reproducible, offline, and always matches the current binary's output:
clean inputs pass, malformed ones are rejected with a *named* rule, and exit
codes are shown.

There are two ways to (re)build it. The **offline generator** is the default —
it needs no extra tools and no interactive terminal. The **asciinema + agg**
pipeline is the alternative when you specifically want an *animated* (typed,
human-paced) recording.

---

## Default: offline generator (static SVG, zero dependencies)

[`scripts/render_demo_svg.py`](../scripts/render_demo_svg.py) runs the headline
checks against `corpus/` and renders a static terminal-window SVG directly. It
drives the actual binary, so the asset can't drift from reality.

```bash
cargo build --release                 # the generator calls ./target/release/seqfw
python3 scripts/render_demo_svg.py    # writes docs/demo.svg
# or, against a seqfw already on PATH:
SEQFW=seqfw python3 scripts/render_demo_svg.py
```

That's the whole flow — there's nothing to record and nothing to install. Preview
`docs/demo.svg` in a browser and commit it.

**Why static, and why this is the default.** A static SVG renders instantly,
stays small (~13 KB), and displays reliably when embedded as an image on GitHub
(which proxies images and strips animation/scripts from many SVGs). The README
embeds it with:

```markdown
![seqfw demo](docs/demo.svg)
```

To change which checks appear, edit the `COMMANDS` list at the top of
`scripts/render_demo_svg.py` (each entry is a `seqfw` argument vector run against
a bundled fixture) and re-run.

---

## Alternative: asciinema + agg (animated SVG)

If you want a typed, human-paced *animation*, record the scripted run with
[`scripts/demo.sh`](../scripts/demo.sh), which runs `seqfw check` against the same
`corpus/` fixtures with pauses between commands.

### Prerequisites

```bash
cargo build --release          # the demo calls ./target/release/seqfw
brew install asciinema agg     # or: cargo install --git https://github.com/asciinema/agg
                               # Linux: pipx install asciinema && cargo install agg
```

- [`asciinema`](https://asciinema.org) records the terminal session to a `.cast` file.
- [`agg`](https://github.com/asciinema/agg) renders that `.cast` to an animated `SVG`/`GIF`.

### Record

From the repo root:

```bash
# 1. Record the scripted run to a cast file (human-paced; ~30s).
asciinema rec docs/demo.cast \
  --overwrite \
  --cols 90 --rows 28 \
  --command './scripts/demo.sh'

# 2. Render the cast to an SVG.
agg docs/demo.cast docs/demo.svg \
  --font-size 16 \
  --theme asciinema \
  --speed 1.0

# 3. (optional) also produce a GIF for places that don't render SVG.
agg docs/demo.cast docs/demo.gif --font-size 16
```

### Tips

- **Speed.** `demo.sh` sleeps between commands so the recording reads naturally.
  Set `DEMO_FAST=1 ./scripts/demo.sh` to dry-run it instantly (no pauses) while
  iterating; record *without* that flag.
- **Binary on PATH.** To record against an installed `seqfw` instead of the
  release build, run `SEQFW=seqfw asciinema rec … --command './scripts/demo.sh'`.
- **Determinism.** The demo only touches files under `corpus/`; it makes no
  network calls and writes nothing, so re-recording is safe and repeatable.
- **Size.** Keep `docs/demo.svg` under ~1 MB. If it's larger, drop `--font-size`
  to 14 or trim the script to the four headline checks.
