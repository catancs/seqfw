#!/bin/sh
# seqfw installer — download the prebuilt `seqfw` binary for this platform from
# the GitHub Release and drop it on your PATH. No git clone, no Rust toolchain.
#
#   curl -LsSf https://github.com/catancs/seqfw/releases/latest/download/seqfw-installer.sh | sh
#
# Environment overrides:
#   SEQFW_VERSION       version tag to install (default: latest), e.g. v0.1.0
#   SEQFW_INSTALL_DIR   install directory (default: $HOME/.local/bin)
#
# POSIX sh on purpose: runs under dash/ash, not just bash.
set -eu

REPO="catancs/seqfw"
BIN="seqfw"
VERSION="${SEQFW_VERSION:-latest}"
INSTALL_DIR="${SEQFW_INSTALL_DIR:-$HOME/.local/bin}"

err() { printf 'seqfw: %s\n' "$1" >&2; exit 1; }

# --- pick the release artifact for this OS/arch -----------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)
    case "$arch" in
      x86_64 | amd64) target="x86_64-unknown-linux-musl" ;;
      *) err "no prebuilt binary for Linux/$arch yet — build from source: https://github.com/$REPO#from-source" ;;
    esac ;;
  Darwin)
    case "$arch" in
      arm64 | aarch64) target="aarch64-apple-darwin" ;;
      x86_64) target="x86_64-apple-darwin" ;;
      *) err "no prebuilt binary for macOS/$arch — build from source: https://github.com/$REPO#from-source" ;;
    esac ;;
  *)
    err "unsupported OS '$os' — build from source: https://github.com/$REPO#from-source" ;;
esac

asset="${BIN}-${target}.tar.gz"
if [ "$VERSION" = "latest" ]; then
  url="https://github.com/$REPO/releases/latest/download/$asset"
else
  url="https://github.com/$REPO/releases/download/$VERSION/$asset"
fi

# --- download + extract -----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

printf 'seqfw: downloading %s (%s)\n' "$asset" "$VERSION"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmp/$asset" || err "download failed: $url"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp/$asset" "$url" || err "download failed: $url"
else
  err "need curl or wget to download"
fi

tar -xzf "$tmp/$asset" -C "$tmp" || err "failed to extract $asset"
[ -f "$tmp/$BIN" ] || err "archive did not contain the '$BIN' binary"

# --- install ----------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
if ! install -m 0755 "$tmp/$BIN" "$INSTALL_DIR/$BIN" 2>/dev/null; then
  mv "$tmp/$BIN" "$INSTALL_DIR/$BIN" && chmod 0755 "$INSTALL_DIR/$BIN"
fi
printf 'seqfw: installed to %s\n' "$INSTALL_DIR/$BIN"

# --- PATH hint + sanity check ----------------------------------------------
# SC2016: the literal $PATH in the printf below is intentional — it's printed
# verbatim for the user to paste into their own shell.
# shellcheck disable=SC2016
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf 'seqfw: %s is not on your PATH. Add it:\n    export PATH="%s:$PATH"\n' "$INSTALL_DIR" "$INSTALL_DIR" ;;
esac
"$INSTALL_DIR/$BIN" --version 2>/dev/null || true
