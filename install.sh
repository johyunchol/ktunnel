#!/usr/bin/env bash
# Download the latest ktunnel release binary for this machine.
# The repository is private, so this uses the GitHub CLI for authentication.
set -euo pipefail

REPO="${KTUNNEL_REPO:-johyunchol/ktunnel}"
PREFIX="${PREFIX:-$HOME/.local/bin}"
USE_UV=0

for arg in "$@"; do
  case "$arg" in
    --uv) USE_UV=1 ;;
    -h|--help)
      echo "usage: ./install.sh [--uv]"
      echo "  --uv   install through 'uv tool install' instead of copying the binary"
      exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux)  os=linux  ;;
  *) echo "unsupported OS: $(uname -s) — on Windows, download the .exe from Releases" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$USE_UV" = 1 ]; then
  case "${os}-${arch}" in
    darwin-arm64)  asset="*macosx_11_0_arm64.whl" ;;
    darwin-amd64)  asset="*macosx_10_12_x86_64.whl" ;;
    linux-amd64)   asset="*manylinux*_x86_64.whl" ;;
    linux-arm64)   asset="*manylinux*_aarch64.whl" ;;
  esac
else
  asset="ktunnel-${os}-${arch}"
fi

command -v gh >/dev/null 2>&1 || {
  echo "gh (GitHub CLI) is required to download from a private repo." >&2
  echo "Install it, run 'gh auth login', then re-run this script." >&2
  exit 1
}

mkdir -p "$PREFIX"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading $asset ..."
gh release download --repo "$REPO" --pattern "$asset" --dir "$tmp" --clobber

if [ "$USE_UV" = 1 ]; then
  command -v uv >/dev/null 2>&1 || { echo "uv is not installed" >&2; exit 1; }
  # GitHub does not serve private release assets without a token, so the wheel
  # is fetched with gh first and handed to uv as a local file.
  uv tool install --force "$tmp"/*.whl
  ktunnel version
  exit 0
fi

install -m 755 "$tmp/$asset" "$PREFIX/ktunnel"
echo "installed → $PREFIX/ktunnel"
"$PREFIX/ktunnel" version

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo
     echo "Add $PREFIX to your PATH:"
     echo "  echo 'export PATH=\"$PREFIX:\$PATH\"' >> ~/.zshrc && exec zsh" ;;
esac
echo
echo "Next:  ktunnel init"
