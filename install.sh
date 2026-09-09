#!/usr/bin/env bash
# Download the latest ktunnel release binary for this machine.
# The repository is private, so this uses the GitHub CLI for authentication.
set -euo pipefail

REPO="${KTUNNEL_REPO:-johyunchol/ktunnel}"
PREFIX="${PREFIX:-$HOME/.local/bin}"

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

asset="ktunnel-${os}-${arch}"
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
