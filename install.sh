#!/usr/bin/env bash
# ktunnel installer
set -euo pipefail

REPO_RAW="${KTUNNEL_RAW_URL:-}"
PREFIX="${PREFIX:-$HOME/.local/bin}"
mkdir -p "$PREFIX"

if [[ -f "$(dirname "$0")/ktunnel" ]]; then
  install -m 755 "$(dirname "$0")/ktunnel" "$PREFIX/ktunnel"
elif [[ -n "$REPO_RAW" ]]; then
  curl -fsSL "$REPO_RAW/ktunnel" -o "$PREFIX/ktunnel"
  chmod 755 "$PREFIX/ktunnel"
else
  echo "error: run this from a checkout, or set KTUNNEL_RAW_URL" >&2
  exit 1
fi

echo "installed → $PREFIX/ktunnel"
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) echo
     echo "Add $PREFIX to your PATH:"
     echo "  echo 'export PATH=\"$PREFIX:\$PATH\"' >> ~/.zshrc && exec zsh" ;;
esac
echo
echo "Next:  ktunnel init"
