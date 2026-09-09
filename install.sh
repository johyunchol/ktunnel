#!/usr/bin/env bash
# Download and verify the latest ktunnel release for this machine.
set -euo pipefail

valid_repo() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$ ]]
}

valid_stable_tag() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

main() {
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

if ! valid_repo "$REPO"; then
  echo "KTUNNEL_REPO must be exactly owner/repo (got: $REPO)" >&2
  exit 1
fi

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

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Authenticated gh remains useful for private forks and API rate limits. Public
# releases take the curl path and require no GitHub account or token.
use_gh=0
if command -v gh >/dev/null 2>&1 && gh auth token >/dev/null 2>&1; then
  if tag="$(gh release view --repo "$REPO" --json tagName --jq .tagName 2>/dev/null)"; then
    use_gh=1
  fi
fi
if [ "$use_gh" = 0 ]; then
  command -v curl >/dev/null 2>&1 || {
    echo "curl is required to download a public release." >&2
    exit 1
  }
  latest_url="$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
    -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")" || {
      echo "could not find the latest public release for ${REPO}." >&2
      echo "For a private fork, install gh and run 'gh auth login'." >&2
      exit 1
    }
  tag="${latest_url##*/}"
fi

if ! valid_stable_tag "$tag"; then
  echo "latest release tag must be a stable vMAJOR.MINOR.PATCH version (got: $tag)" >&2
  exit 1
fi
version="${tag#v}"

if [ "$USE_UV" = 1 ]; then
  command -v uv >/dev/null 2>&1 || { echo "uv is not installed" >&2; exit 1; }
  case "${os}-${arch}" in
    darwin-arm64)  platform=macosx_11_0_arm64 ;;
    darwin-amd64)  platform=macosx_10_12_x86_64 ;;
    linux-amd64)   platform=manylinux2014_x86_64.manylinux_2_17_x86_64 ;;
    linux-arm64)   platform=manylinux2014_aarch64.manylinux_2_17_aarch64 ;;
  esac
  asset="ktunnel-${version}-py3-none-${platform}.whl"
else
  asset="ktunnel-${os}-${arch}"
fi

echo "downloading ktunnel ${tag} (${asset}) ..."
if [ "$use_gh" = 1 ]; then
  gh release download "$tag" --repo "$REPO" --pattern "$asset" --dir "$tmp"
  gh release download "$tag" --repo "$REPO" --pattern SHA256SUMS --dir "$tmp"
else
  base_url="https://github.com/${REPO}/releases/download/${tag}"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/$asset" "$base_url/$asset"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/SHA256SUMS" "$base_url/SHA256SUMS"
fi

expected="$(awk -v file="$asset" '
  {
    name=$2
    sub(/^\*/, "", name)
    if (name == file) print tolower($1)
  }
' "$tmp/SHA256SUMS")"
if [ -z "$expected" ] || [ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" -ne 1 ]; then
  echo "SHA256SUMS must contain exactly one entry for $asset" >&2
  exit 1
fi
if [ "${#expected}" -ne 64 ]; then
  echo "invalid SHA-256 for $asset in SHA256SUMS" >&2
  exit 1
fi
case "$expected" in
  *[!0-9a-f]*)
    echo "invalid SHA-256 for $asset in SHA256SUMS" >&2
    exit 1 ;;
esac

if command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$asset" | awk '{print tolower($1)}')"
elif command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | awk '{print tolower($1)}')"
else
  echo "shasum or sha256sum is required to verify the download." >&2
  exit 1
fi
if [ "$actual" != "$expected" ]; then
  echo "SHA-256 mismatch for $asset; refusing to install." >&2
  exit 1
fi
echo "verified SHA-256"

if [ "$USE_UV" = 1 ]; then
  uv tool install --force "$tmp/$asset"
  uv_root="$(uv tool dir)"
  uv_binary="$uv_root/ktunnel/bin/ktunnel"
  if [ ! -x "$uv_binary" ]; then
    echo "uv installed ktunnel but the expected executable was not found: $uv_binary" >&2
    exit 1
  fi
  "$uv_binary" version
  exit 0
fi

mkdir -p "$PREFIX"
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
echo "Next:  ktunnel login"
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
  main "$@"
fi
