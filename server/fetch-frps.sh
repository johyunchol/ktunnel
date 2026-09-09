#!/usr/bin/env bash
# Fetch the official frps release archive, verify the upstream checksum and
# stage only the frps binary used by Dockerfile.frps.
set -euo pipefail

readonly FRP_VERSION=0.71.0
readonly RELEASE_BASE="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}"

usage() {
  echo "usage: $0 [amd64|arm64]" >&2
}

if [ "$#" -gt 1 ]; then
  usage
  exit 2
fi

requested_arch=${1:-}
if [ -z "$requested_arch" ]; then
  case "$(uname -m)" in
    x86_64|amd64) requested_arch=amd64 ;;
    arm64|aarch64) requested_arch=arm64 ;;
    *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
  esac
fi

# These values are copied from the v0.71.0 official
# frp_sha256_checksums.txt and make an upstream asset change review-visible.
case "$requested_arch" in
  amd64) pinned_sha256=84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716 ;;
  arm64) pinned_sha256=f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266 ;;
  *) usage; exit 2 ;;
esac

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }

umask 077
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
archive="frp_${FRP_VERSION}_linux_${requested_arch}.tar.gz"
archive_root="frp_${FRP_VERSION}_linux_${requested_arch}"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ktunnel-frps.XXXXXX")
staged_binary=
cleanup() {
  [ -z "$staged_binary" ] || rm -f -- "$staged_binary"
  rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --retry 3 \
  --output "$work_dir/$archive" "$RELEASE_BASE/$archive"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --retry 3 \
  --output "$work_dir/frp_sha256_checksums.txt" "$RELEASE_BASE/frp_sha256_checksums.txt"

upstream_sha256=$(awk -v file="$archive" '
  NF == 2 {
    name=$2
    sub(/^\*/, "", name)
    if (name == file) print tolower($1)
  }
' "$work_dir/frp_sha256_checksums.txt")
if [ -z "$upstream_sha256" ] || [ "$(printf '%s\n' "$upstream_sha256" | wc -l | tr -d ' ')" -ne 1 ]; then
  echo "official checksum file must contain exactly one entry for $archive" >&2
  exit 1
fi
case "$upstream_sha256" in
  *[!0-9a-f]*|'') echo "official checksum entry is not hexadecimal" >&2; exit 1 ;;
esac
if [ "${#upstream_sha256}" -ne 64 ] || [ "$upstream_sha256" != "$pinned_sha256" ]; then
  echo "official checksum for $archive differs from the repository-pinned value" >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  actual_sha256=$(shasum -a 256 "$work_dir/$archive" | awk '{print tolower($1)}')
elif command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum "$work_dir/$archive" | awk '{print tolower($1)}')
else
  echo "shasum or sha256sum is required" >&2
  exit 1
fi
if [ "$actual_sha256" != "$pinned_sha256" ]; then
  echo "SHA-256 mismatch for $archive; refusing to stage frps" >&2
  exit 1
fi

# List first and reject unexpected absolute/traversal paths before extraction.
if tar -tzf "$work_dir/$archive" | awk '
  /^\// { bad=1 }
  /(^|\/)\.\.($|\/)/ { bad=1 }
  END { exit bad }
'; then
  :
else
  echo "release archive contains an unsafe path" >&2
  exit 1
fi
entry_type=$(tar -tvzf "$work_dir/$archive" "$archive_root/frps" | awk '
  NR == 1 { type=substr($1, 1, 1) }
  END {
    if (NR != 1) exit 1
    print type
  }
') || { echo "release archive must contain exactly one $archive_root/frps entry" >&2; exit 1; }
if [ "$entry_type" != "-" ]; then
  echo "release archive $archive_root/frps entry is not a regular file" >&2
  exit 1
fi
tar -xzf "$work_dir/$archive" -C "$work_dir" "$archive_root/frps"
if [ ! -f "$work_dir/$archive_root/frps" ]; then
  echo "verified archive does not contain $archive_root/frps" >&2
  exit 1
fi

staged_binary=$(mktemp "$script_dir/.frps.tmp.XXXXXX")
cp -- "$work_dir/$archive_root/frps" "$staged_binary"
chmod 0555 "$staged_binary"
mv -f -- "$staged_binary" "$script_dir/frps"
staged_binary=

echo "staged official frps v${FRP_VERSION} linux/${requested_arch} -> $script_dir/frps"
echo "verified SHA-256: $pinned_sha256"
