#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

bash -n "$script_dir/fetch-frps.sh"

# Architecture is the only user-controlled value that can influence an asset
# name. Unsupported values must fail before any network request is attempted.
for invalid_arch in x86_64 ../amd64 'amd64 --output=x' '' linux-amd64; do
  if [ -n "$invalid_arch" ] && "$script_dir/fetch-frps.sh" "$invalid_arch" >/dev/null 2>&1; then
    echo "accepted unsupported architecture: $invalid_arch" >&2
    exit 1
  fi
done

grep -Fq 'readonly FRP_VERSION=0.71.0' "$script_dir/fetch-frps.sh"
grep -Fq 'frp_sha256_checksums.txt' "$script_dir/fetch-frps.sh"
grep -Fq '84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716' "$script_dir/fetch-frps.sh"
grep -Fq 'f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266' "$script_dir/fetch-frps.sh"
grep -Fq -- "--proto-redir '=https'" "$script_dir/fetch-frps.sh"
grep -Fq 'FROM scratch' "$script_dir/Dockerfile.frps"

echo "fetch-frps validation tests: OK"
