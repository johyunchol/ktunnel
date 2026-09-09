#!/usr/bin/env bash
# Cross-compile release binaries. Uses Docker so no local Go install is needed.
set -euo pipefail
VERSION="${1:-dev}"
OUT=dist
IMAGE=golang:1.25

rm -rf "$OUT" && mkdir -p "$OUT"

docker run --rm -v "$PWD":/src -w /src -v ktunnel-gomod:/go/pkg/mod \
  -e GOTOOLCHAIN=auto -e CGO_ENABLED=0 "$IMAGE" sh -c '
set -e
VERSION="'"$VERSION"'"
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64; do
  os=${target%/*}; arch=${target#*/}
  ext=""; [ "$os" = windows ] && ext=".exe"
  echo "  building $os/$arch"
  for bin in ktunnel ktunneld; do
    GOOS=$os GOARCH=$arch go build -trimpath \
      -ldflags "-s -w -X main.version=$VERSION" \
      -o "dist/${bin}-${os}-${arch}${ext}" ./cmd/$bin
  done
done
'
( cd "$OUT" && shasum -a 256 * > SHA256SUMS 2>/dev/null || sha256sum * > SHA256SUMS )
ls -lh "$OUT"
