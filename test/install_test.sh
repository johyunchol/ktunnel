#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../install.sh
source "$ROOT/install.sh"

for repo in johyunchol/ktunnel owner/repo.name owner-name/repo_name a/b; do
  if ! valid_repo "$repo"; then
    echo "expected valid repository: $repo" >&2
    exit 1
  fi
done

for repo in owner owner/ owner//repo owner/repo/extra -owner/repo owner/-repo owner/. ../repo 'owner/repo name' '--repo=x/y'; do
  if valid_repo "$repo"; then
    echo "accepted unsafe repository: $repo" >&2
    exit 1
  fi
done

for tag in v0.0.0 v0.5.0 v1.20.300; do
  if ! valid_stable_tag "$tag"; then
    echo "expected valid stable tag: $tag" >&2
    exit 1
  fi
done

for tag in latest 0.5.0 v1.2 v1.2.3.4 v01.2.3 v1.02.3 v1.2.03 v1.2.3-rc.1 v1.2.3+build -v1.2.3 . .. / '--help'; do
  if valid_stable_tag "$tag"; then
    echo "accepted unsafe or non-stable tag: $tag" >&2
    exit 1
  fi
done

echo "install.sh validation tests: OK"
