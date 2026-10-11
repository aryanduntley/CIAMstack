#!/usr/bin/env bash
# Download the ForgeOps release this adapter renders for into tools/forgeops/<version>/ at the repository root
# (gitignored), for the tests that build the rendered values and overlay against it (helm template, kustomize build).
# The pins are release.py's (VERSION, COMMIT, SOURCE_SHA256; a test keeps them equal): GitHub's archive of the
# release's commit, checked against the pinned SHA-256 before it is unpacked. Idempotent.
#   packages/opsdir-adapter-forgeops/scripts/fetch-forgeops.sh
set -euo pipefail
VERSION=2026.3.2
COMMIT=3b61b9e0a18b65c4e370dc2512f133296990b363
SHA256=8a9e54a1505098acfe939d16b0a8219d4c46ca94951cd9e379ce9def9ab31d77
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
DEST=$ROOT/tools/forgeops/$VERSION

if [ -f "$DEST/.complete" ]; then
  echo "forgeops $VERSION: already in tools/forgeops"
  exit 0
fi
mkdir -p "$ROOT/tools/forgeops"
work=$(mktemp -d "$ROOT/tools/forgeops/.fetch-XXXXXX")
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/forgeops.tgz" "https://codeload.github.com/ForgeRock/forgeops/tar.gz/$COMMIT"
echo "$SHA256  $work/forgeops.tgz" | sha256sum -c --quiet - ||
  { echo "the ForgeOps $VERSION archive doesn't match its pinned SHA-256" >&2; exit 1; }
mkdir "$work/src"
tar -xzf "$work/forgeops.tgz" -C "$work/src" --strip-components=1 --no-same-owner --no-same-permissions
rm -rf "$DEST"
mv "$work/src" "$DEST"
touch "$DEST/.complete"
echo "forgeops $VERSION: tools/forgeops/$VERSION (verified)"
