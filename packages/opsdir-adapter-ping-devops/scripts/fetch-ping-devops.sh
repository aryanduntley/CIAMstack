#!/usr/bin/env bash
# Download the ping-devops chart this adapter renders for into tools/ping-devops/<version>/ at the repository root
# (gitignored), for the tests that template the rendered values with it (helm template). The pins are release.py's
# (VERSION, SOURCE_SHA256; a test keeps them equal): the chart archive of Ping's GitHub release, checked against the
# digest Ping's chart repository index lists for it before it is unpacked. Idempotent.
#   packages/opsdir-adapter-ping-devops/scripts/fetch-ping-devops.sh
set -euo pipefail
VERSION=0.16.0
SHA256=9fac7be41a22f25fc34ad81577ed49fec762c805011510d9d634c44cdd1a0872
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
DEST=$ROOT/tools/ping-devops/$VERSION

if [ -f "$DEST/.complete" ]; then
  echo "ping-devops $VERSION: already in tools/ping-devops"
  exit 0
fi
mkdir -p "$ROOT/tools/ping-devops"
work=$(mktemp -d "$ROOT/tools/ping-devops/.fetch-XXXXXX")
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/chart.tgz" \
  "https://github.com/pingidentity/helm-charts/releases/download/ping-devops-$VERSION/ping-devops-$VERSION.tgz"
echo "$SHA256  $work/chart.tgz" | sha256sum -c --quiet - ||
  { echo "the ping-devops $VERSION chart doesn't match its pinned SHA-256" >&2; exit 1; }
mkdir "$work/src"
tar -xzf "$work/chart.tgz" -C "$work/src" --no-same-owner --no-same-permissions
rm -rf "$DEST"
mv "$work/src" "$DEST"
touch "$DEST/.complete"
echo "ping-devops $VERSION: tools/ping-devops/$VERSION/ping-devops (verified)"
