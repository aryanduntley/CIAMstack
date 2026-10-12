#!/usr/bin/env bash
# Check rendered Bicep with the Bicep CLI: every file a render's MANIFEST.json declares in format bicep is built
# (bicep build: the ARM template it compiles to) and linted (bicep lint: errors fail, warnings are shown). The CLI is
# the pinned one opsdir/scripts/fetch-tools.sh puts in tools/bin; nothing is deployed or downloaded.
#   opsdir/scripts/validate-bicep.sh [tree ...]      (default: the showcase's golden renders)
# Exit 0 when every file passes (or there is none), 1 with the failures listed otherwise, 2 without the CLI.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BICEP=$ROOT/tools/bin/bicep
[ -x "$BICEP" ] || { echo "no tools/bin/bicep (opsdir/scripts/fetch-tools.sh)" >&2; exit 2; }
[ $# -gt 0 ] || set -- "$ROOT"/examples/showcase/golden/render-*
files=$(find "$@" -name MANIFEST.json -print0 | xargs -0r python3 -c '
import json, os, sys
for manifest in sys.argv[1:]:
    files = json.load(open(manifest)).get("files", {})
    for path, f in sorted(files.items()):
        if f.get("format") == "bicep":
            print(os.path.join(os.path.dirname(manifest), path))')
failed=()
for f in $files; do
  name=${f#"$ROOT"/}
  if out=$("$BICEP" build "$f" --stdout 2>&1 >/dev/null) && lint=$("$BICEP" lint "$f" 2>&1); then
    echo "ok      $name"; [ -z "$lint" ] || printf '%s\n' "$lint" | sed 's/^/    /'
  else echo "FAILED  $name"; printf '%s\n%s\n' "$out" "${lint:-}" | grep -v '^$' | sed 's/^/    /'; failed+=("$name"); fi
done
[ ${#failed[@]} -eq 0 ] && { echo "all $(printf '%s' "$files" | grep -c .) Bicep files build and lint"; exit 0; }
printf 'FAILED: %s\n' "${failed[@]}"
exit 1
