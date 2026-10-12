#!/usr/bin/env bash
# Check rendered CloudFormation templates with cfn-lint: every file a render's MANIFEST.json declares in format
# cloudformation-yaml or cloudformation-json. Each template names the regions it is checked for in its own
# Metadata (cfn-lint: config: regions: the environment's region, so a GovCloud template is checked against GovCloud's
# resource specification). cfn-lint is the pinned one opsdir/scripts/fetch-tools.sh puts in tools/cfn-lint, run
# without the caller's PYTHONPATH; its region specs ship in the wheel, so nothing is downloaded. Errors fail a template;
# warnings (a hardcoded availability zone the record holds, Lambda code `aws cloudformation package` uploads) are
# shown, not failed.
#   opsdir/scripts/validate-cloudformation.sh [tree ...]      (default: the showcase's golden renders)
# Exit 0 when every template passes (or there is none), 1 with the failures listed otherwise, 2 without cfn-lint.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LINT=$ROOT/tools/cfn-lint/venv/bin/cfn-lint
[ -x "$LINT" ] || { echo "no tools/cfn-lint (opsdir/scripts/fetch-tools.sh)" >&2; exit 2; }
[ $# -gt 0 ] || set -- "$ROOT"/examples/showcase/golden/render-*
templates=$(find "$@" -name MANIFEST.json -print0 | xargs -0r python3 -c '
import json, os, sys
for manifest in sys.argv[1:]:
    files = json.load(open(manifest)).get("files", {})
    for path, f in sorted(files.items()):
        if f.get("format") in ("cloudformation-yaml", "cloudformation-json"):
            print(os.path.join(os.path.dirname(manifest), path))')
failed=()
for t in $templates; do
  name=${t#"$ROOT"/}
  if out=$(env -u PYTHONPATH "$LINT" --non-zero-exit-code error -- "$t" 2>&1); then
    echo "ok      $name"; [ -z "$out" ] || printf '%s\n' "$out" | sed 's/^/    /'
  else echo "FAILED  $name"; printf '%s\n' "$out" | sed 's/^/    /'; failed+=("$name"); fi
done
[ ${#failed[@]} -eq 0 ] && { echo "all $(printf '%s' "$templates" | grep -c .) templates pass cfn-lint"; exit 0; }
printf 'FAILED: %s\n' "${failed[@]}"
exit 1
