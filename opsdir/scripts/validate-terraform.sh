#!/usr/bin/env bash
# Check rendered Terraform with the real tool: `terraform fmt -check` on every file, and `init -backend=false` +
# `validate` on every root (each folder holding .tf files: the stack's, the landing zone's, each keeper's). Roots are
# copied to a scratch folder first, so the trees checked stay as rendered. Providers are cached in tools/.
#   opsdir/scripts/validate-terraform.sh [tree ...]     (default: the showcase's golden renders)
# Needs tools/bin/terraform (opsdir/scripts/fetch-tools.sh) and, the first time, network access for the providers.
# Exit 0 when every root passes; the failures are listed otherwise.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TF=${TERRAFORM:-$ROOT/tools/bin/terraform}
[ -x "$TF" ] || { echo "no terraform at $TF: run opsdir/scripts/fetch-tools.sh" >&2; exit 2; }
export TF_PLUGIN_CACHE_DIR=$ROOT/tools/terraform-plugins TF_IN_AUTOMATION=1 CHECKPOINT_DISABLE=1
mkdir -p "$TF_PLUGIN_CACHE_DIR" "$ROOT/tools/tmp"
SCRATCH=$(mktemp -d "$ROOT/tools/tmp/validate.XXXXXX")
trap 'rm -rf "$SCRATCH"' EXIT
[ $# -gt 0 ] || set -- "$ROOT"/examples/showcase/golden/render-*

failed=()
roots=$(find "$@" -name '*.tf' -printf '%h\n' | sort -u)
for dir in $roots; do
  name=${dir#"$ROOT"/}
  work=$SCRATCH/$(printf '%s' "$name" | tr '/' '_')
  mkdir -p "$work" && cp "$dir"/*.tf "$work"/
  if ! "$TF" -chdir="$work" fmt -check -list=true >"$work.fmt" 2>&1; then
    failed+=("$name (fmt: $(tr '\n' ' ' <"$work.fmt"))")
  fi
  if ! "$TF" -chdir="$work" init -backend=false -input=false -no-color >"$work.init" 2>&1; then
    failed+=("$name (init)"); sed 's/^/    /' "$work.init" | grep -v '^    $' | tail -15
    continue
  fi
  if "$TF" -chdir="$work" validate -no-color >"$work.validate" 2>&1; then
    echo "ok      $name"
  else
    failed+=("$name (validate)"); echo "FAILED  $name"; sed 's/^/    /' "$work.validate" | grep -v '^    $'
  fi
done
[ ${#failed[@]} -eq 0 ] && { echo "all $(echo "$roots" | grep -c .) roots valid"; exit 0; }
printf 'FAILED: %s\n' "${failed[@]}"
exit 1
