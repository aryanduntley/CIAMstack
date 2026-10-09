#!/usr/bin/env bash
# Check rendered Kubernetes output with the real tools: every folder holding a kustomization.yaml is built
# (`kustomize build`; components skipped) and what it builds is checked; every other .yaml/.yml file outside those
# folders that holds Kubernetes objects (apiVersion and kind) is checked as it is; each --helm chart/values pair is
# rendered (`helm template`) and checked. Checked means kubeconform -strict against Kubernetes $KUBERNETES_VERSION's
# schemas and, for custom resources (External Secrets, the Secrets Store CSI driver, cert-manager, ...), the
# CRDs-catalog at the commit pinned below; a resource no schema describes fails (named, never passed). Schemas are
# cached in tools/kubeconform-cache (the first run needs network access).
#   opsdir/scripts/validate-kubernetes.sh [--helm CHART_DIR VALUES_FILE]... [tree ...]
# Given nothing at all, it checks the showcase's golden renders' kubernetes/ folders: a deployment kit's output needs
# the kit's charts and bases (examples/showcase/tests/kubernetes/ checks the golden kit output with them).
# Needs tools/bin/{kustomize,kubeconform} and, for --helm, tools/bin/helm (opsdir/scripts/fetch-tools.sh).
# Exit 0 when everything passes (or there is nothing to check); the failures are listed otherwise.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=$ROOT/tools/bin
KUBERNETES_VERSION=${KUBERNETES_VERSION:-1.36.0}       # ForgeOps 2026.3.1 ships kubectl 1.36.1
# datreeio/CRDs-catalog at the commit before its External Secrets 2.12 update (2026-10-08, #988), whose SecretStore
# schema kubeconform 0.8.0 can't compile (the crd provider's field named `properties`); External Secrets 2.5.0 schemas
CRDS=f1e7f6bc0537bf0622ffe6e47dbaa85914fabbec
CACHE=$ROOT/tools/kubeconform-cache
for tool in kustomize kubeconform; do
  [ -x "$BIN/$tool" ] || { echo "no $tool in tools/bin: run opsdir/scripts/fetch-tools.sh" >&2; exit 2; }
done
mkdir -p "$CACHE"

helm_pairs=()
while [ $# -gt 0 ] && [ "$1" = "--helm" ]; do
  [ $# -ge 3 ] || { echo "--helm needs a chart folder and a values file" >&2; exit 2; }
  [ -x "$BIN/helm" ] || { echo "no helm in tools/bin: run opsdir/scripts/fetch-tools.sh" >&2; exit 2; }
  helm_pairs+=("$2" "$3"); shift 3
done
[ $# -gt 0 ] || [ ${#helm_pairs[@]} -gt 0 ] || set -- "$ROOT"/examples/showcase/golden/render-*/*/kubernetes

failed=()
checked=0
# Check the objects on stdin (never through a pipe: failures are recorded in this shell): conform <name>
conform() {
  local out
  checked=$((checked + 1))
  if out=$("$BIN/kubeconform" -strict -summary -output text -kubernetes-version "$KUBERNETES_VERSION" \
      -cache "$CACHE" -schema-location default \
      -schema-location "https://raw.githubusercontent.com/datreeio/CRDs-catalog/$CRDS/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
      - 2>&1); then
    echo "ok      $1"
  else
    failed+=("$1"); echo "FAILED  $1"; printf '%s\n' "$out" | sed 's/^/    /'
  fi
}

trees=("$@")      # none: only the --helm pairs (find with no folder would search the working directory)
kustomizations=$([ ${#trees[@]} -eq 0 ] || find "${trees[@]}" -name kustomization.yaml -printf '%h\n' 2>/dev/null \
                 | sort -u)
for dir in $kustomizations; do
  grep -q '^kind: *Component' "$dir/kustomization.yaml" && continue
  name=${dir#"$ROOT"/}
  if built=$("$BIN/kustomize" build "$dir" 2>&1); then
    conform "$name (kustomize build)" <<<"$built"
  else
    failed+=("$name (kustomize build)"); echo "FAILED  $name (kustomize build)"; printf '%s\n' "$built" | sed 's/^/    /'
  fi
done

while IFS= read -r file; do
  [ -n "$file" ] || continue
  in_kustomization=no
  for dir in $kustomizations; do case "$file" in "$dir"/*) in_kustomization=yes ;; esac; done
  [ "$in_kustomization" = no ] && grep -q '^apiVersion:' "$file" && grep -q '^kind:' "$file" || continue
  conform "${file#"$ROOT"/}" <"$file"
done < <([ ${#trees[@]} -eq 0 ] || find "${trees[@]}" -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null \
         | sort)

for ((i = 0; i < ${#helm_pairs[@]}; i += 2)); do
  chart=${helm_pairs[i]} values=${helm_pairs[i+1]} name="helm template ${helm_pairs[i]#"$ROOT"/} -f ${helm_pairs[i+1]#"$ROOT"/}"
  if rendered=$("$BIN/helm" template opsdir-check "$chart" -f "$values" --kube-version "$KUBERNETES_VERSION" 2>&1); then
    conform "$name" <<<"$rendered"
  else
    failed+=("$name"); echo "FAILED  $name"; printf '%s\n' "$rendered" | sed 's/^/    /'
  fi
done

[ "$checked" -gt 0 ] || [ ${#failed[@]} -gt 0 ] || { echo "nothing to check"; exit 0; }
[ ${#failed[@]} -eq 0 ] && { echo "all $checked checked sets valid (Kubernetes $KUBERNETES_VERSION)"; exit 0; }
printf 'FAILED: %s\n' "${failed[@]}"
exit 1
