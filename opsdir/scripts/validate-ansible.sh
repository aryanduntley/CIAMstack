#!/usr/bin/env bash
# Check rendered Ansible output with the real tools: in every folder named ansible holding inventory/hosts.yml,
# ansible-inventory --list of the inventory folder (every inventory file and its variables parse), ansible-playbook
# --syntax-check of each playbook (*.yml beside the inventory, requirements*.yml left out), ansible-lint with the
# production profile, and each F5 AS3 declaration (f5/*.json) against AS3's JSON schema. The tools, schema,
# collections and roles are the pinned ones opsdir/scripts/fetch-tools.sh puts in tools/ansible (Ansible's own home
# there too, never ~/.ansible); run without the caller's PYTHONPATH.
#   opsdir/scripts/validate-ansible.sh tree [tree ...]
# Exit 0 when everything passes (or there is nothing to check); the failures are listed otherwise.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
A=$ROOT/tools/ansible
[ -x "$A/venv/bin/ansible-playbook" ] || { echo "no tools/ansible (opsdir/scripts/fetch-tools.sh)" >&2; exit 2; }
export ANSIBLE_COLLECTIONS_PATH=$A/collections ANSIBLE_ROLES_PATH=$A/roles ANSIBLE_HOME=$A/home NO_COLOR=1
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT
failed=()
# run <label> <cmd...>: Ansible wants blocking stdio, so its output goes to a file, shown on failure
run() {
  local label=$1; shift
  if (env -u PYTHONPATH "$@" >"$LOG" 2>&1 </dev/null); then echo "ok      $label"
  else echo "FAILED  $label"; sed 's/^/    /' "$LOG"; failed+=("$label"); fi
}
for tree in "$@"; do
  while IFS= read -r inv; do
    dir=$(dirname "$(dirname "$inv")")
    run "$dir (inventory)" "$A/venv/bin/ansible-inventory" -i "$dir/inventory" --list
    for book in "$dir"/*.yml; do
      case "$(basename "$book")" in requirements*.yml) continue ;; esac
      run "$book (syntax)" "$A/venv/bin/ansible-playbook" -i "$dir/inventory" --syntax-check "$book"
    done
    for decl in "$dir"/f5/*.json; do
      [ -f "$decl" ] || continue
      run "$decl (AS3 schema)" "$A/venv/bin/python" -c 'import json, sys, jsonschema
schema, doc = (json.load(open(p)) for p in sys.argv[1:])
errors = list(jsonschema.Draft7Validator(schema).iter_errors(doc))
for e in errors: print(list(e.absolute_path), e.message[:500])
sys.exit(1 if errors else 0)' "$(ls "$A"/as3-schema-*.json | tail -1)" "$decl"
    done
    run "$dir (ansible-lint, production)" bash -c "cd '$dir' && '$A/venv/bin/ansible-lint' --profile production ."
  done < <(find "$tree" -path '*/ansible/inventory/hosts.yml' | sort)
done
[ ${#failed[@]} -eq 0 ] || { echo "${#failed[@]} failed"; exit 1; }
