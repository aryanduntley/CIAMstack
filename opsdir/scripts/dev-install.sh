#!/usr/bin/env bash
# Install the opsdir core and every package in this repository into opsdir/.venv, editable (changes take effect
# without reinstalling; re-run after changing any pyproject.toml). Creates the venv if needed. Development uses
# psycopg's binary build; a FIPS host installs ".[c]" instead (documentation/RECORD-DATABASE.md, FIPS).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || python3 -m venv .venv
# PYTHONPATH unset: packages a shell exports on it (a user library folder) would count as installed, and the venv
# would lack them (ruff's binary among them). PIP_USER=0 overrides a pip config asking for user installs.
env -u PYTHONPATH PIP_USER=0 .venv/bin/pip install --no-cache-dir -q -e ".[binary,test]" \
  $(for p in ../packages/*/; do printf -- '-e %s ' "$p"; done)
[ -x .venv/bin/ruff ] || { echo "dev-install: .venv/bin/ruff is missing after the install" >&2; exit 1; }
.venv/bin/python -c "from opsdir.connectors.registry import ADAPTERS, DOMAINS; print('domains:', ', '.join(d.name for d in DOMAINS)); print('adapters:', ', '.join(a.name for a in ADAPTERS))"
