#!/usr/bin/env bash
# Install the opsdir core and every package in this repository into opsdir/.venv, editable (changes take effect
# without reinstalling; re-run after changing any pyproject.toml). Creates the venv if needed.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || python3 -m venv .venv
PIP_USER=0 .venv/bin/pip install --no-cache-dir -q -e ".[test]" $(for p in ../packages/*/; do printf -- '-e %s ' "$p"; done)
.venv/bin/python -c "from opsdir.connectors.registry import ADAPTERS, DOMAINS; print('domains:', ', '.join(d.name for d in DOMAINS)); print('adapters:', ', '.join(a.name for a in ADAPTERS))"
