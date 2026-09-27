#!/usr/bin/env bash
# Convenience wrapper: runs the CLI from anywhere against OPSDIR_DSN, by default the local dev database
# (scripts/dev-env.sh). Relative paths in the arguments are relative to where you run it.
CORE=$(cd "$(dirname "$0")" && pwd)
. "$CORE/scripts/dev-env.sh"
exec "$CORE/.venv/bin/python" -m opsdir "$@"
