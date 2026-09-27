#!/usr/bin/env bash
# Convenience wrapper: runs the CLI against OPSDIR_DSN, by default the local dev database (scripts/dev-env.sh).
cd "$(dirname "$0")"
. scripts/dev-env.sh
exec .venv/bin/python -m opsdir "$@"
