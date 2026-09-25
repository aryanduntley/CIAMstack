#!/usr/bin/env bash
# Convenience wrapper: runs the CLI against the private demo cluster (starting it if needed).
cd "$(dirname "$0")"
[ -S .pgsock/.s.PGSQL.54329 ] || scripts/pg-local.sh start >/dev/null
export OPSDIR_DSN=${OPSDIR_DSN:-"host=$PWD/.pgsock port=54329 user=opsdir dbname=opsdir"}
exec .venv/bin/python -m opsdir "$@"
