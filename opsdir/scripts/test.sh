#!/usr/bin/env bash
# Every test in one run, from the repository root: core, packages and showcase; unit and integration.
#   scripts/test.sh [pytest args]
# The integration suite DROPS and reloads the opsdir schema in OPSDIR_TEST_DSN (default: the local dev
# database, see README). It never uses OPSDIR_DSN. Here the database is required: unreachable = failure.
set -euo pipefail
CORE=$(cd "$(dirname "$0")/.." && pwd)
cd "$CORE/.."
OPSDIR_TEST_REQUIRE_DB=1 exec "$CORE/.venv/bin/python" -m pytest -m "" "$@"
