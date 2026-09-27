#!/usr/bin/env bash
# Every test in one run: the unit suite (no database) and the integration suite against Postgres.
#   scripts/test.sh [pytest args]
# The integration suite DROPS and reloads the opsdir schema in OPSDIR_TEST_DSN (default: the local dev
# database, see README). It never uses OPSDIR_DSN. Here the database is required: unreachable = failure.
set -euo pipefail
cd "$(dirname "$0")/.."
OPSDIR_TEST_REQUIRE_DB=1 exec .venv/bin/python -m pytest -m "" "$@"
