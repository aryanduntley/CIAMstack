# Local development defaults, sourced by opsdir.sh and demo.sh. Dev/test only (README, Database):
# the local PostgreSQL, role opsdir: database opsdir (the live record) and opsdir_workspace (a migration
# workspace). Values already set in the environment win.
: "${OPSDIR_DSN:=host=localhost port=5432 user=opsdir password=testpass dbname=opsdir}"
: "${OPSDIR_WORKSPACE_DSN:=host=localhost port=5432 user=opsdir password=testpass dbname=opsdir_workspace}"
export OPSDIR_DSN OPSDIR_WORKSPACE_DSN
