# opsdir-adapter-pingds

opsdir adapter for PingDS (ForgeRock Directory Services): dsconfig batch, ACI LDIF, setup scripts, replication checks.

Applies to environments with directory servers whose `ciamProductVersion` is PingDS. Renders the directory domain as PingDS artifacts: an environment-neutral `dsconfig` batch file and ACI LDIF, and per-server setup scripts that join the existing replication deployment. Adds planner checks for replication continuity (same deployment, interconnect, replication port).

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingds`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.
