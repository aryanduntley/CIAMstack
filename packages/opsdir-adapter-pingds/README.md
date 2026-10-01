# opsdir-adapter-pingds

opsdir adapter for PingDS (ForgeRock Directory Services): dsconfig batch, ACI LDIF, setup scripts, replication checks. Built on `opsdir-base-ds` (the DS lineage) and `opsdir-adapter-ldap` (the standard LDAP files).

Applies to environments with directory servers whose `ciamProductVersion` is PingDS. Renders the directory domain as PingDS artifacts: environment-neutral `ldap/schema.ldif`, `ldap/dit.ldif`, `ds/dsconfig.batch` and `ds/acis.ldif`, and per-server setup scripts (`setup --profile ds-user-data`) that join the existing replication deployment. Adds planner checks for replication continuity (same deployment ID, interconnect, replication port). Reads servers' configuration back with the lineage's importers: `pingds/config` (each server's `config.ldif` and archived configurations as observed snapshots, for drift) `pingds/declared` (one server's configuration as the declared configuration) and `pingds/access-log` (the directory's consumers found in the servers' JSON access logs, values-free); see `opsdir-base-ds`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingds`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
