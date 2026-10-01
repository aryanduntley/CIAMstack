# opsdir-adapter-opendj

opsdir adapter for OpenDJ: dsconfig batch, ACI LDIF, setup and dsreplication scripts, replication checks. Built on `opsdir-base-ds` (the DS lineage) and `opsdir-adapter-ldap` (the standard LDAP files).

Applies to environments with directory servers whose `ciamProductVersion` is OpenDJ. Renders:

- environment-neutral: `ldap/schema.ldif`, `ldap/dit.ldif`, `ds/dsconfig.batch` (with OpenDJ's connection handler names), `ds/acis.ldif`;
- per server: `ds/setup-<server>.sh`: `setup --cli` as `cn=Directory Manager`, then `dsreplication enable` and `initialize` through an existing replica (the first directory server of the environment it joins, else the first of its own). OpenDJ has no deployment ID: replicas join a replication topology.

Required roles: `subnet-ds`, `ds-ldaps-service`, `backup-target`, `ds-root-password`, `ds-replication-admin-password`, `ds-tls-keystore`. The secrets agent materializes the TLS keystore, its PIN file and the CA truststore (`$DS_KEYSTORE`, `$DS_KEYSTORE_PIN_FILE`, `$DS_TRUSTSTORE`). Planner check: the target joins the source's topology, over an interconnect with the replication port open.

Reads servers' configuration back with the lineage's importers, `opendj/config` (observed snapshots, for drift), `opendj/declared` (one server's configuration as the declared configuration) and `opendj/access-log` (consumers from the JSON access log); OpenDJ's handler names are read back as the record's names. See `opsdir-base-ds`.

Command and option names follow the OpenDJ 4.x documentation; verify them against the exact target version before use.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `opendj`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
