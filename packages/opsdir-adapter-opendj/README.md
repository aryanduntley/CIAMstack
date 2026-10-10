# opsdir-adapter-opendj

opsdir adapter for OpenDJ: dsconfig batch, ACI LDIF, setup and dsreplication scripts, replication checks. Built on `opsdir-base-ds` (the DS lineage) and `opsdir-adapter-ldap` (the standard LDAP files).

Applies to environments with directory servers whose `ciamProductVersion` is OpenDJ. Renders:

- environment-neutral: `ldap/schema.ldif`, `ldap/dit.ldif`, `ds/dsconfig.batch` (with OpenDJ's connection handler names), `ds/acis.ldif`;
- per server: `ds/setup-<server>.sh`: `setup --cli` as `cn=Directory Manager`, then `dsreplication enable` and `initialize` through an existing replica (the first directory server of the environment it joins, else the first of its own). OpenDJ has no deployment ID: replicas join a replication topology.

Required roles: `subnet-ds`, `ds-ldaps-service`, `backup-target`, `ds-root-password`, `ds-replication-admin-password`, `ds-tls-keystore`. The secrets agent materializes the TLS keystore, its PIN file and the CA truststore (`$DS_KEYSTORE`, `$DS_KEYSTORE_PIN_FILE`, `$DS_TRUSTSTORE`). Planner check: the target joins the source's topology, over an interconnect with the replication port open.

Reads servers' configuration back with the lineage's importers, `opendj/config` (observed snapshots, for drift), `opendj/declared` (one server's configuration as the declared configuration) and `opendj/access-log` (consumers from the JSON access log); OpenDJ's handler names are read back as the record's names. See `opsdir-base-ds`.

Log files it declares for log routes (`logs.py`, relative to `ciamInstallRoot`): `logs/access` and `logs/http-access` (access), `logs/errors` and `logs/server.out` (error), `logs/replication` (replication), as the Open Identity Platform's administration guide names its defaults; the JSON access logger ships disabled and the audit log's default isn't stated, so neither is declared.

The Open Identity Platform fork is at 5.x (5.1.2, 2026-07-17); this adapter still accepts OpenDJ >=4,<5 until milestone 5.13 verifies its commands against 5.x. Command and option names follow the OpenDJ 4.x documentation; verify them against the exact target version before use.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `opendj`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## Collecting the configuration (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter opendj [--ldapsearch PATH] [--ldap-truststore PATH]` reads each directory
server's `cn=config` over LDAPS on its administration port, with this product's own `ldapsearch` (`--bindDN`, `--useSSL`, `--bindPasswordFile /dev/stdin`, `--baseDN`), and
imports it as `opendj/config` (`<host>/config/config.ldif` per server) or `opendj/declared` (the first server's
`config.ldif`) (`opsdir_base_ds.collect`). The environment declares where:

```ldif
dn: cn=ds-config,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: collect-ds-config
ciamImporter: opendj/config
ciamTargetRole: ds                       # the directory servers (their host names), on
ciamPort: 4444                           # the administration connector
ciamLoginName: uid=config-reader,ou=admins,ou=identities
ciamCredentialRole: ds-config-reader      # a binding whose ciamRefUri references the password
```

The password reaches `ldapsearch` only on its standard input. Before anything sees the output, every attribute holding
a credential is dropped (password values, key and trust store PINs, secrets: `opsdir_base_ds.collect.holds_credential`);
the password policies' settings are kept. Only the configuration in effect is read: archived configurations are on
disk only, as are the access logs. Least privilege: an account with the `config-read` privilege and a global ACI on
`cn=config` allowing `read,search,compare` (targetattr `*||+`).

