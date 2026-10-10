# opsdir-adapter-pingds

opsdir adapter for PingDS (ForgeRock Directory Services): dsconfig batch, ACI LDIF, setup scripts, replication checks. Built on `opsdir-base-ds` (the DS lineage) and `opsdir-adapter-ldap` (the standard LDAP files).

Applies to environments with directory servers whose `ciamProductVersion` is PingDS. Renders the directory domain as PingDS artifacts: environment-neutral `ldap/schema.ldif`, `ldap/dit.ldif`, `ds/dsconfig.batch` and `ds/acis.ldif`, and per-server setup scripts (`setup --profile ds-user-data`) that join the existing replication deployment. Adds planner checks for replication continuity (same deployment ID, interconnect, replication port). Reads servers' configuration back with the lineage's importers: `pingds/config` (each server's `config.ldif` and archived configurations as observed snapshots, for drift) `pingds/declared` (one server's configuration as the declared configuration) and `pingds/access-log` (the directory's consumers found in the servers' JSON access logs, values-free); see `opsdir-base-ds`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingds`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## Collecting the configuration (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingds [--ldapsearch PATH] [--ldap-truststore PATH]` reads each directory
server's `cn=config` over LDAPS on its administration port, with this product's own `ldapsearch` (`--bindDn`, `--useSsl`, `--bindPassword:file /dev/stdin`, `--baseDn`), and
imports it as `pingds/config` (`<host>/config/config.ldif` per server) or `pingds/declared` (the first server's
`config.ldif`) (`opsdir_base_ds.collect`). The environment declares where:

```ldif
dn: cn=ds-config,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: collect-ds-config
ciamImporter: pingds/config
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

## Log files (log routes)

`logs.py` declares, relative to `ciamInstallRoot`: `logs/ldap-access.audit.json` and `logs/http-access.audit.json` (access, JSON lines), `logs/errors` and `logs/server.out` (error), `logs/replication` (replication; PingDS 7 only: PingDS 8 writes these to `logs/errors`), and `logs/audit` (audit, LDIF; only once the File-Based Audit Logger is enabled, which it isn't by default).
