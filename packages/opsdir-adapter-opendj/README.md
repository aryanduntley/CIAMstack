# opsdir-adapter-opendj

opsdir adapter for OpenDJ: the directory domain rendered as OpenDJ artifacts (the standard schema and tree LDIF, a `dsconfig` batch with OpenDJ's connection handler names, ACI LDIF, per-server `setup` and `dsreplication` scripts that join the existing replication topology), replication-continuity checks, and the servers' configuration, access logs and its own render read back. A thin product adapter on `opsdir-base-ds`, which holds everything the DS lineage shares; this package supplies OpenDJ's data (`render.OPENDJ`), its setup script, its join check, logs and version changes.

**Applies to** environments where OpenDJ runs: a server, or a Kubernetes workload's binding, whose `ciamProductVersion` starts with `OpenDJ` (`opsdir_base_ds.product.runs`). Supported: OpenDJ `>=4,<6`, i.e. 4.x and the Open Identity Platform fork's 5.x. Every command and option it renders or runs (`setup --cli`, the `dsconfig` batch, `dsreplication enable` / `initialize`, the collectors' `ldapsearch`), the connection handler names, the ports and `config/config.ldif` are the same in 4.x, 5.0 and 5.1 (doc.openidentityplatform.org; research note 2373). OpenDJ 5.x needs Java 11 or later. A 5.x install can keep its configuration, logs and data in an instance directory apart from the tools (`instance.loc`); a server's `ciamInstallRoot` must then name that instance directory, since the log paths are relative to it. Its directory servers are the domain's server role `ds`.

**Depends on** `opsdir` and `opsdir-base-ds` (and through it `opsdir-adapter-ldap`, the standard LDAP files). The setup scripts run OpenDJ's own `setup` and `dsreplication`; collection runs OpenDJ's `ldapsearch`. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `opendj`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## What it renders

| From the record | Rendered as |
|---|---|
| The user schema's own attribute types and object classes | `ldap/schema.ldif` (environment-neutral; `opsdir-adapter-ldap`) |
| The declared backends' base DNs and the containers the record refers to | `ldap/dit.ldif` (environment-neutral; `opsdir-adapter-ldap`) |
| The declared configuration: backends and indexes, password policies, connection handlers (`LDAP`, `LDAPS`, `HTTPS` as `LDAP Connection Handler`, `LDAPS Connection Handler`, `HTTP Connection Handler`), log publishers, the replication purge delay | `ds/dsconfig.batch` (environment-neutral; `opsdir-base-ds`), its header saying how to apply it as `cn=Directory Manager` over the administration port 4444; `Default Password Policy` and `Root Password Policy` are set, not created |
| The ACIs | `ds/acis.ldif` (environment-neutral; `opsdir-base-ds`) |
| Each directory server of the environment, the user backend (its base DN and type), the declared ports, the secret roles `ds-root-password`, `ds-replication-admin-password` | `ds/setup-<server>.sh` (per environment) |

**The setup script** runs `./setup --cli --no-prompt --acceptLicense` with `--hostname`, `--rootUserDN "cn=Directory Manager"` and `--rootUserPassword`, `--adminConnectorPort 4444`, `--ldapPort` and `--ldapsPort` (the declared handlers' ports, else 1389 and 1636), `--usePkcs12keyStore "$DS_KEYSTORE"` with `--keyStorePasswordFile "$DS_KEYSTORE_PIN_FILE"`, `--baseDN` and `--backendType` (the user backend's). OpenDJ has no deployment ID: a new replica joins the replication topology through an existing replica, the first directory server of the environment it joins (`ciamJoinsDeploymentOf`), else the first of its own environment that comes before it: `./bin/dsreplication enable` (both servers on 4444, replication port 8989, the replication administrator `admin`, trusting `$DS_TRUSTSTORE`) and `./bin/dsreplication initialize` from that replica. The first replica of a new topology joins nothing (a comment says so). Every replica of a topology shares the root and replication-administrator passwords. Secrets are run-time lookups of the bound references, or `${UNBOUND_<ROLE>}` for a role the environment doesn't bind: never a value. The secrets agent materializes the TLS keystore, its PIN file and the CA truststore (`$DS_KEYSTORE`, `$DS_KEYSTORE_PIN_FILE`, `$DS_TRUSTSTORE`) before it runs. Its closing comment gives the order to apply the neutral files: schema, tree, `dsconfig` batch, ACIs.

Not rendered: the user data, backup jobs, an HTTPS port at setup (the HTTP connection handler is enabled through the batch).

## What it reads back

The lineage's importers, registered under this adapter's name (`opsdir_base_ds.importers`; details in `opsdir-base-ds`): `opendj/config` (each server's `config.ldif` and archived configurations as observed snapshots, for drift), `opendj/declared` (one server's `config.ldif` as the declared configuration), `opendj/access-log` (the directory's consumers from the JSON access log, values-free), `opendj/rendered` (its own `ds/dsconfig.batch` and `ds/acis.ldif` read back) and `opendj/schema` (a subschema LDIF onto the user schema). OpenDJ's connection handler names are read back as the record's neutral names. **Round trip** (`reads_back`): `rendered` over `ds/*`, `schema` over `ldap/schema.ldif`. OpenDJ's JSON access logger ships disabled: `opendj/access-log` reads only servers that enabled it.

### Collecting the configuration (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter opendj [--ldapsearch PATH] [--ldap-truststore PATH]` reads each directory server's `cn=config` over LDAPS on its administration port, with OpenDJ's own `ldapsearch` (`--bindDN`, `--useSSL`, `--bindPasswordFile /dev/stdin`, `--baseDN`), and imports it as `opendj/config` (`<host>/config/config.ldif` per server) or `opendj/declared` (the first server's `config.ldif`) (`opsdir_base_ds.collect`). The environment declares where:

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

The password reaches `ldapsearch` only on its standard input; the tool and truststore are the operator's, never stored. Before anything sees the output, every attribute holding a credential is dropped (password values, key and trust store PINs, secrets: `opsdir_base_ds.collect.holds_credential`); the password policies' settings are kept. Only the configuration in effect is read: archived configurations are on disk only, as are the access logs. Least privilege: an account with the `config-read` privilege and a global ACI on `cn=config` allowing `read,search,compare` (targetattr `*||+`).

## Schema, vocabulary and secret patterns

None of its own: the directory domain's schema (core) and the user schema hold what it renders. It owns no vocabulary, reference schemes or secret patterns. `profile_terms` are the lineage's (`opsdir_base_ds.profile.TERMS`). Formats: `ldap/*.ldif`, `ds/*.ldif` (LDIF), `ds/dsconfig.batch` (`dsconfig-batch`), `ds/setup-*.sh` (shell).

## Roles, server roles and planner checks

**Required roles**: `subnet-ds`, `ds-ldaps-service`, `backup-target`, `ds-root-password`, `ds-replication-admin-password`, `ds-tls-keystore`.

**Server role** `ds` (the directory domain's):

- **Listeners** (ports matrix, `opsdir_base_ds.listeners`): the handlers the declared configuration enables (their declared ports, else 1389, 1636, 8443), the administration connector 4444, replication 8989 for peers.
- **Logs** (`logs.py`, relative to `ciamInstallRoot`, as the Open Identity Platform's administration guide names its defaults): `logs/access` (access, text), `logs/http-access` (access; once the HTTP connection handler and its File-Based HTTP Access Log Publisher are enabled, both off by default, which the log-collection report says), `logs/errors` and `logs/server.out` (error), `logs/replication` (replication). The JSON access logger ships disabled and the audit log's default isn't stated, so neither is declared.
- No signals are declared.

**Planner check** `check_replication` (`replication.py`):

| Reports | Fix offered |
|---|---|
| Blocker: the target doesn't declare that it joins the source's replication topology (`ciamJoinsDeploymentOf`): a separate topology needs a full export and import, and loses the changelog. OK when it does (replicas join through a source replica; data and changelog carry over) | `replication:joins`: sets `ciamJoinsDeploymentOf` on the target environment |
| Blocker: no interconnect from the target to the source | |
| Blocker: a target replica the source's firewall rules don't admit on port 8989, or one recording no private IP | |

### Upgrades during a move

A migration may upgrade the product within the supported range (OpenDJ `>=4,<6`). The planner names each server role's version jump and every change below that the jump crosses, at its effect. A target outside the range is a blocker, a downgrade an action. From the project's release notes (`versions.py`).

| Since | Change | Effect | Named when |
|---|---|---|---|
| 5.1.2 | the JE backend and changelog formats change, and indexes must be rebuilt | action | always |

Moving to 5.1.2 runs OpenDJ's `upgrade` tool: load the target's data from LDIF (or run `upgrade`, then rebuild every index) and initialise replication before the cutover; plan it as its own change.

## Known limits

- **Not run against a live OpenDJ.** The scripts, batch and ACIs follow the OpenDJ 4.x documentation, unchanged in 5.0 and 5.1; running them is part of the testing plan (milestone 7.2).
- **One user backend**: the setup script sets up the first declared backend; the batch names every backend in a comment and creates its indexes, but creates no backend.
- **The replication administrator** is `admin`, fixed in the script.
- **What `config.ldif` can't show** (replication topology's shape) isn't read; see `opsdir-base-ds`.

## Tests

`tests/test_opendj.py`: registration, applies from the servers' products, OpenDJ 4 and 5 supported, a replication administrator and no deployment ID required, the lineage files rendered with OpenDJ's names, its servers' configuration read back under the record's handler names, 5.1.2's storage format change, its render reading back unchanged. `tests/test_opendj_collect.py`: the same search as PingDS's with OpenDJ's own `ldapsearch` option names. Full renders are exercised by the showcase (`test_directory_products`).

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-opendj/tests
```
