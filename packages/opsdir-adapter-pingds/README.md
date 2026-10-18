# opsdir-adapter-pingds

opsdir adapter for PingDS (ForgeRock Directory Services): the directory domain rendered as PingDS artifacts (the standard schema and tree LDIF, a `dsconfig` batch, ACI LDIF, per-server setup scripts that join the existing replication deployment), replication-continuity checks, and the servers' configuration, access logs and its own render read back. A thin product adapter on `opsdir-base-ds`, which holds everything the DS lineage shares; this package supplies PingDS's data (`render.PINGDS`), its setup script, its join check, logs, signals and version changes.

**Applies to** environments where PingDS runs: a server, or a Kubernetes workload's binding, whose `ciamProductVersion` starts with `PingDS` (`opsdir_base_ds.product.runs`). Supported: PingDS `>=7.2,<9` (DS 7.2 renamed the setup options rendered here, `--deploymentId`). Its directory servers are the domain's server role `ds`; it declares its roles for the kits that deploy it, which find them by product (`Adapter.roles`: server `ds`, service `ds-ldaps-service`).

**Depends on** `opsdir` and `opsdir-base-ds` (and through it `opsdir-adapter-ldap`, the standard LDAP files). The setup scripts run PingDS's own `setup`; collection runs PingDS's `ldapsearch`. Installing the package registers it with opsdir (entry point `opsdir.adapters`: `pingds`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.

## What it renders

| From the record | Rendered as |
|---|---|
| The user schema's own attribute types and object classes (`ou=user-schema`) | `ldap/schema.ldif` (environment-neutral; `opsdir-adapter-ldap`) |
| The declared backends' base DNs and the containers the record refers to | `ldap/dit.ldif` (environment-neutral; `opsdir-adapter-ldap`) |
| The declared configuration (`ou=declared`): backends and indexes, password policies, connection handlers, log publishers, the replication purge delay | `ds/dsconfig.batch` (environment-neutral; `opsdir-base-ds`), its header saying how to apply it as `uid=admin` over the administration port 4444; `Default Password Policy` and `Root Password Policy` are set, not created |
| The ACIs (`ou=acis`) | `ds/acis.ldif` (environment-neutral; `opsdir-base-ds`), with a `# WARNING` line for an ACI with no owner, no justification or all attributes |
| Each directory server of the environment (`ciamServerRole: ds`), the user backend, the declared ports, the replication peers, the secret roles `ds-deployment-id`, `ds-deployment-password`, `ds-root-password` | `ds/setup-<server>.sh` (per environment) |

**The setup script** runs `./setup` with `--serverId`, `--deploymentId` and `--deploymentIdPassword`, `--rootUserDn uid=admin` and `--rootUserPassword`, `--hostname`, `--adminConnectorPort 4444`, `--ldapsPort` and `--httpsPort` (the declared handlers' ports, else 1636 and 8443), `--replicationPort 8989`, one `--bootstrapReplicationServer <host>:8989` per peer (the environment's own directory servers, then those of the environment it joins, `ciamJoinsDeploymentOf`, so target replicas join the existing deployment), `--profile ds-user-data` with `--set ds-user-data/baseDn:<the user backend's base DN>`, and `--acceptLicense`. Secrets are run-time lookups of the bound references (the secret store adapter's command), or `${UNBOUND_<ROLE>}` for a role the environment doesn't bind: never a value. The TLS keystore (`ds-tls-keystore`) is materialized by the secrets agent before it runs. Its closing comment gives the order to apply the neutral files: schema, tree, `dsconfig` batch, ACIs.

Command and property names follow the PingDS documentation; verify them against the exact target version. Not rendered: the user data, backup jobs.

**Schema PingDS ships**: `ldap/schema.ldif` leaves out the record's definitions under the vendor arcs PingDS ships schema under, the lineage's own vendors' (OpenDS `1.3.6.1.4.1.26027`, ForgeRock `1.3.6.1.4.1.36733`; `PINGDS.shipped_arcs`, see `opsdir-base-ds`). Each one left out is a render note (`render_notes`, area `Directory`, severity note) to its record's owners, with its comment in `ldap/schema.ldif`: add the definition by hand where the servers lack it (a setup profile they don't run).

**Its product profile** (`PROFILE`, `opsdir.core.profiles`) is its standard LDAP files under their render paths (`ldap/schema.ldif`, `ldap/dit.ldif`): DS has no instance tree a kit copies over, so a deployment kit places each. `opsdir-adapter-forgeops` builds them into ForgeOps' DS image (target `config-profiles`).

## What it reads back

The lineage's importers, registered under this adapter's name (`opsdir_base_ds.importers`; details in `opsdir-base-ds`):

| Importer | Reads | Records |
|---|---|---|
| `pingds/config` | a copy of each server's `config/` directory (`config.ldif`, `archived-configs/config-<YYYYMMDDhhmmss>Z[.gz]`), a folder per server named by its hostname | observed snapshots under `ou=observed`, for drift (`opsdir report drift`); a new one only when the configuration changed |
| `pingds/declared` | one server's `config.ldif` | the declared configuration (`ou=declared`) |
| `pingds/access-log` | the servers' JSON access logs (`logs/ldap-access.audit.json` and its rotated files) | the directory's consumers (`ou=consumers`), values-free |
| `pingds/rendered` | its own `ds/dsconfig.batch` and `ds/acis.ldif` | the declared configuration, the topology's purge delay and the ACIs |
| `pingds/schema` | a subschema LDIF (its own `ldap/schema.ldif`, or a server's) | the user-schema records (`opsdir-adapter-ldap`'s `schema` importer) |

**Round trip** (`reads_back`): `rendered` over `ds/*`, `schema` over `ldap/schema.ldif`; every showcase environment's render reads back unchanged.

### Collecting the configuration (`opsdir collect`)

`opsdir collect --env CLOUD/ENV --adapter pingds [--ldapsearch PATH] [--ldap-truststore PATH]` reads each directory server's `cn=config` over LDAPS on its administration port, with PingDS's own `ldapsearch` (`--bindDn`, `--useSsl`, `--bindPassword:file /dev/stdin`, `--baseDn`; `--searchScope sub --wrapColumn 0 "(objectClass=*)" "*" "+"`), and imports it as `pingds/config` (`<host>/config/config.ldif` per server, collector `config`) or `pingds/declared` (the first server's `config.ldif`, collector `declared`) (`opsdir_base_ds.collect`). The environment declares where:

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

The password reaches `ldapsearch` only on its standard input; the tool and truststore are the operator's, given when collecting (else `ldapsearch` on the path and the JVM's trust store), never stored. Before anything sees the output, every attribute holding a credential is dropped (password values, key and trust store PINs, secrets: `opsdir_base_ds.collect.holds_credential`); the password policies' settings are kept. A source without its bind DN or credential says so. Only the configuration in effect is read: archived configurations are on disk only, as are the access logs. Least privilege: an account with the `config-read` privilege and a global ACI on `cn=config` allowing `read,search,compare` (targetattr `*||+`).

## Schema, vocabulary and secret patterns

None of its own: the directory domain's schema (core) and the user schema hold what it renders. It owns no vocabulary, reference schemes or secret patterns. `profile_terms` are the lineage's (`opsdir_base_ds.profile.TERMS`: last login `ds-last-login-time` / `ds-pwp-last-login-time`, disabled `ds-pwp-account-disabled: true`). Formats: `ldap/*.ldif`, `ds/*.ldif` (LDIF), `ds/dsconfig.batch` (`dsconfig-batch`), `ds/setup-*.sh` (shell).

## Roles, server roles and planner checks

**Required roles**: `subnet-ds`, `ds-ldaps-service`, `backup-target`, `ds-deployment-id`, `ds-deployment-password`, `ds-root-password`, `ds-tls-keystore`.

**Server role** `ds` (the directory domain's):

- **Listeners** (ports matrix, `opsdir_base_ds.listeners`): the handlers the declared configuration enables (LDAP and LDAPS for clients, HTTPS for the operators; their declared ports, else 1389, 1636, 8443; LDAPS and HTTPS when none is declared), the administration connector 4444, replication 8989 for peers.
- **Logs** (`logs.py`, relative to `ciamInstallRoot`): `logs/ldap-access.audit.json` and `logs/http-access.audit.json` (access, JSON lines), `logs/errors` and `logs/server.out` (error), `logs/replication` (replication; declared for versions before 7.3 only: from 7.3 the server writes these to `logs/errors`, so a role whose servers record a later version, or none, doesn't count it), and `logs/audit` (audit, LDIF; only once the File-Based Audit Logger is enabled, which it isn't by default).
- **Signals** (`signals.py`, at `/metrics/prometheus/0.0.4` on the HTTP connection handler, for a monitor-privileged account; published by default from 8.0): `replication-delay` (`ds_replication_replica_remote_replicas_receive_delay_seconds`), `disk-free` (`ds_disk_free_space_bytes`), `heap-used` (`ds_jvm_memory_heap_used_bytes`), `ldap-errors` (failed LDAP requests per second).
- **Detections** (`detections.py`, offered as alert rules a person adopts: core observability detections; validation documented), on `logs/ldap-access.audit.json`: `brute-force`, 10 binds with invalid credentials (`request.operation` `BIND`, `response.statusCode` `49`) for one `request.dn` within any 5 minutes, T1110.001, sev3; `password-spray`, 10 bind DNs failing so from one `client.ip` within any 10 minutes, T1110.003, sev2 (servers binding as their users, AM's or IDM's, are the client address of their binds). Not declared: administrator bind failures and configuration changes (they are DNs a selector can't hold; the configuration audit log is LDIF).

**Planner check** `check_replication` (`replication.py`):

| Reports | Fix offered |
|---|---|
| Blocker: the target doesn't declare that it joins the source's replication deployment (`ciamJoinsDeploymentOf`): a fresh deployment can't decrypt existing encrypted data or backups. OK when it does (same deployment ID, so keys and encrypted data stay readable) | `replication:joins`: sets `ciamJoinsDeploymentOf` on the target environment (its setup scripts then bootstrap from the source's servers) |
| Blocker: no interconnect from the target to the source (`ciamInterconnect` naming it) | |
| Blocker: a target replica the source's firewall rules don't admit on port 8989, or one recording no private IP (can't be checked) | |

### Upgrades during a move

A migration may upgrade the product within the supported range. The planner names each server role's version jump, from the oldest version the source runs to the newest the target runs, and every change below that the jump crosses (the source version lacks it, the target's has it), at its effect. A target outside the range is a blocker, a downgrade an action. From the vendor's release notes (`versions.py`); none touches what the record holds about a directory, so each is named whenever a move crosses it.

| Since | Change | Effect | Named when |
|---|---|---|---|
| 7.3 | replication messages move from logs/replication to logs/errors | info | always |
| 8.0 | the Prometheus endpoint (/metrics/prometheus/0.0.4) is published by default | info | always |
| 8.1 | rotated access and audit log files are named with UTC timestamps ending in Z | info | always |
| 8.1 | OPENDJ_JFR_ENABLED is renamed DS_JFR_ENABLED | info | always |
| 8.1 | backendstat's output is simplified | info | always |

## Known limits

- **Not run against a live PingDS.** The setup scripts, batch and ACIs follow the PingDS documentation; running them is part of the testing plan (milestone 7.2).
- **One user backend**: the setup script sets up the first declared backend (in DN order) with `--profile ds-user-data`; the batch names every backend in a comment and creates its indexes, but creates no backend.
- **Shipped schema by arc, not by exact OID**: only the OpenDS and ForgeRock arcs are left out. PingDS also ships some definitions under Sun's (`1.3.6.1.4.1.42`), Netscape's (`2.16.840.1.113730`) and other arcs (Samba, RFC-defined ones under enterprise arcs), but not all, so those are still rendered; a record definition PingDS also ships under them is loaded again. Tried on PingDS 8.1.2: one with the shipped definition's OID and name only warns (PingDS keeps its own); one with a shipped name and another OID in a schema file stops PingDS's tools and server from starting. The exact set comes from a live PingDS's own `db/schema` (milestone 7.2).
- **What `config.ldif` can't show** (replication topology's shape) isn't read; see `opsdir-base-ds`.

## Tests

`tests/test_pingds.py`: registration, applies from the servers' products, the roles a directory deployment binds, the neutral files from any directory, reading the servers' configuration as snapshots or the declared configuration, an upgrade naming the changes between releases, its profile (its standard LDAP files) and a note for a definition PingDS ships. `tests/test_pingds_collect.py`: `cn=config` of each server with PingDS's option names and the password on standard input, `declared` reading the first server only, credentials dropped and the configuration reading the same, a source without its bind DN or credential. `tests/ds-export/` is a sample server export. Full renders are exercised by the showcase's golden outputs.

`tests/test_pingds_store.py` (marker `integration`, Postgres via `OPSDIR_TEST_DSN`): a server's configuration (archived configurations compressed) imported under a change and again changing nothing, the latest snapshot compared with the declared configuration, consumers mined from access logs.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-pingds/tests
opsdir/.venv/bin/python -m pytest -m integration packages/opsdir-adapter-pingds/tests
```
