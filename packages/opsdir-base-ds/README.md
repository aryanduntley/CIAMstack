# opsdir-base-ds

The base for directory servers of the DS lineage (OpenDJ → ForgeRock DS → PingDS): what the lineage shares, rendered from the directory domain and read back from the servers. A library, not an adapter: product adapters (`opsdir-adapter-pingds`, `opsdir-adapter-opendj`) build on it and register themselves.

**Applies to** nothing on its own: each product adapter applies where its product runs (`product.runs`: a server's or Kubernetes workload binding's `ciamProductVersion` starting with the product's name). What differs between products is data, a `DsProduct` record (`product.py`): the product name as servers record it, the administrator's bind DN, how to apply the batch file (comment lines), the product's names for connection handlers recorded under neutral names (`LDAP`, `LDAPS`, `HTTPS`), and the password policies every server already has. Setup scripts and the join check's wording stay in each product's adapter.

**Depends on** `opsdir` and `opsdir-adapter-ldap` (the standard LDAP files and the `schema` importer). It registers the format `dsconfig-batch` (entry point `opsdir.formats`). In this repository: `opsdir/scripts/dev-install.sh`.

```python
from opsdir_base_ds.product import DsProduct, runs
from opsdir_base_ds.config import neutral_files, FORMATS
from opsdir_base_ds.setup import setup_inputs, port, ADMIN_PORT
from opsdir_base_ds.replication import check_joins, check_replication_path, peer_ds_hosts, joined_ds_hosts
from opsdir_base_ds.observe import config_entries, server_id
from opsdir_base_ds.importers import importers, READS_BACK
from opsdir_base_ds.collect import config_collectors, PINGDS_FLAGS, OPENDJ_FLAGS
from opsdir_base_ds.listeners import ds_listeners
from opsdir_base_ds.profile import TERMS
```

## What it renders

`config.neutral_files(product, d)`: the environment-neutral files every product of the lineage renders.

| From the record | Rendered as |
|---|---|
| The user schema's own definitions; the backends' base DNs and referenced containers | `ldap/schema.ldif`, `ldap/dit.ldif` (`opsdir-adapter-ldap`'s `render_standard`). The schema leaves out the record's definitions under the vendor arcs the product's servers ship (`DsProduct.shipped_arcs`, `product.shipped_arc`): loading them again clashes with the servers' own, online as in a schema file. Each one left out is a render note (`config.shipped_notes`: area `Directory`, severity note, to the record's owners) with its `# NOTE:` comment at the end of `ldap/schema.ldif`; a product returns them as its `Adapter.notes` (PingDS does; OpenDJ declares no arcs yet, so its render is unchanged) |
| The declared backends (`ou=backends,ou=declared`) and their indexes (`ciamIndex`: the indexed attribute's `ciamLdapName`, `ciamIndexType`) | `ds/dsconfig.batch`: a `# backend <name> (<base DN>)` line per backend, then `create-backend-index --backend-name ... --index-name ... --set index-type:...` |
| Password policies (`ciamPasswordPolicy`: storage scheme, lockout failure count and duration, history count, maximum age) | `create-password-policy --type password-policy`, or `set-password-policy-prop` for a policy the product's servers already have; `password-attribute:userPassword` |
| Connection handlers (`ciamConnectionHandler`: enabled, listen port) | `set-connection-handler-prop` under the product's handler name |
| Log publishers (`ciamLogPublisher`: enabled) | `set-log-publisher-prop` |
| The replication topology's purge delay (`cn=topology,ou=replication,ou=declared`) | `set-synchronization-provider-prop --provider-name "Multimaster Synchronization" --set replication-purge-delay:...` |
| The ACIs (`ou=acis`: target DN, target attributes or all, rights, grantees as consumers' bind DNs) | `ds/acis.ldif`: one `add: aci` modify per ACI in the lineage's syntax, a `# WARNING` line for one with no owner, no justification or `targetattr=*` |

The batch's header says how to apply it (the product's `dsconfig_apply`). The format of every neutral file is declared in `config.FORMATS` (`ldap/*.ldif`, `ds/*.ldif` LDIF; `ds/dsconfig.batch` `dsconfig-batch`); products add their setup scripts.

**For the products' setup scripts** (`setup.py`): the user backend (the first declared backend in DN order), the declared handlers' ports (else the lineage defaults LDAP 1389, LDAPS 1636, HTTPS 8443), the administration connector 4444, the environment's directory servers (`ciamServerRole: ds`), and secret roles as run-time lookups (`"$(<the secret store's command>)"`, or `"${UNBOUND_<ROLE>}"` for a role the environment doesn't bind: never a value). Replication (`replication.py`): port 8989, and bootstrap peers (the environment's own directory servers, then those of the environment it joins, `ciamJoinsDeploymentOf`).

**Listeners** (`listeners.ds_listeners`, each product's `listeners`): the handlers the declared configuration enables (LDAP and LDAPS for clients, HTTPS for the operators; LDAPS and HTTPS when none is declared), the administration connector 4444 for admins, replication 8989 for peers.

Command and property names follow the products' documentation; verify them against the exact target version.

## What it reads back

`importers.importers(product)` returns the importers every product registers (`<product>/config`, `/declared`, `/access-log`, `/rendered`, and `opsdir-adapter-ldap`'s `/schema`); `READS_BACK` is what a product's own render reads back through (`rendered` over `ds/*`, `schema` over `ldap/schema.ldif`).

### Servers' configuration: `config` and `declared`

```bash
opsdir import --change CHG-… pingds/config  EXPORT   # observed snapshots (opendj/config for OpenDJ)
opsdir import --change CHG-… pingds/declared EXPORT  # one server's configuration as the declared configuration
opsdir report drift                                  # each server's latest snapshot vs the declared configuration
```

`EXPORT` holds a copy of each server's `config/` directory in a folder named by the server's hostname (or its record name, when no other environment has a server of that name):

```
EXPORT/ds-1.example.test/config.ldif
EXPORT/ds-1.example.test/archived-configs/config-20260920030000Z.gz
EXPORT/ds-2.example.test/...
```

A `config.ldif` at the top of `EXPORT` is placed by the server ID its global configuration records (`ds-cfg-server-id`, `setup --serverId`).

`observe.py` reads a `config.ldif` (the `cn=config` tree) as the directory domain models configuration:

| `config.ldif` | Recorded |
|---|---|
| database backends (`ds-cfg-je-backend`, `ds-cfg-pdb-backend`) | `ciamBackend` (`ciamBackendType` `je` or `pdb`, `ciamBaseDn`: the first base DN, the others named); the server's internal backends (schema, tasks, monitor, root users, admin data) are the product's and skipped |
| their indexes (`ds-cfg-backend-index`) | `ciamIndex`, linked to the user-schema record of the indexed attribute; an attribute with no record (objectClass, entryUUID, aci, ...) or an index type the record doesn't model is named, not recorded |
| password policies (`ds-cfg-password-policy`) | `ciamPasswordPolicy` (default storage scheme, lockout, history, maximum age); one with no default storage scheme is named |
| connection handlers | `ciamConnectionHandler` under the record's neutral name for the product's handler (enabled, listen port) |
| log publishers | `ciamLogPublisher` (enabled) |

Names holding a DN special character are named, not recorded. The replication topology's shape can't be seen from one server and isn't read.

- **`config`** records each server's `config.ldif` as an observed snapshot, `snap=<cloud>-<env>-<server>-<time>` under `ou=observed`, dated when the export was taken (`--at YYYYMMDDhhmmssZ`, default now; without an import time the current configuration isn't dated and isn't imported). A snapshot is added only when the configuration differs from the server's latest one, so importing again changes nothing. Each archived configuration (the server saves `config.ldif` there before every change made online, as `config-<YYYYMMDDhhmmss>Z.gz`) becomes a snapshot of the configuration in effect until that time, dated by its name: the server's configuration history. `.gz` files are read as they are. Other files in a server's folder are counted in a notice; a folder that names no directory server is named.
- **`declared`** sets the declared configuration (`ou=declared`) from exactly one server's `config.ldif` (any other count imports nothing and says so): each branch the server has (backends, password policies, connection handlers, log publishers) becomes exactly what it runs, entries it doesn't have are removed, and attributes the importer doesn't own (owners, what a policy is for) are kept (`observe.OWNED`). Meant for a record that doesn't declare its configuration yet; review it with `--dry-run` first.

### Its own render: `rendered`

`rendered.py` reads the lineage's render back (the round trip, milestone 5.5): `ds/dsconfig.batch` sets the declared configuration as `declared` does from a `config.ldif` (the same mapping, `observe.records_entries`, from `create-backend-index`, `create-password-policy`, `set-password-policy-prop`, `set-connection-handler-prop`, `set-log-publisher-prop`). Backends are named, with their base DN, by the batch's own `# backend <name> (<base DN>)` lines, because `setup --profile` creates them; their type isn't in the render, so the record's is kept, and a backend the record doesn't hold is named, not read. The replication purge delay (`set-synchronization-provider-prop`) goes onto the topology (named when the record has none). `ds/acis.ldif` makes `ou=acis` exactly its ACIs: name, target DN, target attributes as user-schema records (or all attributes), rights, grantees as the consumers whose bind DN each `userdn` is; owners, justification and review dates are the record's and kept. `ldap/dit.ldif` holds nothing of its own (it is derived from the backends and the record's references), and `ldap/schema.ldif` reads back through the LDAP base's `schema` importer. A render reads back unchanged: `examples/showcase/tests/unit/test_round_trip.py`. With neither file, nothing is imported and a notice says so.

### The directory's consumers: `access-log`

```bash
opsdir import --change CHG-… pingds/access-log LOGS   # LOGS: the servers' logs/ directories, any layout
```

`access_log.py` reads the JSON access log every server of the lineage writes (`logs/ldap-access.audit.json` and its rotated files, UTC-timestamped names included; one JSON object per line, `eventName: DJ-LDAP`). Every operation is attributed to the identity that performed it (`userId`, or the DN a successful bind used). An identity that does more than authenticate is a consumer of the directory: it is recorded under `ou=consumers` (a new one under a name the record doesn't use), or updated when the record already has a consumer with that bind DN, with:

| Attribute | What |
|---|---|
| `ciamObservedSource` | the client addresses it connects from (a /24, or /64 for IPv6, where several share one) |
| `ciamOperationMix` | its operations by kind (`search 70%, bind 25%, modify 5%`) |
| `ciamSubtreeRead` | its search bases (a base-scope read of one entry records the entry's container) |
| `ciamAttrRead` | the attributes it asks for, as the user-schema records that describe them |
| `ciamUnindexedSearchesPerDay` | its unindexed searches per day of the logs |
| `ciamTlsOnly` | whether every connection it used was TLS (LDAPS, or StartTLS before it operated) |
| `ciamPeakOpsPerSec` | the most operations it performed in one second |
| `ciamFirstSeen`, `ciamLastSeen` | widened by what the logs show, never narrowed |

What the record says beyond that (owner, criticality, migration status) is kept; a new consumer's migration status is `unknown`, so the planner asks about it. It is values-free: search filters, entry DNs other than search bases, and attribute values are never read. An identity that only binds is an end user whose password is being checked, not a client: it is counted in the notices and never recorded, unless the record already names it as a consumer. Anonymous operations are counted, not attributed. Import a representative window (a week, say) from every server; importing the same logs again changes nothing. Files that aren't JSON access logs (the CSV and legacy text access logs) are named, not read.

### Collectors (`collect.py`)

`config_collectors(product_name, flags)` gives each product its `config` and `declared` collectors, both declaring the collect options `LDAPSEARCH` (`--ldapsearch PATH`) and `LDAP_TRUSTSTORE` (`--ldap-truststore PATH`), which this module defines once for every product of the lineage: each directory server's `cn=config` searched over LDAPS on the administration port (the collection source's `ciamTargetRole`/`ciamPort`, or an `ldaps://host:port` URL; port 4444 by default) with the product's own `ldapsearch` (`PINGDS_FLAGS`, `OPENDJ_FLAGS`: the option names that differ), `"(objectClass=*)" "*" "+"`, unwrapped; the bind DN from `ciamLoginName`, the password from `ciamCredentialRole`'s reference, only on standard input. The output becomes `<host>/config/config.ldif` (`declared`: the first server's, as `config.ldif`). Before anything sees it (the export, the evidence's hash, `--save`), the attributes that hold credentials are dropped (`holds_credential`: `userPassword`, `authPassword`, settings ending `-password` other than the password policies' `ds-cfg-password-*`, `-pin`, `-secret`). The `ldapsearch` and truststore are the operator's (`--ldapsearch PATH`, `--ldap-truststore PATH`), never stored. A source without a bind DN or credential says so. Only the configuration in effect is read: archived configurations and access logs are on disk only.

## Schema, vocabulary and secret patterns

No schema, vocabulary, reference schemes or secret patterns of its own: it reads and writes the core directory domain's entries. It registers the format `dsconfig-batch` (`config.DSCONFIG_BATCH`: `.batch`, `#` comments).

**What the lineage's attributes mean to the data profile** (`profile.TERMS`, the products' `profile_terms`): the last login time a password policy records (`last-login-time-attribute`: `ds-last-login-time` in PingDS's sample policies, `ds-pwp-last-login-time` in older configurations) and the flag an administrator disables an account with (`ds-pwp-account-disabled: true`); the lineage's own operational attributes (`ds-*`, `etag`, the virtual `isMemberOf`) aren't counted as user data. Both are operational, so ask `ldapsearch` for them (`"*" "+"`). A policy that records the last login in another attribute needs that name added here; a `last-login-time-format` that doesn't start with `yyyyMMdd` counts as `unreadable`.

## Planner checks (for the products)

`replication.check_replication_path(ctx)`: blockers for no interconnect from the target to the source (`ciamInterconnect` naming it), a target replica the source's firewall rules don't admit on port 8989, and a target replica recording no private IP (can't be checked); a target with no replicas is said, not passed as all admitted. `replication.check_joins(d, src, dst, joined_text, missing_text)`: the target declares that it joins the source's replication (`ciamJoinsDeploymentOf`), in the product's wording; a blocker otherwise, with the fix `replication:joins` setting it. Products add these to their `check_replication`.

## Known limits

- **The replication topology's shape** (how many replicas, which replicate with which) can't be seen from one server's `config.ldif` and isn't read.
- **Backends serve one base DN** in the record (the first; others named); internal backends are skipped.
- **Indexes and policies** carry only what the record models (index types, the four policy properties); other settings aren't read or rendered.
- **One user backend** is set up by the products' scripts (the first declared); the batch creates no backend.
- **Not run against live servers** beyond the showcase's round trip (milestone 7.2).
- **Shipped schema is matched by vendor arc** (`DsProduct.shipped_arcs`), not by the exact OIDs of the servers' own schema files: an arc is declared only where every definition under it is the lineage's vendors' (a definition under such an arc that the servers don't ship, from a setup profile they don't run, is named by its note); arcs the servers ship only part of are not declared.

## Tests

`tests/test_base_ds.py` (products as data, handler names, the neutral files, ports from the declared handlers else the defaults, the batch format registered, replicas without a private IP named, no replicas said, built-in policies set not created, the join fix, the schema leaving out what the product ships with a note each), `tests/test_observe.py` (`config.ldif` as the record models it, the server ID, snapshots per server folder and dated, an unchanged configuration adding nothing, archived configurations, folder placement, no import time, drift, the declared configuration from exactly one server), `tests/test_rendered.py` (a render reading back unchanged, an edited one saying what changed, what the render doesn't carry kept, what can't be read named, the purge delay and absent files), `tests/test_access_log.py` (attribution, consumers updated and found values-free, end users only counted, re-import, names, rotated logs), `tests/test_listeners.py`. The shared collectors (`collect.py`) are tested through the products that use them: `test_pingds_collect.py` (the `cn=config` and declared collectors, credentials dropped, a source missing its bind DN or credential) and `test_opendj_collect.py` (OpenDJ's option names).

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-base-ds/tests
```
