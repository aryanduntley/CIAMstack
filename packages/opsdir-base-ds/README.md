# opsdir-base-ds

The base for directory servers of the DS lineage (OpenDJ → ForgeRock DS → PingDS). A library, not an adapter: product adapters build on it and register themselves.

What the lineage shares, rendered from the directory domain:

- `config.py`: the environment-neutral files: the standard LDAP files (from `opsdir-adapter-ldap`), the `dsconfig` batch (backends and indexes, password policies, connection handlers, log publishers, replication purge delay) and the ACIs in the lineage's ACI syntax.
- `setup.py`: what every setup script is built from: the user backend, listener ports, the environment's directory servers, secret references as run-time lookups.
- `replication.py`: the replication port and bootstrap peers, and the planner checks every product shares (an interconnect to the source, the replication port admitted for each new replica), plus `check_joins` for the product's own wording of what joining the source's replication keeps.
- `observe.py`: the other direction: a server's `config.ldif` (the `cn=config` tree) read as the directory domain models configuration: database backends (JE, PDB; the server's internal backends are skipped) and their indexes (linked to the user-schema record of the indexed attribute; others named), password policies, connection handlers under the record's names, log publishers. The replication topology's shape can't be seen from one server and isn't read.
- `importers.py`: the importers every product registers, `config` and `declared` (below).

## Reading servers' configuration back

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

A `config.ldif` at the top of `EXPORT` is placed by the server ID its global configuration records (`setup --serverId`).

- **`config`** records each server's `config.ldif` as an observed snapshot, `snap=<cloud>-<env>-<server>-<time>` under `ou=observed`, dated when the export was taken (`--at YYYYMMDDhhmmssZ`, default now). A snapshot is added only when the configuration differs from the server's latest one, so importing again changes nothing. Each archived configuration (the server saves `config.ldif` there before every change made online, as `config-<YYYYMMDDhhmmss>Z.gz`) becomes a snapshot of the configuration in effect until that time, dated by its name: the server's configuration history. `.gz` files are read as they are.
- **`declared`** sets the declared configuration (`ou=declared`) from one server's `config.ldif`: each branch the server has (backends, password policies, connection handlers, log publishers) becomes exactly what it runs, entries it doesn't have are removed, and attributes the importer doesn't own (owners, what a policy is for) are kept. Meant for a record that doesn't declare its configuration yet; review it with `--dry-run` first.

Anything the importers can't place (an index on an attribute the record has no user-schema record for, an index type the record doesn't model, a folder that names no directory server) is named in the import's notices.

The lineage's `dsconfig` batch syntax is a format of its own, `dsconfig-batch`, which this package registers (entry point `opsdir.formats`); `config.FORMATS` declares the format of every neutral file the lineage renders.

What differs between products is data, a `DsProduct` record: the product name as servers record it, the administrator's bind DN, how to apply the batch file, and the product's names for connection handlers recorded under neutral names (`LDAP`, `LDAPS`, `HTTPS`). Setup scripts and the join check stay in each product's adapter.

```python
from opsdir_base_ds.product import DsProduct, runs
from opsdir_base_ds.config import neutral_files
from opsdir_base_ds.setup import setup_inputs, port
from opsdir_base_ds.replication import check_joins, check_replication_path, peer_ds_hosts
from opsdir_base_ds.observe import config_entries, server_id
from opsdir_base_ds.importers import importers
```

In this repository: `scripts/dev-install.sh`.
