# opsdir-base-ds

The base for directory servers of the DS lineage (OpenDJ → ForgeRock DS → PingDS). A library, not an adapter: product adapters build on it and register themselves.

What the lineage shares, rendered from the directory domain:

- `config.py`: the environment-neutral files: the standard LDAP files (from `opsdir-adapter-ldap`), the `dsconfig` batch (backends and indexes, password policies, connection handlers, log publishers, replication purge delay) and the ACIs in the lineage's ACI syntax.
- `setup.py`: what every setup script is built from: the user backend, listener ports, the environment's directory servers, secret references as run-time lookups.
- `replication.py`: the replication port and bootstrap peers, and the planner checks every product shares (an interconnect to the source, the replication port admitted for each new replica), plus `check_joins` for the product's own wording of what joining the source's replication keeps.

The lineage's `dsconfig` batch syntax is a format of its own, `dsconfig-batch`, which this package registers (entry point `opsdir.formats`); `config.FORMATS` declares the format of every neutral file the lineage renders.

What differs between products is data, a `DsProduct` record: the product name as servers record it, the administrator's bind DN, how to apply the batch file, and the product's names for connection handlers recorded under neutral names (`LDAP`, `LDAPS`, `HTTPS`). Setup scripts and the join check stay in each product's adapter.

```python
from opsdir_base_ds.product import DsProduct, runs
from opsdir_base_ds.config import neutral_files
from opsdir_base_ds.setup import setup_inputs, port
from opsdir_base_ds.replication import check_joins, check_replication_path, peer_ds_hosts
```

In this repository: `scripts/dev-install.sh`.
