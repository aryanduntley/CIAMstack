"""OpenDJ (DS lineage) adapter: applies to environments whose servers run OpenDJ."""
from opsdir.core.contract import Adapter
from opsdir_base_ds.config import FORMATS as LINEAGE_FORMATS
from opsdir_base_ds.collect import OPENDJ_FLAGS, config_collectors
from opsdir_base_ds.importers import importers
from opsdir_base_ds.listeners import ds_listeners
from opsdir_base_ds.profile import TERMS
from opsdir_base_ds.product import runs
from .logs import LOGS
from .render import OPENDJ, render_neutral, setup_scripts
from .replication import check_replication

REQUIRED_ROLES = ("subnet-ds", "ds-ldaps-service", "backup-target", "ds-root-password",
                  "ds-replication-admin-password", "ds-tls-keystore")


def applies(m):
    return runs(OPENDJ, m)


ADAPTER = Adapter(name="opendj", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=setup_scripts, checks=(check_replication,), ref_schemes=(),
                  secret_schemes={}, renders="per-server OpenDJ setup and dsreplication scripts that join the existing "
                                            "topology",
                  neutral_label="DS", vocabulary={}, schema=None,
                  formats=(*LINEAGE_FORMATS, ("ds/setup-*.sh", "shell")),
                  products=(("OpenDJ", ">=4,<5"),),
                  secret_patterns=(), importers=importers(OPENDJ), profile_terms=TERMS, access=None,
                  listeners=ds_listeners, collectors=config_collectors("opendj", OPENDJ_FLAGS), logs=LOGS)
