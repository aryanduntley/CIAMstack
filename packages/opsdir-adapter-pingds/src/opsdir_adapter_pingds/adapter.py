"""PingDS (ForgeRock DS lineage) adapter: applies to environments whose servers run PingDS."""
from opsdir.core.contract import Adapter
from opsdir_base_ds.config import FORMATS as LINEAGE_FORMATS
from opsdir_base_ds.importers import importers
from opsdir_base_ds.profile import TERMS
from opsdir_base_ds.product import runs
from .render import PINGDS, render_neutral, setup_scripts
from .replication import check_replication

REQUIRED_ROLES = ("subnet-ds", "ds-ldaps-service", "backup-target", "ds-deployment-id", "ds-deployment-password",
                  "ds-root-password", "ds-tls-keystore")


def applies(m):
    return runs(PINGDS, m)


ADAPTER = Adapter(name="pingds", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=setup_scripts, checks=(check_replication,), ref_schemes=(),
                  secret_schemes={}, renders="per-server DS setup scripts that join the existing deployment",
                  neutral_label="DS",
                  vocabulary={}, schema=None,
                  formats=(*LINEAGE_FORMATS, ("ds/setup-*.sh", "shell")),
                  products=(("PingDS", ">=7,<9"),),
                  secret_patterns=(), importers=importers(PINGDS), profile_terms=TERMS, access=None)
