"""PingDS (ForgeRock DS lineage) adapter: applies to environments whose servers run PingDS."""
from opsdir.core.contract import Adapter
from opsdir.domains.directory.naming import DIRECTORY_SERVER_ROLE
from opsdir_base_ds.config import FORMATS as LINEAGE_FORMATS
from opsdir_base_ds.collect import PINGDS_FLAGS, config_collectors
from opsdir_base_ds.importers import READS_BACK, importers
from opsdir_base_ds.listeners import ds_listeners
from opsdir_base_ds.profile import TERMS
from opsdir_base_ds.product import runs
from .logs import LOGS
from .render import PINGDS, PROFILE, render_neutral, render_notes, setup_scripts
from .replication import check_replication
from .signals import SIGNALS
from .versions import VERSION_CHANGES

SERVICE_ROLE = "ds-ldaps-service"      # the service name clients reach DS by (Adapter.roles, kind service)
REQUIRED_ROLES = ("subnet-ds", SERVICE_ROLE, "backup-target", "ds-deployment-id", "ds-deployment-password",
                  "ds-root-password", "ds-tls-keystore")


def applies(m):
    return runs(PINGDS, m)


ADAPTER = Adapter(name="pingds", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=setup_scripts, checks=(check_replication,), ref_schemes=(),
                  secret_schemes={}, renders="per-server DS setup scripts that join the existing deployment",
                  neutral_label="DS",
                  vocabulary={}, schema=None,
                  formats=(*LINEAGE_FORMATS, ("ds/setup-*.sh", "shell")),
                  products=(("PingDS", ">=7.2,<9"),),
                  roles=(("server", (DIRECTORY_SERVER_ROLE,)), ("service", (SERVICE_ROLE,))),
                  secret_patterns=(), importers=importers(PINGDS), profile_terms=TERMS, access=None,
                  listeners=ds_listeners, collectors=config_collectors("pingds", PINGDS_FLAGS),
                  signals=SIGNALS, logs=LOGS,
                  version_changes=VERSION_CHANGES, reads_back=READS_BACK, profile=PROFILE,
                  notes=render_notes)
