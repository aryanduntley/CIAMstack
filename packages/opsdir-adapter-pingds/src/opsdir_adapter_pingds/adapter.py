"""PingDS (ForgeRock DS lineage) adapter: applies to environments whose servers run PingDS."""
from opsdir.core.contract import Adapter
from opsdir.core.directory import one
from .render import render_neutral, setup_scripts
from .replication import check_replication

PRODUCT = "PingDS"
REQUIRED_ROLES = ("subnet-ds", "ds-ldaps-service", "backup-target", "ds-deployment-id", "ds-deployment-password",
                  "ds-root-password", "ds-tls-keystore")


def applies(m):
    return any(one(s, "ciamProductVersion", "").startswith(PRODUCT) for s in m.servers)


ADAPTER = Adapter(name="pingds", kind="product", applies=applies, required_roles=REQUIRED_ROLES,
                  render_neutral=render_neutral, render_env=setup_scripts, checks=(check_replication,), ref_schemes=(),
                  secret_schemes={}, renders="per-server DS setup scripts that join the existing deployment",
                  neutral_label="DS",
                  vocabulary={})
