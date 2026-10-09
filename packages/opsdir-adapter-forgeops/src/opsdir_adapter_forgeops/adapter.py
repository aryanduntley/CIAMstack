"""ForgeOps adapter: PingAM, PingIDM, PingDS and PingGateway workloads an environment runs on Kubernetes, deployed
with ForgeOps (Ping Identity's Helm charts and Kustomize bases) at the pinned release, from the record's workloads
and their bindings."""
from opsdir.core.contract import Adapter
from .checks import check_forgeops
from .listeners import listeners
from .render import TARGETS, applies, render

ADAPTER = Adapter(name="forgeops", kind="platform", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_forgeops,), ref_schemes=(),
                  secret_schemes={},
                  renders="ForgeOps Helm values (identity-platform, ping-gateway) and a Kustomize overlay for the "
                          "workloads run on Kubernetes",
                  neutral_label=None, vocabulary={}, schema=None, formats=(("forgeops/*", "yaml"),), products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None, render_targets=TARGETS,
                  listeners=listeners)
