"""ping-devops adapter: PingFederate admin and engine workloads an environment runs on Kubernetes, deployed with
Ping Identity's ping-devops Helm chart at the pinned release, from the record's workloads and their bindings."""
from opsdir.core.contract import Adapter
from .checks import check_ping_devops
from .helm import render
from .listeners import listeners
from .products import applies

ADAPTER = Adapter(name="ping-devops", kind="platform", applies=applies, required_roles=(),
                  render_neutral=None, render_env=render, checks=(check_ping_devops,), ref_schemes=(),
                  secret_schemes={},
                  renders="ping-devops Helm values for the PingFederate admin and engine run on Kubernetes",
                  neutral_label=None, vocabulary={}, schema=None, formats=(("ping-devops/*", "yaml"),), products=(),
                  secret_patterns=(), importers=(), profile_terms=None, access=None, render_targets=(),
                  listeners=listeners)
