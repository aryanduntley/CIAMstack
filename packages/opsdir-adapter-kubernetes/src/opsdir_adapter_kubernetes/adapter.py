"""Kubernetes adapter: Kubernetes secrets as a secret store usable from any environment, and the workloads clusters
run read from their manifests (kubernetes/workloads); it renders nothing itself."""
from opsdir.core.contract import Adapter
from .secrets import secret_command
from .workloads import WORKLOADS_IMPORTER


def applies(m):
    """A secret store renders nothing for an environment; it only resolves k8s-secret:// references."""
    return False


ADAPTER = Adapter(name="kubernetes", kind="secret-store", applies=applies, required_roles=(),
                  render_neutral=None, render_env=None, checks=(), ref_schemes=("k8s-secret",),
                  secret_schemes={"k8s-secret": secret_command}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(),
                  products=(),
                  secret_patterns=(), importers=(WORKLOADS_IMPORTER,), profile_terms=None)
