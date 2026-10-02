"""Compute domain vocabulary: where host baselines and workloads live."""
from ...core.naming import branch

BASELINES = branch("baselines")
WORKLOADS = branch("workloads")
WORKLOAD_KINDS = ("statefulset", "deployment", "daemonset", "other")


def baseline_dn(role):
    """A server role's host baseline: one per role, named by it."""
    return f"cn={role},{BASELINES}"


def workload_dn(name):
    return f"cn={name},{WORKLOADS}"
