"""Compute domain vocabulary: where host baselines and workloads live."""
from ...core.naming import branch

BASELINES = branch("baselines")
WORKLOADS = branch("workloads")
WORKLOAD_KINDS = ("statefulset", "deployment", "daemonset", "other")
QUANTITY = r"^[0-9]+(\.[0-9]+)?(m|k|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei)?$"      # a Kubernetes resource quantity
# <secret name>/<key>=<secret role>: a Secret's name (DNS subdomain), one of its keys, the role that fills it
WORKLOAD_SECRET = r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?/[-._A-Za-z0-9]+ <- [^\s]+$"


def baseline_dn(role):
    """A server role's host baseline: one per role, named by it."""
    return f"cn={role},{BASELINES}"


def workload_dn(name):
    return f"cn={name},{WORKLOADS}"
