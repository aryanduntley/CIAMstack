"""Kubernetes object names from the record's words. Pure."""
import re

# The label marking what opsdir renders (Kubernetes' recommended managed-by label): read back, it is the record's own
# output, derived from what the record holds, not another fact about the cluster.
MANAGED_BY = ("app.kubernetes.io/managed-by", "opsdir")


def k8s_name(text):
    """A Kubernetes object name (DNS label) from any text."""
    return re.sub(r"[^a-z0-9-]+", "-", text.lower()).strip("-")[:63].strip("-") or "x"
