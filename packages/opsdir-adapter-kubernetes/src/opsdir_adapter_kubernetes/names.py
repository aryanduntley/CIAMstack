"""Kubernetes object names from the record's words. Pure."""
import re

NAME = "kubernetes"           # this adapter's name: what Services.render_targets knows its chosen targets by

# The label marking what opsdir renders (Kubernetes' recommended managed-by label): read back, it is the record's own
# output, derived from what the record holds, not another fact about the cluster.
MANAGED_BY = ("app.kubernetes.io/managed-by", "opsdir")

# The annotations a rendered workload carries so it reads back as the record's (workloads.py; on the workload object or
# its pod template, as the deployment kit's chart allows): the binding role of the cluster it runs in, the binding role
# of its workload binding, the binding role of its cloud identity, its record name when the kit names the object
# otherwise; on a pod that is part of another workload (a kit's companion: ForgeOps' UIs and amster with AM),
# "<workload>/<container>": the record's workload whose binding holds its image, under that container name; and the
# containers (comma-separated) the kit derives from the record (log sidecars), which are no images of the workload;
# and "<record container>=<pod container>, ..." where the record keeps an image under another name than the pod's
# container (or init container) running it (a kit's configuration image in its init container).
CLUSTER_ROLE = "opsdir.io/cluster-role"
WORKLOAD_ROLE = "opsdir.io/workload-role"
IDENTITY_ROLE = "opsdir.io/identity-role"
WORKLOAD_NAME = "opsdir.io/workload"
IMAGE_OF = "opsdir.io/image-of"
DERIVED = "opsdir.io/derived-containers"
CONTAINER_NAMES = "opsdir.io/container-names"


def k8s_name(text):
    """A Kubernetes object name (DNS label) from any text."""
    return re.sub(r"[^a-z0-9-]+", "-", text.lower()).strip("-")[:63].strip("-") or "x"
