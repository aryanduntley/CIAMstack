"""What an environment runs with the ping-devops chart, from the record. Pure.

A workload the environment runs on Kubernetes (it binds the workload's ciamWorkloadRole) is the chart's when its role
is pf-admin (pingfederate-admin) or pf-engine (pingfederate-engine). Per namespace, a placement: the first workload
of each product there; the chart runs one of each per release, so any further one is named, not placed.

What each product runs comes from its workload's binding (opsdir-adapter-kubernetes kits): image, replicas, cpu and
memory, storage. An image the record doesn't name is UNBOUND:ping-devops-<product>-image.
"""
from opsdir.core.directory import one
from opsdir.domains.compute.workloads import workload_secrets
from opsdir_adapter_kubernetes.kits import Placement, kit_image, workload_of
from opsdir_adapter_kubernetes.render import namespace_of, on_kubernetes
from .release import PRODUCTS, file_path, product_of


def _ours(m):
    return [(namespace_of(w), product_of(one(w, "ciamTargetRole")).name, w) for w in on_kubernetes(m)
            if product_of(one(w, "ciamTargetRole")) is not None]


def placements(m):
    """Per namespace (in the order workloads name them), the first workload of each product the chart deploys, in the
    chart's product order (kubernetes kits.Placement)."""
    ours = _ours(m)
    spaces = dict.fromkeys(ns for ns, _, _ in ours)
    first = lambda ns, name: next((w for n, x, w in ours if n == ns and x == name), None)
    return tuple(Placement(ns, tuple((p.name, first(ns, p.name)) for p in PRODUCTS if first(ns, p.name) is not None))
                 for ns in spaces)


def unplaced(m):
    """((namespace, product name, workload), ...): workloads of a product beyond the first in their namespace."""
    ours = _ours(m)
    return tuple((ns, name, w) for i, (ns, name, w) in enumerate(ours)
                 if any(n == ns and x == name for n, x, _ in ours[:i]))


def image_of(m, p, name):
    """The image a product runs (kubernetes kits.kit_image over its container names); UNBOUND:ping-devops-<product>-
    image when the record names none."""
    return kit_image(m, p, name, next(x.containers for x in PRODUCTS if x.name == name), "ping-devops")


def secret_keys(w):
    """((secret, key, file path or None), ...): the Secret keys a workload reads (ciamWorkloadSecret), each with the
    path it is mounted at, None for an environment variable."""
    return tuple(dict.fromkeys((s, k, file_path(k)) for s, k, _ in workload_secrets(w)))


def deploys(m, w):
    """Adapter.mounts_secrets: whether the chart deploys a workload in environment m (it mounts the workload's
    SecretProviderClasses in its pods: helm.product_values)."""
    return any(w in (x for _, x in p.placed) for p in placements(m))


def applies(m):
    """Whether environment m runs PingFederate with the ping-devops chart."""
    return bool(placements(m))
