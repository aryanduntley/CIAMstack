"""What an environment runs with the ping-devops chart, from the record. Pure.

A workload the environment runs on Kubernetes (it binds the workload's ciamWorkloadRole) is the chart's when its role
is pf-admin (pingfederate-admin) or pf-engine (pingfederate-engine). Per namespace, a placement: the first workload
of each product there; the chart runs one of each per release, so any further one is named, not placed.

What each product runs comes from its workload's binding (opsdir-adapter-kubernetes kits): image, replicas, cpu and
memory, storage. An image the record doesn't name is UNBOUND:ping-devops-<product>-image.
"""
from collections import namedtuple

from opsdir.core.directory import one
from opsdir.core.environment import UNBOUND
from opsdir.domains.compute.workloads import workload_secrets
from opsdir_adapter_kubernetes.kits import image_named, only_image
from opsdir_adapter_kubernetes.render import namespace_of, on_kubernetes
from .release import PRODUCTS, file_path, product_of

# One namespace's PingFederate: placed ((product name, workload), ...) in the chart's product order.
Placement = namedtuple("Placement", ("namespace", "placed"))


def _ours(m):
    return [(namespace_of(w), product_of(one(w, "ciamTargetRole")).name, w) for w in on_kubernetes(m)
            if product_of(one(w, "ciamTargetRole")) is not None]


def placements(m):
    """Per namespace (in the order workloads name them), the first workload of each product the chart deploys."""
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


def workload_of(p, name):
    """The workload a placement runs as a product, or None."""
    return next((w for x, w in p.placed if x == name), None)


def image_of(m, p, name):
    """The image a product runs: the first of its container names the placement's workload bindings record (its own
    workload's first), else its own workload's only image, else UNBOUND:ping-devops-<product>-image."""
    own = workload_of(p, name)
    containers = next(x.containers for x in PRODUCTS if x.name == name)
    found = image_named(m, [own, *(w for _, w in p.placed)], containers) or only_image(m, own)
    return found or f"{UNBOUND}ping-devops-{name}-image"


def secret_keys(w):
    """((secret, key, file path or None), ...): the Secret keys a workload reads (ciamWorkloadSecret), each with the
    path it is mounted at, None for an environment variable."""
    return tuple(dict.fromkeys((s, k, file_path(k)) for s, k, _ in workload_secrets(w)))


def applies(m):
    """Whether environment m runs PingFederate with the ping-devops chart."""
    return bool(placements(m))
