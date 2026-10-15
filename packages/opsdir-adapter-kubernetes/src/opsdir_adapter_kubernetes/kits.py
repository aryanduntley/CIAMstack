"""What a deployment kit (ForgeOps, ping-devops) reads from a workload and its workload binding: the images its
containers run, replicas, cpu and memory, storage, the labels its pods carry, and the marks (names.py) that make what
it deploys read back as the record's workloads (workloads.py). Shared by the kit adapters, which set them in their own
charts' and bases' terms. Pure.

What the record doesn't hold is None or left out, so the kit's own default stays.

Kits also share how they place what an environment runs: per namespace a Placement, the workload each of their
components or products runs as (workload_of), its image (kit_image) and the ports their pods listen on
(kit_listeners).
"""
from collections import namedtuple

from opsdir.core.contract import Listener
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND
from opsdir.domains.compute.workloads import workload_binding
from .names import CLUSTER_ROLE, IDENTITY_ROLE, IMAGE_OF, WORKLOAD_NAME, WORKLOAD_ROLE
from .render import ROLE_LABEL, identity_binding


def container_images(b):
    """((container, image reference), ...) a workload binding records (ciamContainerImage container=image); () for
    None."""
    return tuple(tuple(v.split("=", 1)) for v in (values(b, "ciamContainerImage") if b is not None else ()) if "=" in v)


def image_named(m, ws, containers):
    """The image of the first of these container names the workloads' bindings record (the first workload's that
    records it), or None."""
    named = dict(reversed([i for w in ws for i in container_images(workload_binding(m, w))]))
    return next((named[c] for c in containers if c in named), None)


def only_image(m, w):
    """A workload's image when its binding records exactly one, else None."""
    found = container_images(workload_binding(m, w))
    return found[0][1] if len(found) == 1 else None


# One namespace of what a kit runs: placed ((component or product name, workload), ...), on (every name that is on,
# parts that come with others among them, such as ForgeOps' companions; () for a kit without such parts).
Placement = namedtuple("Placement", ("namespace", "placed", "on"), defaults=((),))


def workload_of(p, name):
    """The workload a placement runs as a component or product, or None (a component that comes with others)."""
    return next((w for x, w in p.placed if x == name), None)


def kit_image(m, p, name, containers, kit):
    """The image a component or product of placement p runs: the first of its container names the placement's
    workload bindings record (its own workload's first), else its own workload's only image, else
    UNBOUND:<kit>-<name>-image."""
    own = workload_of(p, name)
    ws = [*([own] if own is not None else []), *(w for _, w in p.placed)]
    found = image_named(m, ws, containers) or (only_image(m, own) if own is not None else None)
    return found or f"{UNBOUND}{kit}-{name}-image"


def kit_listeners(placements, pod_ports):
    """The Listeners of the server roles a kit's placements run: its pods' ports (pod_ports: ((role, port, purpose,
    peers), ...)), declared on="kubernetes" so the network policies admit them to the role's pods instead of the
    product's own and the firewall checks leave them out."""
    roles = dict.fromkeys(one(w, "ciamTargetRole") for p in placements for _, w in p.placed)
    return tuple(Listener(role, port, "tcp", purpose, peers, "kubernetes")
                 for role, port, purpose, peers in pod_ports if role in roles)


def split_image(ref):
    """An image reference as (name, tag or None, digest or None); a registry's port is part of the name."""
    rest, _, digest = ref.partition("@")
    slash = rest.rfind("/")
    name, _, tag = rest[slash + 1:].partition(":")
    return rest[:slash + 1] + name, tag or None, digest or None


def chart_image(ref):
    """(repository, tag) for a chart that writes its image as "<repository>:<tag>": a digest as repository
    <name>[:<tag>]@sha256, tag <hex>, which that join turns back into the reference; no tag is latest."""
    name, tag, digest = split_image(ref)
    if digest:
        algorithm, _, hex_digest = digest.partition(":")
        return f"{name}{':' + tag if tag else ''}@{algorithm}", hex_digest
    return name, tag or "latest"


def replicas_of(m, w):
    """The replicas a workload's binding records, or None."""
    b = workload_binding(m, w) if w is not None else None
    return int(one(b, "ciamWorkloadReplicas")) if b is not None and one(b, "ciamWorkloadReplicas") else None


def resources_of(m, w):
    """A workload's container resources from its binding: {requests: {cpu, memory}, limits: {...}}, with only what
    the record holds ({} when nothing)."""
    b = workload_binding(m, w) if w is not None else None
    pick = lambda pairs: {k: one(b, a) for k, a in pairs if b is not None and one(b, a)}
    found = {"requests": pick((("cpu", "ciamCpuRequest"), ("memory", "ciamMemoryRequest"))),
             "limits": pick((("cpu", "ciamCpuLimit"), ("memory", "ciamMemoryLimit")))}
    return {k: v for k, v in found.items() if v}


def storage_of(m, w):
    """(volume size, storage class) a workload's binding records, each None when it doesn't."""
    b = workload_binding(m, w) if w is not None else None
    return (one(b, "ciamStorageSize"), one(b, "ciamStorageClass")) if b is not None else (None, None)


def pod_labels_of(m, services, w):
    """The labels a workload's pods carry: opsdir.io/role (what the network policies select) and the pod labels its
    cloud's workload identity needs (Services.workload_identity for its identity binding)."""
    b = identity_binding(m, w)
    identity = services.workload_identity(m, b) if b is not None else None
    return {ROLE_LABEL: one(w, "ciamTargetRole"), **dict(identity.pod_labels if identity else ())}


def workload_marks(w):
    """The marks a kit sets on a workload it deploys, so it reads back as the record's (whatever the kit names the
    object): {opsdir.io/cluster-role, opsdir.io/workload-role, opsdir.io/identity-role (when it has one),
    opsdir.io/workload: the record's values}."""
    found = ((CLUSTER_ROLE, one(w, "ciamClusterRole")), (WORKLOAD_ROLE, one(w, "ciamWorkloadRole")),
             (IDENTITY_ROLE, one(w, "ciamIdentityRole")), (WORKLOAD_NAME, rdn_value(w)))
    return {k: v for k, v in found if v}


def image_of_mark(m, ws, container):
    """The mark of a kit's companion pod (no workload of its own) whose image the record keeps under this container
    name in a workload's binding: {opsdir.io/image-of: <workload>/<container>} for the first of workloads ws whose
    binding records it, {} when none does."""
    home = next((w for w in ws if container in dict(container_images(workload_binding(m, w)))), None)
    return {IMAGE_OF: f"{rdn_value(home)}/{container}"} if home is not None else {}
