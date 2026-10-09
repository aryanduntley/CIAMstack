"""What a deployment kit (ForgeOps, ping-devops) reads from a workload and its workload binding: the images its
containers run, replicas, cpu and memory, storage, and the labels its pods carry. Shared by the kit adapters, which
set them in their own charts' and bases' terms. Pure.

What the record doesn't hold is None or left out, so the kit's own default stays.
"""
from opsdir.core.directory import one, values
from opsdir.domains.compute.workloads import workload_binding
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
