"""What an environment runs with ForgeOps, from the record. Pure.

A workload the environment runs on Kubernetes (it binds the workload's ciamWorkloadRole) is ForgeOps' when its role is
one ForgeOps deploys: am, idm and ig by role, ds by the workload's name (ForgeOps' ds-idrepo or ds-cts, the names the
kubernetes importer gives workloads read from ForgeOps' manifests). Per namespace, a placement: those workloads, and
every component that is on: amster with AM, ds-set-passwords with an in-cluster DS, keystore-create with AM or IDM,
the platform UIs with AM and IDM both.

What each component runs comes from its workload binding: images (ciamContainerImage container=image, by the
component's container names), replicas, cpu and memory, DS storage. What the record doesn't hold stays the chart's or
base's default, except images: ForgeOps' own are for development and testing only, so an image the record doesn't
name is UNBOUND:forgeops-<component>-image.
"""
from collections import namedtuple

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, one_role
from opsdir.domains.infrastructure.external import role_hosts
from opsdir_adapter_kubernetes.kits import image_named, only_image, pod_labels_of, replicas_of, resources_of, storage_of
from opsdir_adapter_kubernetes.render import ROLE_LABEL, namespace_of, on_kubernetes, service_account_of
from .release import COMPANION_ROLES, COMPONENTS, DS_LDAPS_PORT, ROLE_COMPONENTS, UIS, component

DS_SERVICE_ROLE = "ds-ldaps-service"
DS_STORES = ("ds-idrepo", "ds-cts")

# One namespace's ForgeOps: placed ((component name, workload), ...), on (component names, in release order).
Placement = namedtuple("Placement", ("namespace", "placed", "on"))


def components_of(w):
    """The ForgeOps components a workload runs as: by its role (am, idm, ig), a ds workload by its name (ds-idrepo,
    ds-cts); () when ForgeOps doesn't run it."""
    found = ROLE_COMPONENTS.get(one(w, "ciamTargetRole"), ())
    return tuple(c for c in found if len(found) == 1 or c == rdn_value(w))


def unplaced(m):
    """Workloads environment m runs on Kubernetes whose role ForgeOps serves but which it can't place (a ds workload
    not named ds-idrepo or ds-cts)."""
    return tuple(w for w in on_kubernetes(m) if one(w, "ciamTargetRole") in ROLE_COMPONENTS and not components_of(w))


def _with_companions(names):
    on = set(names)
    on |= {"amster"} if "am" in on else set()
    on |= {"ds-set-passwords"} if on & set(DS_STORES) else set()
    on |= {"keystore-create"} if on & {"am", "idm"} else set()
    on |= set(UIS) if {"am", "idm"} <= on else set()
    return tuple(c.name for c in COMPONENTS if c.name in on)


def placements(m):
    """Per namespace (in the order workloads name them), the workloads environment m runs with ForgeOps and every
    component that is on."""
    placed = [(namespace_of(w), c, w) for w in on_kubernetes(m) for c in components_of(w)]
    spaces = dict.fromkeys(ns for ns, _, _ in placed)
    return tuple(Placement(ns, tuple((c, w) for n, c, w in placed if n == ns),
                           _with_companions(c for n, c, _ in placed if n == ns)) for ns in spaces)


def workload_of(p, name):
    """The workload a placement runs as a component, or None (a component that comes with others)."""
    return next((w for c, w in p.placed if c == name), None)


def image_of(m, p, name):
    """The image a component runs: the first of its container names the placement's workload bindings name (its own
    workload's first), else its own workload's only image, else UNBOUND:forgeops-<component>-image."""
    own = workload_of(p, name)
    ws = [*([own] if own is not None else []), *(w for _, w in p.placed)]
    found = image_named(m, ws, component(name).containers) or (only_image(m, own) if own is not None else None)
    return found or f"{UNBOUND}forgeops-{name}-image"


def replicas(m, p, name):
    """The replicas a component's workload binding records, or None."""
    return replicas_of(m, workload_of(p, name))


def resources(m, p, name):
    """A component's container resources from its workload binding, with only what the record holds."""
    return resources_of(m, workload_of(p, name))


def storage(m, p, name):
    """A DS component's volume size and storage class from its workload binding (None for what it doesn't record)."""
    return storage_of(m, workload_of(p, name))


def ds_servers(m, p, name):
    """host:port of a DS store (ds-idrepo or ds-cts): its pods when it runs here (ForgeOps' service names), else the
    environment's ds-ldaps-service (its port, else LDAPS 1636), else UNBOUND:ds-ldaps-service."""
    if name in p.on:
        return [f"{name}-{i}.{name}:{DS_LDAPS_PORT}" for i in range(replicas(m, p, name) or 1)]
    service = one_role(m, DS_SERVICE_ROLE)
    return list(role_hosts(m, DS_SERVICE_ROLE, (one(service, "ciamPort") if service is not None else None)
                           or DS_LDAPS_PORT))


def external_ds(p):
    """Whether AM runs here with a DS store that doesn't: the platform uses DS on servers."""
    return "am" in p.on and not set(DS_STORES) <= set(p.on)


def ds_in_cluster(p):
    """Whether a DS store runs in the cluster here (ForgeOps then makes the DS certificates)."""
    return bool(set(DS_STORES) & set(p.on))


def split_ds(p):
    """(the DS store run in the cluster, the one on servers) when AM or IDM runs here with only one of ds-idrepo and
    ds-cts in the cluster, else None: ForgeOps then makes the DS certificates, so AM's and IDM's truststore holds
    only its own CA and not the one that signed the DS servers'."""
    inside = tuple(s for s in DS_STORES if s in p.on)
    return ((inside[0], next(s for s in DS_STORES if s not in inside))
            if len(inside) == 1 and {"am", "idm"} & set(p.on) else None)


def idm_ds_env(m, p):
    """[{name, value}, ...]: when IDM runs here and its repository's store (ds-idrepo) doesn't, the environment
    variables that point IDM's repository and its user store at the DS servers (its boot properties
    openidm.repo.host/port and userstore.host/port, which IDM reads from these): the first of ds-idrepo's servers.
    [] otherwise."""
    if "idm" not in p.on or "ds-idrepo" in p.on:
        return []
    host, _, port = ds_servers(m, p, "ds-idrepo")[0].rpartition(":")
    return [{"name": n, "value": v} for n, v in (("OPENIDM_REPO_HOST", host), ("OPENIDM_REPO_PORT", port),
                                                 ("USERSTORE_HOST", host), ("USERSTORE_PORT", port))]


def ingress_hosts(p, names, what):
    """The ingress hosts the workloads of these components record (ciamIngressHost), else
    [UNBOUND:<what>-ingress-host]."""
    found = dict.fromkeys(h for n in names for w in (workload_of(p, n),) if w is not None
                          for h in values(w, "ciamIngressHost"))
    return list(found) or [f"{UNBOUND}{what}-ingress-host"]


def pod_labels(m, services, p, name):
    """The labels a component's pods carry: opsdir.io/role (what the kubernetes adapter's network policies select)
    and the pod labels its cloud's workload identity needs; a component without a workload, the role it comes with
    (release.COMPANION_ROLES; {} for none)."""
    w = workload_of(p, name)
    lead = dict(COMPANION_ROLES).get(name)
    return pod_labels_of(m, services, w) if w is not None else {ROLE_LABEL: lead} if lead else {}


def on_in(p, chart):
    """The components of a chart that are on in a placement, in release order."""
    return tuple(c for c in COMPONENTS if c.chart == chart and c.name in p.on)


def service_account(p, chart):
    """The service account the placed workloads of a chart's components run as (the first's), or None."""
    return next((service_account_of(w) for c, w in p.placed for x in on_in(p, chart) if x.name == c), None)
