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
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, one_role, roles_for
from opsdir.core.profiles import SLOT_PREFIX
from opsdir.core.versions import holds
from opsdir.domains.compute.workloads import recorded_versions, workload_secrets
from opsdir.domains.infrastructure.external import role_hosts
from opsdir_adapter_kubernetes.kits import (Placement, image_named, image_of_mark, kit_image, pod_labels_of,
                                             replicas_of, resources_of, storage_of, workload_marks, workload_of)
from opsdir_adapter_kubernetes.names import CONTAINER_NAMES
from opsdir_adapter_kubernetes.render import ROLE_LABEL, namespace_of, on_kubernetes, service_account_of
from .release import (AMSTER_ENV_SECRET, COMPANION_IMAGES, COMPANION_PRODUCTS, COMPONENTS, CONFIG_INIT,
                      DS_LDAPS_PORT, IDM_ADMIN_UI, IDM_ADMIN_UI_VERSIONS, KEYSTORE_KEY, KEYSTORE_SECRET,
                      PRODUCT_COMPONENTS, PROFILE_BUILDS, UIS, component)

DS_STORES = ("ds-idrepo", "ds-cts")


def components_of(m, w):
    """The ForgeOps components a workload runs as: by its role, a server role of a product ForgeOps deploys
    (release.PRODUCT_COMPONENTS; the roles its adapter declares in environment m), a DS workload by its name
    (ds-idrepo, ds-cts); () when ForgeOps doesn't run it."""
    role = one(w, "ciamTargetRole")
    found = next((c for product, c in PRODUCT_COMPONENTS if role in roles_for(m, product, "server")), ())
    return tuple(c for c in found if len(found) == 1 or c == rdn_value(w))


def unplaced(m):
    """Workloads environment m runs on Kubernetes whose role ForgeOps serves but which it can't place (a ds workload
    not named ds-idrepo or ds-cts)."""
    served = {r for product, _ in PRODUCT_COMPONENTS for r in roles_for(m, product, "server")}
    return tuple(w for w in on_kubernetes(m) if one(w, "ciamTargetRole") in served and not components_of(m, w))


def idm_admin_ui(m, ws):
    """Whether IDM's administration UI pod is on among workloads ws: IDM runs 8.1 or later there (which no longer
    bundles it) and a workload binding names its image."""
    return holds(IDM_ADMIN_UI_VERSIONS, recorded_versions(m, "idm")) and \
        image_named(m, ws, component(IDM_ADMIN_UI).containers) is not None


def _with_companions(names, admin_ui=False):
    on = set(names)
    on |= {IDM_ADMIN_UI} if admin_ui and "idm" in on else set()
    on |= {"amster"} if "am" in on else set()
    on |= {"ds-set-passwords"} if on & set(DS_STORES) else set()
    on |= {"keystore-create"} if on & {"am", "idm"} else set()
    on |= set(UIS) if {"am", "idm"} <= on else set()
    return tuple(c.name for c in COMPONENTS if c.name in on)


def placements(m):
    """Per namespace (in the order workloads name them), the workloads environment m runs with ForgeOps and every
    component that is on, in release order (kubernetes kits.Placement)."""
    placed = [(namespace_of(w), c, w) for w in on_kubernetes(m) for c in components_of(m, w)]
    spaces = dict.fromkeys(ns for ns, _, _ in placed)
    return tuple(Placement(ns, tuple((c, w) for n, c, w in placed if n == ns),
                           _with_companions((c for n, c, _ in placed if n == ns),
                                            idm_admin_ui(m, [w for n, _, w in placed if n == ns])))
                 for ns in spaces)


def image_of(m, p, name):
    """The image a component runs (kubernetes kits.kit_image over its container names); UNBOUND:forgeops-<component>-
    image when the record names none."""
    return kit_image(m, p, name, component(name).containers, "forgeops")


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
    environment's DS service name (PingDS's service role, ds-ldaps-service: its port, else LDAPS 1636), else
    UNBOUND:<that role>."""
    if name in p.on:
        return [f"{name}-{i}.{name}:{DS_LDAPS_PORT}" for i in range(replicas(m, p, name) or 1)]
    role = next(iter(roles_for(m, "PingDS", "service")), "PingDS-service")
    service = one_role(m, role)
    return list(role_hosts(m, role, (one(service, "ciamPort") if service is not None else None) or DS_LDAPS_PORT))


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
    and the pod labels its cloud's workload identity needs; a component without a workload, the server role of the
    product it comes with (release.COMPANION_PRODUCTS; {} for none)."""
    w = workload_of(p, name)
    product = dict(COMPANION_PRODUCTS).get(name)
    lead = next(iter(roles_for(m, product, "server")), None) if product else None
    return pod_labels_of(m, services, w) if w is not None else {ROLE_LABEL: lead} if lead else {}


def pod_annotations(m, p, name, profiled=False):
    """The marks a component's pods carry so the deployment reads back as the record: its workload's (cluster role,
    workload role, name; with config profiles (profiled) and a configuration image the record names, opsdir.io/
    container-names giving its init container's image the record's container name: idm-custom=custom-vol-init), or a
    companion's opsdir.io/image-of naming the workload whose binding keeps its image (release.COMPANION_IMAGES); {}
    otherwise."""
    w = workload_of(p, name)
    custom = f"{name}-custom"
    if w is not None:
        configured = profiled and any(c == name and how == "config" for c, _, how, _ in PROFILE_BUILDS) \
            and image_named(m, [x for _, x in p.placed], (custom,))
        return {**workload_marks(w), **({CONTAINER_NAMES: f"{custom}={CONFIG_INIT}"} if configured else {})}
    return image_of_mark(m, [x for _, x in p.placed], component(name).containers[0]) if name in COMPANION_IMAGES \
        else {}


def on_in(p, chart):
    """The components of a chart that are on in a placement, in release order."""
    return tuple(c for c in COMPONENTS if c.chart == chart and c.name in p.on)


def service_account(p, chart):
    """The service account the placed workloads of a chart's components run as (the first's), or None."""
    return next((service_account_of(w) for c, w in p.placed for x in on_in(p, chart) if x.name == c), None)


def profile_env(p, name):
    """[{name, valueFrom}]: the profile secrets a component's workload records (ciamWorkloadSecret
    <secret>/OPSDIR_<ROLE> <- <role>, core.profiles.slot_env) as environment variables from their Secret keys, which
    its configuration tokens (&{opsdir.<role>}) read; [] for a component without a workload of its own."""
    w = workload_of(p, name)
    return [{"name": key, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}}
            for secret, key, _ in (workload_secrets(w) if w is not None else ()) if key.startswith(SLOT_PREFIX)]


def config_image(m, p, container):
    """The configuration image a component's config profile is built into: the image the placement's workload
    bindings name for that container (ciamContainerImage idm-custom=<ref>), else UNBOUND:forgeops-<container>-image."""
    return image_named(m, [w for _, w in p.placed], (container,)) or f"{UNBOUND}forgeops-{container}-image"


def slot_envs(m, p, name):
    """The profile secret variables (OPSDIR_*) the record delivers to a component in a placement: its workload's
    (profile_env); for amster, the keys of amster-env-secrets the namespace's workloads record (the job reads that
    Secret whole)."""
    if name == "amster":
        return {k for w in on_kubernetes(m) if namespace_of(w) == p.namespace for s, k, _ in workload_secrets(w)
                if s == AMSTER_ENV_SECRET and k.startswith(SLOT_PREFIX)}
    return {e["name"] for e in profile_env(p, name)}


def keystore_from_record(m, p):
    """Whether a workload in a placement's namespace maps the release's keystore Secret (ciamWorkloadSecret
    keystore/keystore.jceks <- <role>): the record's keystore, delivered by the kubernetes adapter, so the release
    generates none (the keystore-create job off)."""
    return any(s == KEYSTORE_SECRET and k == KEYSTORE_KEY for w in on_kubernetes(m) if namespace_of(w) == p.namespace
               for s, k, _ in workload_secrets(w))
