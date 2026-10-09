"""ForgeOps Kustomize overlay (render target kustomize): per namespace, forgeops/kustomize/overlay/<namespace>/ in
ForgeOps' own overlay layout (a folder per component over ../../../base/<component>), so it is copied into a ForgeOps
checkout's kustomize/overlay/ at the pinned release and built there. Pure.

The bases are the secret-generator ones with no generator: no Secret comes from the overlay (the keystore-create job
makes the AM/IDM keystore; the rest come from the record, opsdir-adapter-kubernetes, or the operator). Each component
sets its image (never ForgeOps' public ones, which are for development and testing only), labels its pod templates
with opsdir.io/role and its cloud's workload identity labels (not its selectors), and patches what the record holds:
replicas, the workload's service account, container resources, DS storage, the ingress host (ForgeOps' own overlay
patches the same paths), and IDM's DS host and port when DS runs on servers. The overlay sets the bases' tooling
images (busybox, kubectl) to the chart's defaults at the release. base/ patches platform-config: the platform's host
and the DS AM uses for its stores.
"""
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir_adapter_kubernetes.kits import split_image
from opsdir_adapter_kubernetes.render import service_account_of
from .components import ds_servers, idm_ds_env, image_of, ingress_hosts, pod_labels, replicas, resources, storage, \
    workload_of
from .release import COMPONENTS, IDENTITY_PLATFORM, KUSTOMIZE, TOOLING_IMAGES, VERSION

KUSTOMIZATION = {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization"}
INGRESS = {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"}


def kustomize_image(name, ref):
    """A Kustomize images entry setting a base image name to a reference (newName, newTag and/or digest)."""
    new_name, tag, digest = split_image(ref)
    return {"name": name, "newName": new_name, **({"newTag": tag} if tag else {}),
            **({"digest": digest} if digest else {})}


def _host(p, c):
    return (ingress_hosts(p, ("ig",), "ig") if c.chart != IDENTITY_PLATFORM
            else ingress_hosts(p, ("am", "idm"), "forgeops"))[0]


def platform_config(m, p):
    """The platform-config ConfigMap patch: the platform's host and the DS AM uses for its stores."""
    host = ingress_hosts(p, ("am", "idm"), "forgeops")[0]
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "platform-config"},
            "data": {"FQDN": host, "AM_SERVER_FQDN": host,
                     "AM_STORES_CTS_SERVERS": ",".join(ds_servers(m, p, "ds-cts")),
                     "AM_STORES_USER_SERVERS": ",".join(ds_servers(m, p, "ds-idrepo"))}}


def _workload_patch(m, p, c):
    w = workload_of(p, c.name)
    n, r = replicas(m, p, c.name), resources(m, p, c.name)
    env = idm_ds_env(m, p) if c.name == "idm" else []
    if w is None or c.container is None:
        return None
    container = {**({"resources": r} if r else {}), **({"env": env} if env else {})}
    pod = {"serviceAccountName": service_account_of(w),
           **({"containers": [{"name": c.container, **container}]} if container else {})}
    return {"apiVersion": "apps/v1", "kind": c.kind, "metadata": {"name": c.name},
            "spec": {**({"replicas": n} if n is not None else {}), "template": {"spec": pod}}}


def _storage_ops(m, p, c):
    size, storage_class = storage(m, p, c.name) if c.kind == "StatefulSet" else (None, None)
    at = "/spec/volumeClaimTemplates/0/spec"
    return [*([{"op": "add", "path": f"{at}/resources/requests/storage", "value": size}] if size else []),
            *([{"op": "add", "path": f"{at}/storageClassName", "value": storage_class}] if storage_class else [])]


def component_kustomization(m, services, p, c):
    """One component's overlay kustomization: its base, image, pod-template labels, and patches for what the record
    holds."""
    workload, ops = _workload_patch(m, p, c), _storage_ops(m, p, c)
    host = _host(p, c)
    patches = [*([{"patch": dump(workload)}] if workload else []),
               *([{"target": {"kind": c.kind, "name": c.name}, "patch": dump(ops)}] if ops else []),
               *([{"target": {**INGRESS, "name": c.name},
                   "patch": dump([{"op": "replace", "path": "/spec/rules/0/host", "value": host},
                                  {"op": "replace", "path": "/spec/tls/0/hosts", "value": [host]}])}]
                 if c.ingress else [])]
    labels = pod_labels(m, services, p, c.name)
    return {**KUSTOMIZATION, "resources": [f"../../../base/{c.base}"],
            "images": [kustomize_image(c.image, image_of(m, p, c.name))],
            **({"labels": [{"pairs": labels, "includeSelectors": False, "includeTemplates": True}]} if labels else {}),
            **({"patches": patches} if patches else {})}


def kustomize_files(m, services, p):
    """{path: text}: the overlay forgeops/kustomize/overlay/<namespace>/: its kustomization, base/ and a folder per
    component on."""
    root = f"forgeops/{KUSTOMIZE}/overlay/{p.namespace}"
    on = [c for c in COMPONENTS if c.name in p.on]
    text = lambda what, value: header(m, f"ForgeOps {VERSION} overlay, {what}", YAML) + dump(value)
    return {f"{root}/kustomization.yaml": text(
                f"namespace {p.namespace}: copy this folder into a ForgeOps {VERSION} checkout's kustomize/overlay/",
                {**KUSTOMIZATION, "namespace": p.namespace, "resources": ["./base", *(f"./{c.name}" for c in on)],
                 "images": [kustomize_image(name, ref) for name, ref in TOOLING_IMAGES]}),
            f"{root}/base/kustomization.yaml": text("the platform configuration",
                                                    {**KUSTOMIZATION, "resources": ["../../../base/platform"],
                                                     "patches": [{"path": "platform-config.yaml"}]}),
            f"{root}/base/platform-config.yaml": text("the platform configuration", platform_config(m, p)),
            **{f"{root}/{c.name}/kustomization.yaml": text(c.name, component_kustomization(m, services, p, c))
               for c in on}}
