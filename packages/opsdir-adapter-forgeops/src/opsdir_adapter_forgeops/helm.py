"""ForgeOps Helm values (render target helm): per namespace, values for the identity-platform chart (AM, amster, IDM,
DS, the platform UIs) and the ping-gateway chart (IG), for `helm upgrade --install` from a ForgeOps checkout at the
pinned release. Pure.

Helm merges these values over the chart's own, so what the record doesn't hold stays the chart's default. The chart
makes no Secret (secret-agent configuration off, secrets_enabled with base_generate and no secrets: the layout the
Kustomize bases are generated in) and runs the keystore-create job (force) and the ssh-keygen job (amster's key pair);
every other Secret comes from the record (opsdir-adapter-kubernetes) or the operator. The chart runs every pod as one
service account: the placed workloads' (the kubernetes adapter makes it, create: false). Pod labels are part of the
chart's selectors, so a release first installed without them can't be upgraded to them in place.
"""
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir_adapter_kubernetes.kits import chart_image
from .routes import gateway_fronted
from .components import (ds_in_cluster, ds_servers, external_ds, idm_ds_env, image_of, ingress_hosts, on_in,
                         pod_labels, replicas, resources, service_account, storage)
from .release import COMPONENTS, HELM, IDENTITY_PLATFORM, PING_GATEWAY, VERSION


def helm_image(ref):
    """A chart image block {repository, tag} that the chart's "<repository>:<tag>" turns back into the reference (a
    digest as repository <name>[:<tag>]@sha256, tag <hex>)."""
    repository, tag = chart_image(ref)
    return {"repository": repository, "tag": tag}


def _volume_claim(size, storage_class):
    return {**({"storageClassName": storage_class} if storage_class else {}),
            **({"resources": {"requests": {"storage": size}}} if size else {})}


def component_values(m, services, p, c):
    """One component's values: enabled, and when on its image, replicas, resources, pod labels, (DS) volume claim
    from the record, and (IDM with DS on servers) the variables pointing it at them."""
    if c.name not in p.on:
        return {"enabled": False}
    n, r, labels = replicas(m, p, c.name), resources(m, p, c.name), pod_labels(m, services, p, c.name)
    claim = _volume_claim(*storage(m, p, c.name)) if c.kind == "StatefulSet" else {}
    env = idm_ds_env(m, p) if c.name == "idm" else []
    return {"enabled": True, c.helm_image: helm_image(image_of(m, p, c.name)),
            **({"replicaCount": n} if n is not None and c.kind != "Job" else {}),
            **({"resources": r} if r else {}), **({"podLabels": labels} if labels else {}),
            **({"volumeClaimSpec": claim} if claim else {}), **({"env": env} if env else {}),
            **({"force": True} if c.name == "keystore-create" else {})}


def _service_account(p, chart):
    sa = service_account(p, chart)
    return {"create": False, **({"name": sa} if sa else {})}


def identity_platform_values(m, services, p):
    """The identity-platform chart's values for a placement: the workloads' service account, no Secrets made by the
    chart, ingress hosts (Ingresses off behind a cluster gateway), DS on servers (external_ds; with no DS in the
    cluster, no self-signed DS certificates: the servers' CA comes from the record), each component."""
    platform = {"disable_secret_agent_config": True, "secrets_enabled": True, "base_generate": True, "secrets": {},
                **({} if ds_in_cluster(p) else {"ds_certs": {"enabled": False}}),
                "ingress": ({"enabled": False} if gateway_fronted(m, IDENTITY_PLATFORM) else
                            {"hosts": ingress_hosts(p, ("am", "idm"), "forgeops")})}
    if external_ds(p):
        platform["external_ds"] = {"enabled": True, "cts_hosts": ds_servers(m, p, "ds-cts"),
                                   "idrepo_hosts": ds_servers(m, p, "ds-idrepo")}
    return {"serviceAccount": _service_account(p, IDENTITY_PLATFORM), "platform": platform,
            **{c.values: component_values(m, services, p, c) for c in COMPONENTS if c.chart == IDENTITY_PLATFORM},
            "ssh_keygen": {"enabled": "am" in p.on}}


def ping_gateway_values(m, services, p):
    """The ping-gateway chart's values for a placement: service account, ingress hosts (off behind a cluster gateway),
    ig."""
    (ig,) = (c for c in COMPONENTS if c.chart == PING_GATEWAY)
    return {"serviceAccount": _service_account(p, PING_GATEWAY),
            "platform": {"ingress": ({"enabled": False} if gateway_fronted(m, PING_GATEWAY) else
                                     {"hosts": ingress_hosts(p, ("ig",), "ig")})},
            ig.values: component_values(m, services, p, ig)}


def helm_files(m, services, p):
    """{path: text}: forgeops/helm/<namespace>/<chart>-values.yaml for each chart with a component on."""
    charts = ((IDENTITY_PLATFORM, identity_platform_values), (PING_GATEWAY, ping_gateway_values))
    what = lambda chart: (f"ForgeOps {VERSION} Helm values, chart {chart}: helm upgrade --install {chart} "
                          f"<ForgeOps {VERSION} checkout>/charts/{chart} --namespace {p.namespace} -f <this file>")
    return {f"forgeops/{HELM}/{p.namespace}/{chart}-values.yaml":
            header(m, what(chart), YAML) + dump(values(m, services, p))
            for chart, values in charts if on_in(p, chart)}
