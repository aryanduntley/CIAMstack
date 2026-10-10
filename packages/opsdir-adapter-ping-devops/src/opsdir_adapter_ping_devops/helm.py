"""ping-devops Helm values: per namespace, ping-devops/helm/<namespace>/ping-devops-values.yaml for PingFederate's
admin and engine, for `helm upgrade --install` of the pinned chart. Pure.

Helm merges these values over the chart's own, so what the record doesn't hold stays the chart's default. Each
product on gets its image (repositoryFqn, so the record's registry is used as is), replicas, resources, the
workload's service account (made by the kubernetes adapter; the chart makes none), pod labels (opsdir.io/role and
the cloud's workload identity: pod templates only, the chart's selectors are its own), the Secret keys the workload
reads (environment variables by secretKeyRef; the license as a file), a volume when the binding records storage (a
StatefulSet, as the chart persists /opt/out), and an ingress for the hosts the workload records (none when a cluster
gateway fronts its role: routes.py declares its route), and a sidecar per log file the environment's log routes
pick (log_sidecars.py). The chart makes no Secret. The image's EULA setting
(PING_IDENTITY_ACCEPT_EULA=YES) is set for every product: accepting Ping's terms is the organization's, once, before it
deploys PingFederate, not a step of any deployment.
"""
from opsdir.core.directory import one, values
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir_adapter_kubernetes.kits import chart_image, pod_labels_of, replicas_of, resources_of, storage_of
from opsdir_adapter_kubernetes.render import service_account_of
from .discovery import recorded_query
from .log_sidecars import picked, product_logs, shared_logs
from .routes import gateway_fronted
from .products import image_of, placements, secret_keys, workload_of
from .release import CHART, DNS_QUERY, EULA, PRODUCTS, RELEASE, REPOSITORY, VERSION


def _container(m, w):
    n, r = replicas_of(m, w), resources_of(m, w)
    env = [{"name": k, "valueFrom": {"secretKeyRef": {"name": s, "key": k}}} for s, k, path in secret_keys(w)
           if path is None]
    return {**({"replicaCount": n} if n is not None else {}), **({"resources": r} if r else {}),
            **({"env": env} if env else {})}


def _secret_volumes(w):
    files = [(s, k, path) for s, k, path in secret_keys(w) if path is not None]
    return {s: {"items": {k: path for x, k, path in files if x == s}} for s in dict.fromkeys(s for s, _, _ in files)}


def _claim(m, w):
    size, storage_class = storage_of(m, w)
    return {**({"storageClassName": storage_class} if storage_class else {}),
            **({"resources": {"requests": {"storage": size}}} if size else {})}


def _workload(m, services, w):
    claim = _claim(m, w)
    stateful = {"type": "StatefulSet", "statefulSet": {"persistentvolume": {
        "enabled": True, "volumes": {"out-dir": {"persistentVolumeClaim": claim}}}}} if claim else {}
    return {"labels": pod_labels_of(m, services, w), **stateful}


def _logs(m, p, product):
    """(image, the log sidecars its role's routes pick, whether it is a StatefulSet) of a product run here, or None."""
    w = workload_of(p, product.name)
    if w is None:
        return None
    repository, tag = chart_image(image_of(m, p, product.name))
    return f"{repository}:{tag}", picked(m, product.role), bool(_claim(m, w))


def _ingress(m, w):
    """The chart's Ingress for the hosts a workload records; none behind a cluster gateway (routes.gateway_fronted),
    which serves its role's host instead."""
    hosts = () if gateway_fronted(m, one(w, "ciamTargetRole")) else values(w, "ciamIngressHost")
    return {"enabled": True,
            "hosts": [{"host": h, "paths": [{"path": "/", "pathType": "Prefix", "backend": {"serviceName": "https"}}]}
                      for h in hosts],
            "tls": [{"secretName": "_defaultTlsSecret_", "hosts": list(hosts)}]} if hosts else None


def product_values(m, services, p, product):
    """One product's values: enabled, and when a workload runs it its image, container (replicas, resources, Secret
    environment variables), service account, pod labels and storage, Secret files, ingress, log sidecars."""
    w = workload_of(p, product.name)
    if w is None:
        return {"enabled": False}
    repository, tag = chart_image(image_of(m, p, product.name))
    container, files, ingress = _container(m, w), _secret_volumes(w), _ingress(m, w)
    _, found, stateful = _logs(m, p, product)
    return {"enabled": True, "image": {"repositoryFqn": repository, "tag": tag},
            **({"container": container} if container else {}),
            "rbac": {"serviceAccountName": service_account_of(w)}, "workload": _workload(m, services, w),
            **({"secretVolumes": files} if files else {}), **({"ingress": ingress} if ingress else {}),
            **product_logs(found, stateful)}


def chart_values(m, services, p):
    """The chart's values for a placement: the image's EULA setting, the DNS name the nodes find each other through
    when the record's discovery binding gives one (DNS_PING; the chart's cluster service otherwise), PingFederate
    admin and engine (the chart's other products stay off), the log sidecars and the volume they share."""
    query = recorded_query(m)
    return {"global": {"envs": {EULA: "YES", **({DNS_QUERY: query} if query else {})}},
            **{x.name: product_values(m, services, p, x) for x in PRODUCTS},
            **shared_logs(tuple(found for found in (_logs(m, p, x) for x in PRODUCTS) if found))}


def install_command(namespace):
    """The command that installs a namespace's values."""
    return (f"helm upgrade --install {RELEASE} {CHART} --repo {REPOSITORY} --version {VERSION} --namespace {namespace} "
            f"-f <this file>")


def helm_files(m, services, p):
    """{path: text}: ping-devops/helm/<namespace>/ping-devops-values.yaml."""
    what = f"ping-devops {VERSION} Helm values: {install_command(p.namespace)}"
    return {f"{CHART}/helm/{p.namespace}/{CHART}-values.yaml":
            header(m, what, YAML) + dump(chart_values(m, services, p))}


def render(m, services):
    """Adapter render_env, {path: text}: per namespace, the chart's values."""
    return {path: text for p in placements(m) for path, text in helm_files(m, services, p).items()}
