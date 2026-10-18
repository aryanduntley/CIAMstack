"""Container output on Kubernetes shipped to a Splunk index (milestone 109, decision 3301; research m109b): the Splunk
OpenTelemetry Collector chart's values per cluster. Pure.

Per cluster running a role whose containers a route ships to a Splunk index, kubernetes/splunk-otel-collector/
<cluster>-values.yaml for chart splunk-otel-collector (CHART_VERSION): the cluster's name and distribution (EKS, AKS,
GKE by the cloud's provider), the index's HTTP Event Collector (its ciamIntakeUrl, /services/collector/event), the
index, logs only (no metrics, traces or cluster receiver), container logs with a filter keeping the routed roles'
namespaces only (the chart parses each record's namespace from its log file's path: resource k8s.namespace.name), and
the HEC token from an existing Secret (SECRET_NAME, key splunk_platform_hec_token: secret.create false), never in the
values. Checked with helm template and the chart's values schema (0.162.1).

The Secret is filled from the reference the index's ciamCredentialRole names, when an installed adapter delivers its
scheme to Kubernetes (Services.secret_delivery) and the record gives its store all it needs (no UNBOUND value):
kubernetes/splunk-otel-collector/<cluster>-externalsecrets.yaml, applied before the chart, holds the collector's
namespace (NAMESPACE), the service account the store is read as (READER), a SecretStore with the scheme's External
Secrets Operator provider, and an ExternalSecret writing the token to the chart's Secret and key. An aws-sm:// secret
holds {"hec_token": ...} (the form the AWS adapter's Firehose forwarding reads it in, so one secret serves both): its
remoteRef takes that property; the other schemes hold the token as the secret's value. No value enters a render.

What a person does is a note: give the reader account an identity that can read the reference (the cloud's workload
identity, or the store's Kubernetes auth role: the record names none for the collector), apply the External Secrets
file, install the chart with the values; without a delivering adapter or a complete store, fill the Secret from the
reference by hand or another way. What can't be rendered is a blocker: the index without an intake URL or credential,
or one cluster's routes shipping to more than one index (the chart sends a cluster's containers to one index unless
pods or namespaces carry splunk.com/index annotations).
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND, one_role
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import documents, dump as yaml_dump
from opsdir.core.manifest import header
from opsdir.core.notes import note
from opsdir.domains.compute.workloads import role_clusters, role_namespaces
from opsdir.domains.pki.credentials import secret_store, split_ref
from .naming import index_name

CHART, CHART_VERSION = "splunk-otel-collector", "0.162.1"
REPOSITORY = "https://signalfx.github.io/splunk-otel-collector-chart"
SECRET_NAME, SECRET_KEY = "splunk-otel-collector-hec", "splunk_platform_hec_token"
DISTRIBUTIONS = {"aws": "eks", "azure": "aks", "gcp": "gke"}         # the chart's distribution by cloud provider
EVENT_PATH = "/services/collector/event"
NAMESPACE = "splunk-otel-collector"                 # where the chart, its Secret and the token's ExternalSecret live
READER = "splunk-otel-collector-hec-reader"          # the service account the token's SecretStore reads the store as
TOKEN_PROPERTIES = {"aws-sm": "hec_token"}           # the JSON key a scheme's secret holds the token under, if any


def values_path(cluster):
    return f"kubernetes/splunk-otel-collector/{rdn_value(cluster)}-values.yaml"


def secrets_path(cluster):
    return f"kubernetes/splunk-otel-collector/{rdn_value(cluster)}-externalsecrets.yaml"


def cluster_shipments(m, found):
    """((cluster, (Shipment, ...)), ...): environment m's container Shipments to a Splunk index by the cluster their
    role runs in, in the record's order."""
    by = {}
    for x in found:
        if x.on == "kubernetes":
            for c in role_clusters(m, x.role):
                by.setdefault(c.dn, (c, []))[1].append(x)
    return tuple((c, tuple(xs)) for c, xs in by.values())


def hec_endpoint(index):
    """The HEC event endpoint of a Splunk index's intake URL (its base, /services/collector/event added when the URL
    names no collector path), or None."""
    url = (one(index, "ciamIntakeUrl") or "").rstrip("/")
    if not url.startswith("https://"):
        return None
    return url if "/services/collector" in url else url + EVENT_PATH


def lacking(m, xs):
    """What a cluster's shipments lack to be rendered, in words."""
    indexes = tuple(dict.fromkeys(x.destination.dn for x in xs))
    index = xs[0].destination
    secret = one_role(m, one(index, "ciamCredentialRole") or "")
    return tuple(why for why, missing in (
        (f"one index for the cluster (its routes ship to {', '.join(index_name(x.destination) for x in xs)})",
         len(indexes) > 1),
        (f"an intake URL on {rdn_value(index)} (ciamIntakeUrl, https)", hec_endpoint(index) is None),
        (f"a credential on {rdn_value(index)} (ciamCredentialRole naming a secret reference)",
         secret is None or not one(secret, "ciamRefUri"))) if missing)


def _reference(m, index):
    secret = one_role(m, one(index, "ciamCredentialRole") or "")
    return one(secret, "ciamRefUri") if secret is not None else None


def _unbound(value):
    if isinstance(value, dict):
        return tuple(x for v in value.values() for x in _unbound(v))
    if isinstance(value, (list, tuple)):
        return tuple(x for v in value for x in _unbound(v))
    return (value[len(UNBOUND):],) if isinstance(value, str) and value.startswith(UNBOUND) else ()


def token_delivery(m, services, index, cluster):
    """(SecretStore spec.provider, ExternalSecret remoteRef, None) reading a Splunk index's HEC token in a cluster,
    from the scheme owner's External Secrets provider as READER; (None, None, why not) when no installed adapter
    delivers the reference's scheme or the record leaves its store's values UNBOUND."""
    scheme, rest = split_ref(_reference(m, index))
    d = services.secret_delivery(scheme) if services is not None and scheme else None
    if d is None:
        return None, None, f"no installed adapter delivers {scheme or 'its'}:// references to Kubernetes"
    provider = d.eso_provider(m, secret_store(m, scheme), d.store_key(rest), READER, cluster)
    if _unbound(provider):
        return None, None, (f"the record doesn't give the {scheme} secret store's {', '.join(_unbound(provider))} "
                            f"(ciamSecretStore for {scheme})")
    prop = TOKEN_PROPERTIES.get(scheme)
    return provider, {**d.eso_ref(rest), **({"property": prop} if prop else {})}, None


def token_documents(provider, remote_ref):
    """The External Secrets objects filling the chart's Secret in NAMESPACE: the namespace, READER, a SecretStore
    with the provider, an ExternalSecret writing the token to SECRET_KEY of SECRET_NAME."""
    meta = {"name": SECRET_NAME, "namespace": NAMESPACE}
    return [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": READER, "namespace": NAMESPACE}},
            {"apiVersion": "external-secrets.io/v1", "kind": "SecretStore", "metadata": meta,
             "spec": {"provider": provider}},
            {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret", "metadata": meta,
             "spec": {"refreshInterval": "1h", "secretStoreRef": {"kind": "SecretStore", "name": SECRET_NAME},
                      "target": {"name": SECRET_NAME, "creationPolicy": "Owner"},
                      "data": [{"secretKey": SECRET_KEY, "remoteRef": remote_ref}]}}]


def collector_values(m, cluster, xs):
    """The chart's values for one cluster: the routed roles' namespaces' logs to the index, the token from a Secret."""
    index = xs[0].destination
    namespaces = role_namespaces(m, tuple(dict.fromkeys(x.role for x in xs)), cluster)
    keep = "[" + ", ".join(f'"{n}"' for n in namespaces) + "]"
    distribution = DISTRIBUTIONS.get(one(m.cloud, "ciamCloudProvider") or "")
    return {"clusterName": rdn_value(cluster), **({"distribution": distribution} if distribution else {}),
            "splunkPlatform": {"endpoint": hec_endpoint(index), "index": index_name(index), "logsEnabled": True,
                               "metricsEnabled": False, "tracesEnabled": False},
            "secret": {"create": False, "name": SECRET_NAME},
            "clusterReceiver": {"enabled": False},
            "logsCollection": {"containers": {"enabled": True, "excludeAgentLogs": True, "extraOperators": [
                {"type": "filter", "expr": f'resource["k8s.namespace.name"] not in {keep}'}]}}}


def render_collectors(m, found, services):
    """{path: YAML} per cluster whose container shipments to a Splunk index can be rendered: the chart's values, and
    the External Secrets objects filling its Secret where the token can be delivered (token_delivery)."""
    def of(c, xs):
        provider, remote_ref, _ = token_delivery(m, services, xs[0].destination, c)
        values = header(m, f"Splunk OpenTelemetry Collector values ({CHART} {CHART_VERSION}, cluster {rdn_value(c)})",
                        YAML) + yaml_dump(collector_values(m, c, xs))
        return ((values_path(c), values),
                *(((secrets_path(c), header(m, f"Splunk OpenTelemetry Collector HEC token Secret through the External "
                                               f"Secrets Operator (cluster {rdn_value(c)})", YAML)
                    + documents(token_documents(provider, remote_ref))),) if provider is not None else ()))
    return dict(x for c, xs in cluster_shipments(m, found) if not lacking(m, xs) for x in of(c, xs))


def _install(c):
    return (f"helm upgrade --install {CHART} {CHART} --repo {REPOSITORY} --version {CHART_VERSION} "
            f"--namespace {NAMESPACE} --create-namespace -f {values_path(c)}")


def _held(ref):
    """What an External Secrets-read secret must hold, in words, when its scheme reads one JSON key of it."""
    prop = TOKEN_PROPERTIES.get(split_ref(ref)[0])
    return f": the secret holds {{\"{prop}\": ...}}" if prop else ""


def collector_notes(m, found, services):
    """Per cluster: a blocker naming what is missing, else the action to install the chart after its Secret is
    filled (through the rendered ExternalSecret, or by hand when token_delivery can't); and a note that a role's
    containers are shipped together (all containers in its namespaces)."""
    def of(c, xs):
        index = xs[0].destination
        if lacking(m, xs):
            return (note("Logs", "blocker", f"cluster {rdn_value(c)}",
                         f"containers' output not shipped to Splunk: it needs {'; '.join(lacking(m, xs))}",
                         ("Record what is missing, or route the containers' output to a destination the cluster's "
                          "cloud collects",), c.dn, m.label),)
        ref, (provider, _, why) = _reference(m, index), token_delivery(m, services, index, c)
        install = (note("Logs", "action", f"cluster {rdn_value(c)}",
                        f"install {CHART} {CHART_VERSION} in namespace {NAMESPACE} with {values_path(c)}, after the "
                        f"External Secrets Operator fills Secret {SECRET_NAME} (key {SECRET_KEY}) with the HEC token "
                        f"{ref} references ({secrets_path(c)}{_held(ref)})",
                        (f"Give service account {READER} (namespace {NAMESPACE}) an identity that can read {ref}: "
                         "the cloud's workload identity, or the secret store's Kubernetes auth role",
                         f"kubectl apply -f {secrets_path(c)} (the External Secrets Operator runs in the cluster)",
                         _install(c)), c.dn, m.label)
                   if provider is not None else
                   note("Logs", "action", f"cluster {rdn_value(c)}",
                        f"install {CHART} {CHART_VERSION} in namespace {NAMESPACE} with {values_path(c)}, after "
                        f"Secret {SECRET_NAME} (key {SECRET_KEY}) holds the HEC token {ref} references (the render "
                        f"doesn't deliver it: {why})",
                        ("Fill the Secret from the reference (by hand or the Secrets Store CSI driver), or record "
                         "what External Secrets needs: its value never enters a render", _install(c)),
                        c.dn, m.label))
        return (install,
                note("Logs", "note", f"cluster {rdn_value(c)}",
                     "every container of the routed roles' namespaces is shipped (the chart filters by namespace), "
                     "sidecars included", (), c.dn, m.label))
    return tuple(n for c, xs in cluster_shipments(m, found) for n in of(c, xs))
