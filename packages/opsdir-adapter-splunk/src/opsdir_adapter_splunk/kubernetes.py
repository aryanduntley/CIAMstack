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

READER gets the cloud's workload identity the way a deployment kit's workloads do (task 595). The operator records the
collector as a ciamWorkload placed in the cluster (ciamClusterRole), in NAMESPACE, run as READER (ciamServiceAccount),
assuming an identity role (ciamIdentityRole) each environment binds, with no ciamWorkloadRole (the chart runs it, not
a deployment kit), and a workload principal acting as that identity role permits reading the index's credential
(read-secret <its ciamCredentialRole>). The access domain then has the cloud trust READER through the cluster's OIDC
issuer (workload_identities: its pods) and grant it the read, and READER carries the annotations of the cloud
adapter's K8sIdentity for the identity binding (Services.workload_identity: IRSA's role ARN, the Entra managed
identity's client and tenant ids, GKE's Google service account), which each SecretStore provider reads through its
serviceAccountRef. No pod runs as READER, so the identity's pod labels don't apply; an annotation the record leaves
UNBOUND isn't rendered (READER then has none, and the action says why).

What a person does is a note: apply the External Secrets file and install the chart with the values once READER can
read the reference (the permit its identity role lacks; without a recorded identity, one given by hand, or the store's
Kubernetes auth role, with the exact entries that would record the collector's workload when none is); without a
delivering adapter or a complete store, fill the Secret from the reference by hand or another way. What can't be
rendered is a blocker: the index without an intake URL or credential, or one cluster's routes shipping to more than one
index (the chart sends a cluster's containers to one index unless pods or namespaces carry splunk.com/index
annotations).
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND, one_role
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import documents, dump as yaml_dump
from opsdir.core.manifest import header
from opsdir.core.notes import note
from opsdir.domains.access.principals import permits, principals
from opsdir.domains.compute.naming import workload_dn
from opsdir.domains.compute.workloads import (namespace_of, role_clusters, role_namespaces, runs_on_kubernetes,
                                              service_account_of, workloads)
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
COLLECTOR = "splunk-otel-collector"                 # the name and server role proposed for the collector's workload


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


def collector_workload(m, cluster):
    """The workload recording the collector's token reader in a cluster (binding): run on Kubernetes there, in
    NAMESPACE, as READER; None when the record holds none."""
    def placed(w):
        c = one_role(m, one(w, "ciamClusterRole")) if one(w, "ciamClusterRole") else None
        return c is not None and c.dn == cluster.dn
    return next((w for w in workloads(m.d) if namespace_of(w) == NAMESPACE and service_account_of(w) == READER
                 and runs_on_kubernetes(m, w) and placed(w)), None)


def reader_identity(m, services, cluster):
    """(collector workload, {annotation: value} READER carries for the cloud's workload identity, None) in a cluster;
    (the workload or None, None, why not) when none is recorded there (collector_workload), it assumes no identity
    role this environment binds, no installed adapter gives the cloud's workload identity, or the record leaves one
    of its values UNBOUND."""
    w = collector_workload(m, cluster)
    if w is None:
        return None, None, (f"no workload records it (namespace {NAMESPACE}, service account {READER}, cluster role "
                            f"{one(cluster, 'ciamBindingRole')})")
    role = one(w, "ciamIdentityRole")
    b = one_role(m, role) if role else None
    if b is None:
        return w, None, (f"workload {rdn_value(w)} assumes identity role {role}, which this environment doesn't bind"
                         if role else f"workload {rdn_value(w)} assumes no identity (ciamIdentityRole)")
    identity = services.workload_identity(m, b) if services is not None else None
    if identity is None or not identity.annotations:
        return w, None, "no installed adapter gives this environment's cloud workload identity"
    annotations = dict(identity.annotations)
    if _unbound(annotations):
        return w, None, f"the record doesn't give identity role {role}'s {', '.join(_unbound(annotations))}"
    return w, annotations, None


def reads_credential(m, identity_role, index):
    """Whether a workload principal acting as an identity role (with a server role, so the cloud renders its
    identity) holds the permit to read a Splunk index's credential: read-secret <its ciamCredentialRole>."""
    permit = f"read-secret {one(index, 'ciamCredentialRole')}"
    return any(permit in permits(m.d, p) for p in principals(m.d) if one(p, "ciamPrincipalKind") == "workload"
               and one(p, "ciamIdentityRole") == identity_role and one(p, "ciamTargetRole"))


def token_documents(provider, remote_ref, annotations=None):
    """The External Secrets objects filling the chart's Secret in NAMESPACE: the namespace, READER (with the cloud
    workload identity's annotations, when given), a SecretStore with the provider, an ExternalSecret writing the token
    to SECRET_KEY of SECRET_NAME."""
    meta = {"name": SECRET_NAME, "namespace": NAMESPACE}
    return [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
                "name": READER, "namespace": NAMESPACE, **({"annotations": annotations} if annotations else {})}},
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
    the External Secrets objects filling its Secret where the token can be delivered (token_delivery), READER with
    the cloud workload identity of the collector's workload where the record gives it (reader_identity)."""
    def of(c, xs):
        provider, remote_ref, _ = token_delivery(m, services, xs[0].destination, c)
        annotations = reader_identity(m, services, c)[1]
        values = header(m, f"Splunk OpenTelemetry Collector values ({CHART} {CHART_VERSION}, cluster {rdn_value(c)})",
                        YAML) + yaml_dump(collector_values(m, c, xs))
        return ((values_path(c), values),
                *(((secrets_path(c), header(m, f"Splunk OpenTelemetry Collector HEC token Secret through the External "
                                               f"Secrets Operator (cluster {rdn_value(c)})", YAML)
                    + documents(token_documents(provider, remote_ref, annotations))),) if provider is not None
                   else ()))
    return dict(x for c, xs in cluster_shipments(m, found) if not lacking(m, xs) for x in of(c, xs))


def _install(c):
    return (f"helm upgrade --install {CHART} {CHART} --repo {REPOSITORY} --version {CHART_VERSION} "
            f"--namespace {NAMESPACE} --create-namespace -f {values_path(c)}")


def _held(ref):
    """What an External Secrets-read secret must hold, in words, when its scheme reads one JSON key of it."""
    prop = TOKEN_PROPERTIES.get(split_ref(ref)[0])
    return f": the secret holds {{\"{prop}\": ...}}" if prop else ""


def proposed_workload(c, index):
    """The steps recording the collector's token reader in cluster (binding) c as a workload with the cloud's workload
    identity, reading a Splunk index's credential: the exact entries, in words."""
    return (f"Or record the collector as a workload, so the cloud's workload identity reaches {READER}: "
            f"{workload_dn(COLLECTOR)} (objectClass ciamWorkload; ciamWorkloadKind daemonset, ciamTargetRole "
            f"{COLLECTOR}, ciamNamespace {NAMESPACE}, ciamServiceAccount {READER}, ciamClusterRole "
            f"{one(c, 'ciamBindingRole')}, ciamIdentityRole <an identity role>; no ciamWorkloadRole: the chart runs "
            "it, not a deployment kit)",
            f"With it, a ciamPrincipal of ciamPrincipalKind workload (ciamTargetRole {COLLECTOR}, the same "
            f"ciamIdentityRole) holding a permission set that permits read-secret {one(index, 'ciamCredentialRole')}, "
            "and each environment's ciamIdentityBinding of that identity role")


def _reader(m, services, c, index, ref):
    """(what the install action says of READER's identity, its steps for it): the collector workload's cloud identity
    READER carries (a step granting its identity role the credential's permit when no workload principal holds it),
    else why it carries none and a step giving it one, with the entries recording the workload when none is."""
    w, annotations, why = reader_identity(m, services, c)
    if annotations:
        role = one(w, "ciamIdentityRole")
        return (f"; {READER} carries identity role {role}'s cloud workload identity (workload {rdn_value(w)})",
                () if reads_credential(m, role, index) else (
                    f"Let identity role {role} read {ref}: a permission set permitting read-secret "
                    f"{one(index, 'ciamCredentialRole')}, held by a workload principal acting as it (ciamIdentityRole "
                    f"{role}, a ciamTargetRole), so the cloud grants it",))
    return (f"; {READER} has no cloud workload identity from the record ({why})",
            (f"Give service account {READER} (namespace {NAMESPACE}) an identity that can read {ref}: the cloud's "
             "workload identity, or the secret store's Kubernetes auth role",
             *(proposed_workload(c, index) if w is None else ())))


def collector_notes(m, found, services):
    """Per cluster: a blocker naming what is missing, else the action to install the chart after its Secret is
    filled (through the rendered ExternalSecret, READER carrying the collector workload's cloud identity or told how
    to get one: _reader; or by hand when token_delivery can't); and a note that a role's containers are shipped
    together (all containers in its namespaces)."""
    def of(c, xs):
        index = xs[0].destination
        if lacking(m, xs):
            return (note("Logs", "blocker", f"cluster {rdn_value(c)}",
                         f"containers' output not shipped to Splunk: it needs {'; '.join(lacking(m, xs))}",
                         ("Record what is missing, or route the containers' output to a destination the cluster's "
                          "cloud collects",), c.dn, m.label),)
        ref, (provider, _, why) = _reference(m, index), token_delivery(m, services, index, c)
        said, steps = _reader(m, services, c, index, ref) if provider is not None else ("", ())
        install = (note("Logs", "action", f"cluster {rdn_value(c)}",
                        f"install {CHART} {CHART_VERSION} in namespace {NAMESPACE} with {values_path(c)}, after the "
                        f"External Secrets Operator fills Secret {SECRET_NAME} (key {SECRET_KEY}) with the HEC token "
                        f"{ref} references ({secrets_path(c)}{_held(ref)}){said}",
                        (*steps,
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
