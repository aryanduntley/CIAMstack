"""Container output on Kubernetes shipped to a Splunk index (milestone 109, decision 3301; research m109b): the Splunk
OpenTelemetry Collector chart's values per cluster. Pure.

Per cluster running a role whose containers a route ships to a Splunk index, kubernetes/splunk-otel-collector/
<cluster>-values.yaml for chart splunk-otel-collector (CHART_VERSION): the cluster's name and distribution (EKS, AKS,
GKE by the cloud's provider), the index's HTTP Event Collector (its ciamIntakeUrl, /services/collector/event), the
index, logs only (no metrics, traces or cluster receiver), container logs with a filter keeping the routed roles'
namespaces only (the chart parses each record's namespace from its log file's path: resource k8s.namespace.name), and
the HEC token from an existing Secret (SECRET_NAME, key splunk_platform_hec_token: secret.create false), never in the
values. Checked with helm template and the chart's values schema (0.162.1).

What a person does is a note: install the chart with the values, and fill the Secret from the reference the index's
ciamCredentialRole names (External Secrets, the Secrets Store CSI driver, or by hand). What can't be rendered is a
blocker: the index without an intake URL or credential, or one cluster's routes shipping to more than one index (the
chart sends a cluster's containers to one index unless pods or namespaces carry splunk.com/index annotations).
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump as yaml_dump
from opsdir.core.manifest import header
from opsdir.core.notes import note
from opsdir.domains.compute.workloads import role_clusters, role_namespaces
from .naming import index_name

CHART, CHART_VERSION = "splunk-otel-collector", "0.162.1"
REPOSITORY = "https://signalfx.github.io/splunk-otel-collector-chart"
SECRET_NAME, SECRET_KEY = "splunk-otel-collector-hec", "splunk_platform_hec_token"
DISTRIBUTIONS = {"aws": "eks", "azure": "aks", "gcp": "gke"}         # the chart's distribution by cloud provider
EVENT_PATH = "/services/collector/event"


def values_path(cluster):
    return f"kubernetes/splunk-otel-collector/{rdn_value(cluster)}-values.yaml"


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


def render_collectors(m, found):
    """{path: values YAML} per cluster whose container shipments to a Splunk index can be rendered."""
    return {values_path(c): header(m, f"Splunk OpenTelemetry Collector values ({CHART} {CHART_VERSION}, cluster "
                                      f"{rdn_value(c)})", YAML) + yaml_dump(collector_values(m, c, xs))
            for c, xs in cluster_shipments(m, found) if not lacking(m, xs)}


def collector_notes(m, found):
    """Per cluster: a blocker naming what is missing, else the actions to install the chart and fill its Secret; and
    a note that a role's containers are shipped together (all containers in its namespaces)."""
    def of(c, xs):
        index = xs[0].destination
        if lacking(m, xs):
            return (note("Logs", "blocker", f"cluster {rdn_value(c)}",
                         f"containers' output not shipped to Splunk: it needs {'; '.join(lacking(m, xs))}",
                         ("Record what is missing, or route the containers' output to a destination the cluster's "
                          "cloud collects",), c.dn, m.label),)
        secret = one_role(m, one(index, "ciamCredentialRole"))
        return (note("Logs", "action", f"cluster {rdn_value(c)}",
                     f"install {CHART} {CHART_VERSION} with {values_path(c)}, after Secret {SECRET_NAME} (key "
                     f"{SECRET_KEY}) holds the HEC token {one(secret, 'ciamRefUri')} references",
                     (f"helm upgrade --install {CHART} {CHART} --repo {REPOSITORY} --version {CHART_VERSION} "
                      f"-f {values_path(c)} in the collector's namespace",
                      "Fill the Secret from the reference (External Secrets, the Secrets Store CSI driver, or by "
                      "hand): its value never enters a render"), c.dn, m.label),
                note("Logs", "note", f"cluster {rdn_value(c)}",
                     "every container of the routed roles' namespaces is shipped (the chart filters by namespace), "
                     "sidecars included", (), c.dn, m.label))
    return tuple(n for c, xs in cluster_shipments(m, found) for n in of(c, xs))
