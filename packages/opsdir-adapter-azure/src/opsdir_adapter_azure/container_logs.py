"""Product logs from containers on AKS to Log Analytics (core observability: log routes; what each route ships:
domains/observability/sources), with Container insights' multitenant logging: per cluster and route, a data
collection rule of the ContainerLogV2Extension sending the namespaces its roles run in to the route's workspace,
transformed down to the route's lines. Terraform, and the agent's ConfigMap. Pure.

Per cluster: azurerm_monitor_data_collection_endpoint dce-ciam-<env>-<cluster> (kind Linux; high-scale logging ingests
through it). Per cluster and route: azurerm_monitor_data_collection_rule dcr-ciam-<env>-<route>-<cluster> (its
extension source ContainerLogV2Extension, stream Microsoft-ContainerLogV2-HighScale, settings
{"dataCollectionSettings": {"namespaces": [...]}}; the route's workspace) whose transformation keeps a line when it is
from a pod of one of the route's roles (its label opsdir.io/role, from the pod metadata: the deployment kits set it),
from the container of a source the route reads (a kit's log sidecar by name; the role's other containers for its
main source) and, when the route takes only some of a source's lines, of the route's kinds (kql.kept on the JSON in
LogMessage); and its association to the cluster (its ciamProviderRef). kubernetes/azure-monitor/<cluster>/
container-azm-ms-agentconfig.yaml: the agent's ConfigMap in kube-system turning on high-scale logging, multitenancy
and pod metadata (with labels). It replaces a ConfigMap of that name: merge it with one the cluster already has.
learn.microsoft.com/azure/azure-monitor/containers/container-insights-multitenant, .../container-insights-high-scale,
.../container-insights-logs-schema, aka.ms/aks-enable-monitoring-multitenancy-onboarding-template-file (research
notes 2352, 2354).

Named instead (# NOTE): a route whose destination here isn't a workspace, a role on Kubernetes in no cluster the
environment binds, more than 30 such rules on one cluster (Container insights' limit), and in Azure Government that
multitenant logging there is to be confirmed (no Government availability row names it).
"""
import json

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir.domains.compute.workloads import namespace_of, role_clusters, runs_on_kubernetes, workloads
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import ALL, kept_clauses, shipments
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .account import government, tagged
from .identities import LOC, RG
from .kql import field_of, kept, literal
from .observability import workspace_id

ENDPOINT, RULE, ASSOCIATION = ("azurerm_monitor_data_collection_endpoint", "azurerm_monitor_data_collection_rule",
                               "azurerm_monitor_data_collection_rule_association")
EXTENSION, STREAM = "ContainerLogV2Extension", "Microsoft-ContainerLogV2-HighScale"
ROLE_LABEL = "opsdir.io/role"
LIMIT = 30                                          # ContainerLogV2Extension rules per cluster
CONFIG_MAP = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": "container-azm-ms-agentconfig", "namespace": "kube-system"},
              "data": {"schema-version": "v1",
                       "agent-settings": "[agent_settings.high_log_scale]\n  enabled = true\n",
                       "log-data-collection-settings": (
                           "[log_collection_settings]\n"
                           "  [log_collection_settings.multi_tenancy]\n    enabled = true\n"
                           "    disable_fallback_ingestion = false\n"
                           "  [log_collection_settings.metadata_collection]\n    enabled = true\n"
                           '    include_fields = ["podLabels"]\n')}}


def container_shipments(m, services):
    """Environment m's container Shipments whose destination is a workspace here."""
    return tuple(x for x in shipments(m, log_routes(m.d), services.logs(m))
                 if x.on == "kubernetes" and workspace_id(m, x.destination) is not None)


def cluster_routes(m, services):
    """((cluster binding, route, (Shipment, ...)), ...): per cluster the routes' shipments of roles running in it."""
    found = container_shipments(m, services)

    def runs_in(x, c):
        return c.dn in {k.dn for k in role_clusters(m, x.role)}
    clusters = {c.dn: c for x in found for c in role_clusters(m, x.role)}.values()
    routes = {x.route.dn: x.route for x in found}.values()
    return tuple((c, r, xs) for c in clusters for r in routes
                 for xs in (tuple(x for x in found if x.route.dn == r.dn and runs_in(x, c)),) if xs)


def namespaces(m, cluster, roles):
    """The namespaces environment m runs these roles' workloads in, in a cluster."""
    return tuple(dict.fromkeys(namespace_of(w) for w in workloads(m.d)
                               if one(w, "ciamTargetRole") in roles and runs_on_kubernetes(m, w)
                               and cluster.dn in {c.dn for c in role_clusters(m, one(w, "ciamTargetRole"))}))


def _container(x, sources):
    if x.source.container:
        return f"ContainerName == {literal(x.source.container)}"
    others = [s.container for s in sources if s.server_role == x.role and s.on == "kubernetes" and s.container]
    return f"ContainerName !in ({', '.join(map(literal, others))})" if others else None


def line_filter(x, sources):
    """The KQL keeping a shipment's lines: its role's pods, its source's container, the route's kinds."""
    kinds = (None if x.lines == ALL
             else kept(kept_clauses(x.source, values(x.route, "ciamLogKind")), field_of("LogMessage")))
    parts = (f"tostring(KubernetesMetadata.podLabels[{literal(ROLE_LABEL)}]) == {literal(x.role)}",
             _container(x, sources), kinds and f"({kinds})")
    return " and ".join(p for p in parts if p)


def transform(found, sources):
    """A rule's transformation: the lines any of its shipments keeps."""
    return "source | where " + " or ".join(f"({line_filter(x, sources)})" for x in found)


def _endpoint(m, cluster):
    return block("resource", [ENDPOINT, tf_name(f"logs_{rdn_value(cluster)}")], [
        ("name", f"dce-ciam-{rdn_value(m.env)}-{rdn_value(cluster)}"), ("location", LOC), ("resource_group_name", RG),
        ("kind", "Linux"), ("tags", tagged(m, {"ManagedBy": "opsdir"}))])


def _settings(m, cluster, roles):
    """The extension's settings (JSON text): the namespaces the roles run in, in the cluster."""
    return json.dumps({"dataCollectionSettings": {"namespaces": list(namespaces(m, cluster, roles))}},
                      separators=(",", ":"))


def _rule(m, cluster, route, found, sources):
    n = tf_name(f"logs_{rdn_value(route)}_{rdn_value(cluster)}")
    roles = tuple(dict.fromkeys(x.role for x in found))
    return (block("resource", [RULE, n], [
                ("name", f"dcr-ciam-{rdn_value(m.env)}-{rdn_value(route)}-{rdn_value(cluster)}"), ("location", LOC),
                ("resource_group_name", RG),
                ("description", f"Log route {rdn_value(route)}: container logs of {', '.join(roles)} (opsdir)"),
                ("data_collection_endpoint_id", ref(f"{ENDPOINT}.{tf_name(f'logs_{rdn_value(cluster)}')}.id")),
                ("destinations", Block((("log_analytics", Block((
                    ("name", "workspace"), ("workspace_resource_id", workspace_id(m, found[0].destination))))),))),
                ("data_sources", Block((("extension", Block((
                    ("name", "ciam-containers"), ("extension_name", EXTENSION), ("streams", [STREAM]),
                    ("extension_json", _settings(m, cluster, roles))))),))),
                ("data_flow", Block((("streams", [STREAM]), ("destinations", ["workspace"]),
                                     ("transform_kql", transform(found, sources))))),
                ("tags", tagged(m, {"Realizes": rdn_value(route), "ManagedBy": "opsdir"}))]),
            block("resource", [ASSOCIATION, n], [
                ("name", f"{rdn_value(route)}-{rdn_value(cluster)}"),
                ("target_resource_id", one(cluster, "ciamProviderRef")),
                ("data_collection_rule_id", ref(f"{RULE}.{n}.id"))]))


def render_container_logs(m, services):
    """(HCL blocks, {path: text}) of environment m's container log routes: per cluster its endpoint, rules and
    associations, and the agent's ConfigMap."""
    found, sources = cluster_routes(m, services), services.logs(m)
    clusters = {c.dn: c for c, _, _ in found}.values()
    return ((*(_endpoint(m, c) for c in clusters),
             *(b for c, r, xs in found for b in _rule(m, c, r, xs, sources))),
            {f"kubernetes/azure-monitor/{rdn_value(c)}/container-azm-ms-agentconfig.yaml":
             header(m, "Container insights agent settings: high-scale logging, multitenancy, pod labels (merge with "
                       "an existing container-azm-ms-agentconfig)", YAML) + dump(CONFIG_MAP) for c in clusters})


def container_log_notes(m, services):
    """HCL comments naming the container output environment m's routes don't ship to Log Analytics, and what to
    confirm."""
    every = tuple(x for x in shipments(m, log_routes(m.d), services.logs(m)) if x.on == "kubernetes")
    rules = cluster_routes(m, services)
    per_cluster = {c.dn: (c, sum(1 for k, _, _ in rules if k.dn == c.dn)) for c, _, _ in rules}
    return tuple(dict.fromkeys((
        *(f"# NOTE: log route {rdn_value(x.route)}: role {x.role}'s container output not shipped: its destination "
          f"{rdn_value(x.destination)} isn't a Log Analytics workspace (kind workspace, a workspace ID)"
          for x in every if x.destination is not None and workspace_id(m, x.destination) is None),
        *(f"# NOTE: log route {rdn_value(x.route)}: role {x.role}'s container output not shipped: the role runs on "
          "Kubernetes here in no cluster the environment binds"
          for x in every if workspace_id(m, x.destination) is not None and not role_clusters(m, x.role)),
        *(f"# NOTE: cluster {rdn_value(c)}: {n} log routes need {n} multitenant logging rules; Container insights "
          f"takes {LIMIT} per cluster" for c, n in per_cluster.values() if n > LIMIT),
        *(("# NOTE: Azure Government: Container insights multitenant logging is to be confirmed there (no Government "
           "availability row names it)",) if rules and government(m) else ()))))
