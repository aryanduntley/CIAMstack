"""Product logs from containers on GKE to Cloud Logging buckets (core observability: log routes; what each route ships:
domains/observability/sources): GKE's workload logging writes every container's output to Cloud Logging (resource
type k8s_container, JSON lines parsed into jsonPayload), so a route's container logs are the part of its log sink
(log_sinks) that takes them: per cluster the environment runs a role's workloads in, entries of that cluster
(cluster_name, location), of the namespaces the role runs in there, from its pods (their label opsdir.io/role, set by
the deployment kits, as Cloud Logging writes pod labels: labels."k8s-pod/<key>"; Google's examples write a dotted
key both as is and with the dots as underscores, so both are matched), from its source's container (a kit's log
sidecar by name; the role's other containers for its main source) and, when the route takes only some of a source's
lines, of the route's kinds. Pure.
docs.cloud.google.com/kubernetes-engine/docs/concepts/about-logs, .../logging/docs/structured-logging,
.../logging/docs/view/query-library (research notes 2329, 2363).

Named instead (# NOTE): a role on Kubernetes in no cluster the environment binds, a cluster in another project (its
logs land there: a sink here doesn't see them), and that the clusters' workload logging (logging_config WORKLOADS,
GKE's default) must stay on.
"""
from opsdir.core.directory import rdn_value, values
from opsdir.domains.compute.workloads import role_clusters, role_namespaces
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import ALL, containers_of, kept_clauses, shipments
from .account import project_id
from .kubernetes import cluster_parts
from .logging_filter import all_of, any_of, field_of, kept, literal
from .observability import bucket_parts

ROLE_LABEL = "opsdir.io/role"
POD_LABELS = (f"k8s-pod/{ROLE_LABEL}", "k8s-pod/" + ROLE_LABEL.replace(".", "_"))
CONTAINER = "resource.labels.container_name"


def container_shipments(m, services):
    """Environment m's container Shipments whose destination is a Cloud Logging bucket here."""
    return tuple(x for x in shipments(m, log_routes(m.d), services.logs(m))
                 if x.on == "kubernetes" and bucket_parts(x.destination) is not None)


def visible_clusters(m, role):
    """The clusters environment m runs a role's workloads in whose logs land in its project (their provider ref
    names it, or no project)."""
    return tuple(c for c in role_clusters(m, role) if cluster_parts(c)[0] in (None, project_id(m)))


def _container(x, sources):
    own, others = containers_of(x, sources)
    if own:
        return f"{CONTAINER} = {literal(own)}"
    return all_of(*(f"{CONTAINER} != {literal(c)}" for c in others)) if others else None


def container_filter(m, x, sources):
    """The query taking a container Shipment's lines in the clusters of its project: per cluster its entries of the
    role's namespaces there, pods and container, and the route's kinds when it takes only some lines. None when no
    such cluster runs the role."""
    kinds = None if x.lines == ALL else kept(kept_clauses(x.source, values(x.route, "ciamLogKind")),
                                              field_of("jsonPayload"))
    pods = any_of(tuple(f"labels.{literal(k)} = {literal(x.role)}" for k in POD_LABELS))

    def in_cluster(c):
        _, location, name = cluster_parts(c)
        spaces = role_namespaces(m, (x.role,), c)
        return all_of('resource.type = "k8s_container"',
                      f"resource.labels.cluster_name = {literal(name or rdn_value(c))}",
                      location and f"resource.labels.location = {literal(location)}",
                      spaces and any_of(tuple(f"resource.labels.namespace_name = {literal(n)}" for n in spaces)))
    clusters = visible_clusters(m, x.role)
    return all_of(any_of(tuple(in_cluster(c) for c in clusters)), pods, _container(x, sources), kinds) \
        if clusters else None


def container_log_notes(m, services):
    """HCL comments naming the container output environment m's routes don't ship to Cloud Logging buckets, and what
    shipping it needs."""
    found = container_shipments(m, services)
    shipped = {c.dn: c for x in found for c in visible_clusters(m, x.role)}.values()
    return tuple(dict.fromkeys((
        *(f"# NOTE: log route {rdn_value(x.route)}: role {x.role}'s container output not shipped: the role runs on "
          "Kubernetes here in no cluster the environment binds" for x in found if not role_clusters(m, x.role)),
        *(f"# NOTE: log route {rdn_value(x.route)}: role {x.role}'s container output in cluster {rdn_value(c)} not "
          f"shipped: the cluster is in project {cluster_parts(c)[0]}, whose logs a sink in {project_id(m)} doesn't "
          "see (route them with a sink there)" for x in found for c in role_clusters(m, x.role)
          if cluster_parts(c)[0] not in (None, project_id(m))),
        *((f"# NOTE: GKE clusters {', '.join(rdn_value(c) for c in shipped)}: their workload logging (logging_config "
           "WORKLOADS, GKE's default) must stay on for the log sinks to see container output",) if shipped else ()))))
