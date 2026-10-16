"""Fleet policies shipping the products' container output on Kubernetes to an environment's Elastic data streams
(decision on task 555): Elastic Agent, run on the clusters as Fleet's DaemonSet enrolled in the agent policy
opsdir-<cloud>-<env>-kubernetes, collects a route's containers with a Kubernetes integration policy per server role and
log, its container logs stream alone enabled. Its condition picks the role's pods (their label opsdir.io/role, set by
the deployment kits) in the namespaces the role runs in, and the log's container (a kit's log sidecar by name; for the
role's main output, any container but the ones its other logs name); it writes into the stream's dataset and
namespace. Pure: the policies as the Fleet API takes them (fleet.agent_policy, fleet.package_policy).

The condition is evaluated by the agent on its Kubernetes provider's variables, which config templating leaves dotted
(${kubernetes.labels.opsdir.io/role}, ${kubernetes.namespace}, ${kubernetes.container.name}): checked with Elastic
Agent 9.5.5 in a local kind cluster (task 555), the stream collected for the labelled pod's chosen container only.

Named instead (container_notes): running the agent on the clusters and Elastic's catch-all Kubernetes policy
collecting the same output (an action), routes taking only some of a container's lines (shipped whole: a note) and a
container's output two routes ship to different streams (a blocker).
"""
from opsdir.core.directory import rdn_value
from opsdir.core.notes import note
from opsdir.core.settings import setting_value
from opsdir.domains.compute.workloads import role_clusters, role_namespaces
from opsdir.domains.observability.sources import ALL, containers_of
from .fleet import (agent_policy, clash_note, clashes, elastic_shipments, first_streams, package_policy, routes_named,
                    shipped)
from .naming import KUBERNETES_VERSION, fleet_name, stream_name, stream_parts

KUBERNETES = "kubernetes"                                      # the Kubernetes integration package
ROLE_LABEL = "opsdir.io/role"                                  # the pod label the deployment kits set to the role
CONTAINER_INPUT, CONTAINER_STREAM = "container-logs-filestream", "kubernetes.container_logs"
# the package's other inputs (policy template-input type), turned off: the policy collects container output only
OTHER_INPUTS = ("kubelet-kubernetes/metrics", "kube-state-metrics-kubernetes/metrics",
                "kube-apiserver-kubernetes/metrics", "kube-proxy-kubernetes/metrics",
                "kube-scheduler-kubernetes/metrics", "kube-controller-manager-kubernetes/metrics",
                "events-kubernetes/metrics", "audit-logs-filestream", "audit-logs-aws-cloudwatch",
                "audit-logs-azure-eventhub", "audit-logs-gcp-pubsub")


def container_shipments(m, services):
    """Environment m's container Shipments whose destination is an Elastic data stream."""
    return tuple(x for x in elastic_shipments(m, services) if x.on == "kubernetes")


def _quoted(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _either(terms):
    return terms[0] if len(terms) == 1 else "(" + " or ".join(terms) + ")"


def container_condition(m, x, sources):
    """The agent condition picking container Shipment x's lines of environment m: its role's pods (the label the kits
    set), in the namespaces the role runs in (any, when the record names none), from its log's container."""
    own, others = containers_of(x, sources)
    spaces = role_namespaces(m, (x.role,))
    return " and ".join((f"${{kubernetes.labels.{ROLE_LABEL}}} == {_quoted(x.role)}",
                         *((_either(tuple(f"${{kubernetes.namespace}} == {_quoted(n)}" for n in spaces)),)
                           if spaces else ()),
                         *((f"${{kubernetes.container.name}} == {_quoted(own)}",) if own else
                           (f"${{kubernetes.container.name}} != {_quoted(c)}" for c in others))))


def _part(x):
    return x.source.container or "containers"


def container_policies(m, services):
    """(agent policies, integration policies) shipping environment m's container output to its Elastic data streams:
    the Kubernetes agent policy, a Kubernetes integration policy per role and log."""
    found, sources = shipped(container_shipments(m, services)), services.logs(m)
    logs = tuple(next(x for x in found if (x.role, x.source.container) == k)
                 for k in dict.fromkeys((x.role, x.source.container) for x in found))
    if not logs:
        return (), ()
    agent, version = fleet_name(m, KUBERNETES), setting_value(m.d, KUBERNETES_VERSION)

    def policy(x):
        _, dataset, namespace = stream_parts(stream_name(x.destination))
        routes = routes_named(tuple(dict.fromkeys(rdn_value(y.route) for y in found
                                                  if (y.role, y.source.container) == (x.role, x.source.container))))
        return package_policy(fleet_name(m, x.role, _part(x)), f"opsdir: role {x.role}'s {_part(x)} output into "
                              f"{stream_name(x.destination)} ({routes})", namespace, agent,
                              (KUBERNETES, version),
                              {CONTAINER_INPUT: {"enabled": True, "streams": {CONTAINER_STREAM: {"enabled": True,
                                  "vars": {"data_stream.dataset": dataset,
                                           "condition": container_condition(m, x, sources)}}}},
                               **{i: {"enabled": False} for i in OTHER_INPUTS}})
    return ((agent_policy(agent, stream_parts(stream_name(logs[0].destination))[2],
                          f"opsdir: Elastic Agent on the Kubernetes clusters of {m.label}"),),
            tuple(map(policy, logs)))


def container_notes(m, services):
    """The render notes of shipping environment m's container output to its Elastic data streams: running Elastic
    Agent on the clusters (an action), routes taking only some of a container's lines (a note), a container output
    two routes ship to different streams (a blocker)."""
    found = container_shipments(m, services)
    kept, first = shipped(found), first_streams(found)
    version, agent = setting_value(m.d, KUBERNETES_VERSION), fleet_name(m, KUBERNETES)
    roles = tuple(dict.fromkeys(x.role for x in kept))
    clusters = tuple(dict.fromkeys(rdn_value(c) for role in roles for c in role_clusters(m, role)))
    return (
        *((note("Logs", "action", "Elastic Agent on Kubernetes", f"the routes' container output (roles "
                f"{', '.join(roles)}) reaches the Elastic data streams through the Fleet agent policy {agent} "
                "(rendered): Elastic Agent must run on the clusters as Fleet's DaemonSet enrolled in it, which the "
                "Elastic team deploys",
                (f"Deploy Elastic Agent managed by Fleet on {', '.join(clusters) or 'the clusters running them'} "
                 f"enrolled in {agent} (FLEET_ENROLL=1, FLEET_URL, FLEET_ENROLLMENT_TOKEN from a Secret)",
                 f"Applying the API documents: install the {KUBERNETES} integration package {version} first (POST "
                 f"/api/fleet/epm/packages/{KUBERNETES}/{version}); the Terraform installs it",
                 "A Kubernetes integration policy collecting every container's output (Elastic's default) ships "
                 "these lines into logs-kubernetes.container_logs-* too: narrow its condition, or accept the copies"),
                None, m.label),) if kept else ()),
        *(note("Logs", "note", f"log route {rdn_value(x.route)}", f"role {x.role}'s {_part(x)} output is shipped "
               f"whole to {stream_name(x.destination)}: container lines aren't decoded here, so lines of the kinds the "
               "route doesn't take reach the stream too", (), x.route.dn, m.label)
          for x in kept if x.lines != ALL),
        *(clash_note(m, x, first, f"the {_part(x)} output") for x in clashes(found)))
