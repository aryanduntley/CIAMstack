"""How the products' logs reach an environment's Elastic data streams: not rendered (decision on task 552). Elastic
Agent, enrolled in a Fleet policy, collects them: the Elastic team's. Pure.

What the routes ship to an Elastic data stream is named for that team as data (shipping_notes): one action per
environment listing, per server role, the log files each stream must receive from its servers (their install roots
resolved); a container's output (Kubernetes) a blocker per route, as the provider adapters leave a SIEM's index to its
adapter (Services.siem_keeper).
"""
from opsdir.core.directory import rdn_value
from opsdir.core.notes import note
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.sources import shipments
from .naming import stream_name


def elastic_shipments(m, services):
    """Environment m's Shipments whose destination is an Elastic data stream (naming.stream_name)."""
    return tuple(x for x in shipments(m, log_routes(m.d), services.logs(m))
                 if stream_name(x.destination) is not None)


def shipping_notes(m, services):
    """The render notes of how environment m's logs reach its Elastic data streams: an action listing what Elastic
    Agent must collect from the servers, a blocker per route whose logs are a container's output."""
    found = elastic_shipments(m, services)
    files = tuple(dict.fromkeys((x.role, x.path, stream_name(x.destination), ", ".join(x.hosts))
                                for x in found if x.on == "servers"))
    return (
        *((note("Logs", "action", "Elastic Agent", "the routes' logs on the servers reach the Elastic data streams "
                "through Elastic Agent (a Fleet policy), which the Elastic team keeps; opsdir doesn't render it",
                tuple(f"Collect {path} on role {role} ({hosts or 'no hosts recorded'}) into {stream}"
                      for role, path, stream, hosts in files), None, m.label),) if files else ()),
        *(note("Logs", "blocker", f"log route {rdn_value(x.route)}", f"role {x.role}'s container output not shipped: "
               f"its destination {stream_name(x.destination)} is an Elastic data stream, and nothing rendered ships a "
               "container's output there",
               ("Collect the containers' output with Elastic Agent on the cluster (the Elastic team's Kubernetes "
                "integration), or route it to a destination the cluster's cloud collects",), x.route.dn, m.label)
          for x in found if x.on == "kubernetes"))
