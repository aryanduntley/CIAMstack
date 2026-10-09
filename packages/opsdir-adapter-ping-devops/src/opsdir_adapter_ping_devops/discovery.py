"""PingFederate's cluster discovery on Kubernetes with the ping-devops chart. Pure.

The chart's admin and engine pods share a headless cluster service (release.cluster_query) and set DNS_QUERY_LOCATION
to it, so they find each other by DNS_PING: Ping's recommendation on Kubernetes. The record holds the choice as the
environment's pf-cluster-discovery binding (opsdir-adapter-pingfederate's discovery: pingfedDiscoveryProtocol
DNS_PING, ciamFqdn the DNS name), which the values pass on and the planner checks against the chart's service.
"""
from opsdir.core.directory import one
from opsdir.core.environment import one_role
from opsdir.core.findings import Fix
from opsdir_adapter_pingfederate.discovery import binding_protocol, discovery_records
from opsdir_adapter_pingfederate.naming import DISCOVERY_ROLE
from .release import DNS_QUERY, cluster_query

DNS_PING = "DNS_PING"


def recorded_query(m):
    """The DNS name environment m's pf-cluster-discovery binding has its nodes query (DNS_PING), or None."""
    b = one_role(m, DISCOVERY_ROLE)
    p = binding_protocol(b) if b is not None else None
    return one(b, "ciamFqdn") if p is not None and p.name == DNS_PING else None


def _now(b, have):
    if b is None:
        return f"the record binds no `{DISCOVERY_ROLE}` there"
    if have:
        return (f"its `{DISCOVERY_ROLE}` binding has them query `{have}`, which the chart's service doesn't answer "
                "unless something else publishes the pods there")
    p = binding_protocol(b)
    return f"its `{DISCOVERY_ROLE}` binding uses {p.name if p else 'no known protocol'}"


def discovery_gap(m, p):
    """(what to say, the Fix) when environment m's record doesn't have its PingFederate nodes in placement p find each
    other by DNS_PING through the chart's cluster service, else None."""
    want, have = cluster_query(p.namespace), recorded_query(m)
    if have == want:
        return None
    b = one_role(m, DISCOVERY_ROLE)
    text = (f"PingFederate runs on Kubernetes in {m.label} (namespace `{p.namespace}`): the chart's pods find each "
            f"other by DNS_PING through its cluster service `{want}`, but {_now(b, have)}. Record that binding.")
    fix = Fix(f"ping-devops-discovery:{m.label}:{p.namespace}", "PingFederate on Kubernetes",
              f"Bind PingFederate's cluster discovery in {m.label}: DNS_PING through `{want}`",
              discovery_records(m, b, DNS_PING, {"ciamFqdn": want}),
              (f"Install {m.label}'s rendered ping-devops values (they set {DNS_QUERY} from the binding).",),
              ("Nodes still running the old discovery don't find the new ones: move the cluster as a whole.",))
    return text, fix
