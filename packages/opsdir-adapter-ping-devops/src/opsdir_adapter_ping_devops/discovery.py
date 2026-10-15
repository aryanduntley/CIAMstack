"""PingFederate's cluster discovery on Kubernetes with the ping-devops chart. Pure.

The chart's admin and engine pods share a headless cluster service (release.cluster_query) and set DNS_QUERY_LOCATION
to it, so they find each other by DNS_PING: Ping's recommendation on Kubernetes. The record holds the choice as the
environment's cluster-discovery binding (PingFederate's role as its adapter declares it: core.environment.roles_for),
which the values pass on. What the chart answers is declared (cluster_discovery: a contract.DiscoveryAnswer per
namespace the chart deploys PingFederate in); PingFederate's own planner check compares the binding with it.
"""
from opsdir.core.contract import DiscoveryAnswer
from opsdir.core.directory import one
from opsdir.core.environment import one_role, roles_for
from .logs import PRODUCT
from .products import placements
from .release import DNS_QUERY, cluster_query

KIT = "ping-devops"
DNS_PING = "DNS_PING"


def discovery_role(m):
    """PingFederate's cluster-discovery binding role (pf-cluster-discovery) as its installed adapter declares it, or
    None."""
    return next(iter(roles_for(m, PRODUCT, "cluster-discovery")), None)


def recorded_query(m):
    """The DNS name environment m's PingFederate cluster-discovery binding has its nodes query when it uses DNS_PING,
    or None. The protocol rule repeats PingFederate's (opsdir_adapter_pingfederate.discovery.binding_protocol, the
    source of truth: the protocol the binding states, else DNS_PING when it names a DNS name and no storage); the
    showcase's tests check the two agree."""
    role = discovery_role(m)
    b = one_role(m, role) if role else None
    stated = one(b, "pingfedDiscoveryProtocol") if b is not None else None
    dns = b is not None and (stated == DNS_PING or not stated and not one(b, "ciamStorageRef") and one(b, "ciamFqdn"))
    return one(b, "ciamFqdn") if dns else None


def cluster_discovery(m):
    """What the chart answers for PingFederate's cluster discovery in environment m: per namespace it deploys
    PingFederate in, its cluster service's DNS name, passed to the pods as DNS_QUERY_LOCATION."""
    return tuple(DiscoveryAnswer(PRODUCT, p.namespace, cluster_query(p.namespace), KIT, DNS_QUERY)
                 for p in placements(m))
