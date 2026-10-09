"""Google Cloud: the front before a cluster's in-cluster gateway, and how the gateway's Service is plugged into it.
Pure.

A service name whose role an environment runs only on GKE, in a cluster with a gateway (the core edge domain's
edge.gateways), is fronted as a service on servers is: an Application Load Balancer (regional, or global with Cloud CDN)
with its SSL policy, Certificate Manager certificate and Cloud Armor policy, its DNS record. Its backends are the
gateway's pods instead of instance groups: GKE's standalone zonal network endpoint groups of the gateway's Service (the
plug annotates it with cloud.google.com/neg, a fixed name per port), read here as data in each zone the cluster spans,
balanced by rate. The gateway listens on HTTP, or HTTPS (its internal certificate) when the policy re-encrypts; its
health checks send the service name's host, so the gateway routes them to the product's health endpoint. The firewall
rules admitting the proxies and probes apply to the cluster's node subnets (pods take addresses there).
"""
import json

from opsdir.core.contract import GatewayPlug
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, of_class, one_role
from opsdir.domains.compute.workloads import cluster_subnets
from opsdir.domains.edge.gateways import fronted_services, gateway_port
from opsdir.domains.edge.resolve import front_edge
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .dns import service_record
from .edge import Backend, application_lb

MAX_RATE = 100        # requests per second per endpoint a NEG backend takes before the next is preferred


def neg_name(m, gw, port):
    """The fixed name of the standalone NEGs of a cluster gateway's Service port (the plug's annotation names them)."""
    return f"ciam-{rdn_value(m.env)}-{rdn_value(gw)}-{port}"


def _zones(m, gw):
    cluster = one_role(m, one(gw, "ciamClusterRole")) if one(gw, "ciamClusterRole") else None
    return tuple(values(cluster, "ciamSpansZone")) if cluster is not None else ()


def _neg(gw, port, zone):
    return f"data.google_compute_network_endpoint_group.{tf_name(f'neg_{rdn_value(gw)}_{port}_{zone}')}"


def _ports(m, gw):
    return tuple(sorted({gateway_port(front_edge(m, svc, ())) for svc, g in fronted_services(m) if g.dn == gw.dn}))


def gateway_negs(m):
    """The NEG data sources of environment m's cluster gateways, once each: per gateway, port its fronts use and zone
    its cluster spans; a comment for a cluster that records no zones."""
    return tuple(x for gw in of_class(m, "ciamClusterGateway") for x in (
        (block("data", ["google_compute_network_endpoint_group", _neg(gw, port, zone).rsplit(".", 1)[1]], [
            ("name", neg_name(m, gw, port)), ("zone", zone)]) for port in _ports(m, gw) for zone in _zones(m, gw))
        if _zones(m, gw) else
        ((f"# UNBOUND: the zones cluster `{one(gw, 'ciamClusterRole')}` spans (ciamSpansZone): its gateway's NEGs "
          "are read per zone",) if _ports(m, gw) else ())))


def gateway_backend(m, svc, gw, spec):
    """The Backend of a service name a cluster gateway fronts: the gateway Service port's NEGs in each zone (rate
    balanced), the firewall rules on the cluster's node subnets, health checks sending the service name's host."""
    port = gateway_port(spec)
    cidrs = [one(s, "ciamCidr") for s in cluster_subnets(m, one(svc, "ciamTargetRole")) if one(s, "ciamCidr")]
    return Backend(tuple(("backend", Block((("group", ref(f"{_neg(gw, port, zone)}.self_link")),
                                            ("balancing_mode", "RATE"), ("max_rate_per_endpoint", MAX_RATE))))
                         for zone in _zones(m, gw)),
                   None, port, (("destination_ranges", cidrs or [f"{UNBOUND}cluster-node-subnets"]),),
                   one(svc, "ciamFqdn"))


def gateway_front(m, svc, gw, endpoints, frontend, placement):
    """The Terraform for a service name a cluster gateway fronts: its Application Load Balancer (frontend: (data
    sources, address); placement: the regional forwarding rule's subnetwork when internal) sending to the gateway's
    NEGs, and its DNS record."""
    n, spec = tf_name(rdn_value(svc)), front_edge(m, svc, endpoints)
    return (*application_lb(m, svc, spec, gateway_backend(m, svc, gw, spec), frontend, placement),
            *service_record(m.d, m, svc, n, spec.cdn))


def gateway_plug(m, gw, service):
    """Adapter gateway_plug: the gateway's Service exposes a standalone NEG per port, under the fixed names the
    Terraform reads; the Service stays ClusterIP."""
    _, ports = service
    exposed = {str(p): {"name": neg_name(m, gw, p)} for p in ports}
    return GatewayPlug((("cloud.google.com/neg", json.dumps({"exposed_ports": exposed}, separators=(",", ":"))),),
                       ())
