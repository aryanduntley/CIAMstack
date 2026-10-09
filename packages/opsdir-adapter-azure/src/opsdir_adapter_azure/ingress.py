"""Azure: the front before a cluster's in-cluster gateway, and how the gateway's Service is plugged into it. Pure.

A service name whose role an environment runs only on Kubernetes, in a cluster with a gateway (the core edge domain's
edge.gateways), is fronted as a service on servers is: an Application Gateway v2 (WAF_v2 when its protection policy asks
for inspection) with its TLS policy and certificate, a Front Door when a CDN fronts it, its DNS record. Its backend is
the gateway instead of the servers: the private address of the gateway's internal load balancer (the AKS Service the
plug annotates), on HTTP, or on HTTPS to the gateway's internal certificate when the policy re-encrypts, trusting the
CA that certificate chains to (Key Vault).
"""
from opsdir.core.contract import GatewayPlug
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND, one_role
from opsdir.domains.edge.gateways import gateway_ca, gateway_port
from opsdir.domains.edge.resolve import front_edge
from opsdir_format_terraform.hcl import tf_name
from .dns import service_record
from .edge import Backend, gateway_service
from .frontdoor import endpoint, front_door


def _address(gw):
    return one(gw, "ciamFrontendIp") or f"{UNBOUND}gateway-frontend-ip"


def gateway_plug(m, gw, service):
    """Adapter gateway_plug: the gateway's Service as an AKS internal load balancer at the gateway's private address,
    in the subnet its binding names (<virtual network>/<subnet>)."""
    subnet = one_role(m, one(gw, "ciamSubnetRole")) if one(gw, "ciamSubnetRole") else None
    pref = one(subnet, "ciamProviderRef") if subnet is not None else None
    name = pref.split("/", 1)[1] if pref and "/" in pref else f"{UNBOUND}gateway-subnet"
    return GatewayPlug((("service.beta.kubernetes.io/azure-load-balancer-internal", "true"),
                        ("service.beta.kubernetes.io/azure-load-balancer-internal-subnet", name),
                        ("service.beta.kubernetes.io/azure-load-balancer-ipv4", _address(gw))), (), "LoadBalancer")


def gateway_backend(m, gw, spec):
    """The Backend of a service name a cluster gateway fronts: the gateway's private address on the port its policy
    asks (core gateway_port), trusting the gateway's CA when the front re-encrypts."""
    reencrypt = spec.mode == "reencrypt"
    return Backend("gateway", (_address(gw),), gateway_port(spec),
                   (gateway_ca(m, gw) or f"{UNBOUND}gateway-ca") if reencrypt else None)


def gateway_front(m, svc, gw, endpoints):
    """The Terraform for a service name a cluster gateway fronts: its Application Gateway sending to the gateway, its
    Front Door when a CDN fronts it, and its DNS record."""
    n, spec = tf_name(rdn_value(svc)), front_edge(m, svc, endpoints)
    return (*gateway_service(m, svc, spec, gateway_backend(m, gw, spec)),
            *(front_door(m, svc, spec, n) if spec.cdn else ()),
            *service_record(m.d, m, svc, n, endpoint(n) if spec.cdn else None))
