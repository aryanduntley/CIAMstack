"""What an environment's own stack renders of its network depth, read neutrally for the cloud adapters: the bindings it
keeps (one naming ciamManagedBy is kept by someone else: the landing zone, a network team, whose root renders it), the
subnets a binding names by role, what a private endpoint reaches, the service name an endpoint service exposes, the
egress firewalls whose domain allowlist it renders, the ranges the stack reaches privately and the environment's
firewall model and policy. Nothing recorded, nothing rendered. Pure."""
import re

from ...core.directory import get, is_kind, one, rdn_value, values
from ...core.environment import by_role, of_class, one_role
from .naming import DESTINATION

# what a destination's port is when it names none
HTTPS = 443


def owned(b):
    """Whether the stack keeps a binding itself (no one else is named as managing it)."""
    return one(b, "ciamManagedBy") is None


def kept_by(m, b):
    """The name of who keeps a binding the stack doesn't (the party ciamManagedBy names, else its DN)."""
    dn = one(b, "ciamManagedBy")
    party = get(m.d, dn) if dn else None
    return rdn_value(party) if party is not None else dn


def subnets(m, b):
    """The subnet bindings a binding names by role (ciamSubnetRole), in the order named."""
    return tuple({s.dn: s for role in values(b, "ciamSubnetRole") for s in by_role(m, role)
                  if is_kind(m.d, s, "ciamSubnetBinding")}.values())


def private_endpoints(m):
    """Environment m's private endpoints the stack keeps."""
    return tuple(p for p in of_class(m, "ciamPrivateEndpoint") if owned(p))


def reached(m, p):
    """The bindings a private endpoint reaches (ciamReachesRole) that environment m binds, in the order named."""
    return tuple(b for b in (one_role(m, r) for r in values(p, "ciamReachesRole")) if b is not None)


def endpoint_services(m):
    """((endpoint service, the service name it exposes or None), ...) of environment m."""
    return tuple((e, one_role(m, one(e, "ciamServiceRole"))) for e in of_class(m, "ciamEndpointService"))


def egress_firewalls(m):
    """Environment m's egress firewalls with domain rules (proxy kind firewall) the stack keeps."""
    return tuple(p for p in of_class(m, "ciamProxy") if owned(p) and one(p, "ciamProxyKind") == "firewall")


def allowlist(proxy):
    """((port, (host, ...)), ...) of the sites a proxy or firewall lets egress out to, grouped by port (443 when a
    destination names none), ports ascending, hosts in record order."""
    parsed = tuple((int(port) if port else HTTPS, host)
                   for host, port in (re.match(r"^(.*?)(?::([0-9]+))?$", d).groups()
                                      for d in values(proxy, "ciamAllowedDestination") if re.match(DESTINATION, d)))
    return tuple((port, tuple(dict.fromkeys(h for p, h in parsed if p == port)))
                 for port in sorted({p for p, _ in parsed}))


def private_ranges(m):
    """The ranges the stack reaches without the internet: its network's, its interconnects' (accepted ranges, else
    the other side's) and its private endpoints' own addresses (/32), sorted, unique."""
    net = one_role(m, "network")
    links = (c for ic in of_class(m, "ciamInterconnect")
             for c in (values(ic, "ciamAcceptedCidr") or values(ic, "ciamSourceCidr")))
    ips = (f"{one(p, 'ciamFrontendIp')}/32" for p in of_class(m, "ciamPrivateEndpoint") if one(p, "ciamFrontendIp"))
    return tuple(sorted({*(values(net, "ciamCidr") if net is not None else ()), *links, *ips}))


def firewall_model(m):
    """How environment m's network keeps its firewall rules: 'rules' (on the network, the default) or 'policy'."""
    net = one_role(m, "network")
    return (one(net, "ciamFirewallModel") if net is not None else None) or "rules"


def network_policy(m):
    """Environment m's firewall policy attached to its network (scope network), or None."""
    return next((p for p in of_class(m, "ciamFirewallPolicy") if one(p, "ciamPolicyScope") == "network"), None)


def elsewhere(m):
    """Sentences naming the private endpoints and egress controls of environment m someone else keeps (their root
    renders them) and the proxies that aren't the stack's firewall, for the stack's render to say where they are."""
    kept = tuple(f"Private endpoint '{rdn_value(p)}' ({one(p, 'ciamPrivateService')}) is kept by {kept_by(m, p)}; "
                 "rendered in their root, not here." for p in of_class(m, "ciamPrivateEndpoint") if not owned(p))
    proxies = tuple(f"Egress {one(p, 'ciamProxyKind')} '{rdn_value(p)}' is kept by {kept_by(m, p)}; its allowlist "
                    "is rendered in their root, not here." if not owned(p) else
                    f"Egress passes {one(p, 'ciamProxyKind')} '{rdn_value(p)}'"
                    + (f" ({one(p, 'ciamProxyAddress')})" if one(p, "ciamProxyAddress") else "")
                    + ": its allowlist is kept there, not rendered as cloud firewall rules."
                    for p in of_class(m, "ciamProxy") if not owned(p) or one(p, "ciamProxyKind") != "firewall")
    return (*kept, *proxies)
