"""DNS as the cloud renderers need it: the zone binding a name is published in and who runs it when not the platform,
the other environments answering a name that routes between environments (a failover pair, a weighted set), each
record's TTL and its values taken apart where a record type has parts, and the forwarders: on the platform's managed
resolver, or on DNS servers the environment runs (what those must do is a comment). Pure.

A name that routes between environments is answered from one place: the environment holding the primary (or, for a
weighted set, the first by label) renders the routing with the others' addresses; the others render a comment.
"""
import ipaddress
from collections import namedtuple

from ...core.directory import get, one, rdn_value, subtree, values
from ...core.environment import UNBOUND, environment_of, of_class
from ...core.naming import branch, env_label
from .dns import answer, zone_of

DEFAULT_TTL = 300
ROUTED = ("failover-primary", "failover-secondary", "weighted")
# A routed name's answer in one environment: its label, the binding, the routing policy, the weight
Answer = namedtuple("Answer", ("label", "binding", "policy", "weight"))
# A record an environment publishes in a zone the platform runs: the zone (its name), the name relative to it ('@' for
# the apex), the full name, the type, the values, the TTL, and the binding it comes from
Published = namedtuple("Published", ("zone", "name", "fqdn", "type", "values", "ttl", "binding"))


def ttl(b, default=DEFAULT_TTL):
    """A record's or service name's TTL in seconds."""
    return int(one(b, "ciamTtlSeconds") or default)


def run_by(d, m, name):
    """The party running the zone a name falls in (the zone binding's ciamManagedBy), or None when the platform does
    (or no zone is bound)."""
    zone = zone_of(m, name)
    return get(d, one(zone, "ciamManagedBy")) if zone is not None and one(zone, "ciamManagedBy") else None


def _name(b):
    return (one(b, "ciamFqdn") or one(b, "ciamRecordName") or "").lower()


def answers(d, name):
    """Every environment's routed answer for a name (service names and address records whose routing policy routes
    between environments), primaries first, then by environment label."""
    found = [Answer(env_label(environment_of(b)), b, one(b, "ciamRoutingPolicy"),
                    int(one(b, "ciamRoutingWeight") or 1))
             for oc in ("ciamServiceName", "ciamDnsRecord") for b in subtree(d, branch("environments"), oc)
             if _name(b) == name.lower() and one(b, "ciamRoutingPolicy") in ROUTED]
    return tuple(sorted(found, key=lambda a: (a.policy != "failover-primary", a.label)))


def routing(d, m, b):
    """(policy, answers) when a binding's name routes between environments and environment m renders the routing,
    (policy, ()) when another environment does, None when it doesn't route."""
    policy = one(b, "ciamRoutingPolicy")
    if policy not in ROUTED:
        return None
    found = answers(d, _name(b))
    return (policy, found) if found and found[0].label == m.label else (policy, ())


def address(a):
    """An answer's address as text."""
    return answer(a.binding)


def parts(record_type, value):
    """A record value taken apart where its type has parts: MX (preference, exchange), SRV (priority, weight, port,
    target), CAA (flags, tag, value); others whole."""
    if record_type == "MX":
        preference, exchange = value.split(None, 1)
        return int(preference), exchange
    if record_type == "SRV":
        priority, weight, port, target = value.split()
        return int(priority), int(weight), int(port), target
    if record_type == "CAA":
        flags, tag, rest = value.split(None, 2)
        return int(flags), tag, rest.strip('"')
    return (value,)


def records_in(m):
    """Environment m's DNS records (ciamDnsRecord bindings), by name then type."""
    return tuple(sorted((b for b in m.bindings if "ciamDnsRecord" in b.classes),
                        key=lambda r: (_name(r), one(r, "ciamRecordType"))))


def is_hosted(f):
    """Whether forwarder f runs on DNS servers the environment runs (ciamResolverHost), not the managed resolver."""
    return bool(values(f, "ciamResolverHost"))


def forwarders(m, direction="outbound", hosted=None):
    """Environment m's forwarders in a direction, by name: all, or only those on its own DNS servers (hosted True)
    or on the platform's managed resolver (False)."""
    return tuple(sorted((b for b in m.bindings if "ciamDnsForwarder" in b.classes
                         and (one(b, "ciamForwardDirection") or "outbound") == direction
                         and (hosted is None or is_hosted(b) == hosted)),
                        key=lambda f: tuple(values(f, "ciamForwardDomain"))))


def hosted_notes(m, machines):
    """A comment per forwarder of environment m on its own DNS servers (machines: what the platform calls them): what
    those servers must do, the network's DNS settings pointing at them; neither is rendered here."""
    def note(f):
        doms, hosts = ", ".join(values(f, "ciamForwardDomain")), ", ".join(values(f, "ciamResolverHost"))
        does = (f"forward {doms} to {', '.join(values(f, 'ciamForwardTarget'))} and everything else to the "
                "platform's resolver" if (one(f, "ciamForwardDirection") or "outbound") == "outbound"
                else f"answer other networks' queries for {doms}")
        return (f"# Forwarder `{rdn_value(f)}` runs on DNS servers {hosts} ({machines}), not the managed resolver: "
                f"they {does}, and the network's DNS servers point at them; not managed here")
    return tuple(note(f) for direction in ("outbound", "inbound") for f in forwarders(m, direction, hosted=True))


def _relative(fqdn, zone):
    fqdn, zone = fqdn.lower().rstrip("."), zone.lower().rstrip(".")
    return "@" if fqdn == zone else fqdn[: -len(zone) - 1]


def _values(m, b, own):
    """The values environment m publishes for binding b's name: its own (own), or for a name routing between
    environments, the routing's answers when m renders it (a failover pair: the primary's address only, since a DNS
    server doesn't fail over by itself; a weighted set: every answer's addresses, as round robin), () when another
    environment does."""
    routed = routing(m.d, m, b)
    if routed is None:
        return own
    policy, found = routed
    picked = found[:1] if policy.startswith("failover") else found
    return tuple(v.strip() for a in picked for v in address(a).split(",") if v.strip())


def _address_type(value):
    """A or AAAA by an address's version (an UNBOUND placeholder counts as IPv4)."""
    try:
        return "AAAA" if ipaddress.ip_address(value).version == 6 else "A"
    except ValueError:
        return "A"


def _by_type(vals):
    """((A or AAAA, addresses), ...) of addresses, in the order their types first appear."""
    return tuple((t, tuple(v for v in vals if _address_type(v) == t)) for t in dict.fromkeys(map(_address_type, vals)))


def _wanted(m):
    """(binding, fqdn, type, values) of every name environment m answers: service names' addresses (an A and/or an
    AAAA record by address version), then its other records; routed names as _values gives them."""
    def frontend(svc):
        return _values(m, svc, (one(svc, "ciamFrontendIp") or f"{UNBOUND}{one(svc, 'ciamBindingRole')}-frontend-ip",))
    names = ((svc, one(svc, "ciamFqdn"), rtype, vals)
             for svc in of_class(m, "ciamServiceName") for rtype, vals in _by_type(frontend(svc)))
    others = ((r, one(r, "ciamRecordName"), one(r, "ciamRecordType"), _values(m, r, values(r, "ciamRecordValue")))
              for r in records_in(m))
    return tuple((b, fqdn, rtype, tuple(vals)) for b, fqdn, rtype, vals in (*names, *others) if fqdn and vals)


def published(m):
    """(Published, ...) the records environment m publishes in zones the platform runs, for a DNS server's renderer
    (an appliance add-on): each service name's A or AAAA record (its frontend address, UNBOUND:<role>-frontend-ip when
    none is recorded) and every other record (ciamDnsRecord), in the zone binding its name falls in; a name routing
    between environments only from the environment rendering its routing. What it leaves out (unpublished: names in no
    bound zone, in a zone another party runs, or kept by another party) the keepers' requests name."""
    return tuple(Published(one(z, "ciamDnsZone").rstrip("."), _relative(fqdn, one(z, "ciamDnsZone")),
                           fqdn.rstrip("."), rtype, vals, ttl(b), b)
                 for b, fqdn, rtype, vals in _wanted(m) if not one(b, "ciamManagedBy")
                 for z in (zone_of(m, fqdn),) if z is not None and not one(z, "ciamManagedBy"))


def platform_zones(m):
    """The zones (their names, no trailing dot) environment m binds and the platform runs: where a DNS add-on writes,
    and tidies what it wrote before."""
    return tuple(dict.fromkeys(one(z, "ciamDnsZone").rstrip(".") for z in of_class(m, "ciamDnsZoneBinding")
                               if one(z, "ciamDnsZone") and not one(z, "ciamManagedBy")))


def unpublished(m):
    """((binding, fqdn, why), ...) the names environment m answers that published leaves out: in no zone it binds, in
    a zone another party runs (the zone binding's ciamManagedBy), or kept by another party (the binding's)."""
    def why(b, fqdn):
        z = zone_of(m, fqdn)
        return ("kept by another party" if one(b, "ciamManagedBy")
                else "in no DNS zone the environment binds" if z is None
                else f"in zone {one(z, 'ciamDnsZone')}, run by another party" if one(z, "ciamManagedBy") else None)
    return tuple((b, fqdn, reason) for b, fqdn, _, _ in _wanted(m) for reason in (why(b, fqdn),) if reason)
