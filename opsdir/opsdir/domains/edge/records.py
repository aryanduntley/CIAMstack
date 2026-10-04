"""DNS as the cloud renderers need it: the zone binding a name is published in and who runs it when not the platform,
the other environments answering a name that routes between environments (a failover pair, a weighted set), each
record's TTL and its values taken apart where a record type has parts. Pure.

A name that routes between environments is answered from one place: the environment holding the primary (or, for a
weighted set, the first by label) renders the routing with the others' addresses; the others render a comment.
"""
from collections import namedtuple

from ...core.directory import get, one, subtree, values
from ...core.environment import environment_of
from ...core.naming import branch, env_label
from .dns import answer, zone_of

DEFAULT_TTL = 300
ROUTED = ("failover-primary", "failover-secondary", "weighted")
# A routed name's answer in one environment: its label, the binding, the routing policy, the weight
Answer = namedtuple("Answer", ("label", "binding", "policy", "weight"))


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


def forwarders(m, direction="outbound"):
    """Environment m's forwarders in a direction, by name."""
    return tuple(sorted((b for b in m.bindings if "ciamDnsForwarder" in b.classes
                         and (one(b, "ciamForwardDirection") or "outbound") == direction),
                        key=lambda f: tuple(values(f, "ciamForwardDomain"))))
