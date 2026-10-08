"""Google Cloud DNS: a service name's record set (its forwarding rule's address) with its TTL; a weighted set between
environments as a weighted round robin routing policy rendered by the environment holding the first answer, with the
others' addresses. The environment's other records in their managed zones (TXT values quoted as Cloud DNS wants them)
and its outbound forwarders as private forwarding zones on the network. Nothing is rendered into a zone someone else
runs. Pure.

Known limit: a failover pair is rendered as a plain record with a comment; Cloud DNS's primary-backup policy with
health-checked external endpoints is to be configured by hand.
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.domains.edge.dns import zone_of
from opsdir.domains.edge.records import address, forwarders, hosted_notes, records_in, routing, run_by, ttl
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .names import NETWORK, label


def _elsewhere(d, m, name):
    party = run_by(d, m, name)
    return (f"# `{name}` is in a zone {rdn_value(party)} runs: not rendered here (the plan drafts the request to "
            "them)",) if party is not None else ()


def _zone(svc_or_zone):
    return one(svc_or_zone, "ciamDnsZoneRef") or one(svc_or_zone, "ciamProviderRef") or \
        label(one(svc_or_zone, "ciamDnsZone"))


def service_record(d, m, svc, n, world=False):
    """A service name's record set (the address of its forwarding rule, a global one for a global load balancer),
    with weighted routing between environments when it has it."""
    name = one(svc, "ciamFqdn")
    outside = _elsewhere(d, m, name)
    if outside:
        return outside
    own = ref(f"google_compute_{'global_' if world else ''}forwarding_rule.{n}.ip_address")
    head = (("managed_zone", _zone(svc)), ("name", f"{name}."), ("type", "A"), ("ttl", ttl(svc)))
    routed = routing(d, m, svc)
    if routed is None:
        return (block("resource", ["google_dns_record_set", n], [*head, ("rrdatas", [own])]),)
    policy, found = routed
    if not found:
        return (f"# `{name}` routes between environments ({policy}): the environment holding its primary answers it",)
    if policy != "weighted":
        return (block("resource", ["google_dns_record_set", n], [
            ("#", f"{policy}: configure Cloud DNS's primary-backup policy with health-checked endpoints by hand"),
            *head, ("rrdatas", [own])]),)
    return (block("resource", ["google_dns_record_set", n], [*head, ("routing_policy", Block(tuple(
        ("wrr", Block((("weight", a.weight), ("rrdatas", [own if a.binding.dn == svc.dn else address(a)]))))
        for a in found)))]),)


def _rrdata(rtype, v):
    return '"' + v.strip('"').replace('"', '\\"') + '"' if rtype == "TXT" else v


def records(d, m):
    """The environment's DNS records in the managed zones it binds."""
    def one_record(r):
        name, rtype = one(r, "ciamRecordName"), one(r, "ciamRecordType")
        outside = _elsewhere(d, m, name)
        zone = zone_of(m, name)
        if outside:
            return outside[0]
        if zone is None:
            return f"# UNBOUND: no Cloud DNS zone bound for {rtype} `{name}`"
        return block("resource", ["google_dns_record_set", tf_name(f"record_{rdn_value(r)}")], [
            ("managed_zone", _zone(zone)), ("name", f"{name.rstrip('.')}."), ("type", rtype), ("ttl", ttl(r)),
            ("rrdatas", [_rrdata(rtype, v) for v in values(r, "ciamRecordValue")])])
    return tuple(one_record(r) for r in records_in(m))


def forwarding_zones(m):
    """Outbound forwarders as private forwarding zones on the network; inbound ones are a DNS server policy the
    landing zone keeps (a comment); those on the environment's own DNS servers (Compute Engine instances) a
    comment."""
    return (*(block("resource", ["google_dns_managed_zone", tf_name(f"{rdn_value(f)}_{i}")], [
                ("name", label(f"ciam-{rdn_value(m.env)}-{rdn_value(f)}-{i}")),
                ("dns_name", domain.rstrip(".") + "."), ("visibility", "private"),
                ("description", f"Forwards {domain} ({rdn_value(f)})"),
                ("private_visibility_config", Block((("networks", Block((("network_url", NETWORK),))),))),
                ("forwarding_config", Block(tuple(("target_name_servers", Block((("ipv4_address", ip),)))
                                                  for ip in values(f, "ciamForwardTarget"))))])
              for f in forwarders(m, hosted=False) for i, domain in enumerate(values(f, "ciamForwardDomain"))),
            *(f"# Inbound forwarder `{rdn_value(f)}` ({', '.join(values(f, 'ciamForwardDomain'))}): a DNS server "
              "policy with inbound forwarding, kept by the landing zone; not managed here"
              for f in forwarders(m, "inbound", hosted=False)),
            *hosted_notes(m, "Compute Engine instances"))
