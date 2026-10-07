"""Azure DNS: a service name's A record (in the private zone when its address is private) with its TTL; when the name
routes between environments, a Traffic Manager profile rendered by the environment holding the primary (every
environment's address an external endpoint by priority or weight, checked over TCP) and a CNAME to it, Azure DNS
having no failover of its own. The environment's other records by type, in public or private zones, and its outbound
forwarders as rules of the landing zone's DNS forwarding ruleset. Nothing is rendered into a zone someone else runs.
Pure.
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.network import is_private
from opsdir.domains.edge.dns import zone_of
from opsdir.domains.edge.records import address, forwarders, parts, records_in, routing, run_by, ttl
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .identities import RG
from .account import tagged

FORWARDING_RULESET = "dns_forwarding_ruleset_id"   # the landing zone's DNS forwarding ruleset, an input
PRIVATE_TYPES = ("A", "AAAA", "CNAME", "MX", "SRV", "TXT")


def record_name(fqdn, zone):
    """A name relative to its zone ('@' for the apex), or None when it isn't in the zone."""
    fqdn, zone = fqdn.rstrip("."), zone.rstrip(".")
    return "@" if fqdn == zone else (fqdn[: -len(zone) - 1] if fqdn.endswith("." + zone) else None)


def _elsewhere(d, m, name):
    party = run_by(d, m, name)
    return (f"# `{name}` is in a zone {rdn_value(party)} runs: not rendered here (the plan drafts the request to "
            "them)",) if party is not None else ()


def _traffic_manager(m, svc, n, policy, found):
    name, zone = one(svc, "ciamFqdn"), one(svc, "ciamDnsZone")
    weighted = policy == "weighted"
    return (block("resource", ["azurerm_traffic_manager_profile", n], [
                ("name", f"tm-ciam-{rdn_value(m.env)}-{rdn_value(svc)}"), ("resource_group_name", RG),
                ("traffic_routing_method", "Weighted" if weighted else "Priority"),
                ("dns_config", Block((("relative_name", f"ciam-{rdn_value(m.env)}-{rdn_value(svc)}"),
                                      ("ttl", ttl(svc))))),
                ("monitor_config", Block((("protocol", "TCP"), ("port", int(values(svc, "ciamPort")[0]))))),
                ("tags", tagged(m, {"Service": name, "ManagedBy": "opsdir"}))]),
            *(block("resource", ["azurerm_traffic_manager_external_endpoint", f"{n}_{tf_name(a.label)}"], [
                ("name", a.label.replace("/", "-")), ("profile_id", ref(f"azurerm_traffic_manager_profile.{n}.id")),
                ("target", address(a)),
                ("weight", a.weight) if weighted else ("priority", i + 1)]) for i, a in enumerate(found)),
            block("resource", ["azurerm_dns_cname_record", n], [
                ("name", record_name(name, zone)), ("zone_name", zone), ("resource_group_name", RG),
                ("ttl", ttl(svc)), ("record", ref(f"azurerm_traffic_manager_profile.{n}.fqdn")),
                ("tags", tagged(m, {"Service": name, "ManagedBy": "opsdir"}))]))


def service_record(d, m, svc, n, target=None):
    """A service name's DNS record (a CNAME to target when a CDN fronts it), or the Traffic Manager routing it between
    environments."""
    name, zone, ip = one(svc, "ciamFqdn"), one(svc, "ciamDnsZone"), one(svc, "ciamFrontendIp")
    outside = _elsewhere(d, m, name)
    if outside:
        return outside
    if target is not None:
        return (block("resource", ["azurerm_dns_cname_record", n], [
            ("name", record_name(name, zone)), ("zone_name", zone), ("resource_group_name", RG), ("ttl", ttl(svc)),
            ("record", target), ("tags", tagged(m, {"Service": name, "ManagedBy": "opsdir"}))]),)
    routed = routing(d, m, svc)
    if routed is not None:
        policy, found = routed
        if not found:
            return (f"# `{name}` routes between environments ({policy}): the environment holding its primary "
                    "answers it",)
        if is_private(ip):
            return (f"# `{name}` routes between environments ({policy}), but Traffic Manager answers public names "
                    "only: a single private record is rendered",
                    *_a_record(m, svc, n, name, zone, ip, True))
        return _traffic_manager(m, svc, n, policy, found)
    return _a_record(m, svc, n, name, zone, ip, is_private(ip))


def _a_record(m, svc, n, name, zone, ip, private):
    return (block("resource", ["azurerm_private_dns_a_record" if private else "azurerm_dns_a_record", n], [
        ("name", record_name(name, zone)), ("zone_name", zone), ("resource_group_name", RG), ("ttl", ttl(svc)),
        ("records", [ip]), ("tags", tagged(m, {"Service": name, "ManagedBy": "opsdir"}))]),)


def _values(rtype, vs):
    """The record body for a type: records lists, a single record, or record blocks."""
    if rtype in ("A", "AAAA", "NS"):
        return (("records", list(vs)),)
    if rtype == "CNAME":
        return (("record", vs[0]),)
    keys = {"TXT": ("value",), "MX": ("preference", "exchange"), "SRV": ("priority", "weight", "port", "target"),
            "CAA": ("flags", "tag", "value")}[rtype]
    return tuple(("record", Block(tuple(zip(keys, parts(rtype, v) if rtype != "TXT" else (v,))))) for v in vs)


def records(d, m):
    """The environment's DNS records in the zones it binds, public or private by the zone's visibility."""
    def one_record(r):
        name, rtype = one(r, "ciamRecordName"), one(r, "ciamRecordType")
        outside = _elsewhere(d, m, name)
        zone = zone_of(m, name)
        if outside:
            return outside[0]
        if zone is None:
            return f"# UNBOUND: no DNS zone bound for {rtype} `{name}`"
        private = one(zone, "ciamZoneVisibility") == "private"
        if private and rtype not in PRIVATE_TYPES:
            return f"# {rtype} `{name}`: private DNS zones have no {rtype} records"
        kind = f"azurerm_{'private_' if private else ''}dns_{rtype.lower()}_record"
        return block("resource", [kind, tf_name(f"record_{rdn_value(r)}")], [
            ("name", record_name(name, one(zone, "ciamDnsZone"))), ("zone_name", one(zone, "ciamDnsZone")),
            ("resource_group_name", RG), ("ttl", ttl(r)), *_values(rtype, values(r, "ciamRecordValue"))])
    return tuple(one_record(r) for r in records_in(m))


def forwarding_rules(m):
    """Outbound forwarders as rules of the landing zone's DNS forwarding ruleset; inbound ones are its resolver's
    inbound endpoint (a comment)."""
    return (*(block("resource", ["azurerm_private_dns_resolver_forwarding_rule", tf_name(f"{rdn_value(f)}_{i}")], [
                ("name", tf_name(f"{rdn_value(f)}_{i}").replace("_", "-")),
                ("dns_forwarding_ruleset_id", ref(f"var.{FORWARDING_RULESET}")),
                ("domain_name", domain.rstrip(".") + "."), ("enabled", True),
                *(("target_dns_servers", Block((("ip_address", ip), ("port", 53))))
                  for ip in values(f, "ciamForwardTarget"))])
              for f in forwarders(m) for i, domain in enumerate(values(f, "ciamForwardDomain"))),
            *(f"# Inbound forwarder `{rdn_value(f)}` ({', '.join(values(f, 'ciamForwardDomain'))}): the landing "
              "zone's DNS Private Resolver inbound endpoint; not managed here" for f in forwarders(m, "inbound")))
