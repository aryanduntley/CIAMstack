"""AWS DNS: a service name's Route 53 record (an alias of its load balancer; with a set identifier and a failover or
weighted routing policy when the name routes between environments, the environment holding the primary rendering the
others' answers too, each health-checked), the environment's other records in their zones, and its outbound
forwarders as Resolver rules on the VPC. Nothing is rendered into a zone someone else runs: a comment names them (the
planner drafts the request). Pure.
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.domains.edge.records import address, forwarders, records_in, routing, run_by, ttl
from opsdir.domains.edge.dns import zone_of
from opsdir_format_terraform.hcl import Block, block, ref, tf_name

RESOLVER_ENDPOINT = "resolver_endpoint_id"      # the landing zone's outbound Resolver endpoint, an input


def _policy(policy, weight, label):
    if policy == "weighted":
        return (("set_identifier", label), ("weighted_routing_policy", Block((("weight", weight),))))
    return (("set_identifier", label),
            ("failover_routing_policy", Block((("type", "PRIMARY" if policy == "failover-primary" else "SECONDARY"),))))


def _elsewhere(d, m, name):
    party = run_by(d, m, name)
    return (f"# `{name}` is in a zone {rdn_value(party)} runs: not rendered here (the plan drafts the request to "
            "them)",) if party is not None else ()


def service_record(d, m, svc, n, target=None):
    """A service name's Route 53 records: the alias of its load balancer (or target: (DNS name, zone id), a CloudFront
    distribution), routed when the name routes between environments."""
    name = one(svc, "ciamFqdn")
    outside = _elsewhere(d, m, name)
    if outside:
        return outside
    dns_name, zone_id = target or (ref(f"aws_lb.{n}.dns_name"), ref(f"aws_lb.{n}.zone_id"))
    alias = ("alias", Block((("name", dns_name), ("zone_id", zone_id), ("evaluate_target_health", True))))
    note = (("#", f"an alias takes the load balancer's TTL; the recorded {one(svc, 'ciamTtlSeconds')} s doesn't "
                  "apply"),) if one(svc, "ciamTtlSeconds") else ()
    head = (("zone_id", one(svc, "ciamDnsZoneRef")), ("name", name), ("type", "A"))
    routed = routing(d, m, svc)
    if routed is None:
        return (block("resource", ["aws_route53_record", n], [*head, *note, alias]),)
    policy, found = routed
    if not found:
        return (f"# `{name}` routes between environments ({policy}): the environment holding its primary answers it",)
    port = int(values(svc, "ciamPort")[0])
    return tuple(
        block("resource", ["aws_route53_record", n], [*head, *note, *_policy(a.policy, a.weight, a.label), alias])
        if a.binding.dn == svc.dn else
        "\n\n".join((
            block("resource", ["aws_route53_health_check", f"{n}_{tf_name(a.label)}"], [
                ("ip_address", address(a)), ("port", port), ("type", "TCP"), ("failure_threshold", 3),
                ("request_interval", 30), ("tags", {"Name": f"{name} ({a.label})", "ManagedBy": "opsdir"})]),
            block("resource", ["aws_route53_record", f"{n}_{tf_name(a.label)}"], [
                *head, ("ttl", ttl(a.binding)), ("records", [address(a)]), *_policy(a.policy, a.weight, a.label),
                ("health_check_id", ref(f"aws_route53_health_check.{n}_{tf_name(a.label)}.id"))])))
        for a in found)


def records(d, m):
    """The environment's DNS records in the zones it binds (zone id from the zone binding's provider ref)."""
    def one_record(r):
        name, rtype = one(r, "ciamRecordName"), one(r, "ciamRecordType")
        outside = _elsewhere(d, m, name)
        zone = zone_of(m, name)
        if outside:
            return outside[0]
        if zone is None or not one(zone, "ciamProviderRef"):
            return f"# UNBOUND: no Route 53 zone bound for {rtype} `{name}`"
        return block("resource", ["aws_route53_record", tf_name(f"record_{rdn_value(r)}")], [
            ("zone_id", one(zone, "ciamProviderRef")), ("name", name), ("type", rtype), ("ttl", ttl(r)),
            ("records", list(values(r, "ciamRecordValue")))])
    return tuple(one_record(r) for r in records_in(m))


def resolver_rules(m):
    """Outbound forwarders as Resolver forwarding rules through the landing zone's endpoint, associated with the
    VPC; inbound ones are the landing zone's endpoint (a comment)."""
    out = tuple(
        part for f in forwarders(m) for i, domain in enumerate(values(f, "ciamForwardDomain"))
        for n in (tf_name(f"{rdn_value(f)}_{i}"),)
        for part in (
            block("resource", ["aws_route53_resolver_rule", n], [
                ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(f)}-{i}"), ("domain_name", domain),
                ("rule_type", "FORWARD"), ("resolver_endpoint_id", ref(f"var.{RESOLVER_ENDPOINT}")),
                *(("target_ip", Block((("ip", ip), ("port", 53)))) for ip in values(f, "ciamForwardTarget")),
                ("tags", {"ManagedBy": "opsdir"})]),
            block("resource", ["aws_route53_resolver_rule_association", n], [
                ("resolver_rule_id", ref(f"aws_route53_resolver_rule.{n}.id")),
                ("vpc_id", ref("data.aws_vpc.main.id"))])))
    inbound = tuple(f"# Inbound forwarder `{rdn_value(f)}` ({', '.join(values(f, 'ciamForwardDomain'))}): the "
                    "landing zone's inbound Resolver endpoint; not managed here" for f in forwarders(m, "inbound"))
    return (*out, *inbound)
