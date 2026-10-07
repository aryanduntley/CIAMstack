"""What AWS's edge runs, read back in the edge domain's terms (Terraform state attribute names; the CLI and
CloudFormation readers normalize to them). Pure.

  aws_lb + listeners + target groups   -> facts on its service name: tls-mode (passthrough, terminate, reencrypt from
                                          the listeners' and target groups' protocols), tls-min and tls-profile (the
                                          listener's ELB policy through the TLS table; one it doesn't know is a
                                          setting), an HTTP(S) health check, stickiness, draining and an ALB's idle
                                          timeout when they aren't AWS's defaults
  aws_wafv2_web_acl (+ association,    -> edge service waf: waf-mode (detect when every rule only counts),
    aws_wafv2_ip_set)                     waf-category (the managed groups the WAF table knows; others are settings),
                                          rate-limit (rules named rate-<kind>; others are settings), ip-rule, geo-rule;
                                          fronting the load balancer it is associated with (or its distribution's)
  aws_shield_protection (+ automatic   -> edge service ddos: network-advanced, application-advanced with layer 7
    response)                             automatic response
  aws_cloudfront_distribution          -> edge service cdn in front of the load balancer it has for origin
  aws_route53_zone                     -> DNS zone: name, public or private (VPC associations), zone id
  aws_route53_record                   -> a service name's TTL (an alias: 60 s, the load balancer's) and routing
                                          (failover, weighted); other records as DNS records (name, type, TTL, values,
                                          routing); A records answering for another environment of a routed name are
                                          the routing's, not this environment's: named
  aws_route53_resolver_rule (FORWARD)  -> DNS forwarder: domain, target addresses
Roles: tag Role (or BindingRole), else by convention (zone-<name>, record-<type>-<name>, forwarder-<domain>); an edge
service fronting a service takes <kind>-<the service's role> (core inventory).
"""
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.edge.imports import forwarder_role, record_role, zone_role
from opsdir.domains.edge.resolve import endpoint_kind_named, rate_limit_fact, tls_level
from .edge import TLS_POLICIES, WAF_GROUPS
from .tags import state_tags as _tags

CATEGORIES = {group: category for category, group in WAF_GROUPS.items()}
_DEFAULT_DRAIN, _DEFAULT_IDLE = "300", "60"


def _first(v):
    """The first object of a nested block as state keeps it (a list of objects), or {}."""
    return (v[0] if v else {}) if isinstance(v, list) else (v or {})


def tls_mode(lb, listeners, groups):
    """How a load balancer handles TLS, from its type and its listeners' and target groups' protocols."""
    protocols = {(ls.get("protocol") or "").upper() for ls in listeners}
    if lb.get("load_balancer_type") == "application" or protocols & {"HTTPS", "TLS"}:
        return "reencrypt" if {(g.get("protocol") or "").upper() for g in groups} & {"HTTPS", "TLS"} else "terminate"
    return "passthrough"


def lb_facts(lb, listeners, groups):
    """(facts, settings) of a load balancer, its listeners and the target groups they forward to: what someone chose
    (AWS's defaults left out, but the TLS mode always)."""
    facts, settings = [f"tls-mode {tls_mode(lb, listeners, groups)}"], []
    for policy in sorted({ls.get("ssl_policy") for ls in listeners if ls.get("ssl_policy")}):
        level = tls_level(TLS_POLICIES, policy)
        facts, settings = (facts + [f"tls-min {level[0]}", f"tls-profile {level[1]}"], settings) if level \
            else (facts, settings + [f"ssl_policy {policy}"])
    for g in groups:
        h, st = _first(g.get("health_check")), _first(g.get("stickiness"))
        protocol = (h.get("protocol") or "").lower()
        facts += [f"health {protocol} {h.get('path') or '/'}"] if protocol in ("http", "https") else []
        if st.get("enabled"):
            cookie = st.get("type") in ("lb_cookie", "app_cookie")
            facts += [f"stickiness cookie {st.get('cookie_duration')}" if cookie and st.get("cookie_duration")
                      else "stickiness cookie" if cookie else "stickiness source-ip"]
        drain = g.get("deregistration_delay")
        facts += [f"drain {drain}"] if drain not in (None, "") and str(drain) != _DEFAULT_DRAIN else []
    idle = lb.get("idle_timeout")
    facts += [f"idle-timeout {idle}"] if lb.get("load_balancer_type") == "application" and idle not in (None, "") \
        and str(idle) != _DEFAULT_IDLE else []
    return sorted(set(facts)), settings


def _acts(rule):
    """The rule's action, block, count, allow (managed groups: count when overridden to count)."""
    action, override = _first(rule.get("action")), _first(rule.get("override_action"))
    return "count" if override.get("count") is not None or action.get("count") is not None else \
        "allow" if action.get("allow") is not None else "block"


def _rule_facts(rule, ip_sets):
    """(facts, settings) of one web ACL rule."""
    statement = _first(rule.get("statement"))
    managed, limited = _first(statement.get("managed_rule_group_statement")), \
        _first(statement.get("rate_based_statement"))
    if managed:
        category = CATEGORIES.get(managed.get("name"))
        return ([f"waf-category {category}"], []) if category else \
            ([], [f"managed rule group {managed.get('vendor_name')}/{managed.get('name')}"])
    if limited:
        header = _first(_first(limited.get("custom_key")).get("header")).get("name")
        key = f"header:{header}" if header else "ip"
        window = limited.get("evaluation_window_sec") or 300
        kind = endpoint_kind_named(rule.get("name"))
        return ([rate_limit_fact(kind, limited.get("limit"), window, key)], []) if kind else \
            ([], [f"rate-based rule {rule.get('name')}: {limited.get('limit')}/{window}s per {key}"])
    verdict = "allow" if _acts(rule) == "allow" else "deny"
    reference = _first(statement.get("ip_set_reference_statement"))
    if reference:
        return [f"ip-rule {verdict} {c}" for c in ip_sets.get(reference.get("arn"), ())], []
    geo, negated = _first(statement.get("geo_match_statement")), _first(
        _first(_first(statement.get("not_statement")).get("statement")).get("geo_match_statement"))
    if geo or negated:
        return [f"geo-rule {'deny' if geo else 'allow'} {' '.join((geo or negated).get('country_codes') or ())}"], []
    return [], [f"rule {rule.get('name')}"]


def aliased_names(found, lb):
    """The DNS names a load balancer answers under: its own, and its CloudFront distributions'."""
    return {lb.get("dns_name"), *(d.get("domain_name") for d in of_types(found, "aws_cloudfront_distribution")
                                  for o in d.get("origin") or () if o.get("domain_name") == lb.get("dns_name"))}


def fronted(found):
    """{ARN: the load balancer ARN it fronts}: each load balancer itself, and each CloudFront distribution whose
    origin is one."""
    lbs = {a.get("dns_name"): a.get("arn") for a in of_types(found, "aws_lb", "aws_alb") if a.get("arn")}
    return {**{arn: arn for arn in lbs.values()},
            **{d.get("arn"): lbs[o.get("domain_name")] for d in of_types(found, "aws_cloudfront_distribution")
               for o in d.get("origin") or () if o.get("domain_name") in lbs}}


def edge_services(found):
    """The web ACLs, Shield protections and CloudFront distributions in front of the environment's load balancers."""
    fronts = fronted(found)
    ip_sets = {a.get("arn"): tuple(a.get("addresses") or ()) for a in of_types(found, "aws_wafv2_ip_set")}
    attached = {**{a.get("web_acl_arn"): a.get("resource_arn")
                   for a in of_types(found, "aws_wafv2_web_acl_association")},
                **{d.get("web_acl_id"): d.get("arn") for d in of_types(found, "aws_cloudfront_distribution")
                   if d.get("web_acl_id")}}
    automatic = {a.get("resource_arn") for a in of_types(found, "aws_shield_application_layer_automatic_response")}

    def acl(a):
        rules = a.get("rule") or ()
        parts = [_rule_facts(r, ip_sets) for r in rules]
        mode = "detect" if rules and all(_acts(r) == "count" for r in rules) else "block"
        return resource("edge", a.get("arn"), {
            "ciamEdgeKind": "waf", "ciamEdgeFact": sorted({f"waf-mode {mode}", *(f for fs, _ in parts for f in fs)}),
            "ciamEdgeSetting": sorted({s for _, ss in parts for s in ss})},
            links={"ciamServiceRole": fronts.get(attached.get(a.get("arn")))}, name=a.get("name"),
            role=tagged_role(_tags(a)), tags=_tags(a))
    return (*(acl(a) for a in of_types(found, "aws_wafv2_web_acl") if a.get("arn")),
            *(resource("edge", a.get("arn") or f"shield:{a.get('resource_arn')}", {
                "ciamEdgeKind": "ddos", "ciamEdgeFact": "ddos application-advanced"
                if a.get("resource_arn") in automatic else "ddos network-advanced"},
                links={"ciamServiceRole": fronts.get(a.get("resource_arn"))}, name=a.get("name"),
                role=tagged_role(_tags(a)), tags=_tags(a))
              for a in of_types(found, "aws_shield_protection")),
            *(resource("edge", d.get("arn"), {
                "ciamEdgeKind": "cdn", "ciamEdgeFact": "cdn on",
                "ciamEdgeSetting": f"minimum_protocol_version {minimum}" if minimum else None},
                links={"ciamServiceRole": fronts.get(d.get("arn"))}, name=d.get("id") or d.get("arn"),
                role=tagged_role(_tags(d)), tags=_tags(d))
              for d in of_types(found, "aws_cloudfront_distribution") if d.get("arn")
              for minimum in (_first(d.get("viewer_certificate")).get("minimum_protocol_version"),)))


def routing(record):
    """{ciamRoutingPolicy, ciamRoutingWeight} of a Route 53 record's routing policy, or {}."""
    failover, weighted = _first(record.get("failover_routing_policy")), _first(record.get("weighted_routing_policy"))
    if failover:
        return {"ciamRoutingPolicy": f"failover-{'primary' if failover.get('type') == 'PRIMARY' else 'secondary'}"}
    if weighted:
        return {"ciamRoutingPolicy": "weighted", "ciamRoutingWeight": weighted.get("weight")}
    return {}


def service_dns(record):
    """What a service name's own Route 53 record says of its DNS: TTL (an alias takes the load balancer's 60 s) and
    routing."""
    return {"ciamTtlSeconds": "60" if record.get("alias") else record.get("ttl"), **routing(record)}


def _name(record):
    return (record.get("fqdn") or record.get("name") or "").rstrip(".")


def dns_resources(found, served):
    """(zones, records, forwarders, notices); served: the records services already account for (by id)."""
    zones = {a.get("zone_id"): (a.get("name") or "").rstrip(".") for a in of_types(found, "aws_route53_zone")}
    routed = {_name(r) for r in of_types(found, "aws_route53_record") if r.get("alias") and r.get("set_identifier")}
    elsewhere = [r for r in of_types(found, "aws_route53_record") if id(r) not in served and not r.get("alias")
                 and r.get("set_identifier") and _name(r) in routed]
    records = [r for r in of_types(found, "aws_route53_record") if id(r) not in served and r not in elsewhere]
    return (tuple(resource("zone", a.get("zone_id"), {
                "ciamDnsZone": zones[a.get("zone_id")], "ciamProviderRef": a.get("zone_id"),
                "ciamZoneVisibility": "private" if a.get("vpc") else "public"},
                name=zones[a.get("zone_id")], role=tagged_role(_tags(a)) or zone_role(zones[a.get("zone_id")]),
                           tags=_tags(a))
                  for a in of_types(found, "aws_route53_zone") if a.get("zone_id")),
            tuple(resource("record", f"{r.get('zone_id')}/{_name(r)}/{r.get('type')}/{r.get('set_identifier') or ''}",
                           {"ciamRecordName": _name(r), "ciamRecordType": r.get("type"), "ciamTtlSeconds": r.get("ttl"),
                            "ciamRecordValue": list(r.get("records") or ()) or
                            [_first(r.get("alias")).get("name")], "ciamDnsZone": zones.get(r.get("zone_id")),
                            **routing(r)},
                           name=f"{r.get('type')}-{_name(r)}".lower(), role=record_role(_name(r), r.get("type")))
                  for r in records),
            tuple(resource("forwarder", a.get("id"), {
                "ciamForwardDomain": (a.get("domain_name") or "").rstrip("."), "ciamForwardDirection": "outbound",
                "ciamForwardTarget": [t.get("ip") for t in a.get("target_ip") or ()], "ciamProviderRef": a.get("id")},
                name=a.get("name") or a.get("id"),
                role=tagged_role(_tags(a)) or forwarder_role((a.get("domain_name"),)), tags=_tags(a))
                  for a in of_types(found, "aws_route53_resolver_rule") if a.get("rule_type") == "FORWARD"),
            tuple(f"Route 53 record {r.get('type')} {_name(r)} ({r.get('set_identifier')}) answers for another "
                  "environment of a routed name: not recorded here" for r in elsewhere))


def lb_security_groups(found):
    """The security groups load balancers use: their rules are the load balancer's, not the record's."""
    return {g for lb in of_types(found, "aws_lb", "aws_alb") for g in lb.get("security_groups") or ()}
