"""What Azure's edge runs, read back in the edge domain's terms (Terraform state attribute names). Pure.

  azurerm_lb (rules, probes)                -> facts on its service name: tls-mode passthrough, an HTTP(S) probe,
                                               source-address distribution, an idle timeout other than 4 minutes
  azurerm_application_gateway               -> a service name like a load balancer's (DNS name from the record holding
                                               its frontend address, listener ports, the role of the servers whose
                                               addresses its pool holds) with tls-mode terminate or reencrypt, the
                                               listener's TLS policy through the TLS table, its probe, cookie affinity,
                                               request timeout, draining
  azurerm_web_application_firewall_policy   -> edge service waf of the gateway using it: waf-mode, waf-category (the
                                               managed rule sets the WAF table knows), rate-limit (custom rules named
                                               rate<kind>), ip-rule, geo-rule; others are settings
  azurerm_cdn_frontdoor_profile (+ origin,  -> edge service cdn in front of the service whose public address its origin
    azurerm_cdn_frontdoor_firewall_policy)     names, and the Front Door firewall policy as its waf
  azurerm_network_ddos_protection_plan      -> edge service ddos (network-advanced)
  azurerm_traffic_manager_profile           -> a routed service name's routing (its own address's endpoint: primary
    (+ external endpoints)                     by priority, or its weight); the others' endpoints are named
  azurerm_dns_zone, azurerm_private_dns_zone -> DNS zones (public, private)
  azurerm_(private_)dns_<type>_record       -> DNS records not answering for a service name (name, type, TTL, values)
  azurerm_private_dns_resolver_forwarding_rule -> DNS forwarders
Roles as on AWS: tag Role, else by convention; an edge service takes <kind>-<the role of the service it fronts>.
"""
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.edge.imports import forwarder_role, record_role, zone_role
from opsdir.domains.edge.resolve import endpoint_kind_named, rate_limit_fact, tls_level
from .edge import TLS_POLICIES

RULE_SETS = {"Microsoft_DefaultRuleSet": "core-rules", "Microsoft_BotManagerRuleSet": "bot-control"}
RECORD_TYPES = ("a", "aaaa", "cname", "txt", "mx", "srv", "caa", "ns")


def _low(x):
    return (x or "").lower()


def _first(v):
    return (v[0] if v else {}) if isinstance(v, list) else (v or {})


def _tags(a):
    return a.get("tags") or {}


def fqdn(record):
    """A record's full name from its relative name and zone."""
    name, zone = record.get("name"), (record.get("zone_name") or "").rstrip(".")
    return zone if name == "@" else f"{name}.{zone}"


def _probe_fact(p):
    protocol = _low(p.get("protocol"))
    return [f"health {protocol} {p.get('request_path') or p.get('path') or '/'}"] if protocol in ("http", "https") \
        else []


def lb_facts(lb, found):
    """(facts, settings) of a Standard load balancer: TLS passes through; its probes and rules' choices."""
    rules = [r for r in of_types(found, "azurerm_lb_rule") if _low(r.get("loadbalancer_id")) == _low(lb.get("id"))]
    probes = [p for p in of_types(found, "azurerm_lb_probe") if _low(p.get("loadbalancer_id")) == _low(lb.get("id"))]
    idle = {r.get("idle_timeout_in_minutes") for r in rules} - {None, 4, "4"}
    return sorted({"tls-mode passthrough", *(f for p in probes for f in _probe_fact(p)),
                   *(["stickiness source-ip"] if any(str(r.get("load_distribution") or "").startswith("SourceIP")
                                                     for r in rules) else []),
                   *(f"idle-timeout {int(i) * 60}" for i in idle)}), []


def gateway_facts(gw):
    """(facts, settings) of an Application Gateway."""
    settings = gw.get("backend_http_settings") or []
    mode = "reencrypt" if any(_low(s.get("protocol")) == "https" for s in settings) else "terminate"
    policy = _first(gw.get("ssl_policy"))
    name = policy.get("policy_name")
    level = tls_level(TLS_POLICIES, name) if name else None
    facts = {f"tls-mode {mode}", *((f"tls-min {level[0]}", f"tls-profile {level[1]}") if level else ()),
             *(f for p in gw.get("probe") or () for f in _probe_fact(p)),
             *(["stickiness cookie"] if any(s.get("cookie_based_affinity") == "Enabled" for s in settings) else []),
             *(f"idle-timeout {s.get('request_timeout')}" for s in settings
               if s.get("request_timeout") not in (None, 30, "30")),
             *(f"drain {d.get('drain_timeout_sec')}" for s in settings for d in s.get("connection_draining") or ()
               if d.get("enabled"))}
    return sorted(facts), ([f"ssl_policy {name}"] if name and not level else [])


def _custom_rule_facts(rule):
    """(facts, settings) of a WAF custom rule (Application Gateway or Front Door)."""
    condition = _first(rule.get("match_conditions") or rule.get("match_condition"))
    operator, values = condition.get("operator"), list(condition.get("match_values") or ())
    verdict = "allow" if rule.get("action") == "Allow" else "deny"
    if rule.get("rule_type") == "RateLimitRule" or rule.get("type") == "RateLimitRule":
        kind = endpoint_kind_named(rule.get("name"))
        seconds = 60 if rule.get("rate_limit_duration") == "OneMin" or \
            str(rule.get("rate_limit_duration_in_minutes")) == "1" else 300
        return ([rate_limit_fact(kind, rule.get("rate_limit_threshold"), seconds, "ip")], []) if kind else \
            ([], [f"rate limit rule {rule.get('name')}: {rule.get('rate_limit_threshold')}/{seconds}s"])
    if operator == "IPMatch":
        return [f"ip-rule {verdict} {v if '/' in v else v + '/32'}" for v in values], []
    if operator == "GeoMatch":
        return [f"geo-rule {'allow' if condition.get('negation_condition') else 'deny'} {' '.join(values)}"], []
    return [], [f"custom rule {rule.get('name')}"]


def waf_facts(policy):
    """(facts, settings) of an Application Gateway or Front Door WAF policy."""
    mode = (_first(policy.get("policy_settings")).get("mode") or policy.get("mode") or "Prevention")
    sets = [s.get("type") for m in policy.get("managed_rules") or () for s in m.get("managed_rule_set") or ()] + \
        [m.get("type") for m in policy.get("managed_rule") or ()]
    parts = [_custom_rule_facts(r) for r in (policy.get("custom_rules") or policy.get("custom_rule") or ())]
    return (sorted({f"waf-mode {'detect' if mode == 'Detection' else 'block'}",
                    *(f"waf-category {RULE_SETS[t]}" for t in sets if t in RULE_SETS),
                    *(f for fs, _ in parts for f in fs)}),
            sorted({*(f"managed rule set {t}" for t in sets if t not in RULE_SETS), *(s for _, ss in parts for s in ss),
                    *(f"exclusion {x.get('match_variable')} {x.get('selector')}"
                      for m in policy.get("managed_rules") or () for x in m.get("exclusion") or ())}))


def frontdoor_origins(found):
    """{public address an origin names: Front Door profile id}."""
    groups = {_low(g.get("id")): _low(g.get("cdn_frontdoor_profile_id"))
              for g in of_types(found, "azurerm_cdn_frontdoor_origin_group")}
    return {o.get("host_name"): groups.get(_low(o.get("cdn_frontdoor_origin_group_id")))
            for o in of_types(found, "azurerm_cdn_frontdoor_origin") if o.get("host_name")}


def frontdoor_endpoints(found):
    """{endpoint host name: profile id}."""
    return {e.get("host_name"): _low(e.get("cdn_frontdoor_profile_id"))
            for e in of_types(found, "azurerm_cdn_frontdoor_endpoint") if e.get("host_name")}


def _firewall_of(security_policy):
    return _first(_first(security_policy.get("security_policies")).get("firewall"))


def edge_services(found, services_by_address, gateways):
    """WAF policies, Front Door profiles and their firewall policies, DDoS plans. services_by_address: {frontend
    address: service resource ref}; gateways: {WAF policy id: gateway id}."""
    origins = frontdoor_origins(found)
    fronting = {profile: services_by_address.get(address) for address, profile in origins.items()}
    secured = {_low(sp.get("cdn_frontdoor_profile_id")): _low(_firewall_of(sp).get("cdn_frontdoor_firewall_policy_id"))
               for sp in of_types(found, "azurerm_cdn_frontdoor_security_policy")}
    by_policy = {policy: fronting.get(profile) for profile, policy in secured.items()}

    def waf(p, fronts):
        facts, settings = waf_facts(p)
        return resource("edge", p.get("id"), {"ciamEdgeKind": "waf", "ciamEdgeFact": facts,
                                              "ciamEdgeSetting": settings},
                        links={"ciamServiceRole": fronts}, name=p.get("name"), role=tagged_role(_tags(p)), tags=_tags(p))
    return (*(waf(p, gateways.get(_low(p.get("id"))))
              for p in of_types(found, "azurerm_web_application_firewall_policy")),
            *(waf(p, by_policy.get(_low(p.get("id"))))
              for p in of_types(found, "azurerm_cdn_frontdoor_firewall_policy")),
            *(resource("edge", p.get("id"), {"ciamEdgeKind": "cdn", "ciamEdgeFact": "cdn on",
                                              "ciamEdgeSetting": f"sku {p.get('sku_name')}"},
                       links={"ciamServiceRole": fronting.get(_low(p.get("id")))}, name=p.get("name"),
                       role=tagged_role(_tags(p)), tags=_tags(p)) for p in of_types(found, "azurerm_cdn_frontdoor_profile")),
            *(resource("edge", p.get("id"), {"ciamEdgeKind": "ddos", "ciamEdgeFact": "ddos network-advanced"},
                       name=p.get("name"), role=tagged_role(_tags(p)), tags=_tags(p))
              for p in of_types(found, "azurerm_network_ddos_protection_plan")))


def traffic_routing(found, address):
    """(service routing attributes, other endpoints' addresses) when a Traffic Manager profile routes to address."""
    for profile in of_types(found, "azurerm_traffic_manager_profile"):
        endpoints = [e for e in of_types(found, "azurerm_traffic_manager_external_endpoint")
                     if _low(e.get("profile_id")) == _low(profile.get("id"))]
        own = next((e for e in endpoints if e.get("target") == address), None)
        if own is None:
            continue
        others = tuple(e.get("target") for e in endpoints if e is not own)
        if profile.get("traffic_routing_method") == "Weighted":
            return {"ciamRoutingPolicy": "weighted", "ciamRoutingWeight": own.get("weight")}, others, profile
        first = min(int(e.get("priority") or 1) for e in endpoints)
        return ({"ciamRoutingPolicy": "failover-primary" if int(own.get("priority") or 1) == first
                 else "failover-secondary"}, others, profile)
    return {}, (), None


def _values(t, r):
    if t in ("a", "aaaa", "ns"):
        return list(r.get("records") or ())
    if t == "cname":
        return [r.get("record")]
    keys = {"txt": ("value",), "mx": ("preference", "exchange"), "srv": ("priority", "weight", "port", "target"),
            "caa": ("flags", "tag", "value")}[t]
    return [" ".join(str(x.get(k)) if not (t == "caa" and k == "value") else f'"{x.get(k)}"' for k in keys)
            for x in r.get("record") or ()]


def dns_resources(found, served):
    """(zones, records, forwarders): served are the records answering for service names (by identity)."""
    zones = [(z, "public") for z in of_types(found, "azurerm_dns_zone")] + \
        [(z, "private") for z in of_types(found, "azurerm_private_dns_zone")]
    records = [(t, r) for t in RECORD_TYPES
               for r in of_types(found, f"azurerm_dns_{t}_record", f"azurerm_private_dns_{t}_record")
               if id(r) not in served and r.get("name") and r.get("zone_name")]
    return (tuple(resource("zone", z.get("id") or z.get("name"), {
                "ciamDnsZone": (z.get("name") or "").rstrip("."), "ciamZoneVisibility": visibility,
                "ciamProviderRef": z.get("id")}, name=z.get("name"),
                role=tagged_role(_tags(z)) or zone_role(z.get("name")), tags=_tags(z)) for z, visibility in zones if z.get("name")),
            tuple(resource("record", r.get("id") or f"{fqdn(r)}/{t}", {
                "ciamRecordName": fqdn(r), "ciamRecordType": t.upper(), "ciamTtlSeconds": r.get("ttl"),
                "ciamRecordValue": _values(t, r), "ciamDnsZone": (r.get("zone_name") or "").rstrip(".")},
                name=f"{t}-{fqdn(r)}", role=tagged_role(_tags(r)) or record_role(fqdn(r), t.upper()), tags=_tags(r))
                  for t, r in records),
            tuple(resource("forwarder", f.get("id"), {
                "ciamForwardDomain": (f.get("domain_name") or "").rstrip("."), "ciamForwardDirection": "outbound",
                "ciamForwardTarget": [t.get("ip_address") for t in f.get("target_dns_servers") or ()],
                "ciamProviderRef": f.get("id")}, name=f.get("name"),
                role=forwarder_role((f.get("domain_name"),)))
                  for f in of_types(found, "azurerm_private_dns_resolver_forwarding_rule")))

