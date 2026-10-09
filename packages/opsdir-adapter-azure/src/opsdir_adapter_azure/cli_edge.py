"""What the Azure CLI reports about an environment's edge, item by item from the ARM type, normalized to the
hashicorp/azurerm attribute names the shared mapping reads (opsdir_adapter_azure.edge_inventory). Pure.

  az network application-gateway list            Microsoft.Network/applicationGateways
  az network application-gateway waf-policy list  Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies
  az afd profile / endpoint / origin-group /     Microsoft.Cdn/profiles, …/afdEndpoints, …/originGroups,
    origin / security-policy list                  …/originGroups/origins, …/securityPolicies
  az network front-door waf-policy list          Microsoft.Network/frontdoorWebApplicationFirewallPolicies
  az network ddos-protection list                Microsoft.Network/ddosProtectionPlans
  az network traffic-manager profile list        Microsoft.Network/trafficManagerProfiles (with its endpoints)
  az network dns zone list,                      Microsoft.Network/dnszones, Microsoft.Network/privateDnsZones
    az network private-dns zone list
  az network dns record-set list,                Microsoft.Network/dnszones/<TYPE>, …/privateDnsZones/<TYPE>
    az network private-dns record-set list
  az dns-resolver forwarding-rule list           Microsoft.Network/dnsForwardingRulesets/forwardingRules
"""
from .arm_ids import arm_segment

RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS")


def _low(x):
    return (x or "").lower()


def _id(ref):
    return (ref or {}).get("id") if isinstance(ref, dict) else None


def _of(items, kind):
    return [i for k, i in items if k == kind.lower()]


def _parent(arm_id, after):
    """The ARM ID up to and including the segment after `after` (…/profiles/<name>)."""
    parts = (arm_id or "").split("/")
    low = [p.lower() for p in parts]
    return "/".join(parts[:low.index(after.lower()) + 2]) if after.lower() in low else None


def _gateways(items):
    return [("azurerm_application_gateway", {
                "id": g.get("id"), "name": g.get("name"), "tags": g.get("tags") or {},
                "firewall_policy_id": _id(g.get("firewallPolicy")),
                "frontend_ip_configuration": [{"name": f.get("name"), "private_ip_address": f.get("privateIPAddress"),
                                               "public_ip_address_id": _id(f.get("publicIPAddress"))}
                                              for f in g.get("frontendIPConfigurations") or ()],
                "frontend_port": [{"name": p.get("name"), "port": p.get("port")} for p in g.get("frontendPorts") or ()],
                "backend_address_pool": [{"name": p.get("name"),
                                          "ip_addresses": [a.get("ipAddress") for a in p.get("backendAddresses") or ()
                                                           if a.get("ipAddress")]}
                                         for p in g.get("backendAddressPools") or ()],
                "backend_http_settings": [{"name": s.get("name"), "protocol": s.get("protocol"),
                                           "cookie_based_affinity": s.get("cookieBasedAffinity"),
                                           "request_timeout": s.get("requestTimeout"),
                                           "connection_draining": [{"enabled": (s.get("connectionDraining") or {})
                                                                    .get("enabled"),
                                                                    "drain_timeout_sec":
                                                                        (s.get("connectionDraining") or {})
                                                                        .get("drainTimeoutInSec")}]}
                                          for s in g.get("backendHttpSettingsCollection") or ()],
                "probe": [{"name": p.get("name"), "protocol": p.get("protocol"), "path": p.get("path")}
                          for p in g.get("probes") or ()],
                "ssl_policy": [{"policy_type": (g.get("sslPolicy") or {}).get("policyType"),
                                "policy_name": (g.get("sslPolicy") or {}).get("policyName")}]})
            for g in _of(items, "Microsoft.Network/applicationGateways")]


def _condition(c):
    return {"operator": c.get("operator"), "match_values": c.get("matchValues") or c.get("matchValue") or [],
            "negation_condition": c.get("negationConditon") or c.get("negationCondition") or
            c.get("negateCondition") or False}


def _waf_policies(items):
    gateway = _of(items, "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies")
    frontdoor = _of(items, "Microsoft.Network/frontdoorWebApplicationFirewallPolicies")
    return [*(("azurerm_web_application_firewall_policy", {
                "id": p.get("id"), "name": p.get("name"), "tags": p.get("tags") or {},
                "policy_settings": [{"mode": (p.get("policySettings") or {}).get("mode")}],
                "managed_rules": [{
                    "managed_rule_set": [{"type": s.get("ruleSetType"), "version": s.get("ruleSetVersion")}
                                         for s in (p.get("managedRules") or {}).get("managedRuleSets") or ()],
                    "exclusion": [{"match_variable": x.get("matchVariable"), "selector": x.get("selector")}
                                  for x in (p.get("managedRules") or {}).get("exclusions") or ()]}],
                "custom_rules": [{"name": r.get("name"), "rule_type": r.get("ruleType"), "action": r.get("action"),
                                  "rate_limit_threshold": r.get("rateLimitThreshold"),
                                  "rate_limit_duration": r.get("rateLimitDuration"),
                                  "match_conditions": [_condition(c) for c in r.get("matchConditions") or ()]}
                                 for r in p.get("customRules") or ()]}) for p in gateway),
            *(("azurerm_cdn_frontdoor_firewall_policy", {
                "id": p.get("id"), "name": p.get("name"), "tags": p.get("tags") or {},
                "mode": (p.get("policySettings") or {}).get("mode"),
                "managed_rule": [{"type": s.get("ruleSetType"), "version": s.get("ruleSetVersion")}
                                 for s in (p.get("managedRules") or {}).get("managedRuleSets") or ()],
                "custom_rule": [{"name": r.get("name"), "type": r.get("ruleType"), "action": r.get("action"),
                                 "rate_limit_threshold": r.get("rateLimitThreshold"),
                                 "rate_limit_duration_in_minutes": r.get("rateLimitDurationInMinutes"),
                                 "match_condition": [_condition(c) for c in r.get("matchConditions") or ()]}
                                for r in (p.get("customRules") or {}).get("rules") or ()]}) for p in frontdoor)]


def _front_door(items):
    return [*(("azurerm_cdn_frontdoor_profile", {"id": p.get("id"), "name": p.get("name"), "tags": p.get("tags") or {},
                                                 "sku_name": (p.get("sku") or {}).get("name")})
              for p in _of(items, "Microsoft.Cdn/profiles")),
            *(("azurerm_cdn_frontdoor_endpoint", {"id": e.get("id"), "host_name": e.get("hostName"),
                                                  "cdn_frontdoor_profile_id": _parent(e.get("id"), "profiles")})
              for e in _of(items, "Microsoft.Cdn/profiles/afdEndpoints")),
            *(("azurerm_cdn_frontdoor_origin_group", {"id": g.get("id"),
                                                      "cdn_frontdoor_profile_id": _parent(g.get("id"), "profiles")})
              for g in _of(items, "Microsoft.Cdn/profiles/originGroups")),
            *(("azurerm_cdn_frontdoor_origin", {"id": o.get("id"), "host_name": o.get("hostName"),
                                                "cdn_frontdoor_origin_group_id": _parent(o.get("id"), "originGroups")})
              for o in _of(items, "Microsoft.Cdn/profiles/originGroups/origins")),
            *(("azurerm_cdn_frontdoor_security_policy", {
                "cdn_frontdoor_profile_id": _parent(s.get("id"), "profiles"),
                "security_policies": [{"firewall": [{"cdn_frontdoor_firewall_policy_id":
                                                     _id((s.get("parameters") or {}).get("wafPolicy"))}]}]})
              for s in _of(items, "Microsoft.Cdn/profiles/securityPolicies"))]


def _traffic_managers(items):
    profiles = _of(items, "Microsoft.Network/trafficManagerProfiles")
    return [*(("azurerm_traffic_manager_profile", {"id": p.get("id"), "name": p.get("name"),
                                                   "traffic_routing_method": p.get("trafficRoutingMethod"),
                                                   "fqdn": (p.get("dnsConfig") or {}).get("fqdn")})
              for p in profiles),
            *(("azurerm_traffic_manager_external_endpoint", {"profile_id": p.get("id"), "target": e.get("target"),
                                                             "priority": e.get("priority"), "weight": e.get("weight")})
              for p in profiles for e in p.get("endpoints") or ()
              if _low(e.get("type")).endswith("externalendpoints"))]


def _record_values(item, record_type):
    """A record set's values in azurerm's names for its type."""
    t = record_type.lower()
    if t in ("a", "aaaa"):
        return {"records": [a.get("ipv4Address") or a.get("ipv6Address")
                            for a in item.get(f"{t}Records") or item.get(f"{record_type}Records") or ()]}
    if t == "cname":
        return {"record": (item.get("cnameRecord") or item.get("CNAMERecord") or {}).get("cname")}
    if t == "ns":
        return {"records": [n.get("nsdname") for n in item.get("nsRecords") or ()]}
    if t == "txt":
        return {"record": [{"value": "".join(r.get("value") or ())} for r in item.get("txtRecords") or ()]}
    if t == "mx":
        return {"record": [{"preference": r.get("preference"), "exchange": r.get("exchange")}
                           for r in item.get("mxRecords") or ()]}
    if t == "srv":
        return {"record": [{k: r.get(k) for k in ("priority", "weight", "port", "target")}
                           for r in item.get("srvRecords") or ()]}
    return {"record": [{"flags": r.get("flags"), "tag": r.get("tag"), "value": r.get("value")}
                       for r in item.get("caaRecords") or ()]}


def _dns(items):
    zones = [*(("azurerm_dns_zone", z) for z in _of(items, "Microsoft.Network/dnszones")),
             *(("azurerm_private_dns_zone", z) for z in _of(items, "Microsoft.Network/privateDnsZones"))]
    records = [(f"azurerm_{'private_' if private else ''}dns_{t.lower()}_record", t, r)
               for private, base, key in ((False, "Microsoft.Network/dnszones", "dnszones"),
                                          (True, "Microsoft.Network/privateDnsZones", "privateDnsZones"))
               for t in RECORD_TYPES for r in _of(items, f"{base}/{t}") if not (t == "A" or (
                   not private and t in ("NS",) and r.get("name") == "@"))]
    return [*((t, {"id": z.get("id"), "name": z.get("name"), "tags": z.get("tags") or {}}) for t, z in zones),
            *((tf, {"id": r.get("id"), "name": r.get("name"), "ttl": r.get("ttl") or r.get("TTL"),
                    "zone_name": _low(arm_segment(r.get("id"), "dnszones")
                                      or arm_segment(r.get("id"), "privateDnsZones")),
                    **_record_values(r, t)})
              for tf, t, r in records)]


def _forwarding(items):
    return [("azurerm_private_dns_resolver_forwarding_rule", {
                "id": r.get("id"), "name": r.get("name"), "domain_name": r.get("domainName"),
                "target_dns_servers": [{"ip_address": t.get("ipAddress"), "port": t.get("port")}
                                       for t in r.get("targetDnsServers") or ()]})
            for r in _of(items, "Microsoft.Network/dnsForwardingRulesets/forwardingRules")
            if _low(r.get("forwardingRuleState") or "enabled") == "enabled"]


def edge_items(items):
    """(azurerm type, attributes) pairs of the edge items (A record sets are the main reader's)."""
    return [*_gateways(items), *_waf_policies(items), *_front_door(items),
            *(("azurerm_network_ddos_protection_plan", {"id": p.get("id"), "name": p.get("name"),
                                                         "tags": p.get("tags") or {}})
              for p in _of(items, "Microsoft.Network/ddosProtectionPlans")),
            *_traffic_managers(items), *_dns(items), *_forwarding(items)]
