"""The edge read back from Azure Terraform state: an Application Gateway as a service name with its TLS mode, policy,
probe, affinity, timeout and draining as facts; its WAF policy, the Front Door in front of it with its firewall
policy, and a DDoS plan as edge services; a load balancer routed by Traffic Manager (its weight; the other environment's
endpoint named); DNS zones, records and forwarding rules."""
import json

from opsdir.core.directory import make_directory, one, values
from opsdir_adapter_azure.inventory import read_terraform_state
from support import imported_directory

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"
RG = "/subscriptions/0/resourceGroups/rg-ciam-prod/providers"
GW, WAF, PIP = f"{RG}/Microsoft.Network/applicationGateways/agw-sso", \
    f"{RG}/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-sso", \
    f"{RG}/Microsoft.Network/publicIPAddresses/pip-sso"
FD, FDWAF = f"{RG}/Microsoft.Cdn/profiles/afd-sso", f"{RG}/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/w"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return imported_directory((), {}, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="azure",
             ciamRegion="eastus2"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=sso,{B}", ("ciamServiceName",), cn="sso", ciamBindingRole="pf-sso-service",
             ciamFqdn="sso.example.test", ciamTargetRole="pf-engine", ciamPort="443"),
        _row(f"cn=api,{B}", ("ciamServiceName",), cn="api", ciamBindingRole="api-service",
             ciamFqdn="api.example.test", ciamTargetRole="pf-engine", ciamPort="443")))


def _res(type_, name, attrs):
    return {"mode": "managed", "type": type_, "name": name,
            "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
            "instances": [{"schema_version": 0, "attributes": attrs, "sensitive_attributes": []}]}


def _state():
    nic = f"{RG}/Microsoft.Network/networkInterfaces/nic-pf-1"
    return json.dumps({"version": 4, "terraform_version": "1.9.5", "serial": 1, "lineage": "e", "outputs": {},
                       "resources": [
        _res("azurerm_network_interface", "pf_1", {"id": nic, "ip_configuration": [
            {"primary": True, "private_ip_address": "10.60.2.10", "subnet_id": f"{RG}/x/virtualNetworks/v/subnets/s"}]}),
        _res("azurerm_linux_virtual_machine", "pf_1", {"id": "vm-pf-1", "name": "pf-1", "network_interface_ids": [nic],
                                                       "tags": {"Role": "pf-engine"}}),
        _res("azurerm_public_ip", "sso", {"id": PIP, "name": "pip-sso", "ip_address": "198.51.100.77"}),
        _res("azurerm_application_gateway", "sso", {
            "id": GW, "name": "agw-sso", "firewall_policy_id": WAF,
            "frontend_ip_configuration": [{"name": "frontend", "public_ip_address_id": PIP}],
            "frontend_port": [{"name": "port-443", "port": 443}],
            "backend_address_pool": [{"name": "servers", "ip_addresses": ["10.60.2.10"]}],
            "backend_http_settings": [{"name": "servers-443", "protocol": "Https", "cookie_based_affinity": "Enabled",
                                       "request_timeout": 120,
                                       "connection_draining": [{"enabled": True, "drain_timeout_sec": 30}]}],
            "probe": [{"name": "health-443", "protocol": "Https", "path": "/pf/heartbeat.ping"}],
            "ssl_policy": [{"policy_type": "Predefined", "policy_name": "AppGwSslPolicy20220101"}]}),
        _res("azurerm_web_application_firewall_policy", "sso", {
            "id": WAF, "name": "waf-sso", "policy_settings": [{"mode": "Prevention"}],
            "managed_rules": [{"managed_rule_set": [{"type": "Microsoft_DefaultRuleSet", "version": "2.1"}],
                               "exclusion": [{"match_variable": "RequestArgNames", "selector": "SAMLResponse"}]}],
            "custom_rules": [
                {"name": "denyaddresses0", "rule_type": "MatchRule", "action": "Block",
                 "match_conditions": [{"operator": "IPMatch", "match_values": ["203.0.113.0/24"]}]},
                {"name": "geo0", "rule_type": "MatchRule", "action": "Block",
                 "match_conditions": [{"operator": "GeoMatch", "negation_condition": True,
                                       "match_values": ["US", "CA"]}]},
                {"name": "ratetoken", "rule_type": "RateLimitRule", "action": "Block", "rate_limit_threshold": 100,
                 "rate_limit_duration": "FiveMins",
                 "match_conditions": [{"operator": "Regex", "match_values": ["^/as/token\\.oauth2$"]}]}]}),
        _res("azurerm_cdn_frontdoor_profile", "sso", {"id": FD, "name": "afd-sso", "sku_name": "Premium_AzureFrontDoor"}),
        _res("azurerm_cdn_frontdoor_endpoint", "sso", {"id": f"{FD}/afdEndpoints/e", "cdn_frontdoor_profile_id": FD,
                                                       "host_name": "e-abc.z01.azurefd.net"}),
        _res("azurerm_cdn_frontdoor_origin_group", "sso", {"id": f"{FD}/originGroups/servers",
                                                           "cdn_frontdoor_profile_id": FD}),
        _res("azurerm_cdn_frontdoor_origin", "sso", {"id": f"{FD}/originGroups/servers/origins/o",
                                                     "cdn_frontdoor_origin_group_id": f"{FD}/originGroups/servers",
                                                     "host_name": "198.51.100.77"}),
        _res("azurerm_cdn_frontdoor_firewall_policy", "sso", {"id": FDWAF, "name": "w", "mode": "Detection",
                                                              "managed_rule": [{"type": "Microsoft_BotManagerRuleSet",
                                                                                "version": "1.1"}]}),
        _res("azurerm_cdn_frontdoor_security_policy", "sso", {"cdn_frontdoor_profile_id": FD, "security_policies": [
            {"firewall": [{"cdn_frontdoor_firewall_policy_id": FDWAF}]}]}),
        _res("azurerm_network_ddos_protection_plan", "plan", {"id": f"{RG}/x/ddos", "name": "ddos-ciam",
                                                              "tags": {"Role": "ddos-plan"}}),
        _res("azurerm_dns_cname_record", "sso", {"id": "cname-sso", "name": "sso", "zone_name": "example.test",
                                                 "ttl": 300, "record": "e-abc.z01.azurefd.net"}),
        _res("azurerm_public_ip", "api", {"id": f"{RG}/x/pip-api", "name": "pip-api", "ip_address": "198.51.100.78"}),
        _res("azurerm_lb", "api", {"id": f"{RG}/x/lb-api", "name": "lb-api", "frontend_ip_configuration": [
            {"public_ip_address_id": f"{RG}/x/pip-api"}]}),
        _res("azurerm_lb_rule", "api", {"loadbalancer_id": f"{RG}/x/lb-api", "frontend_port": 443,
                                        "load_distribution": "SourceIP", "idle_timeout_in_minutes": 10}),
        _res("azurerm_lb_probe", "api", {"loadbalancer_id": f"{RG}/x/lb-api", "protocol": "Https",
                                         "request_path": "/health"}),
        _res("azurerm_traffic_manager_profile", "api", {"id": "tm-api", "traffic_routing_method": "Weighted",
                                                        "fqdn": "ciam-prod-api.trafficmanager.net"}),
        _res("azurerm_traffic_manager_external_endpoint", "own", {"profile_id": "tm-api", "target": "198.51.100.78",
                                                                  "weight": 3}),
        _res("azurerm_traffic_manager_external_endpoint", "other", {"profile_id": "tm-api",
                                                                    "target": "198.51.100.90", "weight": 1}),
        _res("azurerm_dns_cname_record", "api", {"id": "cname-api", "name": "api", "zone_name": "example.test",
                                                 "ttl": 60, "record": "ciam-prod-api.trafficmanager.net"}),
        _res("azurerm_dns_zone", "public", {"id": "zone-public", "name": "example.test"}),
        _res("azurerm_private_dns_zone", "corp", {"id": "zone-corp", "name": "corp.example.test"}),
        _res("azurerm_dns_mx_record", "mx", {"id": "mx", "name": "@", "zone_name": "example.test", "ttl": 3600,
                                             "record": [{"preference": 10, "exchange": "mail.example.test"}]}),
        _res("azurerm_private_dns_resolver_forwarding_rule", "ad", {
            "id": "rule-ad", "name": "ad", "domain_name": "ad.corp.example.",
            "target_dns_servers": [{"ip_address": "10.9.0.2", "port": 53}]})]})


def _imported():
    imported = read_terraform_state({"main/prod/terraform.tfstate": _state()}, _record(), ())
    return {e.dn: e for _, es in imported.groups for e in es}, imported.notices


def test_an_application_gateway_and_a_routed_load_balancer_with_what_they_run():
    entries, notices = _imported()
    sso, api = entries[f"cn=sso,{B}"], entries[f"cn=api,{B}"]
    assert set(values(sso, "ciamEdgeFact")) == {
        "tls-mode reencrypt", "tls-min 1.2", "tls-profile intermediate", "health https /pf/heartbeat.ping",
        "stickiness cookie", "idle-timeout 120", "drain 30"}
    assert (one(sso, "ciamFrontendIp"), one(sso, "ciamTtlSeconds"), one(sso, "ciamProviderRef")) == \
        ("198.51.100.77", "300", "pip-sso")
    assert set(values(api, "ciamEdgeFact")) == {"tls-mode passthrough", "health https /health",
                                                 "stickiness source-ip", "idle-timeout 600"}
    assert (one(api, "ciamRoutingPolicy"), one(api, "ciamRoutingWeight"), one(api, "ciamTtlSeconds")) == \
        ("weighted", "3", "60")
    assert any("Traffic Manager endpoint 198.51.100.90 answers for another environment" in n for n in notices)


def test_waf_policies_front_door_and_ddos_are_edge_services():
    entries, _ = _imported()
    edge = sorted((one(e, "ciamEdgeKind"), one(e, "ciamBindingRole"), values(e, "ciamEdgeFact"))
                  for e in entries.values() if "ciamEdgeService" in e.classes)
    assert edge == [
        ("cdn", "cdn-pf-sso-service", ("cdn on",)),
        ("ddos", "ddos-plan", ("ddos network-advanced",)),
        ("waf", "waf-pf-sso-service", ("geo-rule allow US CA", "ip-rule deny 203.0.113.0/24",
                                       "rate-limit token 100/300s per ip", "waf-category core-rules",
                                       "waf-mode block")),
        ("waf", "waf-pf-sso-service", ("waf-category bot-control", "waf-mode detect"))]
    (gateway_waf,) = [e for e in entries.values() if one(e, "ciamProviderRef") == WAF]
    assert values(gateway_waf, "ciamEdgeSetting") == ("exclusion RequestArgNames SAMLResponse",)


def test_zones_records_and_forwarding_rules():
    entries, _ = _imported()
    by_class = {}
    for e in entries.values():
        by_class.setdefault(next(c for c in e.classes if c != "top"), []).append(e)
    assert sorted((one(z, "ciamDnsZone"), one(z, "ciamZoneVisibility")) for z in by_class["ciamDnsZoneBinding"]) == \
        [("corp.example.test", "private"), ("example.test", "public")]
    (mx,) = by_class["ciamDnsRecord"]                         # the service names' CNAMEs are theirs
    assert (one(mx, "ciamRecordName"), values(mx, "ciamRecordValue"), one(mx, "ciamBindingRole")) == \
        ("example.test", ("10 mail.example.test",), "record-mx-example.test")
    (fwd,) = by_class["ciamDnsForwarder"]
    assert (values(fwd, "ciamForwardDomain"), values(fwd, "ciamForwardTarget")) == (("ad.corp.example",), ("10.9.0.2",))
