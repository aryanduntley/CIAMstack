"""The edge read back from Azure CLI output: an Application Gateway with its WAF policy, Front Door (profile, endpoint,
origin group, origin, security policy, firewall policy), a DDoS plan, a load balancer's probe and rules, Traffic
Manager, DNS zones and record sets of several types, forwarding rules: the same facts and edge services as from
Terraform state."""
import json

from opsdir_adapter_azure.cli import cli_resources

RG = "/subscriptions/0/resourceGroups/rg-ciam-prod/providers"
GW, WAF, PIP = f"{RG}/Microsoft.Network/applicationGateways/agw-sso", \
    f"{RG}/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-sso", \
    f"{RG}/Microsoft.Network/publicIPAddresses/pip-sso"
FD = f"{RG}/Microsoft.Cdn/profiles/afd-sso"


def _outputs():
    docs = {
        "nics.json": [{"type": "Microsoft.Network/networkInterfaces", "id": "nic-1", "ipConfigurations": [
            {"primary": True, "privateIPAddress": "10.60.2.10", "subnet": {"id": f"{RG}/x/virtualNetworks/v/subnets/s"}}]}],
        "vms.json": [{"type": "Microsoft.Compute/virtualMachines", "id": "vm-1", "name": "pf-1",
                      "tags": {"Role": "pf-engine"}, "networkProfile": {"networkInterfaces": [{"id": "nic-1"}]}}],
        "pips.json": [{"type": "Microsoft.Network/publicIPAddresses", "id": PIP, "name": "pip-sso",
                       "ipAddress": "198.51.100.77"}],
        "gateways.json": [{"type": "Microsoft.Network/applicationGateways", "id": GW, "name": "agw-sso",
                           "firewallPolicy": {"id": WAF},
                           "frontendIPConfigurations": [{"name": "frontend", "publicIPAddress": {"id": PIP}}],
                           "frontendPorts": [{"name": "port-443", "port": 443}],
                           "backendAddressPools": [{"name": "servers", "backendAddresses": [{"ipAddress": "10.60.2.10"}]}],
                           "backendHttpSettingsCollection": [{"name": "s", "protocol": "Https",
                                                              "cookieBasedAffinity": "Enabled", "requestTimeout": 120,
                                                              "connectionDraining": {"enabled": True,
                                                                                     "drainTimeoutInSec": 30}}],
                           "probes": [{"name": "h", "protocol": "Https", "path": "/pf/heartbeat.ping"}],
                           "sslPolicy": {"policyType": "Predefined", "policyName": "AppGwSslPolicy20220101"}}],
        "waf-policies.json": [{"type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies", "id": WAF,
                               "name": "waf-sso", "policySettings": {"mode": "Prevention"},
                               "managedRules": {"managedRuleSets": [{"ruleSetType": "Microsoft_DefaultRuleSet",
                                                                     "ruleSetVersion": "2.1"}]},
                               "customRules": [{"name": "ratetoken", "ruleType": "RateLimitRule", "action": "Block",
                                                "rateLimitThreshold": 100, "rateLimitDuration": "FiveMins",
                                                "matchConditions": [{"operator": "Regex", "matchValues": ["x"]}]},
                                               {"name": "geo0", "ruleType": "MatchRule", "action": "Block",
                                                "matchConditions": [{"operator": "GeoMatch", "negationConditon": True,
                                                                     "matchValues": ["US"]}]}]}],
        "afd.json": [{"type": "Microsoft.Cdn/profiles", "id": FD, "name": "afd-sso",
                      "sku": {"name": "Premium_AzureFrontDoor"}},
                     {"type": "Microsoft.Cdn/profiles/afdEndpoints", "id": f"{FD}/afdEndpoints/e",
                      "hostName": "e-abc.z01.azurefd.net"},
                     {"type": "Microsoft.Cdn/profiles/originGroups", "id": f"{FD}/originGroups/servers"},
                     {"type": "Microsoft.Cdn/profiles/originGroups/origins",
                      "id": f"{FD}/originGroups/servers/origins/o", "hostName": "198.51.100.77"}],
        "ddos.json": [{"type": "Microsoft.Network/ddosProtectionPlans", "id": "ddos", "name": "ddos",
                       "tags": {"Role": "ddos-plan"}}],
        "zones.json": [{"type": "Microsoft.Network/dnszones", "id": f"{RG}/Microsoft.Network/dnszones/example.test",
                        "name": "example.test"}],
        "records.json": [
            {"type": "Microsoft.Network/dnszones/CNAME", "id": f"{RG}/Microsoft.Network/dnszones/example.test/CNAME/sso",
             "name": "sso", "TTL": 300, "cnameRecord": {"cname": "e-abc.z01.azurefd.net"}},
            {"type": "Microsoft.Network/dnszones/TXT", "id": f"{RG}/Microsoft.Network/dnszones/example.test/TXT/_v",
             "name": "_v", "TTL": 3600, "txtRecords": [{"value": ["token=abc"]}]},
            {"type": "Microsoft.Network/dnszones/NS", "id": f"{RG}/Microsoft.Network/dnszones/example.test/NS/@",
             "name": "@", "TTL": 172800, "nsRecords": [{"nsdname": "ns1-01.azure-dns.com."}]}],
        "rules.json": [{"type": "Microsoft.Network/dnsForwardingRulesets/forwardingRules", "id": "fr-1", "name": "ad",
                        "domainName": "ad.corp.example.", "forwardingRuleState": "Enabled",
                        "targetDnsServers": [{"ipAddress": "10.9.0.2", "port": 53}]}]}
    return {p: json.dumps(d) for p, d in docs.items()}


def test_the_cli_reads_the_edge_back_like_state():
    resources, _ = cli_resources(_outputs())
    (sso,) = [r for r in resources if r.kind == "service"]
    assert set(sso.attrs["ciamEdgeFact"]) == {"tls-mode reencrypt", "tls-min 1.2", "tls-profile intermediate",
                                              "health https /pf/heartbeat.ping", "stickiness cookie",
                                              "idle-timeout 120", "drain 30"}
    assert (sso.attrs["ciamFqdn"], sso.attrs["ciamTtlSeconds"], sso.attrs["ciamTargetRole"]) == \
        (("sso.example.test",), ("300",), ("pf-engine",))
    edge = sorted((r.attrs["ciamEdgeKind"][0], r.links.get("ciamServiceRole"), r.attrs.get("ciamEdgeFact"))
                  for r in resources if r.kind == "edge")
    assert edge == [("cdn", GW, ("cdn on",)), ("ddos", None, ("ddos network-advanced",)),
                    ("waf", GW, ("geo-rule allow US", "rate-limit token 100/300s per ip", "waf-category core-rules",
                                 "waf-mode block"))]
    assert [(r.attrs["ciamDnsZone"]) for r in resources if r.kind == "zone"] == [("example.test",)]
    (txt,) = [r for r in resources if r.kind == "record"]               # the CNAME is sso's, the apex NS the zone's
    assert (txt.attrs["ciamRecordName"], txt.attrs["ciamRecordValue"]) == (("_v.example.test",), ("token=abc",))
    (fwd,) = [r for r in resources if r.kind == "forwarder"]
    assert fwd.attrs["ciamForwardTarget"] == ("10.9.0.2",)
