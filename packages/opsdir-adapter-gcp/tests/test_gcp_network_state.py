"""The network depth read back from Google Cloud: the policy firewall model (rules by secure tag read as firewall rules
of the role bound to the tag, in their policy; probe rules the load balancer's; FQDN egress rules as the policy's
allowlist; the network's enforcement order), hierarchical policies named, routes as one network-wide route table,
Private Service Connect for Google's APIs (not a service name), service attachments, peering and VPN depth, subnet
flow logs, Cloud NAT's allocation; from Terraform state and Cloud Asset Inventory / gcloud alike."""
import json

from opsdir_adapter_gcp.cli import cli_resources
from opsdir_adapter_gcp.inventory import state_resources

HOST, PROJECT = "projects/example-net", "projects/example-ciam"
NETWORK = f"{HOST}/global/networks/ciam"
POLICY = f"{HOST}/global/firewallPolicies/ciam-prod-fw-policy"
SUBNET = f"{HOST}/regions/us-central1/subnetworks/ciam-ds"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


def _rule(n, prio, direction, action, match, tags=("tagValues/1",), name=None):
    return ("google_compute_network_firewall_policy_rule", n, {
        "firewall_policy": "ciam-prod-fw-policy", "priority": prio, "direction": direction, "action": action,
        "rule_name": name, "match": [match], "target_secure_tags": [{"name": t} for t in tags]})


STATE = _state(
    ("google_compute_network", "main", {"id": NETWORK, "name": "ciam",
                                        "network_firewall_policy_enforcement_order": "BEFORE_CLASSIC_FIREWALL"}),
    ("google_compute_subnetwork", "ds", {"id": SUBNET, "name": "ciam-ds", "ip_cidr_range": "10.70.1.0/24",
                                         "network": NETWORK, "log_config": [{"aggregation_interval": "INTERVAL_5_SEC"}]}),
    ("google_compute_instance", "ds_1", {"id": f"{PROJECT}/zones/us-central1-a/instances/ds-1", "name": "ds-1",
                                         "instance_id": "8812", "metadata": {"ciam-role": "ds"},
                                         "tags": ["ciam-prod-ds"], "network_interface": [{"network_ip": "10.70.1.11"}]}),
    ("google_compute_network_firewall_policy", "p", {"id": POLICY, "name": "ciam-prod-fw-policy"}),
    ("google_compute_network_firewall_policy_association", "p", {"firewall_policy": POLICY, "attachment_target": NETWORK}),
    ("google_tags_tag_value", "ds", {"id": "tagValues/1", "short_name": "ds"}),
    ("google_tags_tag_value", "web", {"id": "tagValues/2", "short_name": "web"}),
    ("google_tags_location_tag_binding", "ds_1", {
        "parent": "//compute.googleapis.com/projects/example-ciam/zones/us-central1-a/instances/8812",
        "tag_value": "tagValues/1", "location": "us-central1-a"}),
    _rule("ldaps", 100, "INGRESS", "allow", {"src_ip_ranges": ["10.70.2.0/24"],
                                             "layer4_configs": [{"ip_protocol": "tcp", "ports": ["1636"]}]},
          name="fw-pf-ds-svc"),
    _rule("probes", 70000, "INGRESS", "allow", {"src_ip_ranges": ["35.191.0.0/16"],
                                                "layer4_configs": [{"ip_protocol": "tcp", "ports": ["1636"]}]}),
    _rule("sites_443", 80001, "EGRESS", "allow", {"dest_fqdns": ["idp.partner.test"],
                                                  "layer4_configs": [{"ip_protocol": "tcp", "ports": ["443"]}]},
          tags=("tagValues/1", "tagValues/2")),
    _rule("sites_587", 80002, "EGRESS", "allow", {"dest_fqdns": ["smtp.mail.test"],
                                                  "layer4_configs": [{"ip_protocol": "tcp", "ports": ["587"]}]}),
    _rule("deny", 2147483000, "EGRESS", "deny", {"dest_ip_ranges": ["0.0.0.0/0"],
                                                 "layer4_configs": [{"ip_protocol": "all"}]}),
    ("google_compute_firewall_policy", "org", {"id": "locations/global/firewallPolicies/991", "short_name": "org-base"}),
    ("google_compute_firewall_policy_rule", "org", {"firewall_policy": "locations/global/firewallPolicies/991"}),
    ("google_compute_route", "egress", {"id": f"{HOST}/global/routes/egress", "network": NETWORK,
                                        "dest_range": "0.0.0.0/0", "tags": ["ciam-prod-ds"],
                                        "next_hop_gateway": f"{HOST}/global/gateways/default-internet-gateway"}),
    ("google_compute_route", "dc", {"id": f"{HOST}/global/routes/dc", "network": NETWORK, "dest_range": "10.9.0.0/16",
                                    "next_hop_vpn_tunnel": f"{HOST}/regions/us-central1/vpnTunnels/to-dc"}),
    ("google_compute_global_address", "psc", {"id": f"{HOST}/global/addresses/ciam-prod-psc-apis", "address": "10.70.255.5",
                                              "purpose": "PRIVATE_SERVICE_CONNECT", "labels": {"role": "private-apis"}}),
    ("google_compute_global_address", "psa", {"id": f"{HOST}/global/addresses/ciam-services", "name": "ciam-services",
                                              "address": "10.71.0.0", "prefix_length": 20, "purpose": "VPC_PEERING",
                                              "labels": {"role": "private-services"}}),
    ("google_compute_global_forwarding_rule", "psc", {"id": f"{HOST}/global/forwardingRules/pscapis", "name": "pscapis",
                                                      "target": "all-apis",
                                                      "ip_address": f"{HOST}/global/addresses/ciam-prod-psc-apis"}),
    ("google_compute_service_attachment", "ldaps", {
        "id": f"{PROJECT}/regions/us-central1/serviceAttachments/ciam-prod-ldaps-link", "name": "ciam-prod-ldaps-link",
        "target_service": f"{PROJECT}/regions/us-central1/forwardingRules/ciam-prod-svc-ldaps",
        "connection_preference": "ACCEPT_MANUAL", "nat_subnets": [f"{PROJECT}/regions/us-central1/subnetworks/psc"],
        "consumer_accept_lists": [{"project_id_or_num": "consumer-a"}, {"network_url": "projects/b/global/networks/v"}]}),
    ("google_compute_network_peering", "hub", {"name": "to-hub", "network": NETWORK, "state": "INACTIVE",
                                               "peer_network": "projects/hub/global/networks/hub-net"}),
    ("google_compute_router", "r", {"id": f"{HOST}/regions/us-central1/routers/ciam-router", "bgp": [{"asn": 64514}]}),
    ("google_compute_router_peer", "r", {"router": f"{HOST}/regions/us-central1/routers/ciam-router", "peer_asn": 65010}),
    ("google_compute_vpn_tunnel", "dc", {"id": f"{HOST}/regions/us-central1/vpnTunnels/to-dc", "name": "to-dc",
                                         "peer_ip": "198.51.100.7",
                                         "router": f"{HOST}/regions/us-central1/routers/ciam-router"}),
    ("google_compute_router_nat", "nat", {"id": "example-net/us-central1/ciam-router/ciam-nat", "name": "ciam-nat",
                                          "nat_ip_allocate_option": "AUTO_ONLY"}))


def _by(resources):
    return {(r.kind, r.ref): r for r in resources}


def test_policy_rules_by_secure_tag_are_firewall_rules_of_the_bound_role():
    resources, notices = state_resources(STATE)
    rules = {r.ref: r for r in resources if r.kind == "firewall"}
    assert set(rules) == {"fw-pf-ds-svc"}                                     # the probe rule: the load balancer's
    rule = rules["fw-pf-ds-svc"]
    assert rule.attrs == {"ciamSourceCidr": ("10.70.2.0/24",), "ciamPort": ("1636",), "ciamProtocol": ("tcp",),
                          "ciamTargetRole": ("ds",), "ciamRulePriority": ("100",)}
    assert rule.links == {"ciamPolicyRole": POLICY}
    assert "hierarchical firewall policy rules (1): read, not recorded" in notices


def test_policies_their_order_and_the_egress_allowlist():
    by = _by(state_resources(STATE)[0])
    assert by[("firewall-policy", POLICY)].attrs == {"ciamPolicyScope": ("network",), "ciamPolicyOrder": ("policy-first",)}
    assert by[("firewall-policy", "locations/global/firewallPolicies/991")].attrs == {"ciamPolicyScope": ("hierarchical",)}
    assert by[("proxy", POLICY)].attrs == {"ciamProxyKind": ("firewall",),
                                           "ciamAllowedDestination": ("idp.partner.test", "smtp.mail.test:587")}


def test_routes_are_one_network_wide_table():
    rt = _by(state_resources(STATE)[0])[("route-table", f"{NETWORK}/routes")]
    assert rt.role == "routes"
    assert rt.attrs["ciamRoute"] == ("0.0.0.0/0 internet for ds",
                                     f"10.9.0.0/16 vpn {HOST}/regions/us-central1/vpnTunnels/to-dc")


def test_psc_for_googles_apis_is_a_private_endpoint_not_a_service():
    by = _by(state_resources(STATE)[0])
    pe = by[("private-endpoint", f"{HOST}/global/forwardingRules/pscapis")]
    assert pe.attrs == {"ciamPrivateService": ("apis",), "ciamPrivateEndpointKind": ("all-apis",),
                        "ciamFrontendIp": ("10.70.255.5",)}
    assert pe.role == "private-apis" and not [k for k, _ in by if k == "service"]


def test_private_services_access_is_a_peered_private_endpoint_with_its_range():
    pe = _by(state_resources(STATE)[0])[("private-endpoint", f"{HOST}/global/addresses/ciam-services")]
    assert pe.attrs == {"ciamPrivateEndpointKind": ("peered-service",), "ciamCidr": ("10.71.0.0/20",)}
    assert pe.role == "private-services"


def test_attachments_links_flow_logs_and_nat():
    by = _by(state_resources(STATE)[0])
    sa = by[("endpoint-service", f"{PROJECT}/regions/us-central1/serviceAttachments/ciam-prod-ldaps-link")]
    assert sa.attrs["ciamAcceptanceRequired"] == ("TRUE",)
    assert sa.attrs["ciamAllowedPrincipal"] == ("consumer-a", "projects/b/global/networks/v")
    assert sa.links["ciamServiceRole"] == f"{PROJECT}/regions/us-central1/forwardingRules/ciam-prod-svc-ldaps"
    peering = by[("interconnect", f"{NETWORK}/peerings/to-hub")]
    assert peering.attrs["ciamPeerAccepted"] == ("FALSE",) and peering.role == "peering-hub-net"
    assert peering.links["ciamPeerEnvironment"] == ("projects/hub/global/networks/hub-net", "hub-net")
    vpn = by[("interconnect", f"{HOST}/regions/us-central1/vpnTunnels/to-dc")].attrs
    assert vpn["ciamPeerGateway"] == ("198.51.100.7",) and vpn["ciamLocalAsn"] == ("64514",)
    assert vpn["ciamPeerAsn"] == ("65010",)
    log = by[("flow-log", f"{SUBNET}/logConfig")]
    assert log.attrs == {"ciamFlowScope": ("subnet",)} and log.links["ciamSubnetRole"] == SUBNET
    assert by[("egress", "example-net/us-central1/ciam-router/ciam-nat")].attrs["ciamNatAllocation"] == ("automatic",)


ASSETS = [
    {"assetType": "compute.googleapis.com/Network", "resource": {"data": {
        "selfLink": f"https://www.googleapis.com/compute/v1/{NETWORK}", "name": "ciam",
        "networkFirewallPolicyEnforcementOrder": "AFTER_CLASSIC_FIREWALL",
        "peerings": [{"name": "to-hub", "network": "projects/hub/global/networks/hub", "state": "ACTIVE"}]}}},
    {"assetType": "compute.googleapis.com/Instance", "resource": {"data": {
        "selfLink": f"https://www.googleapis.com/compute/v1/{PROJECT}/zones/us-central1-a/instances/ds-1", "id": "8812",
        "name": "ds-1", "labels": {"role": "ds"},
        "networkInterfaces": [{"network": f"https://www.googleapis.com/compute/v1/{NETWORK}", "networkIP": "10.70.1.11"}]}}},
    {"assetType": "compute.googleapis.com/NetworkFirewallPolicy", "resource": {"data": {
        "selfLink": f"https://www.googleapis.com/compute/v1/{POLICY}", "name": "ciam-prod-fw-policy",
        "associations": [{"attachmentTarget": f"https://www.googleapis.com/compute/v1/{NETWORK}"}],
        "rules": [{"priority": 100, "direction": "INGRESS", "action": "allow", "ruleName": "fw-pf-ds-svc",
                   "match": {"srcIpRanges": ["10.70.2.0/24"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["1636"]}]},
                   "targetSecureTags": [{"name": "tagValues/1"}]},
                  {"priority": 80001, "direction": "EGRESS", "action": "allow",
                   "match": {"destFqdns": ["idp.partner.test"], "layer4Configs": [{"ipProtocol": "tcp", "ports": ["443"]}]},
                   "targetSecureTags": [{"name": "tagValues/1"}]}]}}},
    {"name": "tagBindings/x", "parent": "//compute.googleapis.com/projects/example-ciam/zones/us-central1-a/instances/8812",
     "tagValue": "tagValues/1"},
    {"name": "tagValues/1", "shortName": "ds-servers", "parent": "tagKeys/7"},
    {"assetType": "compute.googleapis.com/ServiceAttachment", "resource": {"data": {
        "selfLink": f"https://www.googleapis.com/compute/v1/{PROJECT}/regions/us-central1/serviceAttachments/link",
        "name": "link", "connectionPreference": "ACCEPT_AUTOMATIC",
        "targetService": f"https://www.googleapis.com/compute/v1/{PROJECT}/regions/us-central1/forwardingRules/ldaps"}}},
    {"kind": "compute#address", "selfLink": f"https://www.googleapis.com/compute/v1/{HOST}/global/addresses/psc",
     "name": "psc", "address": "10.70.255.5", "purpose": "PRIVATE_SERVICE_CONNECT"},
    {"kind": "compute#address", "selfLink": f"https://www.googleapis.com/compute/v1/{HOST}/global/addresses/psa",
     "name": "psa", "address": "10.71.0.0", "prefixLength": 20, "purpose": "VPC_PEERING"},
    {"kind": "compute#forwardingRule", "selfLink": f"https://www.googleapis.com/compute/v1/{HOST}/global/forwardingRules/pscapis",
     "name": "pscapis", "target": "all-apis", "IPAddress": "10.70.255.5"},
]


def test_the_asset_inventory_reads_the_same_depth():
    resources, notices = cli_resources({"assets.json": "\n".join(json.dumps(a) for a in ASSETS)})
    by = _by(resources)
    rule = next(r for r in resources if r.kind == "firewall")
    assert rule.attrs["ciamTargetRole"] == ("ds",) and rule.links == {"ciamPolicyRole": POLICY}   # bound, not short
    assert by[("firewall-policy", POLICY)].attrs["ciamPolicyOrder"] == ("rules-first",)
    assert by[("proxy", POLICY)].attrs["ciamAllowedDestination"] == ("idp.partner.test",)
    assert by[("interconnect", f"{NETWORK}/peerings/to-hub")].attrs["ciamPeerAccepted"] == ("TRUE",)
    sa = by[("endpoint-service", f"{PROJECT}/regions/us-central1/serviceAttachments/link")]
    assert sa.attrs["ciamAcceptanceRequired"] == ("FALSE",)
    assert by[("private-endpoint", f"{HOST}/global/forwardingRules/pscapis")].attrs["ciamFrontendIp"] == ("10.70.255.5",)
    assert by[("private-endpoint", f"{HOST}/global/addresses/psa")].attrs["ciamCidr"] == ("10.71.0.0/20",)
    assert not [k for k, _ in by if k == "service"]
    assert not [n for n in notices if "not read" in n], notices


def _key(key_id, description):
    return ("google_tags_tag_key", key_id.replace("/", "_"), {"id": key_id, "short_name": "role",
                                                              "purpose": "GCE_FIREWALL", "description": description})


def test_the_policy_references_a_tag_key_someone_else_made_never_its_own():
    policy = ("google_compute_network_firewall_policy", "p", {"id": POLICY, "name": "ciam-prod-fw-policy"})
    own = _state(policy, _key("tagKeys/1", "CIAM server role (standby/prod): what the firewall policy's rules target. "
                                           "Managed by opsdir"))
    assert "ciamTagKeyRef" not in _by(state_resources(own)[0])[("firewall-policy", POLICY)].attrs
    foreign = _state(policy, _key("tagKeys/2", "Server roles (network team)"))
    assert _by(state_resources(foreign)[0])[("firewall-policy", POLICY)].attrs["ciamTagKeyRef"] == ("tagKeys/2",)
    resources, notices = state_resources(_state(policy, _key("tagKeys/2", ""), _key("tagKeys/3", "")))
    assert "ciamTagKeyRef" not in _by(resources)[("firewall-policy", POLICY)].attrs
    assert ("firewall tag keys not made by opsdir (tagKeys/2, tagKeys/3): which one the network policy targets by is "
            "the record's to say; not recorded") in notices


def test_the_asset_inventory_reads_tag_keys():
    keys = [{"assetType": "cloudresourcemanager.googleapis.com/TagKey", "resource": {"data": {
                "name": "tagKeys/2", "shortName": "role", "purpose": "GCE_FIREWALL", "description": "network team"}}},
            {"name": "tagKeys/9", "shortName": "env", "purpose": "GCE_FIREWALL",
             "description": "x. Managed by opsdir"}]
    resources, _ = cli_resources({"assets.json": "\n".join(json.dumps(a) for a in (*ASSETS, *keys))})
    assert _by(resources)[("firewall-policy", POLICY)].attrs["ciamTagKeyRef"] == ("tagKeys/2",)


def test_a_tag_key_for_another_network_or_named_like_the_renders_is_not_the_policys():
    network = ("google_compute_network", "main", {"id": NETWORK, "name": "ciam"})
    policy = ("google_compute_network_firewall_policy", "p", {"id": POLICY, "name": "ciam-prod-fw-policy"})

    def key(key_id, short, net):
        return ("google_tags_tag_key", key_id.replace("/", "_"), {"id": key_id, "short_name": short,
                                                                  "purpose": "GCE_FIREWALL", "description": "",
                                                                  "purpose_data": {"network": net}})
    resources, _ = state_resources(_state(network, policy, key("tagKeys/4", "server-role", "example-net/ciam"),
                                          key("tagKeys/5", "server-role", "other-project/vpc"),
                                          key("tagKeys/6", "ciam-prod-role", "example-net/ciam")))
    assert _by(resources)[("firewall-policy", POLICY)].attrs["ciamTagKeyRef"] == ("tagKeys/4",)
