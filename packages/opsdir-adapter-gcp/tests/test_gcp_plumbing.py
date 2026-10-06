"""The network plumbing a Google Cloud environment's landing zone (or another party) keeps, rendered into their root:
Cloud Router + Cloud NAT, network-wide routes, VPC peering, HA VPN with BGP, flow logs and network ACLs named, what
others keep of the stack's depth; import blocks for what exists, a folder per keeper."""
from opsdir_adapter_gcp.landing import render_landing
from opsdir_adapter_gcp.plumbing import render_plumbing
from opsdir.domains.network.plumbing import keepers
from network_fixtures import ALPHA, BETA, entry, model

TEAM = "cn=network-team,ou=owners,dc=ciam-ops"
GAMMA = "env=prod,cloud=gamma,ou=environments,dc=ciam-ops"
NET = "projects/host-proj/global/networks/vpc-gamma"
TREE = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
        f"dn: {TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: network-team\nciamOwnerKind: team\n",
        "dn: cloud=gamma,ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCloud\ncloud: gamma\n"
        "ciamCloudProvider: gcp\nciamRegion: us-central1\n",
        f"dn: {GAMMA}\nobjectClass: top\nobjectClass: ciamEnvironment\nenv: prod\n",
        f"dn: ou=bindings,{GAMMA}\nobjectClass: top\nobjectClass: organizationalUnit\nou: bindings\n",
        entry(GAMMA, "net", "ciamNetwork", ciamBindingRole="network", ciamCidr="10.9.0.0/16", ciamProviderRef=NET))


def _render(*records):
    d, alpha, _ = model(alpha=records, tree=TREE)
    return render_landing(alpha)


def _network(*records):
    return "\n".join(t for p, t in _render(*records).items() if p.endswith("network.tf"))


def test_no_plumbing_and_no_identities_renders_nothing():
    assert render_landing(model()[1]) == {}


def test_static_cloud_nat_on_its_router_adopted_from_its_ref():
    out = _network(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/32",
                         ciamNatAllocation="static", ciamProviderRef="proj/us-central1/router-a/nat-a"))
    assert 'resource "google_compute_router" "egress"' in out and 'name    = "router-a"' in out
    assert 'filter  = "address:203.0.113.10"' in out
    assert 'nat_ip_allocate_option             = "MANUAL_ONLY"' in out
    assert "nat_ips                            = [data.google_compute_addresses.egress_0.addresses[0].self_link]" \
        in out
    assert 'source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"' in out
    assert "data.google_compute_subnetwork.subnet_ds.self_link" in out
    assert 'to = google_compute_router.egress\n  id = "proj/us-central1/router-a"' in out
    assert 'to = google_compute_router_nat.egress\n  id = "proj/us-central1/router-a/nat-a"' in out
    assert "ignore_changes = [source_subnetwork_ip_ranges_to_nat, subnetwork]" in out     # not recorded: left as is


def test_automatic_nat_and_private_nat():
    auto = _network(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/32",
                          ciamNatAllocation="automatic"))
    assert '"AUTO_ONLY"' in auto and "nat_ips" not in auto and "import {" not in auto
    assert "lifecycle" not in auto                                          # a new NAT serves the subnetworks named
    private = _network(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="10.1.9.0/24"))
    assert "Private NAT" in private and "google_compute_router_nat" not in private


def test_routes_are_network_wide_tagged_for_their_roles():
    out = _network(entry(ALPHA, "routes", "ciamRouteTable", ciamBindingRole="routes", ciamSubnetRole="subnet-ds",
                         ciamRoute=("0.0.0.0/0 internet for ds", "10.8.0.0/16 appliance 10.1.1.9",
                                    "10.7.0.0/16 gateway-lb projects/p/regions/r/forwardingRules/ilb",
                                    "10.6.0.0/16 peering", "0.0.0.0/0 firewall egress-fw"),
                         ciamProviderRef="projects/p/global/networks/n/routes"),
                   entry(ALPHA, "egress-fw", "ciamProxy", ciamBindingRole="egress-fw", ciamProxyKind="firewall"))
    assert 'next_hop_gateway = "default-internet-gateway"' in out and 'tags             = ["ciam-prod-ds"]' in out
    assert 'next_hop_ip = "10.1.1.9"' in out
    assert 'next_hop_ilb = "projects/p/regions/r/forwardingRules/ilb"' in out
    assert "next_hop_ilb = var.egress_fw_ilb" in out
    assert "a peering's routes are exchanged by the peering" in out
    assert "subnet-ds aren't associated" in out and "existing routes keep their own names" in out
    assert 'name             = "ciam-prod-routes-0"' in out


def test_peering_with_a_google_cloud_network_and_the_other_half_named():
    out = _network(entry(ALPHA, "link", "ciamInterconnect", ciamBindingRole="link", ciamInterconnectKind="peering",
                         ciamLinkKind="peering", ciamPeerEnvironment=GAMMA, ciamSourceCidr="10.9.0.0/16"))
    assert 'resource "google_compute_network_peering" "link"' in out
    assert f'peer_network = "https://www.googleapis.com/compute/v1/{NET}"' in out
    assert "the other network adds its half" in out


def test_peering_with_another_provider_is_a_vpn():
    out = _network(entry(ALPHA, "link", "ciamInterconnect", ciamBindingRole="link", ciamInterconnectKind="peering",
                         ciamLinkKind="peering", ciamPeerEnvironment=BETA, ciamSourceCidr="10.1.0.0/16"))
    assert "record it as a vpn link" in out and "google_compute_network_peering" not in out


def test_ha_vpn_with_bgp_secret_and_link_local_addresses_as_inputs():
    files = _render(entry(ALPHA, "vpn", "ciamInterconnect", ciamBindingRole="vpn", ciamInterconnectKind="VPN",
                          ciamLinkKind="vpn", ciamPeerEnvironment=BETA, ciamSourceCidr="10.1.0.0/16",
                          ciamPeerGateway=("198.51.100.1", "198.51.100.2"), ciamLocalAsn="64514",
                          ciamPeerAsn="65010", ciamAdvertisedCidr="10.1.0.0/16",
                          ciamProviderRef="projects/p/regions/us-east1/vpnTunnels/t0"))
    out, providers = files["terraform/landing-zone/network.tf"], files["terraform/landing-zone/providers.tf"]
    assert 'redundancy_type = "TWO_IPS_REDUNDANCY"' in out
    assert "asn               = 64514" in out and "peer_asn        = 65010" in out
    assert 'range = "10.1.0.0/16"' in out and 'region                          = "us-east1"' in out
    assert "shared_secret                   = var.vpn_shared_secret" in out
    assert 'resource "google_compute_vpn_tunnel" "vpn_1"' in out
    assert 'to = google_compute_vpn_tunnel.vpn_0\n  id = "projects/p/regions/us-east1/vpnTunnels/t0"' in out
    assert 'variable "vpn_shared_secret"' in providers and "sensitive   = true" in providers
    assert 'variable "vpn_1_bgp_peer_ip"' in providers


def test_vpn_without_asns_or_gateway_and_other_links_are_named():
    out = _network(entry(ALPHA, "vpn", "ciamInterconnect", ciamBindingRole="vpn", ciamInterconnectKind="VPN",
                         ciamLinkKind="vpn", ciamPeerEnvironment=BETA, ciamSourceCidr="10.1.0.0/16",
                         ciamPeerGateway="198.51.100.1"),
                   entry(ALPHA, "dc", "ciamInterconnect", ciamBindingRole="dc", ciamInterconnectKind="VPN",
                         ciamLinkKind="vpn", ciamPeerEnvironment=BETA, ciamSourceCidr="10.1.0.0/16"),
                   entry(ALPHA, "ic", "ciamInterconnect", ciamBindingRole="ic", ciamInterconnectKind="circuit",
                         ciamLinkKind="dedicated", ciamPeerEnvironment=BETA, ciamSourceCidr="10.1.0.0/16"),
                   entry(ALPHA, "old", "ciamInterconnect", ciamBindingRole="old", ciamInterconnectKind="legacy VPN",
                         ciamPeerEnvironment=BETA, ciamSourceCidr="10.1.0.0/16"))
    assert "record both ends' ASNs" in out and "UNBOUND: a VPN needs the other end's gateway" in out
    assert "Cloud Interconnect attachment" in out and "legacy VPN: what kind of link it is isn't recorded" in out
    assert "google_compute_vpn_tunnel" not in out


def test_flow_logs_and_acls_are_named_not_rendered():
    out = _network(entry(ALPHA, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="subnet",
                         ciamSubnetRole="subnet-ds", ciamLogDestinationRole="logs", ciamRetentionDays="30"),
                   entry(ALPHA, "logs", "ciamLogDestination", ciamBindingRole="logs", ciamDestinationKind="log-group",
                         ciamProviderRef="projects/p/locations/global/buckets/flows"),
                   entry(ALPHA, "acl", "ciamNetworkAcl", ciamBindingRole="acl", ciamAclRule="100 allow in tcp 636 "
                                                                                           "10.0.0.0/8"))
    assert "subnetwork subnet-ds logs its flows to Cloud Logging, routed to logs" in out and "kept 30 days" in out
    assert "no stateless network ACLs" in out and 'resource "' not in out


def test_what_another_party_keeps_goes_in_their_root():
    files = _render(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/32",
                          ciamNatAllocation="automatic"),
                    entry(ALPHA, "psc", "ciamPrivateEndpoint", ciamBindingRole="psc", ciamPrivateService="apis",
                          ciamPrivateEndpointKind="all-apis", ciamFrontendIp="10.1.255.5", ciamManagedBy=TEAM,
                          ciamProviderRef="projects/p/global/forwardingRules/pscapis"),
                    entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall",
                          ciamAllowedDestination="login.vendor.test", ciamManagedBy=TEAM,
                          ciamProviderRef="projects/p/global/firewallPolicies/hub-policy"))
    assert set(files) == {"terraform/landing-zone/providers.tf", "terraform/landing-zone/network.tf",
                          "terraform/landing-zone/network-team/providers.tf",
                          "terraform/landing-zone/network-team/network.tf"}
    theirs = files["terraform/landing-zone/network-team/network.tf"]
    assert "kept by network-team" in theirs and 'resource "google_compute_global_forwarding_rule" "psc"' in theirs
    assert 'to = google_compute_global_forwarding_rule.psc\n  id = "projects/p/global/forwardingRules/pscapis"' \
        in theirs
    assert 'firewall_policy = "hub-policy"' in theirs and 'dest_fqdns = ["login.vendor.test"]' in theirs
    assert "target_secure_tags" not in theirs
    assert "google_compute_router_nat" not in theirs
    assert "google_compute_router_nat" in files["terraform/landing-zone/network.tf"]


def test_keepers_folder_order_and_render_plumbing_data_first():
    d, alpha, _ = model(alpha=(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress",
                                     ciamCidr="203.0.113.10/32", ciamNatAllocation="automatic"),), tree=TREE)
    (k,) = keepers(alpha)
    r = render_plumbing(alpha, k)
    assert r.shared[0].startswith('data "google_compute_network" "main"') and "UNBOUND" in r.shared[0]
    assert r.blocks[0].startswith('resource "google_compute_router" "egress"')


def test_private_services_access_goes_in_its_keepers_root_with_its_range():
    files = _render(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/32",
                          ciamNatAllocation="automatic"),
                    entry(ALPHA, "psa", "ciamPrivateEndpoint", ciamBindingRole="private-services",
                          ciamPrivateService="database", ciamPrivateEndpointKind="peered-service",
                          ciamCidr="10.71.0.0/20", ciamManagedBy=TEAM,
                          ciamProviderRef="projects/p/global/addresses/ciam-services"))
    theirs = files["terraform/landing-zone/network-team/network.tf"]
    assert 'resource "google_compute_global_address" "psa"' in theirs
    for line in ('name          = "ciam-services"', 'purpose       = "VPC_PEERING"', 'address       = "10.71.0.0"',
                 "prefix_length = 20", 'role       = "private-services"'):
        assert line in theirs, line
    assert 'resource "google_service_networking_connection" "psa"' in theirs
    assert 'service                 = "servicenetworking.googleapis.com"' in theirs
    assert "reserved_peering_ranges = [google_compute_global_address.psa.name]" in theirs
    assert 'to = google_compute_global_address.psa\n  id = "projects/p/global/addresses/ciam-services"' in theirs
    assert "to = google_service_networking_connection.psa" not in theirs     # its id needs the network's ref
