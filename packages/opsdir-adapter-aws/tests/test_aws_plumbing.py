"""The network plumbing an AWS environment's landing zone or another party keeps, rendered into their root: NAT
gateways on their elastic IPs, route tables (targets rendered here, by provider ref, or an input), network ACLs,
peering / transit / VPN, flow logs, and the private endpoints and egress allowlists someone else keeps; import blocks
for what exists, inputs for what only the keeper knows, notes for what isn't rendered."""
from opsdir.domains.network.plumbing import keepers
from opsdir_adapter_aws.landing import render_landing
from opsdir_adapter_aws.plumbing import render_plumbing
from network_fixtures import ALPHA, BETA, entry, model

NET_TEAM = "cn=net-team,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {NET_TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: net-team\nciamOwnerKind: team\n")
EGRESS = entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/31",
               ciamProviderRef="nat-1", ciamZone="zone-a")
LOGS = entry(ALPHA, "flow-logs", "ciamLogDestination", ciamBindingRole="flow-logs", ciamDestinationKind="log-group",
             ciamProviderRef="arn:aws:logs:region-1:1:log-group:fl")


def _render(*records, beta=()):
    m = model(alpha=records, beta=beta, tree=OWNERS)[1]
    return {k.folder: render_plumbing(m, k) for k in keepers(m)}


def _main(*records, beta=()):
    r = _render(*records, beta=beta)["terraform/landing-zone"]
    return "\n\n".join((*r.shared, *r.blocks)), "\n\n".join(r.variables)


def test_nothing_recorded_renders_no_landing_zone():
    assert render_landing(model()[1]) == {}


def test_a_nat_gateway_on_its_elastic_ips_adopted_by_its_id():
    out, inputs = _main(EGRESS)
    assert 'data "aws_eip" "egress_0" {\n  public_ip = "203.0.113.10"\n}' in out
    assert 'data "aws_eip" "egress_1" {\n  public_ip = "203.0.113.11"\n}' in out
    assert 'connectivity_type        = "public"' in out and "allocation_id            = data.aws_eip.egress_0.id" in out
    assert "secondary_allocation_ids = [data.aws_eip.egress_1.id]" in out
    assert "subnet_id                = var.egress_subnet_id" in out
    assert 'import {\n  to = aws_nat_gateway.egress\n  id = "nat-1"\n}' in out
    assert 'variable "egress_subnet_id"' in inputs and "NAT gateway egress sits in (zone-a)" in inputs


def test_a_private_range_is_a_private_nat_gateway():
    out, _ = _main(entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="10.1.9.0/24"))
    assert 'connectivity_type = "private"' in out and "aws_eip" not in out and "import" not in out


def test_routes_point_at_what_is_rendered_here_else_its_ref_else_an_input():
    out, inputs = _main(EGRESS, entry(
        ALPHA, "rt-ds", "ciamRouteTable", ciamBindingRole="rt-ds", ciamSubnetRole="subnet-ds", ciamProviderRef="rtb-1",
        ciamRoute=("10.1.0.0/16 local", "0.0.0.0/0 nat egress", "pl-123 endpoint vpce-9", "10.8.0.0/16 transit",
                   "10.7.0.0/16 firewall fw", "::/0 egress-only eigw-1", "10.6.0.0/16 none",
                   "10.5.0.0/16 peering link", "10.4.0.0/16 appliance eni-1 for ds")),
        entry(ALPHA, "link", "ciamInterconnect", ciamBindingRole="link", ciamInterconnectKind="peering",
              ciamLinkKind="peering", ciamPeerEnvironment=BETA, ciamSourceCidr="10.9.0.0/16"),
        entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall", ciamProviderRef="arn:policy"))
    assert "10.1.0.0/16" not in out                                         # the local route is implicit
    assert "nat_gateway_id = aws_nat_gateway.egress.id" in out
    assert 'destination_prefix_list_id = "pl-123"' in out and 'vpc_endpoint_id            = "vpce-9"' in out
    assert "transit_gateway_id = var.transit_gateway_id" in out and 'variable "transit_gateway_id"' in inputs
    assert "vpc_endpoint_id = var.fw_endpoint_id" in out and "Network Firewall endpoint of fw" in inputs
    assert 'ipv6_cidr_block        = "::/0"' in out and 'egress_only_gateway_id = "eigw-1"' in out
    assert "# 10.6.0.0/16: a blackhole route; Terraform doesn't create those" in out
    assert "# UNBOUND: 10.5.0.0/16 peering: its target link isn't rendered here and has no provider ref" in out
    assert "# 10.4.0.0/16 applies to ds only elsewhere; AWS routes apply to the whole subnet" in out
    assert 'import {\n  to = aws_route_table.rt_ds\n  id = "rtb-1"\n}' in out
    assert "subnet_id      = data.aws_subnet.subnet_ds.id\n  route_table_id = aws_route_table.rt_ds.id" in out


def test_the_main_table_is_the_vpc_s_default_route_table_and_internet_its_gateway():
    out, _ = _main(entry(ALPHA, "rt-main", "ciamRouteTable", ciamBindingRole="rt-main",
                         ciamRoute="0.0.0.0/0 internet", ciamMainTable="TRUE", ciamProviderRef="rtb-main"))
    assert 'resource "aws_default_route_table" "rt_main"' in out
    assert "default_route_table_id = data.aws_vpc.main.main_route_table_id" in out
    assert "gateway_id = data.aws_internet_gateway.main.id" in out and 'data "aws_internet_gateway" "main"' in out
    assert "import" not in out                                              # the default table adopts itself


def test_a_network_acl_with_its_rules_both_ways_on_its_subnets():
    out, _ = _main(entry(ALPHA, "acl", "ciamNetworkAcl", ciamBindingRole="acl", ciamSubnetRole="subnet-ds",
                         ciamProviderRef="acl-1", ciamAclRule=("200 allow out tcp 1024-65535 10.0.0.0/8",
                                                               "100 allow in tcp 636 10.0.0.0/8",
                                                               "300 deny in all all 0.0.0.0/0",
                                                               "400 allow in icmp all ::/0")))
    assert "subnet_ids = [data.aws_subnet.subnet_ds.id]" in out
    assert out.index("rule_no    = 100") < out.index("rule_no    = 200")
    assert "ingress {\n    rule_no    = 100" in out and "egress {\n    rule_no    = 200" in out
    assert 'protocol   = "-1"' in out and 'ipv6_cidr_block = "::/0"' in out and "icmp_type       = -1" in out
    assert 'import {\n  to = aws_network_acl.acl\n  id = "acl-1"\n}' in out


def test_peering_with_the_other_environment_s_vpc_only_on_the_same_provider():
    link = entry(ALPHA, "link", "ciamInterconnect", ciamBindingRole="link", ciamInterconnectKind="peering",
                 ciamLinkKind="peering", ciamPeerEnvironment=BETA, ciamSourceCidr="10.9.0.0/16")
    out, _ = _main(link)
    assert "# link: peering joins two networks of one provider, and the other end is on fakecloud" in out


def test_a_vpn_with_bgp_or_static_routes_and_the_vpc_s_vpn_gateway_once():
    bgp = entry(ALPHA, "vpn-a", "ciamInterconnect", ciamBindingRole="vpn-a", ciamInterconnectKind="VPN",
                ciamLinkKind="vpn", ciamPeerEnvironment=BETA, ciamSourceCidr="10.9.0.0/16",
                ciamPeerGateway="198.51.100.1", ciamPeerAsn="65010", ciamLocalAsn="64512", ciamProviderRef="vpn-1")
    static = entry(ALPHA, "vpn-b", "ciamInterconnect", ciamBindingRole="vpn-b", ciamInterconnectKind="VPN",
                   ciamLinkKind="vpn", ciamPeerEnvironment=BETA, ciamSourceCidr="10.9.0.0/16",
                   ciamPeerGateway="198.51.100.2", ciamAcceptedCidr="192.168.0.0/16")
    out, _ = _main(bgp, static)
    assert out.count('resource "aws_vpn_gateway" "main"') == 1 and "amazon_side_asn = 64512" in out
    assert 'bgp_asn    = 65010\n  ip_address = "198.51.100.1"' in out and "static_routes_only  = false" in out
    assert 'import {\n  to = aws_vpn_connection.vpn_a\n  id = "vpn-1"\n}' in out
    assert "bgp_asn    = 65000" in out and "static_routes_only  = true" in out
    assert 'destination_cidr_block = "192.168.0.0/16"' in out


def test_links_aws_doesn_t_render_are_named():
    def link(cn, **kind):
        return entry(ALPHA, cn, "ciamInterconnect", ciamBindingRole=cn, ciamInterconnectKind=f"{cn} link",
                     ciamPeerEnvironment=BETA, ciamSourceCidr="10.9.0.0/16", **kind)
    out, inputs = _main(link("dx", ciamLinkKind="dedicated"), link("hub", ciamLinkKind="hub"), link("odd"),
                        link("tgw", ciamLinkKind="transit"), link("novpn", ciamLinkKind="vpn"))
    assert "# dx: a dedicated circuit (Direct Connect)" in out and "# hub: AWS has no managed hub connection" in out
    assert "# odd: odd link: what kind of link it is isn't recorded (ciamLinkKind)" in out
    assert "# novpn: UNBOUND: a VPN needs the other end's gateway address" in out
    assert 'resource "aws_ec2_transit_gateway_vpc_attachment" "tgw"' in out
    assert "subnet_ids         = [data.aws_subnet.subnet_ds.id, data.aws_subnet.subnet_web.id]" in out
    assert inputs.count('variable "transit_gateway_id"') == 1


def test_flow_logs_on_the_vpc_or_each_subnet_to_their_destination():
    out, inputs = _main(LOGS, entry(ALPHA, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="network",
                                    ciamLogDestinationRole="flow-logs", ciamRetentionDays="90", ciamProviderRef="fl-1"),
                        entry(ALPHA, "fl-sub", "ciamFlowLog", ciamBindingRole="fl-sub", ciamFlowScope="subnet",
                              ciamSubnetRole=("subnet-ds", "subnet-web"), ciamLogDestinationRole="flow-logs",
                              ciamProviderRef="fl-2"),
                        entry(ALPHA, "fl-eni", "ciamFlowLog", ciamBindingRole="fl-eni", ciamFlowScope="interface",
                              ciamLogDestinationRole="flow-logs"),
                        entry(ALPHA, "fl-x", "ciamFlowLog", ciamBindingRole="fl-x", ciamFlowScope="network",
                              ciamLogDestinationRole="nowhere"))
    assert "# fl: kept 90 days, the retention of flow-logs (not set here)" in out
    assert 'vpc_id               = data.aws_vpc.main.id\n  traffic_type         = "ALL"' in out
    assert 'log_destination_type = "cloud-watch-logs"' in out and "iam_role_arn         = var.flow_logs_role_arn" in out
    assert 'import {\n  to = aws_flow_log.fl\n  id = "fl-1"\n}' in out
    assert 'resource "aws_flow_log" "fl_sub_subnet_ds"' in out and 'resource "aws_flow_log" "fl_sub_subnet_web"' in out
    assert "aws_flow_log.fl_sub" not in out                                 # one ref, several flow logs: no import
    assert "# fl-eni: a flow log on interfaces needs their ids" in out
    assert "# fl-x: UNBOUND: its log destination has no binding with an ARN here" in out
    assert 'variable "flow_logs_role_arn"' in inputs


def test_what_another_party_keeps_renders_in_their_root_with_its_own_providers():
    pe = entry(ALPHA, "pe-hub", "ciamPrivateEndpoint", ciamBindingRole="pe-hub", ciamPrivateService="secrets",
               ciamPrivateEndpointKind="interface", ciamSubnetRole="subnet-ds", ciamManagedBy=NET_TEAM,
               ciamProviderRef="vpce-1")
    fw = entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall", ciamManagedBy=NET_TEAM,
               ciamAllowedDestination="metadata.example.test")
    files = render_landing(model(alpha=(EGRESS, pe, fw), tree=OWNERS)[1])
    assert sorted(files) == ["terraform/landing-zone/net-team/network.tf",
                             "terraform/landing-zone/net-team/providers.tf",
                             "terraform/landing-zone/network.tf", "terraform/landing-zone/providers.tf"]
    theirs = files["terraform/landing-zone/net-team/network.tf"]
    assert "AWS network kept by net-team for the CIAM platform" in theirs
    assert 'resource "aws_vpc_endpoint" "pe_hub"' in theirs and 'to = aws_vpc_endpoint.pe_hub' in theirs
    assert 'resource "aws_networkfirewall_rule_group" "fw_domains"' in theirs
    assert 'data "aws_vpc" "main"' in theirs and "aws_nat_gateway" not in theirs
    assert 'variable "egress_subnet_id"' in files["terraform/landing-zone/providers.tf"]
    assert "variable" not in files["terraform/landing-zone/net-team/providers.tf"]
    assert "main.tf" not in " ".join(files)                                 # no identities or guardrails
