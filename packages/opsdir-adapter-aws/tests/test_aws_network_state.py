"""The network depth read back from AWS Terraform state: route tables with their routes (targets as provider refs, a
Network Firewall endpoint as the firewall), subnets and main table; network ACLs; VPC endpoints (not a Gateway Load
Balancer's) and their security groups left out of the firewall rules; endpoint services with their principals and the
load balancer they expose; an egress firewall's domain list; peering, transit and VPN depth; flow logs with their log
group's retention."""
import json

from opsdir_adapter_aws.inventory import state_resources

ACCT, REGION = "111122223333", "us-east-1"
POLICY = f"arn:aws:network-firewall:{REGION}:{ACCT}:firewall-policy/ciam-egress"
GROUP = f"arn:aws:network-firewall:{REGION}:{ACCT}:stateful-rulegroup/ciam-domains"
LOGS = f"arn:aws:logs:{REGION}:{ACCT}:log-group:/vpc/flow"
NLB = f"arn:aws:elasticloadbalancing:{REGION}:{ACCT}:loadbalancer/net/ciam-ldaps/1"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("aws_route_table", "private", {"id": "rtb-1", "vpc_id": "vpc-1", "tags": {"Role": "rt-private"}, "route": [
        {"cidr_block": "0.0.0.0/0", "nat_gateway_id": "nat-1"},
        {"cidr_block": "10.9.0.0/16", "gateway_id": "vgw-9"},
        {"cidr_block": "10.30.0.0/16", "transit_gateway_id": "tgw-3"},
        {"destination_prefix_list_id": "pl-63a5400a", "vpc_endpoint_id": "vpce-s3"},
        {"cidr_block": "192.0.2.0/24", "vpc_endpoint_id": "vpce-fw"}]}),
    ("aws_route", "extra", {"route_table_id": "rtb-1", "destination_cidr_block": "10.40.0.0/16",
                            "vpc_peering_connection_id": "pcx-4"}),
    ("aws_route_table_association", "ds", {"route_table_id": "rtb-1", "subnet_id": "subnet-ds"}),
    ("aws_default_route_table", "main", {"id": "rtb-main", "default_route_table_id": "rtb-main",
                                         "route": [{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"}]}),
    ("aws_network_acl", "ds", {"id": "acl-1", "subnet_ids": ["subnet-ds"], "tags": {"Role": "acl-ds"},
                               "ingress": [{"rule_no": 100, "action": "allow", "protocol": "6", "from_port": 1636,
                                            "to_port": 1636, "cidr_block": "10.0.0.0/8"},
                                           {"rule_no": 120, "action": "allow", "protocol": "6", "from_port": 1024,
                                            "to_port": 65535, "ipv6_cidr_block": "::/0"}],
                               "egress": [{"rule_no": 100, "action": "allow", "protocol": "-1", "from_port": 0,
                                           "to_port": 0, "cidr_block": "0.0.0.0/0"}]}),
    ("aws_network_acl_rule", "deny", {"network_acl_id": "acl-1", "rule_number": 200, "egress": False,
                                      "protocol": "tcp", "rule_action": "deny", "from_port": 22, "to_port": 22,
                                      "cidr_block": "0.0.0.0/0"}),
    ("aws_vpc_endpoint", "secrets", {"id": "vpce-sm", "vpc_id": "vpc-1", "vpc_endpoint_type": "Interface",
                                     "service_name": f"com.amazonaws.{REGION}.secretsmanager",
                                     "subnet_ids": ["subnet-ds", "subnet-pf"], "private_dns_enabled": True,
                                     "security_group_ids": ["sg-endpoint"], "tags": {"Role": "private-secrets"}}),
    ("aws_vpc_endpoint", "s3", {"id": "vpce-s3", "vpc_endpoint_type": "Gateway",
                                "service_name": f"com.amazonaws.{REGION}.s3", "route_table_ids": ["rtb-1"]}),
    ("aws_vpc_endpoint", "gwlb", {"id": "vpce-gwlb", "vpc_endpoint_type": "GatewayLoadBalancer",
                                  "service_name": "com.amazonaws.vpce.us-east-1.vpce-svc-appliance"}),
    ("aws_security_group", "endpoint", {"id": "sg-endpoint", "name": "ciam-prod-pe-secrets", "vpc_id": "vpc-1",
                                        "ingress": [{"cidr_blocks": ["10.20.0.0/16"], "from_port": 443,
                                                     "to_port": 443, "protocol": "tcp",
                                                     "description": "the network to pe-secrets"}]}),
    ("aws_vpc_endpoint_service", "ldaps", {"id": "vpce-svc-1", "acceptance_required": True,
                                           "service_name": f"com.amazonaws.vpce.{REGION}.vpce-svc-1",
                                           "network_load_balancer_arns": [NLB],
                                           "allowed_principals": [f"arn:aws:iam::{ACCT}:root"],
                                           "tags": {"Role": "ldaps-endpoint-service"}}),
    ("aws_vpc_endpoint_service_allowed_principal", "partner", {"vpc_endpoint_service_id": "vpce-svc-1",
                                                               "principal_arn": "arn:aws:iam::444455556666:root"}),
    ("aws_networkfirewall_rule_group", "domains", {"arn": GROUP, "tags": {"Role": "egress-firewall",
                                                                          "FirewallPolicy": POLICY},
                                                   "rule_group": [{"rules_source": [{"rules_source_list": [{
                                                       "generated_rules_type": "ALLOWLIST",
                                                       "target_types": ["TLS_SNI", "HTTP_HOST"],
                                                       "targets": ["idp.partner.test", ".okta.test"]}]}]}]}),
    ("aws_networkfirewall_firewall", "egress", {"arn": "arn:fw", "firewall_policy_arn": POLICY, "firewall_status": [
        {"sync_states": [{"attachment": [{"endpoint_id": "vpce-fw"}]}]}]}),
    ("aws_vpc_peering_connection", "partner", {"id": "pcx-4", "accept_status": "pending-acceptance",
                                               "vpc_id": "vpc-1", "peer_vpc_id": "vpc-partner",
                                               "tags": {"Role": "peer-partner", "PeerEnvironment": "partner/prod"}}),
    ("aws_ec2_transit_gateway_vpc_attachment", "hub", {"id": "tgw-attach-1", "transit_gateway_id": "tgw-3"}),
    ("aws_customer_gateway", "dc", {"id": "cgw-1", "ip_address": "198.51.100.7", "bgp_asn": "65010"}),
    ("aws_vpn_gateway", "vgw", {"id": "vgw-9", "amazon_side_asn": "64512"}),
    ("aws_vpn_connection", "dc", {"id": "vpn-1", "customer_gateway_id": "cgw-1", "vpn_gateway_id": "vgw-9"}),
    ("aws_cloudwatch_log_group", "flow", {"arn": LOGS, "name": "/vpc/flow", "retention_in_days": 90}),
    ("aws_flow_log", "vpc", {"id": "fl-1", "vpc_id": "vpc-1", "log_destination_type": "cloud-watch-logs",
                             "log_destination": LOGS, "tags": {"Role": "flow-vpc"}}))


def _by(kind):
    resources, notices = state_resources(STATE)
    return {r.ref: r for r in resources if r.kind == kind}, notices


def test_route_tables_with_their_routes_subnets_and_main_table():
    tables, _ = _by("route-table")
    rt = tables["rtb-1"]
    assert rt.attrs["ciamRoute"] == ("0.0.0.0/0 nat nat-1", "10.9.0.0/16 vpn vgw-9", "10.30.0.0/16 transit tgw-3",
                                     "pl-63a5400a endpoint vpce-s3", f"192.0.2.0/24 firewall {POLICY}",
                                     "10.40.0.0/16 peering pcx-4")
    assert rt.attrs["ciamMainTable"] == ("FALSE",) and rt.links["ciamSubnetRole"] == ("subnet-ds",)
    assert rt.role == "rt-private"
    assert tables["rtb-main"].attrs == {"ciamRoute": ("0.0.0.0/0 internet igw-1",), "ciamMainTable": ("TRUE",)}


def test_network_acls_in_number_order_and_ipv6_named():
    acls, notices = _by("acl")
    assert acls["acl-1"].attrs["ciamAclRule"] == ("100 allow in tcp 1636 10.0.0.0/8", "100 allow out all all 0.0.0.0/0",
                                                  "200 deny in tcp 22 0.0.0.0/0")
    assert acls["acl-1"].links["ciamSubnetRole"] == ("subnet-ds",)
    assert "network ACL acl-1 rule 120: IPv6 range ::/0; not recorded" in notices


def test_vpc_endpoints_and_their_security_groups():
    endpoints, _ = _by("private-endpoint")
    assert set(endpoints) == {"vpce-sm", "vpce-s3"}                         # a Gateway Load Balancer's is routing
    sm = endpoints["vpce-sm"]
    assert sm.attrs == {"ciamPrivateService": ("secrets",), "ciamPrivateEndpointKind": ("interface",),
                        "ciamPrivateDns": ("TRUE",)}
    assert sm.links["ciamSubnetRole"] == ("subnet-ds", "subnet-pf") and sm.role == "private-secrets"
    assert endpoints["vpce-s3"].attrs == {"ciamPrivateService": ("object-storage",),
                                          "ciamPrivateEndpointKind": ("gateway",)}
    rules, _ = _by("firewall")
    assert rules == {}                                                       # the endpoint's group: not the record's


def test_an_endpoint_service_its_principals_and_load_balancer():
    services, _ = _by("endpoint-service")
    s = services["vpce-svc-1"]
    assert s.attrs["ciamAllowedPrincipal"] == (f"arn:aws:iam::{ACCT}:root", "arn:aws:iam::444455556666:root")
    assert s.attrs["ciamAcceptanceRequired"] == ("TRUE",)
    assert s.attrs["ciamServiceAlias"] == (f"com.amazonaws.vpce.{REGION}.vpce-svc-1",)
    assert s.links["ciamServiceRole"] == NLB


def test_an_egress_firewalls_domain_list_under_its_policy():
    proxies, _ = _by("proxy")
    p = proxies[POLICY]
    assert p.attrs == {"ciamProxyKind": ("firewall",), "ciamAllowedDestination": ("idp.partner.test", "*.okta.test")}
    assert p.role == "egress-firewall"


def test_interconnect_depth_and_flow_logs():
    links, _ = _by("interconnect")
    assert links["pcx-4"].attrs["ciamPeerAccepted"] == ("FALSE",)
    assert links["pcx-4"].attrs["ciamPeerEnvironment"] == ("env=prod,cloud=partner,ou=environments,dc=ciam-ops",)
    assert links["pcx-4"].links["ciamPeerEnvironment"] == ("vpc-1", "vpc-partner")    # core takes the other side's
    assert links["tgw-attach-1"].attrs["ciamLinkKind"] == ("transit",)
    vpn = links["vpn-1"].attrs
    assert vpn["ciamPeerGateway"] == ("198.51.100.7",) and vpn["ciamPeerAsn"] == ("65010",)
    assert vpn["ciamLocalAsn"] == ("64512",) and vpn["ciamLinkKind"] == ("vpn",)
    logs, _ = _by("flow-log")
    assert logs["fl-1"].attrs == {"ciamFlowScope": ("network",), "ciamRetentionDays": ("90",)}
    assert logs["fl-1"].links["ciamLogDestinationRole"] == LOGS and logs["fl-1"].role == "flow-vpc"


CLI = {
    "route-tables.json": {"RouteTables": [
        {"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Tags": [{"Key": "Role", "Value": "rt-private"}],
         "Associations": [{"RouteTableId": "rtb-1", "SubnetId": "subnet-ds", "Main": False}],
         "Routes": [{"DestinationCidrBlock": "10.20.0.0/16", "GatewayId": "local"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"},
                    {"DestinationPrefixListId": "pl-63a5400a", "GatewayId": "vpce-s3"}]},
        {"RouteTableId": "rtb-main", "VpcId": "vpc-1", "Associations": [{"Main": True}],
         "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]}]},
    "network-acls.json": {"NetworkAcls": [
        {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-ds"}],
         "Entries": [{"RuleNumber": 100, "Protocol": "6", "RuleAction": "allow", "Egress": False,
                      "CidrBlock": "10.0.0.0/8", "PortRange": {"From": 1636, "To": 1636}},
                     {"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny", "Egress": False,
                      "CidrBlock": "0.0.0.0/0"}]}]},
    "vpc-endpoints.json": {"VpcEndpoints": [
        {"VpcEndpointId": "vpce-sm", "VpcId": "vpc-1", "VpcEndpointType": "Interface",
         "ServiceName": f"com.amazonaws.{REGION}.secretsmanager", "SubnetIds": ["subnet-ds"],
         "PrivateDnsEnabled": True, "Groups": [{"GroupId": "sg-endpoint"}], "State": "available"},
        {"VpcEndpointId": "vpce-s3", "VpcId": "vpc-1", "VpcEndpointType": "Gateway",
         "ServiceName": f"com.amazonaws.{REGION}.s3"}]},
    "endpoint-services.json": {"ServiceConfigurations": [
        {"ServiceId": "vpce-svc-1", "ServiceName": f"com.amazonaws.vpce.{REGION}.vpce-svc-1",
         "AcceptanceRequired": True, "NetworkLoadBalancerArns": [NLB]}]},
    "service-permissions/vpce-svc-1.json": {"AllowedPrincipals": [{"Principal": "arn:aws:iam::444455556666:root"}]},
    "peering.json": {"VpcPeeringConnections": [{"VpcPeeringConnectionId": "pcx-4", "Status": {"Code": "active"},
                                                "RequesterVpcInfo": {"VpcId": "vpc-1"},
                                                "AccepterVpcInfo": {"VpcId": "vpc-partner"}}]},
    "rule-group.json": {"RuleGroupResponse": {"RuleGroupArn": GROUP,
                                              "Tags": [{"Key": "Role", "Value": "egress-firewall"},
                                                       {"Key": "FirewallPolicy", "Value": POLICY}]},
                        "RuleGroup": {"RulesSource": {"RulesSourceList": {
                            "GeneratedRulesType": "ALLOWLIST", "TargetTypes": ["TLS_SNI"],
                            "Targets": ["idp.partner.test", ".okta.test"]}}}},
    "flow-logs.json": {"FlowLogs": [{"FlowLogId": "fl-1", "ResourceId": "subnet-ds",
                                     "LogDestinationType": "s3", "LogDestination": "arn:aws:s3:::flow-logs"}]},
}


def test_the_cli_reads_the_same_depth():
    from opsdir_adapter_aws.cli import cli_resources
    resources, notices = cli_resources({p: json.dumps(doc) for p, doc in CLI.items()})
    by = {(r.kind, r.ref): r for r in resources}
    rt = by[("route-table", "rtb-1")]
    assert rt.attrs["ciamRoute"] == ("0.0.0.0/0 nat nat-1", "pl-63a5400a endpoint vpce-s3")   # no local route
    assert rt.links["ciamSubnetRole"] == ("subnet-ds",) and by[("route-table", "rtb-main")].attrs["ciamMainTable"] == ("TRUE",)
    assert by[("acl", "acl-1")].attrs["ciamAclRule"] == ("100 allow in tcp 1636 10.0.0.0/8",)       # no 32767
    assert by[("private-endpoint", "vpce-sm")].attrs["ciamPrivateDns"] == ("TRUE",)
    assert by[("endpoint-service", "vpce-svc-1")].attrs["ciamAllowedPrincipal"] == ("arn:aws:iam::444455556666:root",)
    assert by[("interconnect", "pcx-4")].attrs["ciamPeerAccepted"] == ("TRUE",)
    assert by[("interconnect", "pcx-4")].links["ciamPeerEnvironment"] == ("vpc-1", "vpc-partner")
    assert by[("proxy", POLICY)].attrs["ciamAllowedDestination"] == ("idp.partner.test", "*.okta.test")
    assert by[("flow-log", "fl-1")].attrs["ciamFlowScope"] == ("subnet",)
    assert by[("flow-log", "fl-1")].links["ciamSubnetRole"] == "subnet-ds"
    assert not [n for n in notices if "not an AWS CLI output" in n]


TEMPLATE = """
Resources:
  Private:
    Type: AWS::EC2::RouteTable
    Properties: {VpcId: vpc-1, Tags: [{Key: Role, Value: rt-private}]}
  Default:
    Type: AWS::EC2::Route
    Properties: {RouteTableId: !Ref Private, DestinationCidrBlock: 0.0.0.0/0, NatGatewayId: nat-1}
  PrivateDs:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: {RouteTableId: !Ref Private, SubnetId: subnet-ds}
  Acl:
    Type: AWS::EC2::NetworkAcl
    Properties: {VpcId: vpc-1}
  AclLdaps:
    Type: AWS::EC2::NetworkAclEntry
    Properties: {NetworkAclId: !Ref Acl, RuleNumber: 100, Protocol: 6, RuleAction: allow, Egress: false,
                 CidrBlock: 10.0.0.0/8, PortRange: {From: 1636, To: 1636}}
  AclDs:
    Type: AWS::EC2::SubnetNetworkAclAssociation
    Properties: {NetworkAclId: !Ref Acl, SubnetId: subnet-ds}
  Secrets:
    Type: AWS::EC2::VPCEndpoint
    Properties: {VpcId: vpc-1, VpcEndpointType: Interface, ServiceName: com.amazonaws.us-east-1.secretsmanager,
                 SubnetIds: [subnet-ds], PrivateDnsEnabled: true}
  Ldaps:
    Type: AWS::EC2::VPCEndpointService
    Properties: {AcceptanceRequired: true, NetworkLoadBalancerArns: [arn:nlb]}
  LdapsPartner:
    Type: AWS::EC2::VPCEndpointServicePermissions
    Properties: {ServiceId: !Ref Ldaps, AllowedPrincipals: ["arn:aws:iam::444455556666:root"]}
  Domains:
    Type: AWS::NetworkFirewall::RuleGroup
    Properties:
      Tags: [{Key: Role, Value: egress-firewall}]
      RuleGroup: {RulesSource: {RulesSourceList: {GeneratedRulesType: ALLOWLIST, TargetTypes: [TLS_SNI],
                                                  Targets: [idp.partner.test]}}}
  Flow:
    Type: AWS::EC2::FlowLog
    Properties: {ResourceType: VPC, ResourceId: vpc-1, LogDestinationType: s3, LogDestination: "arn:aws:s3:::flow"}
"""
PHYSICAL = {"Private": "rtb-1", "Default": "rtb-1|0.0.0.0/0", "PrivateDs": "rtbassoc-1", "Acl": "acl-1",
            "AclLdaps": "acl-1|100", "AclDs": "aclassoc-1", "Secrets": "vpce-sm", "Ldaps": "vpce-svc-1",
            "LdapsPartner": "perm-1", "Domains": GROUP, "Flow": "fl-1"}


def test_cloudformation_declares_the_same_depth():
    from opsdir_adapter_aws.cloudformation import cloudformation_resources
    resources, notices = cloudformation_resources({
        "net/template.yaml": TEMPLATE,
        "net/resources.json": json.dumps({"StackResourceSummaries": [
            {"LogicalResourceId": k, "PhysicalResourceId": v, "ResourceStatus": "CREATE_COMPLETE"}
            for k, v in PHYSICAL.items()]})})
    by = {(r.kind, r.ref): r for r in resources}
    rt = by[("route-table", "rtb-1")]
    assert rt.attrs["ciamRoute"] == ("0.0.0.0/0 nat nat-1",) and rt.links["ciamSubnetRole"] == ("subnet-ds",)
    acl = by[("acl", "acl-1")]
    assert acl.attrs["ciamAclRule"] == ("100 allow in tcp 1636 10.0.0.0/8",) and acl.links["ciamSubnetRole"] == ("subnet-ds",)
    assert by[("private-endpoint", "vpce-sm")].attrs["ciamPrivateDns"] == ("TRUE",)
    service = by[("endpoint-service", "vpce-svc-1")]
    assert service.attrs["ciamAllowedPrincipal"] == ("arn:aws:iam::444455556666:root",)
    assert service.links["ciamServiceRole"] == "arn:nlb" and "ciamServiceAlias" not in service.attrs
    assert by[("proxy", GROUP)].attrs["ciamAllowedDestination"] == ("idp.partner.test",)
    assert by[("flow-log", "fl-1")].attrs["ciamFlowScope"] == ("network",)
    assert not [n for n in notices if "not read" in n], notices
