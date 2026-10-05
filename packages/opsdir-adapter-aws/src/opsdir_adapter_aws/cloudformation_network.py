"""The network depth CloudFormation stacks declare, normalized to the Terraform attribute names the shared mapping reads
(opsdir_adapter_aws.network_inventory). Properties come resolved (Ref to physical IDs); what a stack can't say (an
endpoint service's name for consumers, a peering's acceptance, a firewall's endpoints) is left to the record. Pure.

  AWS::EC2::RouteTable (+ Route, SubnetRouteTableAssociation)         -> aws_route_table, aws_route,
                                                                          aws_route_table_association
  AWS::EC2::NetworkAcl (+ NetworkAclEntry, SubnetNetworkAclAssociation) -> aws_network_acl, aws_network_acl_rule,
                                                                          aws_network_acl_association
  AWS::EC2::VPCEndpoint                                                -> aws_vpc_endpoint
  AWS::EC2::VPCEndpointService (+ VPCEndpointServicePermissions)       -> aws_vpc_endpoint_service (+ allowed
                                                                          principals)
  AWS::EC2::VPCPeeringConnection, TransitGatewayAttachment,            -> peering, transit attachment, VPN with its
    TransitGatewayVpcAttachment, VPNConnection (+ CustomerGateway,        gateways
    VPNGateway)
  AWS::EC2::FlowLog                                                    -> aws_flow_log
  AWS::NetworkFirewall::RuleGroup, FirewallPolicy, Firewall            -> rule groups, policies, firewalls
"""
from types import MappingProxyType

NETWORK_TYPES = ("AWS::EC2::RouteTable", "AWS::EC2::Route", "AWS::EC2::SubnetRouteTableAssociation",
                 "AWS::EC2::NetworkAcl", "AWS::EC2::NetworkAclEntry", "AWS::EC2::SubnetNetworkAclAssociation",
                 "AWS::EC2::VPCEndpoint", "AWS::EC2::VPCEndpointService", "AWS::EC2::VPCEndpointServicePermissions",
                 "AWS::EC2::VPCPeeringConnection", "AWS::EC2::TransitGatewayAttachment",
                 "AWS::EC2::TransitGatewayVpcAttachment", "AWS::EC2::VPNConnection", "AWS::EC2::CustomerGateway",
                 "AWS::EC2::VPNGateway", "AWS::EC2::FlowLog", "AWS::NetworkFirewall::RuleGroup",
                 "AWS::NetworkFirewall::FirewallPolicy", "AWS::NetworkFirewall::Firewall")
# a route's property -> the Terraform attribute
_ROUTE = MappingProxyType({
    "RouteTableId": "route_table_id", "DestinationCidrBlock": "destination_cidr_block",
    "DestinationIpv6CidrBlock": "destination_ipv6_cidr_block", "DestinationPrefixListId": "destination_prefix_list_id",
    "GatewayId": "gateway_id", "NatGatewayId": "nat_gateway_id", "TransitGatewayId": "transit_gateway_id",
    "VpcPeeringConnectionId": "vpc_peering_connection_id", "NetworkInterfaceId": "network_interface_id",
    "EgressOnlyInternetGatewayId": "egress_only_gateway_id", "VpcEndpointId": "vpc_endpoint_id",
    "CarrierGatewayId": "carrier_gateway_id", "CoreNetworkArn": "core_network_arn",
    "LocalGatewayId": "local_gateway_id"})
_FLOW_SCOPES = MappingProxyType({"VPC": "vpc_id", "Subnet": "subnet_id", "NetworkInterface": "eni_id",
                                 "TransitGateway": "transit_gateway_id",
                                 "TransitGatewayAttachment": "transit_gateway_attachment_id"})


def _tags(tags):
    return {t.get("Key"): t.get("Value") for t in tags or () if isinstance(t, dict) and t.get("Key")}


def _truth(v):
    return None if v is None else str(v).lower() == "true"


def _of(declared, *types):
    return [(p, pid) for _, t, p, _, pid in declared if t in types]


def _routing(declared):
    return [*(("aws_route_table", {"id": pid, "vpc_id": p.get("VpcId"), "tags": _tags(p.get("Tags")), "route": []})
              for p, pid in _of(declared, "AWS::EC2::RouteTable")),
            *(("aws_route", {attr: p.get(key) for key, attr in _ROUTE.items() if p.get(key)})
              for p, _ in _of(declared, "AWS::EC2::Route")),
            *(("aws_route_table_association", {"route_table_id": p.get("RouteTableId"), "subnet_id": p.get("SubnetId")})
              for p, _ in _of(declared, "AWS::EC2::SubnetRouteTableAssociation")),
            *(("aws_network_acl", {"id": pid, "vpc_id": p.get("VpcId"), "tags": _tags(p.get("Tags"))})
              for p, pid in _of(declared, "AWS::EC2::NetworkAcl")),
            *(("aws_network_acl_rule", {
                "network_acl_id": p.get("NetworkAclId"), "rule_number": p.get("RuleNumber"),
                "egress": _truth(p.get("Egress")) or False, "protocol": str(p.get("Protocol")),
                "rule_action": p.get("RuleAction"), "cidr_block": p.get("CidrBlock"),
                "ipv6_cidr_block": p.get("Ipv6CidrBlock"), "from_port": (p.get("PortRange") or {}).get("From", 0),
                "to_port": (p.get("PortRange") or {}).get("To", 0)})
              for p, _ in _of(declared, "AWS::EC2::NetworkAclEntry")),
            *(("aws_network_acl_association", {"network_acl_id": p.get("NetworkAclId"), "subnet_id": p.get("SubnetId")})
              for p, _ in _of(declared, "AWS::EC2::SubnetNetworkAclAssociation"))]


def _endpoints(declared):
    return [*(("aws_vpc_endpoint", {
                "id": pid, "vpc_id": p.get("VpcId"), "service_name": p.get("ServiceName"),
                "vpc_endpoint_type": p.get("VpcEndpointType") or "Gateway", "subnet_ids": p.get("SubnetIds") or [],
                "route_table_ids": p.get("RouteTableIds") or [],
                "private_dns_enabled": _truth(p.get("PrivateDnsEnabled")),
                "security_group_ids": p.get("SecurityGroupIds") or [], "tags": _tags(p.get("Tags"))})
              for p, pid in _of(declared, "AWS::EC2::VPCEndpoint")),
            *(("aws_vpc_endpoint_service", {
                "id": pid, "acceptance_required": _truth(p.get("AcceptanceRequired")),
                "network_load_balancer_arns": p.get("NetworkLoadBalancerArns") or [], "tags": _tags(p.get("Tags"))})
              for p, pid in _of(declared, "AWS::EC2::VPCEndpointService")),
            *(("aws_vpc_endpoint_service_allowed_principal", {"vpc_endpoint_service_id": p.get("ServiceId"),
                                                              "principal_arn": principal})
              for p, _ in _of(declared, "AWS::EC2::VPCEndpointServicePermissions")
              for principal in p.get("AllowedPrincipals") or ())]


def _links(declared):
    return [*(("aws_vpc_peering_connection", {"id": pid, "tags": _tags(p.get("Tags")), "vpc_id": p.get("VpcId"),
                                              "peer_vpc_id": p.get("PeerVpcId")})
              for p, pid in _of(declared, "AWS::EC2::VPCPeeringConnection")),
            *(("aws_ec2_transit_gateway_vpc_attachment", {"id": pid, "transit_gateway_id": p.get("TransitGatewayId"),
                                                          "vpc_id": p.get("VpcId"), "tags": _tags(p.get("Tags"))})
              for p, pid in _of(declared, "AWS::EC2::TransitGatewayAttachment",
                                "AWS::EC2::TransitGatewayVpcAttachment")),
            *(("aws_vpn_connection", {"id": pid, "customer_gateway_id": p.get("CustomerGatewayId"),
                                      "vpn_gateway_id": p.get("VpnGatewayId"), "tags": _tags(p.get("Tags"))})
              for p, pid in _of(declared, "AWS::EC2::VPNConnection")),
            *(("aws_customer_gateway", {"id": pid, "ip_address": p.get("IpAddress"), "bgp_asn": p.get("BgpAsn")})
              for p, pid in _of(declared, "AWS::EC2::CustomerGateway")),
            *(("aws_vpn_gateway", {"id": pid, "amazon_side_asn": p.get("AmazonSideAsn")})
              for p, pid in _of(declared, "AWS::EC2::VPNGateway"))]


def _flow_logs(declared):
    return [("aws_flow_log", {"id": pid, "log_destination_type": p.get("LogDestinationType"),
                              "log_destination": p.get("LogDestination"), "log_group_name": p.get("LogGroupName"),
                              "tags": _tags(p.get("Tags")),
                              **({_FLOW_SCOPES[p["ResourceType"]]: p.get("ResourceId")}
                                 if p.get("ResourceType") in _FLOW_SCOPES else {})})
            for p, pid in _of(declared, "AWS::EC2::FlowLog")]


def _firewalls(declared):
    def listed(p):
        source = ((p.get("RuleGroup") or {}).get("RulesSource") or {}).get("RulesSourceList") or {}
        return [{"rules_source": [{"rules_source_list": [{
            "generated_rules_type": source.get("GeneratedRulesType"), "target_types": source.get("TargetTypes") or [],
            "targets": source.get("Targets") or []}]}]}] if source else []
    return [*(("aws_networkfirewall_rule_group", {"arn": pid, "tags": _tags(p.get("Tags")), "rule_group": listed(p)})
              for p, pid in _of(declared, "AWS::NetworkFirewall::RuleGroup")),
            *(("aws_networkfirewall_firewall_policy", {
                "arn": pid, "tags": _tags(p.get("Tags")),
                "firewall_policy": [{"stateful_rule_group_reference": [
                    {"resource_arn": r.get("ResourceArn")}
                    for r in (p.get("FirewallPolicy") or {}).get("StatefulRuleGroupReferences") or ()]}]})
              for p, pid in _of(declared, "AWS::NetworkFirewall::FirewallPolicy")),
            *(("aws_networkfirewall_firewall", {"arn": pid, "firewall_policy_arn": p.get("FirewallPolicyArn")})
              for p, pid in _of(declared, "AWS::NetworkFirewall::Firewall"))]


def network_stack_pairs(declared):
    """(Terraform resource type, attributes) pairs of the network depth among a stack's declared resources ((logical
    ID, type, resolved properties, raw properties, physical ID), ...)."""
    return [*_routing(declared), *_endpoints(declared), *_links(declared), *_flow_logs(declared),
            *_firewalls(declared)]
