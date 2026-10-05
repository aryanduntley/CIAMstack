"""What the AWS CLI reports about an environment's network depth, normalized to the Terraform attribute names the
shared mapping reads (opsdir_adapter_aws.network_inventory). Pure.

  ec2 describe-route-tables                      RouteTables            -> aws_route_table (+ associations; the main
                                                                           one as aws_main_route_table_association);
                                                                           the VPC's local route left out, as state
                                                                           leaves it
  ec2 describe-network-acls                      NetworkAcls            -> aws_network_acl (the default rule 32767, *
                                                                           in the console, left out, as state does)
  ec2 describe-vpc-endpoints                     VpcEndpoints           -> aws_vpc_endpoint
  ec2 describe-vpc-endpoint-service-             ServiceConfigurations  -> aws_vpc_endpoint_service
    configurations
  ec2 describe-vpc-endpoint-service-permissions  AllowedPrincipals      -> aws_vpc_endpoint_service_allowed_principal;
                                                                           an output that doesn't name its service:
                                                                           save it as service-permissions/<service
                                                                           id>.json
  ec2 describe-vpc-peering-connections           VpcPeeringConnections  -> aws_vpc_peering_connection
  ec2 describe-transit-gateway-vpc-attachments   TransitGatewayVpcAttachments
                                                                        -> aws_ec2_transit_gateway_vpc_attachment
  ec2 describe-vpn-connections                   VpnConnections         -> aws_vpn_connection
  ec2 describe-customer-gateways                 CustomerGateways       -> aws_customer_gateway
  ec2 describe-vpn-gateways                      VpnGateways            -> aws_vpn_gateway
  ec2 describe-flow-logs                         FlowLogs               -> aws_flow_log
  network-firewall describe-rule-group           RuleGroupResponse      -> aws_networkfirewall_rule_group
  network-firewall describe-firewall-policy      FirewallPolicyResponse -> aws_networkfirewall_firewall_policy
  network-firewall describe-firewall             FirewallStatus         -> aws_networkfirewall_firewall (its endpoints)
"""
KEYS = ("RouteTables", "NetworkAcls", "VpcEndpoints", "ServiceConfigurations", "AllowedPrincipals",
        "VpcPeeringConnections", "TransitGatewayVpcAttachments", "VpnConnections", "CustomerGateways", "VpnGateways",
        "FlowLogs", "RuleGroupResponse", "FirewallPolicyResponse", "FirewallStatus")
DEFAULT_ACL_RULE = 32767
# a route's CLI target key -> the Terraform attribute
_ROUTE_TARGETS = (("NatGatewayId", "nat_gateway_id"), ("TransitGatewayId", "transit_gateway_id"),
                  ("VpcPeeringConnectionId", "vpc_peering_connection_id"),
                  ("NetworkInterfaceId", "network_interface_id"),
                  ("EgressOnlyInternetGatewayId", "egress_only_gateway_id"), ("LocalGatewayId", "local_gateway_id"),
                  ("CarrierGatewayId", "carrier_gateway_id"), ("CoreNetworkArn", "core_network_arn"))


def _tags(tags):
    return {t["Key"]: t.get("Value", "") for t in tags or () if isinstance(t, dict) and "Key" in t}


def _all(outs, key):
    return [item for _, k, doc in outs if k == key for item in doc.get(key) or ()]


def _docs(outs, key):
    return [(p, doc) for p, k, doc in outs if k == key]


def _stem(path):
    return path.rsplit("/", 1)[-1].rsplit(".", 1)[0]


def _route(r):
    gateway = r.get("GatewayId") or ""
    return {"cidr_block": r.get("DestinationCidrBlock"), "ipv6_cidr_block": r.get("DestinationIpv6CidrBlock"),
            "destination_prefix_list_id": r.get("DestinationPrefixListId"),
            **({"vpc_endpoint_id": gateway} if gateway.startswith("vpce-") else
               {"gateway_id": gateway} if gateway else {}),
            **({"vpc_endpoint_id": r["VpcEndpointId"]} if r.get("VpcEndpointId") else {}),
            **{attr: r.get(key) for key, attr in _ROUTE_TARGETS if r.get(key)}}


def _route_tables(outs):
    tables = _all(outs, "RouteTables")
    return [*(("aws_route_table", {"id": t.get("RouteTableId"), "vpc_id": t.get("VpcId"), "tags": _tags(t.get("Tags")),
                                   "route": [_route(r) for r in t.get("Routes") or ()
                                             if r.get("GatewayId") != "local"]}) for t in tables),
            *(("aws_main_route_table_association", {"route_table_id": t.get("RouteTableId"), "vpc_id": t.get("VpcId")})
              for t in tables if any(a.get("Main") for a in t.get("Associations") or ())),
            *(("aws_route_table_association", {"route_table_id": t.get("RouteTableId"), "subnet_id": a["SubnetId"]})
              for t in tables for a in t.get("Associations") or () if a.get("SubnetId"))]


def _acl_entry(e):
    ports = e.get("PortRange") or {}
    return {"rule_no": e.get("RuleNumber"), "action": e.get("RuleAction"), "protocol": e.get("Protocol"),
            "from_port": ports.get("From", 0), "to_port": ports.get("To", 0), "cidr_block": e.get("CidrBlock"),
            "ipv6_cidr_block": e.get("Ipv6CidrBlock")}


def _acls(outs):
    return [("aws_network_acl", {
        "id": a.get("NetworkAclId"), "vpc_id": a.get("VpcId"), "tags": _tags(a.get("Tags")),
        "subnet_ids": [s.get("SubnetId") for s in a.get("Associations") or () if s.get("SubnetId")],
        "ingress": [_acl_entry(e) for e in a.get("Entries") or ()
                    if not e.get("Egress") and e.get("RuleNumber") != DEFAULT_ACL_RULE],
        "egress": [_acl_entry(e) for e in a.get("Entries") or ()
                   if e.get("Egress") and e.get("RuleNumber") != DEFAULT_ACL_RULE]})
        for a in _all(outs, "NetworkAcls")]


def _endpoints(outs):
    return [("aws_vpc_endpoint", {
        "id": e.get("VpcEndpointId"), "vpc_id": e.get("VpcId"), "vpc_endpoint_type": e.get("VpcEndpointType"),
        "service_name": e.get("ServiceName"), "subnet_ids": e.get("SubnetIds") or [],
        "route_table_ids": e.get("RouteTableIds") or [], "private_dns_enabled": e.get("PrivateDnsEnabled"),
        "security_group_ids": [g.get("GroupId") for g in e.get("Groups") or ()], "tags": _tags(e.get("Tags"))})
        for e in _all(outs, "VpcEndpoints") if e.get("State", "available").lower() not in ("deleted", "deleting")]


def _endpoint_services(outs):
    return [*(("aws_vpc_endpoint_service", {
                "id": s.get("ServiceId"), "service_name": s.get("ServiceName"),
                "acceptance_required": s.get("AcceptanceRequired"),
                "network_load_balancer_arns": s.get("NetworkLoadBalancerArns") or [], "tags": _tags(s.get("Tags"))})
              for s in _all(outs, "ServiceConfigurations")),
            *(("aws_vpc_endpoint_service_allowed_principal", {
                "vpc_endpoint_service_id": a.get("ServiceId") or _stem(path), "principal_arn": a.get("Principal")})
              for path, doc in _docs(outs, "AllowedPrincipals") for a in doc.get("AllowedPrincipals") or ())]


def _links(outs):
    return [*(("aws_vpc_peering_connection", {"id": p.get("VpcPeeringConnectionId"), "tags": _tags(p.get("Tags")),
                                              "accept_status": (p.get("Status") or {}).get("Code"),
                                              "vpc_id": (p.get("RequesterVpcInfo") or {}).get("VpcId"),
                                              "peer_vpc_id": (p.get("AccepterVpcInfo") or {}).get("VpcId")})
              for p in _all(outs, "VpcPeeringConnections")),
            *(("aws_ec2_transit_gateway_vpc_attachment", {
                "id": t.get("TransitGatewayAttachmentId"), "transit_gateway_id": t.get("TransitGatewayId"),
                "vpc_id": t.get("VpcId"), "tags": _tags(t.get("Tags"))})
              for t in _all(outs, "TransitGatewayVpcAttachments")),
            *(("aws_vpn_connection", {"id": v.get("VpnConnectionId"), "customer_gateway_id": v.get("CustomerGatewayId"),
                                      "vpn_gateway_id": v.get("VpnGatewayId"), "tags": _tags(v.get("Tags"))})
              for v in _all(outs, "VpnConnections")),
            *(("aws_customer_gateway", {"id": g.get("CustomerGatewayId"), "ip_address": g.get("IpAddress"),
                                        "bgp_asn": g.get("BgpAsn")}) for g in _all(outs, "CustomerGateways")),
            *(("aws_vpn_gateway", {"id": g.get("VpnGatewayId"), "amazon_side_asn": g.get("AmazonSideAsn")})
              for g in _all(outs, "VpnGateways"))]


_FLOW_SCOPES = (("vpc-", "vpc_id"), ("subnet-", "subnet_id"), ("eni-", "eni_id"),
                ("tgw-attach-", "transit_gateway_attachment_id"), ("tgw-", "transit_gateway_id"))


def _flow_logs(outs):
    return [("aws_flow_log", {
        "id": f.get("FlowLogId"), "log_destination_type": f.get("LogDestinationType"),
        "log_destination": f.get("LogDestination"), "log_group_name": f.get("LogGroupName"),
        "tags": _tags(f.get("Tags")),
        **next(({attr: f.get("ResourceId")} for prefix, attr in _FLOW_SCOPES
                if (f.get("ResourceId") or "").startswith(prefix)), {})})
        for f in _all(outs, "FlowLogs")]


def _firewalls(outs):
    def listed(group):
        source = ((group.get("RuleGroup") or {}).get("RulesSource") or {}).get("RulesSourceList") or {}
        return [{"rules_source": [{"rules_source_list": [{
            "generated_rules_type": source.get("GeneratedRulesType"), "target_types": source.get("TargetTypes") or [],
            "targets": source.get("Targets") or []}]}]}] if source else []
    return [*(("aws_networkfirewall_rule_group", {
                "arn": (doc["RuleGroupResponse"] or {}).get("RuleGroupArn"),
                "tags": _tags((doc["RuleGroupResponse"] or {}).get("Tags")), "rule_group": listed(doc)})
              for _, doc in _docs(outs, "RuleGroupResponse")),
            *(("aws_networkfirewall_firewall_policy", {
                "arn": (doc["FirewallPolicyResponse"] or {}).get("FirewallPolicyArn"),
                "tags": _tags((doc["FirewallPolicyResponse"] or {}).get("Tags")),
                "firewall_policy": [{"stateful_rule_group_reference": [
                    {"resource_arn": r.get("ResourceArn")}
                    for r in (doc.get("FirewallPolicy") or {}).get("StatefulRuleGroupReferences") or ()]}]})
              for _, doc in _docs(outs, "FirewallPolicyResponse")),
            *(("aws_networkfirewall_firewall", {
                "arn": (doc.get("Firewall") or {}).get("FirewallArn"),
                "firewall_policy_arn": (doc.get("Firewall") or {}).get("FirewallPolicyArn"),
                "firewall_status": [{"sync_states": [
                    {"attachment": [{"endpoint_id": (state.get("Attachment") or {}).get("EndpointId")}]}
                    for state in ((doc.get("FirewallStatus") or {}).get("SyncStates") or {}).values()]}]})
              for _, doc in _docs(outs, "FirewallStatus"))]


def network_pairs(outs):
    """(Terraform resource type, attributes) pairs of the network depth among the recognized CLI outputs ((path, key,
    document), ...)."""
    return [*_route_tables(outs), *_acls(outs), *_endpoints(outs), *_endpoint_services(outs), *_links(outs),
            *_flow_logs(outs), *_firewalls(outs)]
