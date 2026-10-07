"""What AWS's networks carry beyond VPCs, subnets and security groups, read back in the network domain's terms
(Terraform state attribute names; the CLI and CloudFormation readers normalize to them). Pure.

  aws_route_table (+ aws_route,          -> route table: routes '<destination> <kind> [<target>]' (a CIDR or prefix
    _association, aws_main_route_table      list; kind from the target: internet, nat, transit, peering, vpn, endpoint,
    _association, aws_default_route_table)   firewall for a Network Firewall's endpoint, appliance, egress-only,
                                             local; the target its provider ref, read as the role of the binding with
                                             it), the subnets associated, whether it is the VPC's main table
  aws_network_acl (+ _rule, _association, -> network ACL: rules '<number> <allow|deny> <in|out> <protocol> <ports>
    aws_default_network_acl)                  <cidr>' (IPv6 entries named, not recorded), the subnets associated
  aws_vpc_endpoint                        -> private endpoint: what it reaches (the service name's last part), kind
                                             (Interface, Gateway), subnets, private DNS; Gateway Load Balancer endpoints
                                             (a firewall's or an appliance's) are routing, not private endpoints
  aws_vpc_endpoint_service (+ _allowed_    -> endpoint service: the service name of the load balancer it exposes, its
    principal)                                name for consumers, the principals allowed, whether connections wait to
                                             be accepted
  aws_networkfirewall_rule_group with a   -> egress firewall (proxy kind firewall): the sites its domain lists allow
    domain list (+ _firewall_policy,         (.example as *.example); the firewall policy is the binding's provider
    _firewall)                               ref (the rule group's tag FirewallPolicy, else the policy referencing it,
                                             else the rule group)
  aws_vpc_peering_connection,            -> interconnect depth: kind (peering, transit, vpn), whether the other side
    aws_ec2_transit_gateway_vpc_attachment,  accepted, a VPN's peer gateway and BGP numbers; a peering's other side is
    aws_vpn_connection (+ customer and       the environment whose network is one of its two VPCs (core), else the
    VPN gateways)                            tag PeerEnvironment
  aws_flow_log                           -> flow log: what it records (network, subnet, interface, transit), the log
                                             destination it writes to, its retention when that is a log group
Roles: tag Role (or BindingRole); the security groups VPC endpoints use are theirs, not the record's firewall rules.
"""
from opsdir.core.inventory import of_types, peer_environment, resource, tagged_role
from opsdir.domains.network.ports import acl_rule_text
from opsdir.domains.network.routing import Route, route_text
from .network import SERVICES
from .tags import state_tags as _tags

# the kind of service a VPC endpoint's service name reaches (com.amazonaws.<region>.<service>)
SERVICE_KINDS = {**{v: k for k, v in SERVICES.items()}, "ecr.dkr": "registry", "dynamodb": "database",
                 "sqs": "messaging", "events": "messaging", "monitoring": "logs"}
PROTOCOLS = {"-1": "all", "all": "all", "6": "tcp", "tcp": "tcp", "17": "udp", "udp": "udp", "1": "icmp",
             "icmp": "icmp"}
# a route's target attribute -> its kind (a gateway's by its id's prefix)
_TARGETS = (("nat_gateway_id", "nat"), ("transit_gateway_id", "transit"), ("vpc_peering_connection_id", "peering"),
            ("egress_only_gateway_id", "egress-only"), ("network_interface_id", "appliance"),
            ("local_gateway_id", "appliance"), ("carrier_gateway_id", "internet"), ("core_network_arn", "transit"))
_GATEWAYS = {"igw-": "internet", "vgw-": "vpn", "local": "local"}


def _first(v):
    return (v[0] if v else {}) if isinstance(v, list) else (v or {})


def firewall_endpoints(found):
    """{VPC endpoint id: the firewall policy's ARN} of the Network Firewall endpoints the firewalls report."""
    return {att.get("endpoint_id"): fw.get("firewall_policy_arn")
            for fw in of_types(found, "aws_networkfirewall_firewall")
            for status in fw.get("firewall_status") or () for sync in status.get("sync_states") or ()
            for att in sync.get("attachment") or () if att.get("endpoint_id")}


def _route(r, firewalls, endpoints):
    """A Route of a route (inline or aws_route) with its target as the provider ref, or None for a target the record
    has no kind for. A VPC endpoint is a firewall's (Network Firewall), a Gateway Load Balancer's or a gateway
    endpoint's (S3, DynamoDB)."""
    dest = r.get("cidr_block") or r.get("destination_cidr_block") or r.get("ipv6_cidr_block") or \
        r.get("destination_ipv6_cidr_block") or r.get("destination_prefix_list_id")
    endpoint = r.get("vpc_endpoint_id")
    gateway = r.get("gateway_id") or ""
    target = next(((kind, r[attr]) for attr, kind in _TARGETS if r.get(attr)), None) or \
        (("firewall", firewalls[endpoint]) if endpoint in firewalls else
         ("gateway-lb" if endpoints.get(endpoint) == "GatewayLoadBalancer" else "endpoint", endpoint) if endpoint else
         next(((kind, "" if kind == "local" else gateway) for prefix, kind in _GATEWAYS.items()
               if gateway.startswith(prefix)), None))
    return Route(dest, target[0], target[1] or "", ()) if dest and target else None


def _route_tables(found):
    firewalls = firewall_endpoints(found)
    endpoints = {e.get("id"): e.get("vpc_endpoint_type") for e in of_types(found, "aws_vpc_endpoint")}
    tables = of_types(found, "aws_route_table", "aws_default_route_table")
    main = {a.get("route_table_id") for a in of_types(found, "aws_main_route_table_association")} | \
        {a.get("id") for a in of_types(found, "aws_default_route_table")}
    separate = of_types(found, "aws_route")
    associations = of_types(found, "aws_route_table_association")

    def one_table(t):
        ref = t.get("id") or t.get("default_route_table_id")
        routes = (*(t.get("route") or ()), *(r for r in separate if r.get("route_table_id") == ref))
        return resource("route-table", ref, {
            "ciamRoute": tuple(dict.fromkeys(route_text(r) for r in (_route(x, firewalls, endpoints) for x in routes)
                                             if r)),
            "ciamMainTable": "TRUE" if ref in main else "FALSE"},
            links={"ciamSubnetRole": tuple(a.get("subnet_id") for a in associations
                                           if a.get("route_table_id") == ref and a.get("subnet_id"))},
            name=_tags(t).get("Name") or ref, role=tagged_role(_tags(t)), tags=_tags(t))
    return tuple(one_table(t) for t in tables if t.get("id") or t.get("default_route_table_id"))


def _acl_rule(rule, egress):
    """(ciamAclRule text, or None and why) of one ACL entry."""
    cidr = rule.get("cidr_block")
    if not cidr:
        return None, f"IPv6 range {rule.get('ipv6_cidr_block')}" if rule.get("ipv6_cidr_block") else "no range"
    protocol = PROTOCOLS.get(str(rule.get("protocol")).lower())
    if protocol is None:
        return None, f"protocol {rule.get('protocol')}"
    low, high = rule.get("from_port"), rule.get("to_port")
    ports = (0, 65535) if protocol in ("all", "icmp") or (not low and not high) else (int(low), int(high or low))
    action = (rule.get("action") or rule.get("rule_action") or "").lower()
    number = rule.get("rule_no") or rule.get("rule_number")
    return acl_rule_text(int(number), action, "out" if egress else "in", protocol, ports, cidr), None


def _acls(found):
    """(network ACLs, notices)."""
    separate = of_types(found, "aws_network_acl_rule")
    associated = of_types(found, "aws_network_acl_association")

    def entries(acl, ref):
        return (*((r, False) for r in acl.get("ingress") or ()), *((r, True) for r in acl.get("egress") or ()),
                *((r, bool(r.get("egress"))) for r in separate if r.get("network_acl_id") == ref))

    out, notices = [], []
    for acl in of_types(found, "aws_network_acl", "aws_default_network_acl"):
        ref = acl.get("id") or acl.get("default_network_acl_id")
        read = [(_acl_rule(r, egress), r) for r, egress in entries(acl, ref)]
        notices += [f"network ACL {ref} rule {r.get('rule_no') or r.get('rule_number')}: {why}; not recorded"
                    for (text, why), r in read if text is None]
        out.append(resource("acl", ref, {"ciamAclRule": sorted({t for (t, _), _ in read if t},
                                                                 key=lambda t: (int(t.split(" ", 1)[0]), t))},
                            links={"ciamSubnetRole": tuple(dict.fromkeys((
                                *(acl.get("subnet_ids") or ()),
                                *(a.get("subnet_id") for a in associated if a.get("network_acl_id") == ref))))},
                            name=_tags(acl).get("Name") or ref, role=tagged_role(_tags(acl)), tags=_tags(acl)))
    return tuple(out), tuple(notices)


def endpoint_security_groups(found):
    """The security groups VPC endpoints use: their rules are the endpoints', not the record's."""
    return {g for e in of_types(found, "aws_vpc_endpoint") for g in e.get("security_group_ids") or ()}


def _private_endpoints(found):
    def one_endpoint(e):
        service = (e.get("service_name") or "").split(".", 3)[-1]
        kind = (e.get("vpc_endpoint_type") or "Gateway").lower()
        return resource("private-endpoint", e.get("id"), {
            "ciamPrivateService": SERVICE_KINDS.get(service, "other"), "ciamPrivateEndpointKind": kind,
            "ciamPrivateDns": ("TRUE" if e.get("private_dns_enabled") else "FALSE") if kind == "interface" else None},
            links={"ciamSubnetRole": tuple(e.get("subnet_ids") or ())},
            name=_tags(e).get("Name") or e.get("id"), role=tagged_role(_tags(e)), tags=_tags(e))
    return tuple(one_endpoint(e) for e in of_types(found, "aws_vpc_endpoint")
                 if e.get("id") and (e.get("vpc_endpoint_type") or "") != "GatewayLoadBalancer")


def _endpoint_services(found):
    allowed = of_types(found, "aws_vpc_endpoint_service_allowed_principal")

    def one_service(s):
        principals = (*(s.get("allowed_principals") or ()),
                      *(a.get("principal_arn") for a in allowed if a.get("vpc_endpoint_service_id") == s.get("id")))
        return resource("endpoint-service", s.get("id"), {
            "ciamServiceAlias": s.get("service_name"), "ciamAllowedPrincipal": tuple(dict.fromkeys(principals)),
            "ciamAcceptanceRequired": "TRUE" if s.get("acceptance_required") else "FALSE"},
            links={"ciamServiceRole": next(iter(s.get("network_load_balancer_arns") or ()), None)},
            name=_tags(s).get("Name") or s.get("id"), role=tagged_role(_tags(s)), tags=_tags(s))
    return tuple(one_service(s) for s in of_types(found, "aws_vpc_endpoint_service") if s.get("id"))


def _domain(target):
    """A domain list target as the record writes a site: .example (the domain and its subdomains) is *.example."""
    return "*" + target if target.startswith(".") else target


def _proxies(found):
    """An egress firewall per firewall policy whose rule groups hold domain lists (a rule group no policy here
    references stands for its tagged policy, else for itself)."""
    groups = {g.get("arn"): g for g in of_types(found, "aws_networkfirewall_rule_group")
              if _first(_first(_first(g.get("rule_group")).get("rules_source")).get("rules_source_list"))}
    policies = {p.get("arn"): p for p in of_types(found, "aws_networkfirewall_firewall_policy")}
    referenced = {ref.get("resource_arn"): arn for arn, p in policies.items()
                  for ref in _first(p.get("firewall_policy")).get("stateful_rule_group_reference") or ()}
    owner = {arn: _tags(g).get("FirewallPolicy") or referenced.get(arn) or arn for arn, g in groups.items()}

    def sites(arn):
        listed = _first(_first(_first(groups[arn].get("rule_group")).get("rules_source")).get("rules_source_list"))
        return tuple(_domain(t) for t in listed.get("targets") or ()) \
            if (listed.get("generated_rules_type") or "").upper() == "ALLOWLIST" else ()

    def one_proxy(ref):
        mine = [arn for arn, o in owner.items() if o == ref]
        tagged = next((_tags(x) for x in (*(groups[a] for a in mine), policies.get(ref) or {})
                       if tagged_role(_tags(x))), {})
        allowed = tuple(dict.fromkeys(s for a in mine for s in sites(a)))
        return resource("proxy", ref, {"ciamProxyKind": "firewall", "ciamAllowedDestination": allowed},
                        name=tagged.get("Name") or ref.rsplit("/", 1)[-1], role=tagged_role(tagged), tags=tagged)
    return tuple(one_proxy(ref) for ref in dict.fromkeys(owner.values()))


def _interconnects(found):
    gateways = {g.get("id"): g for g in of_types(found, "aws_customer_gateway")}
    vgws = {g.get("id"): g for g in of_types(found, "aws_vpn_gateway")}

    def link(kind, a, text, extra=None, networks=()):
        return resource("interconnect", a.get("id"), {
            "ciamLinkKind": kind, "ciamInterconnectKind": text,
            "ciamPeerEnvironment": peer_environment(_tags(a)), **(extra or {})},
            links={"ciamPeerEnvironment": tuple(n for n in networks if n)},
            name=_tags(a).get("Name") or a.get("id"), role=tagged_role(_tags(a)), tags=_tags(a))
    peerings = (link("peering", p, "VPC peering",
                     {"ciamPeerAccepted": None if not p.get("accept_status") else
                      "TRUE" if p.get("accept_status") == "active" else "FALSE"},
                     (p.get("vpc_id"), p.get("peer_vpc_id")))              # either may be ours: core takes the other
                for p in of_types(found, "aws_vpc_peering_connection"))
    transits = (link("transit", t, "Transit gateway attachment") for t in
                of_types(found, "aws_ec2_transit_gateway_vpc_attachment"))
    vpns = (link("vpn", v, "Site-to-site VPN", {
                "ciamPeerGateway": (gateways.get(v.get("customer_gateway_id")) or {}).get("ip_address"),
                "ciamPeerAsn": (gateways.get(v.get("customer_gateway_id")) or {}).get("bgp_asn"),
                "ciamLocalAsn": (vgws.get(v.get("vpn_gateway_id")) or {}).get("amazon_side_asn")})
            for v in of_types(found, "aws_vpn_connection"))
    return tuple(r for r in (*peerings, *transits, *vpns) if r.ref)


def _flow_logs(found):
    groups = {g.get("arn"): g for g in of_types(found, "aws_cloudwatch_log_group")}
    by_name = {g.get("name"): g for g in groups.values()}
    scopes = (("vpc_id", "network"), ("subnet_id", "subnet"), ("eni_id", "interface"),
              ("transit_gateway_id", "transit"), ("transit_gateway_attachment_id", "transit"))

    def one_log(f):
        dest = f.get("log_destination") or ""
        group = groups.get(dest) or groups.get(dest.removesuffix(":*")) or by_name.get(f.get("log_group_name"))
        return resource("flow-log", f.get("id"), {
            "ciamFlowScope": next((scope for attr, scope in scopes if f.get(attr)), None),
            "ciamRetentionDays": (group or {}).get("retention_in_days") or None},
            links={"ciamSubnetRole": f.get("subnet_id"),
                   "ciamLogDestinationRole": (group or {}).get("arn") or dest or None},
            name=_tags(f).get("Name") or f.get("id"), role=tagged_role(_tags(f)), tags=_tags(f))
    return tuple(one_log(f) for f in of_types(found, "aws_flow_log") if f.get("id"))


def network_resources(found):
    """(resources, notices) of the network depth among (Terraform resource type, attributes) pairs."""
    acls, notices = _acls(found)
    return ((*_route_tables(found), *acls, *_private_endpoints(found), *_endpoint_services(found), *_proxies(found),
             *_interconnects(found), *_flow_logs(found)), notices)
