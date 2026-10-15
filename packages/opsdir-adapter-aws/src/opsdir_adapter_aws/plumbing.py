"""AWS: the network plumbing an environment's landing zone, or another party, keeps (opsdir.domains.network.plumbing),
rendered into their root (terraform/landing-zone/[<party>/]network.tf). What already exists (a provider ref) is
adopted with an import block; what doesn't is created.

  NAT egress        a NAT gateway: public, its elastic IPs looked up by address (secondary ones too), or private when
                    its range is private; the public subnet it sits in is an input
  route tables      a route table with its routes, each target the resource rendered here, else the binding's provider
                    ref, else the ref the route names; its subnet associations. The main table is the VPC's default
                    route table (adopted without an import)
  network ACLs      a network ACL with its rules both ways, on its subnets
  interconnects     VPC peering (with the other environment's VPC, AWS only), a transit gateway attachment (the transit
                    gateway an input), a site-to-site VPN: customer gateway, the VPC's VPN gateway, the connection with
                    BGP or static routes. Dedicated circuits and hubs are named, not rendered
  flow logs         on the VPC, each subnet or the transit gateway, to its log destination's ARN (CloudWatch Logs with
                    the delivery role an input, S3, Firehose); retention is the destination's
  kept elsewhere    private endpoints and egress firewalls' domain lists someone else keeps (opsdir_adapter_aws.network)
Tags Name and Role, read back by the importers. What it leaves out or to a person is a render note (core.notes, flow
43) written as its comment, enumerated the way the keepers' roots are walked (plumbing_notes). Pure.
"""
import ipaddress
from typing import NamedTuple

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.environment import of_class, one_role
from opsdir.core.network import is_private
from opsdir.core.notes import RECORD, note_comment
from opsdir.domains.network.plumbing import (adopted, cross_cloud_peering_note, flow_scope_note, keeper_notes,
                                             link_kind_note, network_note, peer_cloud, peer_half_note, peer_network,
                                             route_target, subnet_wide_note)
from opsdir.domains.network.ports import acl_rules
from opsdir.domains.network.routing import parse_route
from opsdir.domains.network.stack import subnets
from opsdir_format_terraform.hcl import (Block, blocks_of, comment, distinct, from_entry, ref, tf_block, tf_import,
                                         tf_name)
from .network import binding_tags, domain_rules, endpoint_notes, firewall_notes, private_endpoint

VPC = "data.aws_vpc.main.id"
# blocks: what the binding renders; variables: inputs only its keeper knows; shared: data sources and resources
# rendered once in the root, however many bindings use them
Rendered = NamedTuple("Rendered", [("blocks", tuple), ("variables", tuple), ("shared", tuple)])
# the route attribute each kind of target goes in
TARGETS = {"internet": "gateway_id", "vpn": "gateway_id", "egress-only": "egress_only_gateway_id",
           "nat": "nat_gateway_id", "transit": "transit_gateway_id", "peering": "vpc_peering_connection_id",
           "endpoint": "vpc_endpoint_id", "gateway-lb": "vpc_endpoint_id", "firewall": "vpc_endpoint_id",
           "appliance": "network_interface_id"}
PROTOCOLS = {"all": "-1", "tcp": "tcp", "udp": "udp", "icmp": "icmp"}
# a flow log destination's kind by its ARN
DESTINATIONS = (("arn:aws:s3", "s3"), ("arn:aws:firehose", "kinesis-data-firehose"),
                ("arn:aws:logs", "cloud-watch-logs"))
IGW = tf_block("data", ["aws_internet_gateway", "main"], [
    ("filter", Block((("name", "attachment.vpc-id"), ("values", [ref(VPC)]))))])
TRANSIT = "transit_gateway_id"


def network_data(m):
    """Data sources for environment m's VPC and subnets (by their provider refs)."""
    def by_ref(b):
        ref_ = one(b, "ciamProviderRef") if b is not None else None
        return [("id", ref_)] if ref_ else [("#", "UNBOUND: the binding has no provider ref")]
    return (tf_block("data", ["aws_vpc", "main"], by_ref(one_role(m, "network"))),
            *(tf_block("data", ["aws_subnet", tf_name(rdn_value(s))], by_ref(s))
              for s in of_class(m, "ciamSubnetBinding")))


def _var(name, description):
    return tf_block("variable", [name], [("type", ref("string")), ("description", description)])


def _adopt(address, b, id_=None):
    """An import block for a binding that exists (its provider ref, or the id given), else ()."""
    return (tf_import(address, id_ or one(b, "ciamProviderRef")),) if adopted(b) else ()


def _note(b, text):
    return Rendered((comment(f"{rdn_value(b)}: {text}"),), (), ())


def _noted(notes):
    """Rendered of render notes' comments."""
    return Rendered(tuple(comment(note_comment(n)) for n in notes), (), ())


def _subnet(s):
    return ref(f"data.aws_subnet.{tf_name(rdn_value(s))}.id")


# ------------------------------------------------------------------ NAT egress
def _addresses(cidr):
    """The addresses of an egress range small enough to be elastic IPs (up to 16), else ()."""
    net = ipaddress.ip_network(cidr, strict=False)
    return tuple(str(a) for a in net) if net.num_addresses <= 16 else ()


def egress(m, b, here=()):
    """A NAT gateway: public with its elastic IPs (looked up by address) when its range is public, else private."""
    n = tf_name(rdn_value(b))
    public = tuple(a for c in values(b, "ciamCidr") if not is_private(c) for a in _addresses(c))
    zone = one(b, "ciamZone")
    return Rendered(
        (tf_block("resource", ["aws_nat_gateway", n], [
            ("connectivity_type", "public" if public else "private"),
            *((("allocation_id", ref(f"data.aws_eip.{n}_0.id")),) if public else ()),
            *((("secondary_allocation_ids", [ref(f"data.aws_eip.{n}_{i}.id") for i in range(1, len(public))]),)
              if len(public) > 1 else ()),
            ("subnet_id", ref(f"var.{n}_subnet_id")), ("tags", binding_tags(b))]),
         *_adopt(f"aws_nat_gateway.{n}", b)),
        (_var(f"{n}_subnet_id", f"The {'public ' if public else ''}subnet NAT gateway {rdn_value(b)} sits in"
              + (f" ({zone})" if zone else "")),),
        tuple(tf_block("data", ["aws_eip", f"{n}_{i}"], [("public_ip", a)]) for i, a in enumerate(public)))


# ------------------------------------------------------------------ route tables
def _peers(m, b):
    """The other end's VPC id when an interconnect can be rendered as VPC peering (the other end on AWS), else None."""
    cloud, net = peer_cloud(m.d, b), peer_network(m.d, b)
    aws = cloud is None or one(cloud, "ciamCloudProvider") == "aws"
    return one(net, "ciamProviderRef") if aws and net is not None else None


def _address(m, b):
    """The Terraform expression of a binding rendered in the same root, as a route target, or None (not rendered)."""
    n, kind = tf_name(rdn_value(b)), one(b, "ciamLinkKind")
    if is_kind(m.d, b, "ciamEgress"):
        return f"aws_nat_gateway.{n}.id"
    if is_kind(m.d, b, "ciamInterconnect") and kind == "peering" and _peers(m, b):
        return f"aws_vpc_peering_connection.{n}.id"
    if is_kind(m.d, b, "ciamInterconnect") and kind == "vpn" and one(b, "ciamPeerGateway"):
        return "aws_vpn_gateway.main.id"
    return None


def _target(m, route, here):
    """(expression or None, variables, shared) a route's target is written as."""
    b = route_target(m, route)
    if route.kind == "transit":
        return ref(f"var.{TRANSIT}"), (_var(TRANSIT, "The transit gateway the network attaches to (the hub's)"),), ()
    if route.kind == "internet" and not route.target:
        return ref("data.aws_internet_gateway.main.id"), (), (IGW,)
    if b is not None and b.dn in here and _address(m, b):
        return ref(_address(m, b)), (), ()
    if b is not None and route.kind == "vpn" and _gateway_link(m) is not None:
        return ref("aws_vpn_gateway.main.id"), (), ()     # the VPC's one, read across roots when another writes it
    if b is not None and route.kind == "vpn":
        return ref("var.vpn_gateway_id"), (_var("vpn_gateway_id", f"The VPN gateway {rdn_value(b)} connects to (kept "
                                                                  "with the VPN)"),), ()
    if b is not None and route.kind == "firewall":
        name = f"{tf_name(one(b, 'ciamBindingRole'))}_endpoint_id"
        return ref(f"var.{name}"), (_var(name, f"The Network Firewall endpoint of {rdn_value(b)} the route sends "
                                               "traffic to (the one in the subnets' zone)"),), ()
    if b is not None:
        return one(b, "ciamProviderRef"), (), ()
    return route.target or None, (), ()


def _blackhole_note(m, b, route):
    return network_note(m, b, "blocker", f"{route.destination}: a blackhole route; Terraform doesn't create those: "
                        "not rendered", (f"Drop the route and deny {route.destination} in the subnets' network ACL "
                                         f"instead, {RECORD}",))


def _routes(b):
    return tuple(r for r in map(parse_route, values(b, "ciamRoute")) if r and r.kind != "local")


def route_notes(m, b, here=()):
    """The render notes of route table b's routes as _route writes them: a blackhole route (a blocker), a route for
    some roles whose target renders (a plain note: AWS routes apply to the whole subnet); each once."""
    return tuple(dict.fromkeys(n for r in _routes(b) for n in (
        (_blackhole_note(m, b, r),) if r.kind == "none" else
        (subnet_wide_note(m, b, r, "AWS"),) if r.roles and _target(m, r, here)[0] is not None else ())))


def _route(m, b, route, here):
    """Rendered whose blocks are body items of table b: ("route", Block) or a comment."""
    if route.kind == "none":
        return Rendered((("#", note_comment(_blackhole_note(m, b, route))),), (), ())
    value, variables, shared = _target(m, route, here)
    if value is None:
        return Rendered((("#", f"UNBOUND: {route.destination} {route.kind}: its target {route.target} isn't rendered "
                               "here and has no provider ref" if route.target else
                               f"UNBOUND: {route.destination} {route.kind} names no target"),), (), ())
    net = route.destination if "/" in route.destination else None
    dest = ("destination_prefix_list_id" if net is None else
            "ipv6_cidr_block" if ipaddress.ip_network(net, strict=False).version == 6 else "cidr_block")
    scoped = (("#", note_comment(subnet_wide_note(m, b, route, "AWS"))),) if route.roles else ()
    return Rendered((*scoped, ("route", Block(((dest, route.destination), (TARGETS[route.kind], value))))),
                    variables, shared)


def route_table(m, b, here=()):
    """A route table with its routes and subnet associations; the main table as the VPC's default route table."""
    n, main = tf_name(rdn_value(b)), one(b, "ciamMainTable") == "TRUE"
    parts = tuple(_route(m, b, r, here) for r in _routes(b))
    kind = "aws_default_route_table" if main else "aws_route_table"
    table = tf_block("resource", [kind, n], [
        ("default_route_table_id", ref("data.aws_vpc.main.main_route_table_id")) if main else ("vpc_id", ref(VPC)),
        *(x for p in parts for x in p.blocks), ("tags", binding_tags(b))])
    found = subnets(m, b)
    associations = tuple(x for s in found for x in (
        tf_block("resource", ["aws_route_table_association", f"{n}_{tf_name(rdn_value(s))}"], [
            ("subnet_id", _subnet(s)), ("route_table_id", ref(f"{kind}.{n}.id"))]),
        *(_adopt(f"aws_route_table_association.{n}_{tf_name(rdn_value(s))}", b,
                 f"{one(s, 'ciamProviderRef')}/{one(b, 'ciamProviderRef')}") if one(s, "ciamProviderRef") else ())))
    return Rendered((table, *(() if main else _adopt(f"aws_route_table.{n}", b)), *associations),
                    tuple(v for p in parts for v in p.variables), tuple(x for p in parts for x in p.shared))


# ------------------------------------------------------------------ network ACLs
def _acl_entry(r):
    lo, hi = (0, 0) if r.protocol in ("all", "icmp") else r.ports
    return ("ingress" if r.direction == "in" else "egress", Block((
        ("rule_no", r.number), ("action", r.action), ("protocol", PROTOCOLS[r.protocol]),
        ("ipv6_cidr_block" if ":" in r.cidr else "cidr_block", r.cidr), ("from_port", lo), ("to_port", hi),
        *((("icmp_type", -1), ("icmp_code", -1)) if r.protocol == "icmp" else ()))))


def network_acl(m, b, here=()):
    """A network ACL with its rules both ways, on its subnets."""
    n, found = tf_name(rdn_value(b)), subnets(m, b)
    return Rendered((tf_block("resource", ["aws_network_acl", n], [
        ("vpc_id", ref(VPC)), *((("subnet_ids", [_subnet(s) for s in found]),) if found else ()),
        *(_acl_entry(r) for r in acl_rules(b)), ("tags", binding_tags(b))]), *_adopt(f"aws_network_acl.{n}", b)),
        (), ())


# ------------------------------------------------------------------ interconnects
def _gateway_link(m):
    """The VPN link the VPC's VPN gateway renders with: the first one the environment renders. A VPC attaches one VPN
    gateway, so the other links' VPN connections read it, across roots when someone else keeps them."""
    return next((i for i in of_class(m, "ciamInterconnect")
                 if one(i, "ciamLinkKind") == "vpn" and one(i, "ciamPeerGateway")), None)


def _vpn_gateway(m):
    """The VPC's VPN gateway, its Amazon-side ASN the first VPN link's local one."""
    asn = next((one(i, "ciamLocalAsn") for i in of_class(m, "ciamInterconnect")
                if one(i, "ciamLinkKind") == "vpn" and one(i, "ciamLocalAsn")), None)
    return tf_block("resource", ["aws_vpn_gateway", "main"], [
        ("vpc_id", ref(VPC)), *((("amazon_side_asn", int(asn)),) if asn else ()),
        ("tags", {"Name": f"ciam-{rdn_value(m.env)}", "ManagedBy": "opsdir"})])


def _cross_cloud(m, b):
    cloud = peer_cloud(m.d, b)
    return cloud is not None and one(cloud, "ciamCloudProvider") != "aws"


def _accept_note(m, b):
    return peer_half_note(m, b, "the other side accepts the peering in its account "
                                "(aws_vpc_peering_connection_accepter)")


def _peering(m, b, n):
    cloud, peer = peer_cloud(m.d, b), _peers(m, b)
    if _cross_cloud(m, b):
        return _noted((cross_cloud_peering_note(m, b, "AWS"),))
    if peer is None:
        return _note(b, "UNBOUND: the other environment's network has no provider ref to peer with. Not rendered.")
    region = one(cloud, "ciamRegion") if cloud is not None else None
    return Rendered((
        *((comment(note_comment(_accept_note(m, b))),) if one(b, "ciamPeerAccepted") != "TRUE" else ()),
        tf_block("resource", ["aws_vpc_peering_connection", n], [
            ("vpc_id", ref(VPC)), ("peer_vpc_id", peer),
            *((("peer_region", region),) if region and region != one(m.cloud, "ciamRegion") else ()),
            ("tags", binding_tags(b))]),
        *_adopt(f"aws_vpc_peering_connection.{n}", b)), (), ())


def _vpn(m, b, n):
    gateway, peer_asn = one(b, "ciamPeerGateway"), one(b, "ciamPeerAsn")
    if gateway is None:
        return _note(b, "UNBOUND: a VPN needs the other end's gateway address (ciamPeerGateway). Not rendered.")
    static = tuple(tf_block("resource", ["aws_vpn_connection_route", f"{n}_{i}"], [
        ("destination_cidr_block", c), ("vpn_connection_id", ref(f"aws_vpn_connection.{n}.id"))])
        for i, c in enumerate(values(b, "ciamAcceptedCidr"))) if peer_asn is None else ()
    owns = _gateway_link(m).dn == b.dn
    return Rendered((
        *((_vpn_gateway(m),) if owns else ()),
        tf_block("resource", ["aws_customer_gateway", n], [
            ("bgp_asn", int(peer_asn or 65000)), ("ip_address", gateway), ("type", "ipsec.1"),
            ("tags", binding_tags(b))]),
        tf_block("resource", ["aws_vpn_connection", n], [
            ("customer_gateway_id", ref(f"aws_customer_gateway.{n}.id")),
            ("vpn_gateway_id", ref("aws_vpn_gateway.main.id")), ("type", "ipsec.1"),
            ("static_routes_only", peer_asn is None), ("tags", binding_tags(b))]),
        *_adopt(f"aws_vpn_connection.{n}", b), *static), (), ())


def interconnect_notes(m, b, here=()):
    """The render notes of interconnect b as interconnect writes them: a peering to another cloud (a blocker), the
    other side accepting a peering (peer_half_note), a Direct Connect circuit ordered by hand (an action), a hub link
    (a blocker: AWS has none), an unrecorded kind of link (a blocker); an UNBOUND link has none."""
    kind = one(b, "ciamLinkKind")
    if kind == "peering" and _cross_cloud(m, b):
        return (cross_cloud_peering_note(m, b, "AWS"),)
    if kind == "peering":
        return (_accept_note(m, b),) if _peers(m, b) is not None and one(b, "ciamPeerAccepted") != "TRUE" else ()
    if kind in ("transit", "vpn"):
        return ()
    if kind == "dedicated":
        return (network_note(m, b, "action", "a dedicated circuit (Direct Connect) is ordered from a provider; its "
                             "virtual interface attaches to the VPN gateway or a Direct Connect gateway: not rendered",
                             ("Order the Direct Connect connection (or a hosted one from a partner) and attach its "
                              "virtual interface to the VPN gateway or a Direct Connect gateway",)),)
    if kind == "hub":
        return (network_note(m, b, "blocker", "AWS has no managed hub connection: a transit gateway attachment is a "
                             "transit link: not rendered", (f"Record it as a transit link (ciamLinkKind), {RECORD}",)),)
    return (link_kind_note(m, b),)


def interconnect(m, b, here=()):
    """An interconnect by its kind: peering, transit attachment, VPN; dedicated circuits, hubs and unrecorded kinds
    their notes' comments (interconnect_notes)."""
    n, kind = tf_name(rdn_value(b)), one(b, "ciamLinkKind")
    if kind == "peering":
        return _peering(m, b, n)
    if kind == "transit":
        found = of_class(m, "ciamSubnetBinding")
        return Rendered((tf_block("resource", ["aws_ec2_transit_gateway_vpc_attachment", n], [
            ("transit_gateway_id", ref(f"var.{TRANSIT}")), ("vpc_id", ref(VPC)),
            ("subnet_ids", [_subnet(s) for s in found]), ("tags", binding_tags(b))]),
            *_adopt(f"aws_ec2_transit_gateway_vpc_attachment.{n}", b)),
            (_var(TRANSIT, "The transit gateway the network attaches to (the hub's)"),), ())
    if kind == "vpn":
        return _vpn(m, b, n)
    return _noted(interconnect_notes(m, b))


# ------------------------------------------------------------------ flow logs
def _destination(m, b):
    """(log destination binding, its ARN) of a flow log, either None."""
    dest = one_role(m, one(b, "ciamLogDestinationRole") or "")
    return dest, one(dest, "ciamProviderRef") if dest is not None else None


def _flows_on(m, b, n):
    """((resource name, target body item), ...) of what a flow log is on: the VPC, the transit gateway or each
    subnet; () for another scope."""
    return ({"network": ((n, ("vpc_id", ref(VPC))),),
             "transit": ((n, ("transit_gateway_id", ref(f"var.{TRANSIT}"))),),
             "subnet": tuple((f"{n}_{tf_name(rdn_value(s))}", ("subnet_id", _subnet(s))) for s in subnets(m, b))}
            .get(one(b, "ciamFlowScope"), ()))


def _retention_note(m, b, dest, days):
    return network_note(m, b, "action", f"kept {days} days, the retention of {rdn_value(dest)} (not set here)",
                        (f"Set the retention of {rdn_value(dest)} to {days} days where it is kept",))


def flow_log_notes(m, b, here=()):
    """The render notes of flow log b as flow_log writes them: a scope whose ids aren't recorded (flow_scope_note),
    the retention its destination keeps, not set here (an action); none when its destination is UNBOUND."""
    dest, arn = _destination(m, b)
    days = one(b, "ciamRetentionDays")
    return (() if arn is None else (flow_scope_note(m, b),) if not _flows_on(m, b, tf_name(rdn_value(b))) else
            (_retention_note(m, b, dest, days),) if days else ())


def flow_log(m, b, here=()):
    """A flow log on the VPC, each subnet or the transit gateway, to its log destination's ARN; its notes' comments
    (flow_log_notes)."""
    n, scope = tf_name(rdn_value(b)), one(b, "ciamFlowScope")
    dest, arn = _destination(m, b)
    if arn is None:
        return _note(b, "UNBOUND: its log destination has no binding with an ARN here. Not rendered.")
    kind = next((k for prefix, k in DESTINATIONS if arn.startswith(prefix)), "cloud-watch-logs")
    on = _flows_on(m, b, n)
    if not on:
        return _noted(flow_log_notes(m, b))
    role = (("iam_role_arn", ref("var.flow_logs_role_arn")),) if kind == "cloud-watch-logs" else ()
    days = one(b, "ciamRetentionDays")
    return Rendered((
        *((comment(note_comment(_retention_note(m, b, dest, days))),) if days else ()),
        *(x for name, target in on for x in (
            tf_block("resource", ["aws_flow_log", name], [
                target, ("traffic_type", "ALL"), ("log_destination_type", kind), ("log_destination", arn), *role,
                ("tags", binding_tags(b))]),
            *(_adopt(f"aws_flow_log.{name}", b) if len(on) == 1 else ())))),
        (*((_var("flow_logs_role_arn", "The IAM role flow logs deliver to CloudWatch Logs with"),) if role else ()),
         *((_var(TRANSIT, "The transit gateway the network attaches to (the hub's)"),) if scope == "transit" else ())),
        ())


# ------------------------------------------------------------------ kept elsewhere
def kept_elsewhere(m, b, here=()):
    """A private endpoint or an egress firewall's domain list someone else keeps, as the stack would render it."""
    if is_kind(m.d, b, "ciamProxy"):
        return Rendered(domain_rules(m, b), (), ())
    blocks = private_endpoint(m, b)
    made = bool(blocks_of(blocks, "resource", "aws_vpc_endpoint"))
    return Rendered((*blocks, *(_adopt(f"aws_vpc_endpoint.{tf_name(rdn_value(b))}", b) if made else ())), (), ())


def kept_notes(m, b, here=()):
    """The render notes of a private endpoint or egress firewall someone else keeps, as kept_elsewhere renders it."""
    return firewall_notes(m, b) if is_kind(m.d, b, "ciamProxy") else endpoint_notes(m, b)


NOTES = (("ciamRouteTable", route_notes), ("ciamInterconnect", interconnect_notes), ("ciamFlowLog", flow_log_notes),
         ("ciamPrivateEndpoint", kept_notes), ("ciamProxy", kept_notes))


def plumbing_notes(m):
    """The render notes of environment m's plumbing as its keepers' roots write them (core keeper_notes over
    NOTES)."""
    return keeper_notes(m, NOTES)


RENDERERS = (("ciamEgress", egress), ("ciamRouteTable", route_table), ("ciamNetworkAcl", network_acl),
             ("ciamInterconnect", interconnect), ("ciamFlowLog", flow_log), ("ciamPrivateEndpoint", kept_elsewhere),
             ("ciamProxy", kept_elsewhere))


def render_plumbing(m, keeper):
    """Rendered of what a keeper keeps of environment m's plumbing (opsdir.domains.network.plumbing.Keeper): the
    VPC and subnet data sources and what bindings share first, inputs unique by name; each binding's blocks stamped
    with its entry, what they share with the keeper's first (hcl.from_entry: the render places them in its root)."""
    here = {b.dn for b in keeper.bindings}
    parts = tuple((b, next(fn for oc, fn in RENDERERS if is_kind(m.d, b, oc))(m, b, here)) for b in keeper.bindings)
    return Rendered(tuple(x for b, p in parts for x in from_entry(b.dn, p.blocks)),
                    distinct(tuple(v for _, p in parts for v in p.variables)),
                    (*network_data(m), *from_entry(keeper.bindings[0].dn,
                                                   distinct(tuple(x for _, p in parts for x in p.shared)))))
