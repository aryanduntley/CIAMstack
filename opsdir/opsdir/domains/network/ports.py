"""The ports matrix: the ports each server role listens on and who must reach them, from what the installed products
declare (contract.Listener), and whether an environment's firewall rules and stateless network ACLs let that traffic
through. Pure: the listeners come in as data (the connectors ask the adapters).

A flow is one listener and one kind of source: clients (consumers, which the firewall rules name), admin (the
operators' ways in: the access domain's), or a server role (the listener's own role for peers), whose servers' subnets
are the ranges a rule must admit.
"""
import ipaddress
import re
from typing import NamedTuple

from ...core.contract import Listener
from ...core.directory import is_kind, one, rdn_value, values
from ...core.environment import of_class, one_role, servers_with_role, subnet_of
from ...core.network import covers
from .naming import ACL_RULE, EPHEMERAL

Flow = NamedTuple("Flow", [("listener", object), ("source", str), ("cidrs", tuple)])
AclRule = NamedTuple("AclRule", [("number", int), ("action", str), ("direction", str), ("protocol", str),
                                 ("ports", tuple), ("cidr", str)])
PORTS_HEADERS = ("environment", "role", "port", "protocol", "purpose", "from", "firewall rules", "status")
OPEN, UNCOVERED, BLOCKED, UNCHECKED = "open", "no rule", "blocked by ACL", "not checked"


def role_cidrs(m, role):
    """The ranges of the subnets environment m's servers of a role sit in (sorted, without repeats)."""
    return tuple(sorted({one(subnet_of(m, s), "ciamCidr") for s in servers_with_role(m, role)
                         if subnet_of(m, s) is not None and one(subnet_of(m, s), "ciamCidr")}))


def _subnet_roles(m, role):
    """The binding roles of the subnets environment m's servers of a role sit in."""
    return {one(subnet_of(m, s), "ciamBindingRole") for s in servers_with_role(m, role) if subnet_of(m, s) is not None}


def flows(m, listeners):
    """The flows environment m needs: for each listener whose role has servers here, one per kind of source; a server
    role source only when it has servers here too (peers only when the role has more than one)."""
    def sources(listener):
        alone = len(servers_with_role(m, listener.server_role)) < 2
        named = (listener.server_role if p == "peers" else p for p in listener.peers if not (p == "peers" and alone))
        return tuple(dict.fromkeys(named))
    return tuple(Flow(listener, src, () if src in ("clients", "admin") else role_cidrs(m, src))
                 for listener in listeners if servers_with_role(m, listener.server_role)
                 for src in sources(listener) if src in ("clients", "admin") or servers_with_role(m, src))


def _rules_for(m, listener):
    """Environment m's firewall rules admitting a listener's port and protocol to its role."""
    return tuple(fw for fw in of_class(m, "ciamFirewallRule")
                 if one(fw, "ciamTargetRole") == listener.server_role and str(listener.port) in values(fw, "ciamPort")
                 and (one(fw, "ciamProtocol") or "tcp") == listener.protocol)


def _services_to(m, role):
    """Environment m's service names whose load balancers send traffic to a server role."""
    return tuple(s for s in of_class(m, "ciamServiceName") if one(s, "ciamTargetRole") == role)


def _open_within(m, cidr):
    """Whether one of environment m's networks admits traffic within itself unless a rule denies it, and holds cidr."""
    return any(one(n, "ciamOpenWithinNetwork") == "TRUE" and one(n, "ciamCidr") and covers((one(n, "ciamCidr"),), cidr)
               for n in of_class(m, "ciamNetwork"))


def admitting(m, flow):
    """(the rules admitting a flow, what none of them covers): for a server role the source ranges no rule covers
    (a network open within itself covers its own); for clients, ('clients',) unless a rule admits the port or a service
    name carries clients to the role (its load balancer's rules are the edge's); admin flows aren't judged (rules,
    ())."""
    rules = _rules_for(m, flow.listener)
    if flow.source == "admin":
        return rules, ()
    if flow.source == "clients":
        return rules, () if rules or _services_to(m, flow.listener.server_role) else ("clients",)
    allowed = tuple(c for fw in rules for c in values(fw, "ciamSourceCidr"))
    return rules, tuple(c for c in flow.cidrs if not covers(allowed, c) and not _open_within(m, c))


def via_service(m, binding_role, purpose, peers, port=None):
    """Listeners for a product's connection to a service name: the port (given, else the service's) on the server role
    behind it, reached by peers; () when the role isn't bound to a service name in environment m."""
    b = one_role(m, binding_role)
    if b is None or not is_kind(m.d, b, "ciamServiceName") or not one(b, "ciamTargetRole"):
        return ()
    return tuple(Listener(one(b, "ciamTargetRole"), int(p), "tcp", purpose, tuple(peers))
                 for p in ((str(port),) if port else values(b, "ciamPort")))


def stray_ports(m, listeners, fw):
    """The ports a firewall rule of environment m opens to a role whose products declare listeners that none of them
    declares and no service name sends traffic to (in the rule's order; () for a role nothing declares)."""
    if one(fw, "ciamTargetRole") not in {lst.server_role for lst in listeners}:
        return ()
    declared = {(lst.server_role, str(lst.port), lst.protocol) for lst in listeners} | \
        {(one(s, "ciamTargetRole"), p, "tcp") for s in of_class(m, "ciamServiceName") for p in values(s, "ciamPort")}
    return tuple(p for p in values(fw, "ciamPort")
                 if (one(fw, "ciamTargetRole"), p, one(fw, "ciamProtocol") or "tcp") not in declared)


def stray_rules(m, listeners):
    """Environment m's firewall rules opening ports nothing is known to listen on (stray_ports)."""
    return tuple(fw for fw in of_class(m, "ciamFirewallRule") if stray_ports(m, listeners, fw))


def _ports(text):
    if text == "all":
        return (0, 65535)
    lo, _, hi = text.partition("-")
    return int(lo), int(hi or lo)


def acl_rules(acl):
    """A network ACL's rules, in evaluation (number) order."""
    parsed = (re.match(ACL_RULE, v) and v.split(" ") for v in values(acl, "ciamAclRule"))
    return tuple(sorted((AclRule(int(n), a, d, p, _ports(ports), c) for n, a, d, p, ports, c in filter(None, parsed)),
                        key=lambda r: r.number))


def acl_rule_text(number, action, direction, protocol, ports, cidr):
    """One network ACL rule as a ciamAclRule value (the inverse of acl_rules): ports a (from, to) pair, (0, 65535) for
    all; protocol tcp, udp, icmp or all."""
    lo, hi = ports
    span = "all" if protocol == "all" or (lo, hi) == (0, 65535) else str(lo) if lo == hi else f"{lo}-{hi}"
    return f"{number} {action} {direction} {protocol} {span} {cidr}"


def _net(c):
    return ipaddress.ip_network(c, strict=False)


def acl_allows(rules, direction, protocol, ports, cidr):
    """Whether stateless rules let traffic one way through for every port in a range from or to a range: the first
    rule that matches part of it decides (a deny refuses, an allow must cover it all); nothing matching refuses."""
    for r in rules:
        overlaps = (r.direction == direction and r.protocol in (protocol, "all") and r.ports[0] <= ports[1]
                    and ports[0] <= r.ports[1] and _net(r.cidr).version == _net(cidr).version
                    and _net(r.cidr).overlaps(_net(cidr)))
        if overlaps:
            return r.action == "allow" and r.ports[0] <= ports[0] and ports[1] <= r.ports[1] \
                and _net(cidr).subnet_of(_net(r.cidr))
    return False


def _acls(m, subnet_roles):
    return tuple(a for a in of_class(m, "ciamNetworkAcl") if subnet_roles & set(values(a, "ciamSubnetRole")))


def acl_blocks(m, flow):
    """Why environment m's network ACLs stop a flow between server roles, one reason per ACL and direction ((): they
    don't, or the flow isn't between server roles). Stateless: the reply needs the clients' ephemeral ports too. An
    ACL sits at a subnet's edge, so traffic within one subnet never meets it."""
    if flow.source in ("clients", "admin"):
        return ()
    lst = flow.listener
    port = (lst.port, lst.port)
    dst_cidrs = tuple(c for c in role_cidrs(m, lst.server_role) if c not in flow.cidrs)
    src_cidrs = tuple(c for c in flow.cidrs if c not in role_cidrs(m, lst.server_role))

    def ephemeral(acl):
        return _ports(one(acl, "ciamEphemeralPorts") or EPHEMERAL)

    checks = ((acl, "in", port, c, f"in {lst.protocol} {lst.port} from {c}")
              for acl in _acls(m, _subnet_roles(m, lst.server_role)) for c in src_cidrs)
    replies = ((acl, "out", ephemeral(acl), c, f"out {lst.protocol} {one(acl, 'ciamEphemeralPorts') or EPHEMERAL} "
                f"to {c}") for acl in _acls(m, _subnet_roles(m, lst.server_role)) for c in src_cidrs)
    sends = ((acl, "out", port, c, f"out {lst.protocol} {lst.port} to {c}")
             for acl in _acls(m, _subnet_roles(m, flow.source)) for c in dst_cidrs)
    answers = ((acl, "in", ephemeral(acl), c, f"in {lst.protocol} {one(acl, 'ciamEphemeralPorts') or EPHEMERAL} "
                f"from {c}") for acl in _acls(m, _subnet_roles(m, flow.source)) for c in dst_cidrs)
    return tuple(f"network ACL `{rdn_value(acl)}` refuses {what}"
                 for acl, direction, ports, cidr, what in (*checks, *replies, *sends, *answers)
                 if not acl_allows(acl_rules(acl), direction, lst.protocol, ports, cidr))


def flow_status(m, flow):
    """(status, rule names, reasons) of one flow in environment m."""
    rules, uncovered = admitting(m, flow)
    names = ", ".join(rdn_value(fw) for fw in rules) or "-"
    if flow.source == "admin":
        return UNCHECKED, names, ()
    lst = flow.listener
    if uncovered and flow.source == "clients":
        return UNCOVERED, names, (f"no firewall rule admits {lst.protocol} {lst.port} to `{lst.server_role}` and no "
                                  "service name carries clients to it",)
    if uncovered:
        return UNCOVERED, names, tuple(f"no firewall rule admits {lst.protocol} {lst.port} to `{lst.server_role}` "
                                       f"from {c}" for c in uncovered)
    if not rules and not flow.cidrs and flow.source != "clients":
        return UNCOVERED, names, (f"no firewall rule admits {lst.protocol} {lst.port} to `{lst.server_role}` (the "
                                  f"subnets of `{flow.source}` record no range)",)
    blocks = acl_blocks(m, flow)
    return (BLOCKED if blocks else OPEN), names, blocks


def ports_rows(m, listeners):
    """The ports matrix of environment m: one row per flow."""
    def row(f):
        status, names, _ = flow_status(m, f)
        return (m.label, f.listener.server_role, f.listener.port, f.listener.protocol, f.listener.purpose, f.source,
                names, status)
    return [row(f) for f in flows(m, listeners)]
