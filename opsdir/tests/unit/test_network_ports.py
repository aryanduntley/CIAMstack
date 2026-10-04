"""The ports matrix: listeners the products declare, the flows they need in an environment, whether firewall rules
admit them and network ACLs let them (and their replies) through, rules nothing listens behind, and the planner's
findings in the source and the target."""
from types import SimpleNamespace

from opsdir.connectors.network import network_check
from opsdir.core.contract import Listener
from opsdir.domains.network.ports import (BLOCKED, OPEN, UNCHECKED, UNCOVERED, acl_allows, acl_rules, admitting,
                                          flow_status, flows, ports_rows, role_cidrs, stray_rules, via_service)
from network_fixtures import ALPHA, BETA, context, entry, model, rule

GOOD_RULES = lambda env: (rule(env, "fw-ldaps", ("10.1.2.0/24", "192.0.2.0/24"), "1636", "ds"),  # noqa: E731
                          rule(env, "fw-repl", "10.1.1.0/24", "8989", "ds"),
                          rule(env, "fw-runtime", "0.0.0.0/0", "9031", "web"))
LISTENERS = (Listener("ds", 1636, "tcp", "LDAPS", ("clients", "web")),
             Listener("ds", 8989, "tcp", "replication", ("peers",)),
             Listener("ds", 4444, "tcp", "administration", ("admin",)),
             Listener("web", 9031, "tcp", "runtime", ("clients",)))


def _flow(m, role, port, source):
    return next(f for f in flows(m, LISTENERS) if f.listener.server_role == role and f.listener.port == port
                and f.source == source)


def test_flows_follow_the_roles_with_servers():
    _, m, _ = model()
    assert [(f.listener.port, f.source, f.cidrs) for f in flows(m, LISTENERS)] == [
        (1636, "clients", ()), (1636, "web", ("10.1.2.0/24",)), (8989, "ds", ("10.1.1.0/24",)),
        (4444, "admin", ()), (9031, "clients", ())]
    assert role_cidrs(m, "ds") == ("10.1.1.0/24",)
    assert flows(m, (Listener("am", 8443, "tcp", "https", ("clients",)),)) == ()      # no am servers here


def test_rules_admit_flows_by_port_protocol_and_source_range():
    _, m, _ = model(alpha=GOOD_RULES(ALPHA))
    assert [flow_status(m, f)[0] for f in flows(m, LISTENERS)] == [OPEN, OPEN, OPEN, UNCHECKED, OPEN]
    rules, uncovered = admitting(m, _flow(m, "ds", 1636, "web"))
    assert [r.dn.split(",")[0] for r in rules] == ["cn=fw-ldaps"] and uncovered == ()


def test_a_missing_or_narrow_rule_leaves_the_flow_uncovered():
    _, m, _ = model(alpha=(rule(ALPHA, "fw-repl", "10.1.1.0/25", "8989", "ds"),))
    status, names, reasons = flow_status(m, _flow(m, "ds", 8989, "ds"))
    assert (status, names) == (UNCOVERED, "fw-repl")
    assert reasons == ("no firewall rule admits tcp 8989 to `ds` from 10.1.1.0/24",)
    assert flow_status(m, _flow(m, "ds", 1636, "web"))[0] == UNCOVERED


def test_rules_on_ports_nothing_listens_on_are_stray():
    _, m, _ = model(alpha=(*GOOD_RULES(ALPHA), rule(ALPHA, "fw-telnet", "10.0.0.0/8", "23", "ds"),
                            rule(ALPHA, "fw-other", "10.0.0.0/8", "22", "bastion")))
    assert [s.dn.split(",")[0] for s in stray_rules(m, LISTENERS)] == ["cn=fw-telnet"]   # bastion declares nothing


def test_acl_first_match_decides_and_an_allow_must_cover_it_all():
    acl = SimpleNamespace(attrs={"ciamAclRule": ("200 allow in tcp 0-65535 10.0.0.0/8", "100 deny in tcp 23 10.0.0.0/8",
                                                 "300 allow out tcp 1024-2048 10.0.0.0/8")})
    rules = acl_rules(acl)
    assert [r.number for r in rules] == [100, 200, 300]
    assert acl_allows(rules, "in", "tcp", (636, 636), "10.1.2.0/24")
    assert not acl_allows(rules, "in", "tcp", (20, 30), "10.1.2.0/24")             # the deny matches part of it
    assert not acl_allows(rules, "out", "tcp", (1024, 65535), "10.1.2.0/24")       # the allow covers only some
    assert not acl_allows(rules, "in", "udp", (53, 53), "10.1.2.0/24")             # nothing matches: refused


def test_a_stateless_acl_must_let_the_reply_through_too():
    acl = entry(ALPHA, "acl-ds", "ciamNetworkAcl", ciamBindingRole="acl-ds", ciamSubnetRole="subnet-ds",
                 ciamAclRule=("100 allow in tcp 8989 10.1.1.0/24", "110 allow in tcp 1636 10.1.2.0/24",
                              "120 allow out tcp 1024-65535 10.1.1.0/24"))
    _, m, _ = model(alpha=(*GOOD_RULES(ALPHA), acl))
    assert flow_status(m, _flow(m, "ds", 8989, "ds"))[0] == OPEN                 # in, reply and both ends' ACL
    status, _, reasons = flow_status(m, _flow(m, "ds", 1636, "web"))
    assert status == BLOCKED
    assert reasons == ("network ACL `acl-ds` refuses out tcp 1024-65535 to 10.1.2.0/24",)


def test_the_acl_ephemeral_range_is_data():
    acl = entry(ALPHA, "acl-ds", "ciamNetworkAcl", ciamBindingRole="acl-ds", ciamSubnetRole="subnet-ds",
                 ciamEphemeralPorts="32768-60999",
                 ciamAclRule=("100 allow in tcp 8989 10.1.1.0/24", "120 allow out tcp 32768-60999 10.1.1.0/24"))
    _, m, _ = model(alpha=(*GOOD_RULES(ALPHA), acl))
    assert flow_status(m, _flow(m, "ds", 8989, "ds"))[0] == OPEN


def test_ports_rows():
    _, m, _ = model(alpha=GOOD_RULES(ALPHA))
    assert ports_rows(m, LISTENERS)[1] == ("alpha/prod", "ds", 1636, "tcp", "LDAPS", "web", "fw-ldaps", OPEN)


def _plan(d, src, dst, adapters):
    return network_check(adapters, adapters)(context(d, src, dst))


def test_target_gaps_between_roles_block_and_source_gaps_are_questions():
    adapter = SimpleNamespace(listeners=lambda m: LISTENERS)
    d, alpha, beta = model(alpha=GOOD_RULES(ALPHA), beta=(rule(BETA, "fw-runtime", "0.0.0.0/0", "9031", "web"),
                                                           rule(BETA, "fw-telnet", "10.0.0.0/8", "23", "ds")))
    f = _plan(d, alpha, beta, (adapter,))
    assert [b[1] for b in f.blockers] == [
        "beta/prod: `ds` listens on tcp 1636 (LDAPS) for `web`, but no firewall rule admits tcp 1636 to `ds` from "
        "10.1.2.0/24.",
        "beta/prod: `ds` listens on tcp 8989 (replication) for its peers, but no firewall rule admits tcp 8989 to `ds` "
        "from 10.1.1.0/24."]
    assert [a[1] for a in f.actions] == [
        "beta/prod: `ds` listens on tcp 1636 (LDAPS) for clients, but no firewall rule admits tcp 1636 to `ds` and no "
        "service name carries clients to it. Consumers can't connect until a rule admits them.",
        "beta/prod: firewall rules open ports no installed product listens on: `fw-telnet` (ds 23). Close them, or "
        "record what listens there."]
    assert f.ok == ("alpha/prod: 4 flow(s) of the ports matrix get through.",)
    back = _plan(d, beta, alpha, (adapter,))
    assert not back.blockers and all("Record the rule if it exists" in a[1] for a in back.actions)


def test_no_listeners_no_findings():
    d, alpha, beta = model()
    assert _plan(d, alpha, beta, (SimpleNamespace(listeners=None),)) == ((), (), (), ())


def test_a_network_open_within_itself_admits_its_own_roles():
    net = entry(ALPHA, "net", "ciamNetwork", ciamBindingRole="network", ciamCidr="10.1.0.0/16",
                ciamOpenWithinNetwork="TRUE")
    _, m, _ = model(alpha=(net,))
    assert flow_status(m, _flow(m, "ds", 8989, "ds"))[0] == OPEN
    assert flow_status(m, _flow(m, "ds", 1636, "web"))[0] == OPEN


def test_a_service_name_carries_clients_and_its_ports_are_not_stray():
    svc = entry(ALPHA, "svc-web", "ciamServiceName", ciamBindingRole="web-service", ciamFqdn="web.example.test",
                ciamPort="443", ciamTargetRole="web")
    _, m, _ = model(alpha=(svc, rule(ALPHA, "fw-web-public", "0.0.0.0/0", "443", "web")))
    assert flow_status(m, _flow(m, "web", 9031, "clients"))[0] == OPEN
    assert stray_rules(m, LISTENERS) == ()


def test_connections_through_a_service_name_reach_the_role_behind_it():
    svc = entry(ALPHA, "svc-ldaps", "ciamServiceName", ciamBindingRole="ds-ldaps-service", ciamFqdn="ldap.example.test",
                ciamPort=("636", "1636"), ciamTargetRole="ds")
    _, m, _ = model(alpha=(svc,))
    assert via_service(m, "ds-ldaps-service", "connector", ("web",)) == (
        Listener("ds", 636, "tcp", "connector", ("web",)), Listener("ds", 1636, "tcp", "connector", ("web",)))
    assert via_service(m, "ds-ldaps-service", "store", ("web",), port=1636) == \
        (Listener("ds", 1636, "tcp", "store", ("web",)),)
    assert via_service(m, "subnet-ds", "x", ("web",)) == () and via_service(m, "nowhere", "x", ("web",)) == ()
