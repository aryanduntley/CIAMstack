"""The network depth a cloud reports, placed: new kinds matched by provider ref, links naming several subnets by their
roles, a route's target written as a provider ref read as the role of the binding with that ref, an interconnect's
other side from its tag, what a new entry lacks named."""
from opsdir.core.directory import values
from opsdir.core.directory import make_directory
from opsdir.core.inventory import environment_groups, peer_environment, resource
from opsdir.domains.network.ports import acl_rule_text
from opsdir.domains.network.routing import Route, parse_route, route_text
from support import imported_directory

ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"


def _d(*entries):
    return imported_directory((), {}, (
        ("cloud=main,ou=environments,dc=ciam-ops", ("top", "ciamCloud"), {"cloud": ["main"]}),
        (ENV, ("top", "ciamEnvironment"), {"env": ["prod"]}),
        (B, ("top", "organizationalUnit"), {"ou": ["bindings"]}), *entries))


def _binding(cn, oc, role, **attrs):
    return f"cn={cn},{B}", ("top", oc), {"cn": [cn], "ciamBindingRole": [role], **attrs}


SUBNETS = (_binding("snet-a", "ciamSubnetBinding", "subnet-ds", ciamCidr=["10.0.1.0/24"], ciamProviderRef=["sub-a"]),
           _binding("snet-b", "ciamSubnetBinding", "subnet-pf", ciamCidr=["10.0.2.0/24"], ciamProviderRef=["sub-b"]))
NAT = _binding("nat", "ciamEgress", "pf-egress", ciamCidr=["203.0.113.10/32"], ciamProviderRef=["nat-1"])


def _placed(d, *resources):
    groups, notices = environment_groups(d, "main/prod", resources)
    return {e.dn: e for _, (e,) in groups}, notices


def test_a_route_tables_subnets_and_route_targets_read_as_roles():
    d = _d(*SUBNETS, NAT)
    table = resource("route-table", "rtb-1", {"ciamRoute": ("0.0.0.0/0 nat nat-1", "10.9.0.0/16 vpn vgw-9"),
                                              "ciamMainTable": "FALSE"},
                     links={"ciamSubnetRole": ("sub-a", "sub-b", "sub-unknown")}, name="rt-private", role="rt-private")
    entries, notices = _placed(d, table, resource("subnet", "sub-a", {}), resource("subnet", "sub-b", {}),
                               resource("egress", "nat-1", {}))
    rt = entries[f"cn=rt-private,{B}"]
    assert values(rt, "ciamRoute") == ("0.0.0.0/0 nat pf-egress", "10.9.0.0/16 vpn vgw-9")    # vgw-9 not reported
    assert values(rt, "ciamSubnetRole") == ("subnet-ds", "subnet-pf")
    assert values(rt, "ciamProviderRef") == ("rtb-1",)
    assert "main/prod: route-table rt-private added (role rt-private)" in notices


def test_a_recorded_binding_is_matched_by_ref_and_keeps_what_the_source_doesnt_say():
    d = _d(*SUBNETS, _binding("pe", "ciamPrivateEndpoint", "private-secrets", ciamPrivateService=["secrets"],
                              ciamReachesRole=["admin-password"], ciamProviderRef=["vpce-1"]))
    entries, _ = _placed(d, resource("private-endpoint", "vpce-1", {"ciamPrivateService": "secrets",
                                                                    "ciamPrivateEndpointKind": "interface",
                                                                    "ciamPrivateDns": "TRUE"},
                                     links={"ciamSubnetRole": ("sub-a",)}),
                         resource("subnet", "sub-a", {}))
    pe = entries[f"cn=pe,{B}"]
    assert values(pe, "ciamReachesRole") == ("admin-password",)             # the record's: the source can't say
    assert values(pe, "ciamPrivateDns") == ("TRUE",) and values(pe, "ciamSubnetRole") == ("subnet-ds",)


def test_a_new_interconnect_needs_the_other_sides_environment():
    d = _d()
    link = {"ciamInterconnectKind": "peering", "ciamLinkKind": "peering", "ciamSourceCidr": "10.20.0.0/16"}
    _, notices = _placed(d, resource("interconnect", "pcx-1", link, name="pcx-1", role="peer-source"))
    assert notices == ("main/prod: interconnect pcx-1 lacks ciamPeerEnvironment; not imported",)
    peer = peer_environment({"PeerEnvironment": "source/prod"})
    assert peer == "env=prod,cloud=source,ou=environments,dc=ciam-ops"
    assert peer_environment({"PeerEnvironment": "nonsense"}) is None and peer_environment({}) is None


def test_the_texts_the_clouds_write_read_back():
    assert route_text(Route("0.0.0.0/0", "nat", "pf-egress", ())) == "0.0.0.0/0 nat pf-egress"
    assert route_text(Route("10.0.0.0/8", "vpn", "", ("ds", "pf"))) == "10.0.0.0/8 vpn for ds,pf"
    assert parse_route(route_text(Route("pl-1a", "endpoint", "vpce-1", ()))) == Route("pl-1a", "endpoint", "vpce-1", ())
    assert acl_rule_text(100, "allow", "in", "tcp", (636, 636), "10.0.0.0/8") == "100 allow in tcp 636 10.0.0.0/8"
    assert acl_rule_text(110, "allow", "in", "tcp", (1024, 65535), "0.0.0.0/0") == "110 allow in tcp 1024-65535 0.0.0.0/0"
    assert acl_rule_text(200, "deny", "out", "all", (0, 65535), "0.0.0.0/0") == "200 deny out all all 0.0.0.0/0"


def test_a_role_link_names_a_binding_of_its_kind_when_two_share_a_ref():
    policy = "projects/net/global/firewallPolicies/ciam"
    d = _d(_binding("fw-policy", "ciamFirewallPolicy", "firewall-policy", ciamPolicyScope=["network"],
                    ciamProviderRef=[policy]),
           _binding("egress-firewall", "ciamProxy", "egress-firewall", ciamProxyKind=["firewall"],
                    ciamProviderRef=[policy]),
           _binding("fw-ldaps", "ciamFirewallRule", "fw-ldaps", ciamSourceCidr=["10.0.0.0/8"], ciamPort=["1636"],
                    ciamTargetRole=["ds"]))
    entries, _ = _placed(d, resource("firewall-policy", policy, {"ciamPolicyScope": "network"}),
                         resource("proxy", policy, {"ciamProxyKind": "firewall"}),
                         resource("firewall", "fw-ldaps", {"ciamPort": "1636"}, links={"ciamPolicyRole": policy},
                                  name="fw-ldaps"))
    assert values(entries[f"cn=fw-ldaps,{B}"], "ciamPolicyRole") == ("firewall-policy",)


PEER_ENV = "env=prod,cloud=hub,ou=environments,dc=ciam-ops"


def _hub():
    return (("cloud=hub,ou=environments,dc=ciam-ops", ("top", "ciamCloud"), {"cloud": ["hub"]}),
            (PEER_ENV, ("top", "ciamEnvironment"), {"env": ["prod"]}),
            (f"ou=bindings,{PEER_ENV}", ("top", "organizationalUnit"), {"ou": ["bindings"]}),
            (f"cn=net,ou=bindings,{PEER_ENV}", ("top", "ciamNetwork"),
             {"cn": ["net"], "ciamBindingRole": ["network"], "ciamCidr": ["10.9.0.0/16"], "ciamProviderRef": ["vpc-hub"]}))


def test_the_other_side_is_the_environment_whose_network_has_the_peer_ref():
    d = _d(*_hub(), _binding("vpc", "ciamNetwork", "network", ciamCidr=["10.1.0.0/16"], ciamProviderRef=["vpc-main"]))
    link = {"ciamInterconnectKind": "VPC peering", "ciamLinkKind": "peering", "ciamSourceCidr": "10.9.0.0/16"}
    entries, notices = _placed(d, resource("interconnect", "pcx-1", link, links={"ciamPeerEnvironment": ("vpc-main",
                                                                                                         "vpc-hub")},
                                           name="pcx-1", role="peering-hub"))
    assert values(entries[f"cn=pcx-1,{B}"], "ciamPeerEnvironment") == (PEER_ENV,)        # our own network skipped
    assert "main/prod: interconnect pcx-1 added (role peering-hub)" in notices
    tagged = resource("interconnect", "pcx-2", {**link, "ciamPeerEnvironment": "env=prod,cloud=dc,ou=environments,dc=ciam-ops"},
                      links={"ciamPeerEnvironment": "vpc-hub"}, name="pcx-2", role="peering-dc")
    entries, _ = _placed(d, tagged)
    assert values(entries[f"cn=pcx-2,{B}"], "ciamPeerEnvironment") == ("env=prod,cloud=dc,ou=environments,dc=ciam-ops",)
    entries, _ = _placed(d, resource("interconnect", "pcx-4", link, links={"ciamPeerEnvironment": "VPC-HUB"},
                                     name="pcx-4", role="peering-hub"))
    assert values(entries[f"cn=pcx-4,{B}"], "ciamPeerEnvironment") == (PEER_ENV,)            # case aside
    _, notices = _placed(d, resource("interconnect", "pcx-3", link, links={"ciamPeerEnvironment": "vpc-elsewhere"},
                                     name="pcx-3", role="peering-x"))
    assert notices == ("main/prod: interconnect pcx-3 lacks ciamPeerEnvironment; not imported",)


def test_a_flow_log_without_a_role_takes_its_subnets():
    d = _d(*SUBNETS)
    entries, notices = _placed(d, resource("subnet", "sub-a", {}),
                               resource("flow-log", "sub-a/logConfig", {"ciamFlowScope": "subnet"},
                                        links={"ciamSubnetRole": "sub-a"}, name="ciam-ds-flow-logs"))
    log = entries[f"cn=ciam-ds-flow-logs,{B}"]
    assert values(log, "ciamBindingRole") == ("flow-logs-subnet-ds",) and values(log, "ciamSubnetRole") == ("subnet-ds",)
