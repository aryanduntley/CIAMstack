"""The network plumbing a landing zone or another party keeps, read neutrally: which bindings it is (NAT egress, route
tables, ACLs, interconnects and flow logs always; private endpoints and egress firewalls only when kept elsewhere),
who keeps each and in which root, what exists already, and the requests the planner drafts for what doesn't."""
import datetime as dt

from opsdir.core.directory import rdn_value
from opsdir.domains.network.checks import check_plumbing
from opsdir.domains.network.plumbing import (LANDING_ZONE, adopted, describe, keepers, peer_cloud, peer_network,
                                             plumbing, plumbing_requests, plumbing_unasked, route_target)
from opsdir.domains.network.routing import parse_route
from network_fixtures import ALPHA, BETA, context, entry, model

LZ_TEAM = "cn=lz-team,ou=owners,dc=ciam-ops"
NET_TEAM = "cn=net-team,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {LZ_TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: lz-team\nciamOwnerKind: team\n",
          f"dn: {NET_TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: net-team\nciamOwnerKind: team\n")
# the landing zone's owner is its guardrails' owner
GUARDRAIL = entry(ALPHA, "fence", "ciamGuardrail", ciamBindingRole="fence", ciamDenies="public-storage",
                  ciamOwner=LZ_TEAM)
EGRESS = entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="egress", ciamCidr="203.0.113.10/32",
               ciamProviderRef="nat-1")
TABLE = entry(ALPHA, "rt-ds", "ciamRouteTable", ciamBindingRole="rt-ds", ciamRoute="0.0.0.0/0 nat egress",
              ciamSubnetRole="subnet-ds")
VPN = entry(ALPHA, "vpn-dc", "ciamInterconnect", ciamBindingRole="vpn-dc", ciamInterconnectKind="VPN",
            ciamLinkKind="vpn", ciamPeerEnvironment=BETA, ciamSourceCidr="10.9.0.0/16", ciamManagedBy=NET_TEAM)
PE_OWN = entry(ALPHA, "pe-own", "ciamPrivateEndpoint", ciamBindingRole="pe-own", ciamPrivateService="secrets")
PE_HUB = entry(ALPHA, "pe-hub", "ciamPrivateEndpoint", ciamBindingRole="pe-hub", ciamPrivateService="secrets",
               ciamManagedBy=NET_TEAM)
FIREWALL = entry(ALPHA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall", ciamManagedBy=NET_TEAM,
                 ciamAllowedDestination=("a.example.test", "b.example.test"))
SQUID = entry(ALPHA, "squid", "ciamProxy", ciamBindingRole="squid", ciamProxyKind="forward-proxy",
              ciamManagedBy=NET_TEAM)


def _alpha(*records):
    return model(alpha=records, tree=OWNERS)[1]


def _named(bs):
    return [rdn_value(b) for b in bs]


def test_plumbing_is_always_kept_outside_and_the_rest_only_when_someone_else_keeps_it():
    m = _alpha(PE_OWN, PE_HUB, FIREWALL, SQUID, VPN, TABLE, EGRESS)
    assert _named(plumbing(m)) == ["egress", "rt-ds", "vpn-dc", "pe-hub", "fw"]


def test_nothing_recorded_is_no_one_s_plumbing():
    m = _alpha()
    assert plumbing(m) == () and keepers(m) == () and plumbing_requests(m) == ()


def test_the_landing_zone_owner_keeps_what_names_no_one_else_and_each_party_gets_its_own_root():
    m = _alpha(GUARDRAIL, EGRESS, TABLE, VPN, PE_HUB, FIREWALL)
    lz, net = keepers(m)
    assert (lz.name, lz.folder, lz.party.dn, _named(lz.bindings)) == (
        "lz-team", LANDING_ZONE, LZ_TEAM, ["egress", "rt-ds"])
    assert (net.name, net.folder, net.party.dn, _named(net.bindings)) == (
        "net-team", f"{LANDING_ZONE}/net-team", NET_TEAM, ["vpn-dc", "pe-hub", "fw"])


def test_a_party_that_is_the_landing_zone_s_owner_keeps_it_in_the_landing_zone():
    m = _alpha(GUARDRAIL, entry(ALPHA, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="network",
                                ciamManagedBy=LZ_TEAM))
    (k,) = keepers(m)
    assert (k.folder, _named(k.bindings)) == (LANDING_ZONE, ["fl"])


def test_what_has_a_provider_ref_exists():
    m = _alpha(EGRESS, TABLE)
    assert [adopted(b) for b in plumbing(m)] == [True, False]


def test_route_targets_and_the_other_end_of_a_link():
    m = _alpha(EGRESS, TABLE, VPN)
    assert rdn_value(route_target(m, parse_route("0.0.0.0/0 nat egress"))) == "egress"
    assert route_target(m, parse_route("0.0.0.0/0 nat nat-0abc")) is None
    assert route_target(m, parse_route("0.0.0.0/0 internet")) is None
    vpn = plumbing(m)[-1]
    assert peer_cloud(m.d, vpn).dn == "cloud=beta,ou=environments,dc=ciam-ops"
    assert peer_network(m.d, vpn).dn == f"cn=net,ou=bindings,{BETA}"


def test_describe_says_what_each_binding_is():
    m = _alpha(EGRESS, TABLE, VPN, PE_HUB, FIREWALL,
               entry(ALPHA, "acl", "ciamNetworkAcl", ciamBindingRole="acl",
                     ciamAclRule=("100 allow in tcp 636 10.0.0.0/8", "200 deny in all all 0.0.0.0/0")),
               entry(ALPHA, "fl", "ciamFlowLog", ciamBindingRole="fl", ciamFlowScope="subnet",
                     ciamSubnetRole="subnet-ds", ciamLogDestinationRole="logs", ciamRetentionDays="90"))
    said = {rdn_value(b): describe(m, b) for b in plumbing(m)}
    assert said["egress"] == "NAT egress `egress` sending from 203.0.113.10/32"
    assert said["rt-ds"] == "Route table `rt-ds` for subnets `subnet-ds`: 0.0.0.0/0 nat egress"
    assert said["acl"] == "Network ACL `acl` (2 rules)"
    assert said["vpn-dc"] == "vpn `vpn-dc` to beta/prod"
    assert said["fl"] == "Flow log `fl` (subnet for subnets `subnet-ds`) to `logs`, kept 90 days"
    assert said["pe-hub"] == "Private endpoint `pe-hub` to secrets"
    assert said["fw"] == "Domain allowlist of egress firewall `fw` (2 sites)"


def test_requests_ask_each_keeper_for_what_isn_t_built_yet():
    m = _alpha(GUARDRAIL, EGRESS, TABLE, VPN)
    by = dt.date(2026, 11, 1)
    asked = [(p.dn, text) for p, text, when in plumbing_requests(m, by) if when == by]
    assert asked == [
        (LZ_TEAM, f"Everything you keep for {m.label} is rendered in `{LANDING_ZONE}/` (what already exists carries "
                  "import blocks, so you can adopt it into your state)."),
        (LZ_TEAM, f"Route table `rt-ds` for subnets `subnet-ds`: 0.0.0.0/0 nat egress: to set up "
                  f"(`{LANDING_ZONE}/network.tf`)."),
        (NET_TEAM, f"Everything you keep for {m.label} is rendered in `{LANDING_ZONE}/net-team/` (what already "
                   "exists carries import blocks, so you can adopt it into your state)."),
        (NET_TEAM, f"vpn `vpn-dc` to beta/prod: to set up (`{LANDING_ZONE}/net-team/network.tf`).")]


def test_a_keeper_with_everything_built_is_not_asked():
    m = _alpha(GUARDRAIL, EGRESS)
    assert plumbing_requests(m) == () and plumbing_unasked(m) == ()


def test_the_planner_asks_keepers_and_says_when_no_one_is_recorded_to_ask():
    target = (entry(BETA, "rt", "ciamRouteTable", ciamBindingRole="rt", ciamRoute="0.0.0.0/0 internet"),
              entry(BETA, "fw", "ciamProxy", ciamBindingRole="fw", ciamProxyKind="firewall", ciamManagedBy=NET_TEAM))
    d, alpha, beta = model(beta=target, tree=OWNERS)
    f = check_plumbing(context(d, alpha, beta, cutover=dt.date(2026, 11, 1)))
    assert [(party.dn, topic) for party, _, _, topic, _ in f.requests] == [(NET_TEAM, "network"), (NET_TEAM, "network")]
    ((area, text, _, by),) = f.actions
    assert (area, by) == ("Network", dt.date(2026, 11, 1))
    assert "1 plumbing items in `terraform/landing-zone/`" in text and "no party is recorded" in text
