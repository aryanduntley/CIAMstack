"""What the stack renders of its network depth, read neutrally: who keeps each binding, the subnets it names, what a
private endpoint reaches, the egress allowlist by port, the ranges reached privately, the firewall model."""
from opsdir.core.directory import rdn_value
from opsdir.domains.network.stack import (allowlist, egress_firewalls, elsewhere, endpoint_services, firewall_model,
                                          kept_by, network_policy, owned, private_endpoints, private_ranges, reached,
                                          subnets)
from network_fixtures import ALPHA, entry, model

NET_TEAM = "cn=net-team,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {NET_TEAM}\nobjectClass: top\nobjectClass: ciamParty\ncn: net-team\nciamOwnerKind: team\n")


def _alpha(*records):
    return model(alpha=records, tree=OWNERS)[1]


def _named(bs):
    return [rdn_value(b) for b in bs]


SECRET = entry(ALPHA, "secret-a", "ciamSecretRef", ciamBindingRole="admin-password", ciamRefUri="fake://a")


def test_the_stack_keeps_what_names_no_one_else():
    m = _alpha(SECRET,
               entry(ALPHA, "pe-secrets", "ciamPrivateEndpoint", ciamBindingRole="pe-secrets",
                     ciamPrivateService="secrets", ciamReachesRole=("admin-password", "nowhere"),
                     ciamSubnetRole=("subnet-web", "subnet-ds", "subnet-web")),
               entry(ALPHA, "pe-hub", "ciamPrivateEndpoint", ciamBindingRole="pe-hub", ciamPrivateService="apis",
                     ciamManagedBy=NET_TEAM))
    ours, = private_endpoints(m)
    assert rdn_value(ours) == "pe-secrets" and owned(ours)
    assert _named(subnets(m, ours)) == ["subnet-web", "subnet-ds"]          # in the order named, once
    assert _named(reached(m, ours)) == ["secret-a"]                          # what alpha doesn't bind is left out
    hub = next(b for b in m.bindings if rdn_value(b) == "pe-hub")
    assert not owned(hub) and kept_by(m, hub) == "net-team"
    assert elsewhere(m) == ("Private endpoint 'pe-hub' (apis) is kept by net-team; rendered in their root, "
                            "not here.",)


def test_the_allowlist_groups_sites_by_port():
    fw = entry(ALPHA, "egress-fw", "ciamProxy", ciamBindingRole="egress-firewall", ciamProxyKind="firewall",
               ciamAllowedDestination=("idp.partner.example", "*.okta.example", "ocsp.ca.example:80",
                                       "idp.partner.example"))
    m = _alpha(fw)
    proxy, = egress_firewalls(m)
    assert allowlist(proxy) == ((80, ("ocsp.ca.example",)), (443, ("idp.partner.example", "*.okta.example")))


def test_only_the_stacks_own_firewalls_render_their_allowlist_and_other_proxies_are_named():
    m = _alpha(entry(ALPHA, "hub-fw", "ciamProxy", ciamBindingRole="hub-firewall", ciamProxyKind="firewall",
                     ciamManagedBy=NET_TEAM),
               entry(ALPHA, "squid", "ciamProxy", ciamBindingRole="forward-proxy", ciamProxyKind="forward-proxy",
                     ciamProxyAddress="proxy.example.test:3128"))
    assert egress_firewalls(m) == ()
    assert elsewhere(m) == (
        "Egress firewall 'hub-fw' is kept by net-team; its allowlist is rendered in their root, not here.",
        "Egress passes forward-proxy 'squid' (proxy.example.test:3128): its allowlist is kept there, not rendered "
        "as cloud firewall rules.")


def test_private_ranges_are_the_network_interconnects_and_endpoint_addresses():
    m = _alpha(entry(ALPHA, "link", "ciamInterconnect", ciamBindingRole="link", ciamInterconnectKind="vpn",
                     ciamPeerEnvironment="env=prod,cloud=beta,ou=environments,dc=ciam-ops",
                     ciamSourceCidr="10.2.0.0/16"),
               entry(ALPHA, "link-2", "ciamInterconnect", ciamBindingRole="link-2", ciamInterconnectKind="vpn",
                     ciamPeerEnvironment="env=prod,cloud=beta,ou=environments,dc=ciam-ops",
                     ciamSourceCidr="10.3.0.0/16", ciamAcceptedCidr="10.3.1.0/24"),
               entry(ALPHA, "psc", "ciamPrivateEndpoint", ciamBindingRole="psc", ciamPrivateService="apis",
                     ciamFrontendIp="10.255.0.5"))
    assert private_ranges(m) == ("10.1.0.0/16", "10.2.0.0/16", "10.255.0.5/32", "10.3.1.0/24")


def test_the_firewall_model_defaults_to_rules_and_the_policy_is_the_networks():
    m = _alpha()
    assert firewall_model(m) == "rules" and network_policy(m) is None and endpoint_services(m) == ()
    m = _alpha(entry(ALPHA, "org-policy", "ciamFirewallPolicy", ciamBindingRole="org-policy",
                     ciamPolicyScope="hierarchical"),
               entry(ALPHA, "policy", "ciamFirewallPolicy", ciamBindingRole="firewall-policy",
                     ciamPolicyScope="network"),
               entry(ALPHA, "ldaps-link", "ciamEndpointService", ciamBindingRole="ldaps-link",
                     ciamServiceRole="sso-service"))
    assert rdn_value(network_policy(m)) == "policy"
    (e, svc), = endpoint_services(m)
    assert rdn_value(e) == "ldaps-link" and rdn_value(svc) == "svc-sso"
