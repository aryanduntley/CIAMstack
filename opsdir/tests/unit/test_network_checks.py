"""The network domain's checks and reports: egress partners allowlist, private endpoints, endpoint-service
consumers, interconnects, outside sites against the egress proxy or firewall, time sources and flow logs; routes
parsed from the record."""
import datetime as dt

from opsdir.domains.network.checks import (check_egress, check_endpoint_services, check_flow_logs, check_interconnects,
                                           check_private_endpoints, check_sites, check_time, overlaps)
from opsdir.domains.network.reports import endpoint_service_rows, private_endpoint_rows, route_rows, site_rows
from opsdir.domains.network.routing import Route, allows, default_routes, parse_route, required_sites
from network_fixtures import ALPHA, BETA, context, entry, model

CUTOVER = dt.date(2026, 11, 2)
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          "dn: cn=partner,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: partner\n"
          "ciamOwnerKind: external\n",
          "dn: cn=hr-app,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: hr-app\n"
          "ciamOwnerKind: team\n")


def _texts(found):
    return [x[1] for x in found]


def test_routes_parse_with_targets_and_scopes():
    assert parse_route("0.0.0.0/0 nat pf-egress") == Route("0.0.0.0/0", "nat", "pf-egress", ())
    assert parse_route("10.20.0.0/16 vpn") == Route("10.20.0.0/16", "vpn", "", ())
    assert parse_route("0.0.0.0/0 firewall egress-fw for pf-engine,am") == \
        Route("0.0.0.0/0", "firewall", "egress-fw", ("pf-engine", "am"))
    assert parse_route("pl-63a5400a gateway-lb gwlbe-1") == Route("pl-63a5400a", "gateway-lb", "gwlbe-1", ())
    assert parse_route("0.0.0.0/0 teleport x") is None


def _egress(env, cn="nat", cidr="198.51.100.7/32", **attrs):
    return entry(env, cn, "ciamEgress", ciamBindingRole="pf-egress", ciamCidr=cidr, **attrs)


def _allowlist():
    return ("dn: ou=external-allowlists,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: external-allowlists\n",
            entry("ou=external-allowlists,dc=ciam-ops", "partner-fw", "ciamExternalAllowlist",
                  ciamManagedBy="cn=partner,ou=owners,dc=ciam-ops", ciamRefersToRole="pf-egress",
                  ciamRecordedCidr="203.0.113.7/32", ciamAllowlistDirection="partner-ingress"))


def test_partners_need_a_fixed_public_egress_the_routes_use():
    table = entry(BETA, "rt-private", "ciamRouteTable", ciamBindingRole="rt-private", ciamSubnetRole="subnet-web",
                  ciamRoute=("10.0.0.0/8 local", "0.0.0.0/0 nat other-nat"))
    d, alpha, beta = model(beta=(_egress(BETA, cidr="100.64.0.0/24", ciamNatAllocation="automatic"), table),
                           tree=(*OWNERS, *_allowlist()))
    found = check_egress(context(d, alpha, beta, CUTOVER))
    assert _texts(found.actions) == [
        "`partner-fw` (partner) allows beta/prod's `pf-egress`, but the provider picks its addresses (automatic "
        "allocation), so there is nothing fixed to allow: give it static addresses.",
        "`partner-fw` (partner) allows beta/prod's `pf-egress`, but its range 100.64.0.0/24 is private address space, "
        "so partners see whichever public address the traffic leaves by.",
        "`partner-fw` (partner) allows beta/prod's `pf-egress`, but no route table sends traffic for the internet "
        "through it."]
    assert all(a[3] == CUTOVER for a in found.actions)
    good = entry(BETA, "rt-private", "ciamRouteTable", ciamBindingRole="rt-private", ciamRoute="0.0.0.0/0 nat pf-egress")
    d, alpha, beta = model(beta=(_egress(BETA), good), tree=(*OWNERS, *_allowlist()))
    assert check_egress(context(d, alpha, beta)).actions == ()
    assert [r.target for _, r in default_routes(beta)] == ["pf-egress"]


def _endpoint(env, cn, **attrs):
    return entry(env, cn, "ciamPrivateEndpoint", ciamBindingRole=cn, **attrs)


def test_private_endpoints_reach_bound_roles_and_keep_private_dns():
    secret = entry(ALPHA, "secret-x", "ciamSecretRef", ciamBindingRole="ds-root-password",
                   ciamRefUri="fake://secrets/x")
    d, alpha, beta = model(
        alpha=(secret, _endpoint(ALPHA, "pe-secrets", ciamPrivateService="secrets",
                                 ciamReachesRole="ds-root-password", ciamPrivateDns="TRUE")),
        beta=(_endpoint(BETA, "pe-secrets", ciamPrivateService="secrets", ciamReachesRole="ds-root-password",
                        ciamPrivateDns="FALSE"),))
    assert _texts(check_private_endpoints(context(d, alpha, beta)).actions) == [
        "beta/prod: private endpoint `pe-secrets` reaches `ds-root-password`, which beta/prod doesn't bind.",
        "alpha/prod's private endpoint `pe-secrets` answers the secrets service's usual name inside the network; "
        "beta/prod's (`pe-secrets`) doesn't, so clients using that name reach the public endpoint: turn on private "
        "DNS, or point them at the endpoint's own name."]


def _service(env, alias, principals=(), consumers=(), **attrs):
    return entry(env, "es-ldaps", "ciamEndpointService", ciamBindingRole="ldaps-private", ciamServiceRole="ldaps",
                 **({"ciamServiceAlias": alias} if alias else {}),
                 **({"ciamAllowedPrincipal": principals} if principals else {}),
                 **({"ciamAllowsConsumer": consumers} if consumers else {}), **attrs)


def test_endpoint_service_consumers_reconnect_to_the_new_name():
    consumers = ("dn: ou=consumers,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: consumers\n",
                 entry("ou=consumers,dc=ciam-ops", "hr", "ciamConsumer", ciamOwner="cn=hr-app,ou=owners,dc=ciam-ops"))
    hr = "cn=hr,ou=consumers,dc=ciam-ops"
    d, alpha, beta = model(alpha=(_service(ALPHA, "com.amazonaws.vpce.r.vpce-svc-1", ("111122223333", "444455556666"),
                                           (hr,), ciamAcceptanceRequired="TRUE"),),
                           beta=(_service(BETA, None, ("111122223333",)),), tree=(*OWNERS, *consumers))
    found = check_endpoint_services(context(d, alpha, beta, CUTOVER))
    assert [(a[1], a[2]) for a in found.actions] == [
        ("Consumer `hr` connects to `es-ldaps` privately (com.amazonaws.vpce.r.vpce-svc-1); for beta/prod it must "
         "create an endpoint to the target service (its name not recorded yet) and be accepted before cutover.",
         "hr-app"),
        ("alpha/prod allows `444455556666` to connect to `es-ldaps`; beta/prod's `es-ldaps` doesn't: allow them, or "
         "confirm they no longer connect.", "**NO OWNER**"),
        ("beta/prod: anyone who knows `es-ldaps`'s name may connect without being accepted (no visibility restriction "
         "recorded, acceptance not required): restrict who sees it, or require acceptance.", "**NO OWNER**")]
    same = model(alpha=(_service(ALPHA, "svc-1", ciamAcceptanceRequired="TRUE"),),
                 beta=(_service(BETA, "svc-1", ciamVisibleTo="111122223333"),))
    assert check_endpoint_services(context(*same)).actions == ()


def test_interconnects_with_overlapping_networks_or_half_done():
    def link(env, peer, accepted="TRUE"):
        return entry(env, "link", "ciamInterconnect", ciamBindingRole="link", ciamInterconnectKind="peering",
                     ciamPeerEnvironment=peer, ciamSourceCidr="10.1.0.0/16", ciamLinkKind="peering",
                     ciamPeerAccepted=accepted)
    d, alpha, beta = model(alpha=(link(ALPHA, BETA),), beta=(link(BETA, ALPHA, "FALSE"),))  # both use 10.1.0.0/16
    found = check_interconnects(context(d, alpha, beta, CUTOVER))
    assert _texts(found.blockers) == ["beta/prod: `link` links to alpha/prod, but their networks overlap (10.1.0.0/16 "
                                      "and 10.1.0.0/16): traffic for the overlap can't be routed."]
    assert _texts(found.actions) == [
        "alpha/prod: `link` links to beta/prod, but their networks overlap (10.1.0.0/16 and 10.1.0.0/16): traffic "
        "for the overlap can't be routed.",
        "beta/prod: the other side of `link` (alpha/prod) hasn't accepted or configured its half."]
    assert overlaps(("10.1.0.0/16", "fd00::/8"), ("10.2.0.0/16", "10.1.4.0/24")) == (("10.1.0.0/16", "10.1.4.0/24"),)


SITES = ("dn: ou=egress-destinations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\n"
         "ou: egress-destinations\n",
         entry("ou=egress-destinations,dc=ciam-ops", "partner-md", "ciamEgressDestination",
               ciamDestination="metadata.partner.example", ciamSiteKind="partner-metadata", ciamNeededByRole="web"),
         entry("ou=egress-destinations,dc=ciam-ops", "ocsp", "ciamEgressDestination",
               ciamDestination="*.ocsp.example:80", ciamSiteKind="ocsp-crl"),
         "dn: ou=external-services,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\n"
         "ou: external-services\n",
         entry("ou=external-services,dc=ciam-ops", "duo", "ciamExternalService", ciamServiceKind="mfa",
               ciamEndpointHost="api-1.duosecurity.example", ciamReachedFrom="web"))


def _proxy(env, *allowed, kind="firewall"):
    return entry(env, "egress-fw", "ciamProxy", ciamBindingRole="egress-fw", ciamProxyKind=kind,
                 ciamAllowedDestination=allowed)


def test_outside_sites_come_from_the_record_and_the_vendors():
    d, _, _ = model(tree=SITES)
    assert [(s.host, s.kind, s.needed_by) for s in required_sites(d)] == [
        ("api-1.duosecurity.example", "mfa", ("web",)), ("*.ocsp.example:80", "ocsp-crl", ()),
        ("metadata.partner.example", "partner-metadata", ("web",))]


def test_the_egress_firewall_must_allow_the_sites_and_be_routed_through():
    table = entry(BETA, "rt", "ciamRouteTable", ciamBindingRole="rt", ciamRoute="0.0.0.0/0 nat pf-egress")
    d, alpha, beta = model(beta=(_proxy(BETA, "duosecurity.example", "metadata.partner.example"), table), tree=SITES)
    assert _texts(check_sites(context(d, alpha, beta, CUTOVER)).actions) == [
        "beta/prod's egress passes `egress-fw` (firewall), which doesn't allow `*.ocsp.example:80` (ocsp-crl): allow "
        "them before cutover, or what the platform fetches there fails (metadata, signing keys, certificate status, "
        "vendors).",
        "beta/prod: no route sends internet egress through `egress-fw`, so its domain rules aren't enforced: route the "
        "subnets' default route through it."]
    routed = entry(BETA, "rt", "ciamRouteTable", ciamBindingRole="rt", ciamRoute="0.0.0.0/0 firewall egress-fw")
    d, alpha, beta = model(beta=(_proxy(BETA, "*.duosecurity.example", "partner.example", "ocsp.example"), routed),
                           tree=SITES)
    assert check_sites(context(d, alpha, beta)).actions == ()
    narrow = model(beta=(_proxy(BETA, "a.ocsp.example"),))[2]
    assert not allows(narrow.bindings[-1], required_sites(model(tree=SITES)[0])[1])   # a host doesn't cover *.ocsp


def test_time_source_recorded_somewhere():
    d, alpha, beta = model()
    assert _texts(check_time(context(d, alpha, beta)).actions) == [
        "Neither alpha/prod nor beta/prod records where its servers get their time (the provider's time service, NTP "
        "servers): record it, since clock skew breaks SAML assertions and replication."]
    ts = entry(ALPHA, "time", "ciamTimeSource", ciamBindingRole="time-source", ciamTimeServer="169.254.169.123",
               ciamTimeKind="provider")
    assert check_time(context(*model(alpha=(ts,)))).actions == ()          # the role check judges the target


def test_flow_logs_kept_as_long_and_sent_somewhere_bound():
    def flow(env, days, dest="flow-logs"):
        return entry(env, "fl", "ciamFlowLog", ciamBindingRole="vpc-flow-logs", ciamFlowScope="network",
                     ciamRetentionDays=days, ciamLogDestinationRole=dest)
    d, alpha, beta = model(alpha=(flow(ALPHA, "365"), entry(ALPHA, "logs", "ciamLogDestination",
                                                             ciamBindingRole="flow-logs", ciamProviderRef="lg-1")),
                           beta=(flow(BETA, "90"),))
    assert _texts(check_flow_logs(context(d, alpha, beta)).actions) == [
        "`fl` keeps flow logs 90 days in beta/prod; alpha/prod keeps them 365.",
        "beta/prod: flow log `fl` goes to `flow-logs`, which beta/prod doesn't bind."]


def test_reports():
    table = entry(ALPHA, "rt", "ciamRouteTable", ciamBindingRole="rt", ciamMainTable="TRUE",
                  ciamRoute=("0.0.0.0/0 nat pf-egress", "10.20.0.0/16 vpn link for ds"))
    d, _, _ = model(alpha=(table, _endpoint(ALPHA, "pe-kms", ciamPrivateService="keys", ciamPrivateEndpointKind="interface",
                                            ciamSubnetRole="subnet-ds", ciamPrivateDns="TRUE"),
                           _service(ALPHA, "svc-1", ("111122223333",))),
                    beta=(_proxy(BETA, "partner.example"),), tree=SITES)
    assert route_rows(d) == [("alpha/prod", "rt", "main", "0.0.0.0/0", "nat", "pf-egress", ""),
                             ("alpha/prod", "rt", "main", "10.20.0.0/16", "vpn", "link", "ds")]
    assert private_endpoint_rows(d) == [("alpha/prod", "pe-kms", "keys", "interface", "", "subnet-ds", "yes")]
    assert endpoint_service_rows(d) == [("alpha/prod", "es-ldaps", "ldaps", "svc-1", "111122223333", "",
                                         "automatic", "anyone with the name")]
    assert site_rows(d) == [("api-1.duosecurity.example", "mfa", "web", ""),
                            ("*.ocsp.example:80", "ocsp-crl", "", ""),
                            ("metadata.partner.example", "partner-metadata", "web", "beta/prod: egress-fw")]
