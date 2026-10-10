"""The records an environment publishes in zones the platform runs (core edge.records.published): service names' A or
AAAA records, other records, relative names; a routed name only from the environment rendering its routing; names in
no bound zone, in a zone another party runs, or kept by another party left out (unpublished, with why)."""
from opsdir.core.interchange.ldif import parse
from opsdir.domains.edge.records import published, unpublished
from edge_samples import DNS, PARTY, TERMINATE, TLS, alpha_with_dns
from network_fixtures import ALPHA, BETA, entry, model
from pki_samples import ca_records


def test_service_names_and_records_in_the_platforms_zones():
    found = {(p.zone, p.name, p.type, p.values, p.ttl) for p in published(alpha_with_dns())}
    assert found == {("example.test", "sso", "A", ("10.1.9.10",), 300),
                     ("example.test", "@", "TXT", ("v=opsdir1",), 300),
                     ("example.test", "@", "MX", ("10 mail.example.test",), 3600)}      # the partner's zone left out


def _zone(env):
    return entry(env, "zone-example", "ciamDnsZoneBinding", ciamBindingRole="zone-example", ciamDnsZone="example.test",
                 ciamZoneVisibility="private")


def _routed(env, policy, address, weight=None):
    return entry(env, "rec-api", "ciamDnsRecord", ciamBindingRole="rec-api", ciamRecordName="api.example.test",
                 ciamRecordType="A", ciamRecordValue=address, ciamRoutingPolicy=policy,
                 **({"ciamRoutingWeight": weight} if weight else {}))


def test_a_routed_name_is_published_once_by_the_environment_rendering_its_routing():
    _, alpha, beta = model(alpha=(_zone(ALPHA), _routed(ALPHA, "failover-primary", "10.1.0.5")),
                           beta=(_zone(BETA), _routed(BETA, "failover-secondary", "10.2.0.5")))
    assert [(p.fqdn, p.values) for p in published(alpha) if p.name == "api"] == [("api.example.test", ("10.1.0.5",))]
    assert [p for p in published(beta) if p.name == "api"] == []           # the secondary's answer isn't written
    _, alpha, beta = model(alpha=(_zone(ALPHA), _routed(ALPHA, "weighted", "10.1.0.5", "3")),
                           beta=(_zone(BETA), _routed(BETA, "weighted", "10.2.0.5", "1")))
    assert [p.values for p in published(alpha) if p.name == "api"] == [("10.1.0.5", "10.2.0.5")]
    assert [p for p in published(beta) if p.name == "api"] == []


def test_an_ipv6_frontend_is_an_aaaa_record():
    svc = (f"dn: cn=svc-sso,ou=bindings,{ALPHA}\nchangetype: modify\nreplace: ciamFrontendIp\n"
           "ciamFrontendIp: fd00::10\n-\n")
    _, alpha, _ = model(alpha=DNS, tree=(*ca_records(), *TERMINATE, *PARTY),
                        changes=tuple(r for t in (*TLS, svc) for r in parse(t)))
    assert [(p.type, p.values) for p in published(alpha) if p.name == "sso"] == [("AAAA", ("fd00::10",))]


def test_what_isnt_published_says_why():
    kept = entry(ALPHA, "rec-kept", "ciamDnsRecord", ciamBindingRole="rec-kept", ciamRecordName="kept.example.test",
                 ciamRecordType="A", ciamRecordValue="10.1.0.9", ciamManagedBy="cn=site-infra,ou=parties,dc=ciam-ops")
    stray = entry(ALPHA, "rec-stray", "ciamDnsRecord", ciamBindingRole="rec-stray", ciamRecordName="x.nowhere.test",
                  ciamRecordType="A", ciamRecordValue="10.1.0.8")
    alpha = alpha_with_dns(kept, stray)
    assert {(f, why) for _, f, why in unpublished(alpha)} == {
        ("sso.partner.example", "in zone partner.example, run by another party"),
        ("kept.example.test", "kept by another party"), ("x.nowhere.test", "in no DNS zone the environment binds")}
    assert not {"kept", "x.nowhere.test"} & {p.name for p in published(alpha)}
