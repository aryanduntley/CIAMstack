"""The showcase's applications (97-applications) through the application view, the dependency graph and the estate
counts (milestone 6.4): each application's sections hold its parts and what they reach; what depends on the Skyline
Air signing certificate reaches its application; the counts' evidence names their entries."""
from opsdir.connectors.application import application_view
from opsdir.connectors.graph import dependency_graph
from opsdir.connectors.summary import estate_counts
from opsdir.core.directory import children, values
from opsdir.core.environment import env_model
import example_estate.governance as governance

APPS = "ou=applications,dc=ciam-ops"
BLAST = "cn=skyline-air-idp-signing,ou=certificates,dc=ciam-ops"


def _rows(view, section):
    return next(s.rows for s in view.sections if s.name == section)


def test_each_application_shows_its_parts_and_what_they_reach(estate, as_of):
    d = estate["before"]
    held = children(d, APPS, "ciamApplication")
    assert [a.dn for a in held] == sorted(f"cn={cn},{APPS}" for cn, *_ in governance.APPLICATIONS)
    for app in held:
        v = application_view(d, app.dn, as_of)
        evidence = {r[5] for s in v.sections for r in s.rows}
        assert set(values(app, "ciamApplicationPart")) <= evidence, app.dn         # every part, in its section
        assert all(r[5] for s in v.sections for r in s.rows)                       # every row names its entry


def test_the_customer_portal_in_the_target(estate, as_of):
    d = estate["before"]
    v = application_view(d, f"cn=customer-portal,{APPS}", as_of, env_model(d, "target/prod"))
    assert {r[2] for r in _rows(v, "directory")} == {"customer-portal-svc", "aci-portal-write"}
    assert {(r[0], r[2]) for r in _rows(v, "edge and service names")} == {("target/prod", "svc-ldaps"),
                                                                       ("target/prod", "svc-sso")}
    assert {r[2] for r in _rows(v, "certificates")} >= {"customer-portal-sp-signing", "sso-tls-2026"}
    assert {(r[1], r[2]) for r in _rows(v, "monitoring")} >= {("ciamCanary", "portal-sso"),
                                                               ("ciamCanaryBinding", "portal-sso")}
    assert all(r[0] in ("", "target/prod") for s in v.sections for r in s.rows)   # no other environment's


def test_what_depends_on_the_skyline_air_certificate_reaches_its_application(estate):
    g = dependency_graph(estate["before"], BLAST, "up", 3)
    assert {(x.source, x.via) for x in g.edges} >= {
        ("cn=skyline-air-federation,ou=integrations,dc=ciam-ops", "ciamUsesCertificate"),
        (f"cn=skyline-air-partner,{APPS}", "ciamApplicationPart")}


def test_the_estate_counts_name_their_evidence(estate, as_of):
    counts = {c.what: c for c in estate_counts(estate["after"], as_of)}
    assert counts["applications"].count == len(governance.APPLICATIONS)
    assert all(c.count == len(c.evidence) for c in counts.values())
