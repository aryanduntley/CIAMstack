"""The application view and dependency graph (milestone 6.4): a graph of what an entry names and what names it, by
DN and by role (roles bound per environment), written as JSON, DOT or a tree; an application's view in sections from
the parts it records, nothing grouped that the record doesn't group; the estate in counts with their evidence."""
import datetime as dt
import json

from opsdir.connectors.application import HEADERS, application_view, view_document, view_parts
from opsdir.connectors.graph import dependency_graph, graph_document, graph_dot, graph_lines, role_attributes
from opsdir.connectors.summary import estate_counts
from opsdir.core.directory import get
from network_fixtures import ALPHA, BETA, entry, model

R = "dc=ciam-ops"
TEAM = f"cn=portal-team,ou=owners,{R}"
INTEGRATION = f"cn=portal,ou=integrations,{R}"
CONSUMER = f"cn=portal-svc,ou=consumers,{R}"
OTHER = f"cn=reports-svc,ou=consumers,{R}"               # the same owner, recorded in no application
CERT = f"cn=portal-signing,ou=certificates,{R}"
CANARY = f"cn=portal-login,ou=canaries,{R}"
APP = f"cn=portal,ou=applications,{R}"
AS_OF = dt.date(2026, 10, 1)


def _ou(name):
    return f"dn: ou={name},{R}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {name}\n"


TREE = (*(_ou(n) for n in ("owners", "certificates", "integrations", "consumers", "acis", "canaries", "applications",
                           "changes", "incidents")),
        entry(f"ou=owners,{R}", "portal-team", "ciamParty", ciamOwnerKind="team"),
        entry(f"ou=changes,{R}", "CHG-1", "ciamChange", ciamTitle="Grant the portal's attributes",
              ciamChangeStatus="approved"),
        entry(f"ou=certificates,{R}", "portal-signing", "ciamCertificate", ciamNotAfter="20261020000000Z",
              ciamOwner=TEAM),
        entry(f"ou=integrations,{R}", "portal", "ciamIntegration", ciamProtocolType="saml2-sp",
              ciamServedBy=f"cn=sso,ou=identity-services,{R}", ciamUsesCertificate=CERT, ciamOwner=TEAM),
        entry(f"ou=consumers,{R}", "portal-svc", "ciamConsumer", ciamBindDn="uid=portal,ou=apps,dc=example,dc=test",
              ciamOwner=TEAM, ciamChangeRef=f"cn=CHG-1,ou=changes,{R}"),
        entry(f"ou=consumers,{R}", "reports-svc", "ciamConsumer", ciamBindDn="uid=reports,ou=apps,dc=example,dc=test",
              ciamOwner=TEAM),
        entry(f"ou=acis,{R}", "aci-portal", "ciamAci", ciamAciGrantee=CONSUMER, ciamAciRight="read",
              ciamAciTargetDn="ou=people,dc=example,dc=test"),
        entry(f"ou=canaries,{R}", "portal-login", "ciamCanary", ciamCheckedService="sso-service",
              ciamCanaryFlow="saml-sso", ciamStartsFrom=INTEGRATION),
        entry(f"ou=incidents,{R}", "INC-1", "ciamIncident", ciamTitle="Portal bind failures",
              ciamOpenedAt="20260901000000Z", ciamSeverity="sev3", ciamInvolved=CONSUMER),
        entry(f"ou=applications,{R}", "portal", "ciamApplication", ciamApplicationPart=(INTEGRATION, CONSUMER),
              ciamUsesRole="network", ciamCriticality="high", ciamOwner=TEAM))
CANARY_BINDING = entry(ALPHA, "portal-login", "ciamCanaryBinding", ciamBindingRole="canary-portal-login",
                       ciamRealizes="portal-login", ciamProviderRef="test-1")


def _model():
    return model(alpha=(CANARY_BINDING,), tree=TREE)


def test_the_graph_follows_dn_references_both_ways_and_roles_to_their_bindings():
    d, alpha, _ = _model()
    down = dependency_graph(d, INTEGRATION, "down", 2)
    assert {(x.source, x.target, x.via, x.kind) for x in down.edges} == {
        (INTEGRATION, CERT, "ciamUsesCertificate", "dn"),
        (INTEGRATION, f"cn=sso,ou=identity-services,{R}", "ciamServedBy", "dn"),
        (f"cn=sso,ou=identity-services,{R}", "server-role:web", "ciamTargetRole", "role")}
    assert {x.source for x in dependency_graph(d, CONSUMER, "up", 1).edges} == {
        f"cn=aci-portal,ou=acis,{R}", APP}                     # the change and the incident are no dependencies
    bound = dependency_graph(d, CANARY, "down", 2, alpha)
    assert ("role:sso-service", f"cn=svc-sso,ou=bindings,{ALPHA}", "ciamBindingRole", "binding") in {
        tuple(x) for x in bound.edges}
    assert not any(x.target.endswith(BETA) for x in bound.edges)            # alpha's bindings only
    assert all(not x.source.startswith("role:") for x in dependency_graph(d, CANARY, "down", 2).edges)
    assert "ciamUsesRole" in role_attributes(d) and "ciamBindingRole" not in role_attributes(d)


def test_the_graph_is_written_as_json_dot_and_a_tree():
    d, _, _ = _model()
    g = dependency_graph(d, APP, "both", 2)
    doc = graph_document(g)
    assert json.loads(json.dumps(doc)) == doc and doc["root"] == APP
    assert [n["id"] for n in doc["nodes"]] == sorted(n["id"] for n in doc["nodes"])
    assert {"id": APP, "kind": "ciamApplication", "label": "portal", "owner": "portal-team"} in doc["nodes"]
    dot = graph_dot(g)
    assert dot.startswith('digraph "portal" {\n') and dot.endswith("}\n")
    assert f'"{APP}" -> "{INTEGRATION}" [label="ciamApplicationPart"];' in dot
    assert '"role:network" [label="network\\nrole", shape=ellipse];' in dot
    assert f'"{APP}" -> "role:network" [label="ciamUsesRole", style=dashed];' in dot
    lines = graph_lines(g).splitlines()
    assert lines[0] == "portal (ciamApplication, portal-team)"
    assert "  -> portal (ciamIntegration, portal-team) [ciamApplicationPart]" in lines


def test_an_application_s_view_shows_its_parts_in_sections_with_their_evidence():
    d, alpha, _ = _model()
    v = application_view(d, APP, AS_OF, alpha)
    assert v.parts == (INTEGRATION, CONSUMER) and v.roles == ("network",) and v.environment == "alpha/prod"
    rows = {s.name: s.rows for s in v.sections}
    assert [r[2] for r in rows["identity"]] == ["portal", "sso", "portal"]          # application, service, integration
    assert {r[5] for r in rows["directory"]} == {CONSUMER, f"cn=aci-portal,ou=acis,{R}"}
    assert rows["certificates"] == (("", "ciamCertificate", "portal-signing", "expires 2026-10-20 (19 days)",
                                     "portal-team", CERT),)
    assert {r[2] for r in rows["edge and service names"]} == {"svc-sso"}            # the canary's checked service
    assert [r[2] for r in rows["monitoring"]] == ["portal-login", "portal-login"]   # the canary and alpha's binding
    assert [(r[1], r[2]) for r in rows["changes and incidents"]] == [("change", "CHG-1"), ("incident", "INC-1")]
    assert rows["owners"] == (("", "team", "portal-team", "owns 3: portal, portal-signing, portal-svc", "", TEAM),)
    assert OTHER not in {r[5] for s in v.sections for r in s.rows}                 # sharing an owner groups nothing
    doc = view_document(v)
    assert doc["sections"][4]["rows"][0] == dict(zip(HEADERS, rows["certificates"][0]))


def test_any_entry_is_a_view_of_itself_and_another_environment_s_bindings_are_left_out():
    d, alpha, beta = _model()
    assert view_parts(d, get(d, CONSUMER)) == ((CONSUMER,), ())
    every = {r[5] for s in application_view(d, CANARY, AS_OF).sections for r in s.rows}
    assert {f"cn=svc-sso,ou=bindings,{ALPHA}", f"cn=svc-sso,ou=bindings,{BETA}"} <= every
    in_beta = {r[5] for s in application_view(d, CANARY, AS_OF, beta).sections for r in s.rows}
    assert f"cn=svc-sso,ou=bindings,{BETA}" in in_beta and not any(dn.endswith(ALPHA) for dn in in_beta)


def test_the_estate_in_counts_names_its_evidence():
    d, _, _ = _model()
    counts = {c.what: c for c in estate_counts(d, AS_OF)}
    assert (counts["applications"].count, counts["applications"].evidence) == (1, (APP,))
    assert counts["directory consumers"].evidence == (CONSUMER, OTHER)
    assert counts["certificates expiring within 30 days"].evidence == (CERT,)
    assert counts["pending changes"].evidence == (f"cn=CHG-1,ou=changes,{R}",)
    assert counts["incidents"].count == 1 and counts["awaiting import"].count == 0
