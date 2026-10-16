"""The web access domain: protected web applications in neutral terms, whatever product enforces them. The planner's
view (an application nothing in the target protects; a move to another product and what it needs; the fixes writing
the target's overrides), the projection helpers product importers share (ownership by ciamProjectedFrom), what a
product can't express (express.losses), and the report."""
import datetime as dt

from opsdir.core.contract import Imported, PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import as_seen, env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.webaccess.apps import enforcer, path_resources, protected_app_rows
from opsdir.domains.webaccess.checks import AREA, check_protected_apps, protect_fix
from opsdir.domains.webaccess.express import Capabilities, losses, pattern_as
from opsdir.domains.webaccess.naming import app_dn, resource_dn, rule_dn
from opsdir.domains.webaccess.projection import after_import, neutral_entry, owns, projected
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
CREW = app_dn("crew")
CONTRACT = "cn=crew-user,ou=header-contracts,dc=ciam-ops"
SOURCE = "cn=crew,ou=realms,ou=product,dc=ciam-ops"


def server(env, name, role):
    return f"dn: cn={name},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {name}\nciamServerRole: {role}\n" \
           f"ciamHostname: {name}.example.test\nciamSubnet: cn=net,ou=bindings,{env}\n"


def override(env, name, entry, attr, value):
    return f"dn: cn={name},ou=overrides,{env}\nobjectClass: top\nobjectClass: ciamOverride\ncn: {name}\n" \
           f"ciamOverrides: {entry}\nciamOverrideAttribute: {attr}\nciamOverrideValue: {value}\n"


# alpha runs the agent protecting the crew portal; beta runs a gateway, publishes the portal and its web server
BASE = f"""{server(ALPHA, "web-1", "old-agent")}
{server(BETA, "gw-1", "new-gw")}
dn: cn=svc-crew,ou=bindings,{BETA}
objectClass: top
objectClass: ciamServiceName
cn: svc-crew
ciamBindingRole: crew-service
ciamFqdn: crew.beta.example.test
ciamPort: 443
ciamTargetRole: new-gw

dn: ou=header-contracts,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: header-contracts

dn: {CONTRACT}
objectClass: top
objectClass: ciamHeaderContract
cn: crew-user
ciamHeaderName: X-Crew-User
ciamHeaderKind: identity
ciamSetByRole: old-agent
ciamHeaderValue: attribute uid

dn: ou=protected-applications,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: protected-applications

dn: ou=access-rules,ou=protected-applications,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: access-rules

dn: {rule_dn("crew-group")}
objectClass: top
objectClass: ciamObject
objectClass: ciamAccessRule
cn: crew-group
ciamEffect: allow
ciamWho: group cn=crew,ou=groups,dc=example,dc=test

dn: {rule_dn("no-contractors")}
objectClass: top
objectClass: ciamObject
objectClass: ciamAccessRule
cn: no-contractors
ciamEffect: deny
ciamWho: attribute employeeType=contractor

dn: {CREW}
objectClass: top
objectClass: ciamObject
objectClass: ciamProtectedApp
cn: crew
ciamBasePath: /crew/
ciamEnforcedByRole: old-agent
ciamSignOn: form
ciamIdleTimeout: 1800
ciamMaxSessionTime: 28800
ciamSetsHeader: {CONTRACT}
ciamRuleRef: {rule_dn("no-contractors")}

dn: {resource_dn(CREW, "pages")}
objectClass: top
objectClass: ciamObject
objectClass: ciamPathResource
cn: pages
ciamPathPattern: /*
ciamMatchKind: wildcard
ciamHttpMethod: GET
ciamHttpMethod: POST
ciamRuleRef: {rule_dn("crew-group")}

dn: {resource_dn(CREW, "roster")}
objectClass: top
objectClass: ciamObject
objectClass: ciamPathResource
cn: roster
ciamPathPattern: ^/roster/(publish|swap)
ciamMatchKind: regex
ciamOrder: 1
"""
MOVED = f"""dn: ou=overrides,{BETA}
objectClass: top
objectClass: organizationalUnit
ou: overrides

{override(BETA, "crew-enforcer", CREW, "ciamEnforcedByRole", "new-gw")}"""
READY = """dn: ou=integrations,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: integrations

dn: cn=crew-portal,ou=integrations,dc=ciam-ops
objectClass: top
objectClass: ciamIntegration
cn: crew-portal
ciamProtocolType: oidc-client
ciamClientId: crew-portal
"""
WITH_ROLES = [("ciamPublishedAs", "crew-service"), ("ciamBackendRole", "crew-service"),
              ("ciamSignInAs", "cn=crew-portal,ou=integrations,dc=ciam-ops")]


def directory(*extra, changes=()):
    return build_directory(REGISTRY, parse("\n".join((mini_estate.LDIF, BASE, *extra))), changes)


def with_attrs(text, pairs):
    """BASE with the crew application's entry given extra attribute values."""
    return text.replace("ciamRuleRef: " + rule_dn("no-contractors") + "\n",
                        "ciamRuleRef: " + rule_dn("no-contractors") + "\n" + "".join(f"{a}: {v}\n" for a, v in pairs))


def ctx(d, src="alpha/prod", dst="beta/prod"):
    return PlanContext(d, as_seen(env_model(d, src)), as_seen(env_model(d, dst)), dt.date(2026, 11, 1),
                       dt.date(2026, 10, 1), {}, {}, ())


def test_an_application_nothing_in_the_target_protects_is_a_blocker():
    found = check_protected_apps(ctx(directory()))
    assert found.blockers == ((AREA, "Protected application `crew` (`/crew/`) is enforced by `old-agent`, which "
                                     "beta/prod doesn't run: its 2 resource(s), its rules (`no-contractors`, "
                                     "`crew-group`), its form sign-on, and the headers the application trusts "
                                     "(`X-Crew-User`) stop being enforced. Have a product beta/prod runs protect it "
                                     "(its enforcing role overridden there), or retire it.", "**NO OWNER**"),)
    assert check_protected_apps(ctx(directory(), "beta/prod", "alpha/prod")) == check_protected_apps(
        ctx(directory(), "beta/prod", "alpha/prod"))._replace(blockers=())     # beta doesn't enforce it: nothing


def test_a_move_to_another_product_needs_its_hosts_backend_and_sign_in_from_the_record():
    d = directory(MOVED)
    assert (enforcer(env_model(d, "alpha/prod"), get(d, CREW)), enforcer(as_seen(env_model(d, "beta/prod")),
                                                                          get(d, CREW))) == ("old-agent", "new-gw")
    found = check_protected_apps(ctx(d))
    assert [b[1].split(":")[0] for b in found.blockers] == [
        "Protected application `crew` moves to `new-gw`, but the record names no service name clients reach it at",
        "Protected application `crew` was enforced inside its own web server; `new-gw` must send requests on to it",
        "Protected application `crew`'s users sign in with form collected by `old-agent`; `new-gw` signs them in "
        "through an identity service"]
    (action,) = found.actions
    assert action[1].startswith("Header `X-Crew-User` (contract `crew-user`), which `crew` trusts, is set by "
                                "`old-agent` in beta/prod, where `new-gw` protects the application")
    (fix,) = found.fixes
    assert fix.key == "enforcer-header:crew-user"
    assert [(r.dn, r.attrs.get("ciamOverrideAttribute"), r.attrs.get("ciamOverrideValue")) for r in fix.records] == [
        (f"cn=crew-user-setter,ou=overrides,{BETA}", ("ciamSetByRole",), ("new-gw",))]


def test_a_ready_move_is_kept_and_the_header_override_clears_the_action():
    d = build_directory(REGISTRY, parse("\n".join((mini_estate.LDIF, with_attrs(BASE, WITH_ROLES), MOVED, READY,
                                                    override(BETA, "crew-user-setter", CONTRACT, "ciamSetByRole",
                                                             "new-gw")))), ())
    found = check_protected_apps(ctx(d))
    assert (found.blockers, found.actions) == ((), ())
    assert found.ok == ("Protected application `crew` moves from `old-agent` to `new-gw` in beta/prod.",)


def test_the_protect_fix_overrides_the_enforcer_in_the_target_only():
    d = directory()
    fix = protect_fix(as_seen(env_model(d, "beta/prod")), get(d, CREW), "new-gw", "NewGateway", "newgw")
    assert fix.key == "protect:newgw/crew"
    assert [(r.changetype, r.dn) for r in fix.records] == [("add", f"ou=overrides,{BETA}"),
                                                           ("add", f"cn=crew-enforcer,ou=overrides,{BETA}")]
    assert fix.records[1].attrs["ciamOverrides"] == (CREW,) and fix.records[1].attrs["ciamOverrideValue"] == (
        "new-gw",)
    again = protect_fix(as_seen(env_model(directory(MOVED), "beta/prod")), get(d, CREW), "other", "Other", "other")
    assert [(r.changetype, r.mods) for r in again.records] == [("modify", (("replace", "ciamOverrideValue",
                                                                             ("other",)),))]


def test_resources_are_ordered_by_their_order_then_most_specific_first():
    d = directory()
    assert [r.dn.split(",")[0] for r in path_resources(d, get(d, CREW))] == ["cn=roster", "cn=pages"]


CAPS = Capabilities("Gateway", ("regex",), (("wildcard", "regex"),), ("standard",), ("authenticated", "attribute"),
                    ("oidc",), False, ("idle",), False)


def test_losses_name_what_a_product_cant_express():
    d = build_directory(REGISTRY, parse("\n".join((mini_estate.LDIF, with_attrs(BASE, WITH_ROLES), READY))), ())
    assert [(x.severity, x.text) for x in losses(d, get(d, CREW), CAPS)] == [
        ("action", "users sign in with form today; Gateway signs them in through the identity service, which must "
                   "offer that sign-on"),
        ("action", "its max session limit (28800s) isn't enforced by Gateway: the identity service's session must "
                   "hold it"),
        ("info", "resource `pages` matches by wildcard, rendered as regex"),
        ("blocker", "rule `no-contractors` denies, which Gateway can't render, so the render leaves it out: rewrite "
                    "it as an allowance of everyone else"),
        ("blocker", "rule `crew-group` admits `group cn=crew,ou=groups,dc=example,dc=test`, which Gateway can't test, "
                    "so the render leaves the rule out and admits every signed-in user: release it as a claim of the "
                    "sign-in integration and test that (attribute <claim>=<value>)")]


def test_patterns_translate_between_match_kinds_without_changing_what_they_match():
    assert pattern_as("prefix", "/docs/", "wildcard") == "/docs/*"
    assert pattern_as("prefix", "/docs/", "regex") == "^/docs/"
    assert pattern_as("wildcard", "/docs/*.pdf", "regex") == "^/docs/.*\\.pdf$"
    assert pattern_as("regex", "^/a+", "wildcard") == "^/a+"


def _app(name, base, source):
    return neutral_entry(app_dn(name), "ciamProtectedApp", {"cn": (name,), "ciamBasePath": (base,),
                                                            "ciamEnforcedByRole": ("old-agent",),
                                                            "ciamPublishedAs": (), "ciamProjectedFrom": (source,)})


def test_a_projection_owns_only_its_own_entries_and_keeps_what_the_record_adds():
    d = build_directory(REGISTRY, parse("\n".join((mini_estate.LDIF, with_attrs(BASE, [
        ("ciamProjectedFrom", SOURCE), ("ciamBackendRole", "crew-service")])))), ())
    mine = _app("crew", "/crew/", SOURCE)
    assert owns(d, mine) and not owns(d, _app("crew", "/crew/", "cn=other,ou=product,dc=ciam-ops"))
    found = projected(d, ((mine, ()),), (), ("ou=product,dc=ciam-ops",), "Product")
    (app_group,) = [g for g in found.groups if g[0] == CREW]
    entry = app_group[1][0]
    assert one(entry, "ciamBackendRole") == "crew-service"            # the product says nothing about it: kept
    assert values(entry, "ciamSetsHeader") == (CONTRACT,)             # what the record holds, the projection omits
    assert values(entry, "ciamPublishedAs") == ()                     # the product says it has none
    assert [e.dn for e in app_group[1][1:]] == [resource_dn(CREW, "pages"), resource_dn(CREW, "roster")]
    other = projected(d, ((_app("crew", "/crew", "cn=other,ou=product2,dc=ciam-ops"), ()),), (),
                      ("ou=product2,dc=ciam-ops",), "Other")
    assert other.groups == () and other.notices == (
        f"Other: crew (ou=protected-applications) is projected from {SOURCE}, which this import doesn't change; what "
        "it read differs: ciamBasePath /crew/ -> /crew",)


def test_a_projection_removes_what_its_product_no_longer_has():
    d = build_directory(REGISTRY, parse("\n".join((mini_estate.LDIF, with_attrs(BASE, [
        ("ciamProjectedFrom", SOURCE)])))), ())
    found = projected(d, (), (), ("ou=product,dc=ciam-ops",), "Product")
    assert (CREW, ()) in found.groups
    assert projected(d, (), (), ("ou=elsewhere,dc=ciam-ops",), "Product").groups == ()


def test_after_import_replaces_each_group_subtree():
    d = directory()
    after = after_import(d, Imported((), ((CREW, (get(d, CREW),)),), ()))
    assert get(after, CREW) is not None and get(after, resource_dn(CREW, "pages")) is None


def test_the_report_lists_each_application():
    d = directory()
    assert protected_app_rows(d) == [("crew", "/crew/", "old-agent", "", "", "form", "", "2",
                                      "no-contractors, crew-group", "", "**NO OWNER**")]
