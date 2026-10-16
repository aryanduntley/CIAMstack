"""The SiteMinder adapter: registered and chosen from the products on the servers, renders nothing; an XPSExport read
into the record (policy domains, realms, rules, policies, schemes, user directories and agents in its own schema;
partnerships as standard integrations served by its identity service; header responses as header contracts; what has
no equivalent as source objects), sensitive settings never stored, exports of other releases or with a DOCTYPE
refused, a re-import changing nothing and keeping the record's decisions; and its source checks for a plan from an
environment that runs it."""
import datetime as dt
from pathlib import Path
from types import SimpleNamespace

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import ADAPTERS, core_fragments
from opsdir.core.contract import PlanContext
from opsdir.core.directory import children, get, make_directory, one, subtree, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir.domains.governance.source_objects import check_source_objects
from opsdir_adapter_siteminder.adapter import ADAPTER, PRODUCTS
from opsdir_adapter_siteminder.carried import CARRY
from opsdir.domains.webaccess.checks import AREA as WEB_ACCESS, check_protected_apps
from opsdir_adapter_siteminder.checks import AREA, check_user_directories
from opsdir_adapter_siteminder.importer import VERSIONS, release
from opsdir_adapter_siteminder.naming import AGENTS, CARRIED, DOMAINS, SERVER_ROLES, SERVICE, USER_DIRECTORIES
from opsdir_adapter_siteminder.schema import FRAGMENT
from opsdir_adapter_siteminder.xps import KINDS
import mini_estate
from support import build_directory

EXPORT = Path(__file__).resolve().parent / "xps" / "policy-store.xml"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
AT = dt.datetime(2026, 9, 20, 3, 0, tzinfo=dt.timezone.utc)
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
DOMAIN = f"cn=crew-portal,{DOMAINS}"
CREW = f"cn=crew,ou=realms,{DOMAIN}"
ADMIN = f"cn=crew-admin,ou=realms,{DOMAIN}"
PARTS = "cn=aog-parts-exchange,ou=integrations,dc=ciam-ops"
SECRETS = ("c2VjcmV0LWFnZW50LWtleQ", "badge-shared-secret-123", "clear-text-bind-password", "trusted-host-secret",
           "backchannel-pw", "fixed-application-key")
NO_RECORDS = make_directory((), {}, ())
EXTRA = (
    "dn: ou=consumers,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: consumers\n",
    "dn: cn=siteminder-ps,ou=consumers,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
    "objectClass: ciamConsumer\ncn: siteminder-ps\nciamBindDn: cn=siteminder-ps,ou=services,dc=example,dc=test\n",
    "dn: ou=user-schema,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: user-schema\n",
    "dn: cn=mail,ou=user-schema,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
    "objectClass: ciamUserAttribute\ncn: mail\nciamLdapName: mail\nciamDataClass: pii\n",
    "dn: ou=certificates,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: certificates\n",
    "dn: cn=sm-idp-signing,ou=certificates,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
    "objectClass: ciamCertificate\ncn: sm-idp-signing\nciamFingerprint: AA:BB:CC\nciamNotAfter: 20270101000000Z\n"
    "ciamCertPurpose: saml-signing\n",
)


def _server(env, cn, role, version):
    return (f"dn: cn={cn},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: {role}\n"
            f"ciamHostname: {cn}.example.test\nciamSubnet: cn=net,ou=bindings,{env}\nciamProductVersion: {version}\n")


SERVERS = (_server(ALPHA, "ps-1", "sm-policy-server", "SiteMinder 12.8.8"),
           _server(ALPHA, "crew-web-1", "sm-agent", "SiteMinder Web Agent 12.8.8"))


def directory(extra=(), changes=()):
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *extra)))), changes)


def files(text=None):
    return {"policy-store.xml": text if text is not None else EXPORT.read_text()}


def imported(extra=EXTRA, text=None, d=None):
    """(the record after importing the export, the change records, notices)."""
    base = d if d is not None else directory(extra)
    changes, notices = preview_import(base, "siteminder", files(text), (ADAPTER,), at=AT)
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *extra)))), changes) \
        if d is None else None, changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def test_registered_and_chosen_from_the_products_on_the_servers():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "product" and ADAPTER.schema.arc == "1.3.6.1.4.1.32473.3.6"
    server = lambda v: SimpleNamespace(attrs={"ciamProductVersion": (v,)})   # noqa: E731
    assert ADAPTER.applies(SimpleNamespace(servers=(server("SiteMinder Web Agent 12.8.8"),), d=NO_RECORDS))
    assert not ADAPTER.applies(SimpleNamespace(servers=(server("PingAccess 9.0.1"),), d=NO_RECORDS))
    assert VERSIONS == ">=12.8,<13" and all(v == VERSIONS for _, v in PRODUCTS)
    assert ADAPTER.render_neutral is None and ADAPTER.render_env is None and ADAPTER.checks == ()
    assert ADAPTER.source_checks == (check_user_directories,)
    assert ADAPTER.vocabulary["ciamServerRole"] == SERVER_ROLES and [i.name for i in ADAPTER.importers] == ["xps"]


def test_policy_domains_realms_rules_and_policies_land_in_its_own_branch(after):
    d, _ = after
    crew, admin = get(d, CREW), get(d, ADMIN)
    assert one(crew, "smResourceFilter") == "/crew/" and one(crew, "smIdleTimeout") == "1800"
    assert one(crew, "smAgent") == f"cn=crew-agent,{AGENTS}"
    assert one(crew, "smAuthScheme").startswith("cn=crew-forms,")          # through an XREF and its ReferenceValue
    assert one(admin, "smResourceFilter") == "/crew/admin/"                 # a nested realm, named after its parent
    rule = get(d, f"cn=admin-pages,{ADMIN}")
    assert one(rule, "smRegex") == "TRUE" and values(rule, "smAction") == ("GET",) and one(rule, "smAllow") == "TRUE"
    assert values(get(d, f"cn=crew-pages,{CREW}"), "smAction") == ("GET", "POST")
    policy = get(d, f"cn=all-crew,ou=policies,{DOMAIN}")
    assert values(policy, "smRule") == (f"cn=crew-pages,{CREW}",)
    assert values(policy, "smSubject") == ("Crew Directory group cn=crew,ou=groups,dc=example,dc=test",)
    assert one(policy, "smXid") == "CA.SM::Policy@08-all-crew" and one(policy, "smClass") == "CA.SM::Policy"
    assert one(get(d, DOMAIN), "description") == "The crew scheduling portal"


def test_agents_schemes_and_user_directories(after):
    d, _ = after
    assert one(get(d, f"cn=crew-agent,{AGENTS}"), "ciamTargetRole") == "sm-agent"
    assert one(get(d, f"cn=parts-gateway,{AGENTS}"), "ciamTargetRole") == "sm-access-gateway"
    scheme = get(d, "cn=badge-login,ou=auth-schemes,ou=siteminder,dc=ciam-ops")
    assert one(scheme, "smSchemeType") == "Custom Template" and one(scheme, "smLibrary") == "badgeauth"
    directory_ = get(d, f"cn=crew-directory,{USER_DIRECTORIES}")
    assert one(directory_, "smConsumer") == "cn=siteminder-ps,ou=consumers,dc=ciam-ops"
    assert one(directory_, "smNamespace") == "LDAP:"
    assert values(directory_, "smWithheld") == ("Password: the bind password of the connection; re-provision in the "
                                                "target",)


def test_partnerships_become_integrations_served_by_its_identity_service(after):
    d, notices = after
    parts = get(d, PARTS)
    assert one(parts, "ciamProtocolType") == "saml2-sp" and one(parts, "ciamEntityId") == "https://parts.example.test/sp"
    assert one(parts, "ciamAcsUrl") == "https://parts.example.test/acs" and one(parts, "ciamSamlBinding") == "HTTP-POST"
    assert values(parts, "ciamNameIdFormat") == ("emailAddress",) and one(parts, "ciamServedBy") == SERVICE
    assert one(parts, "ciamUsesCertificate") == "cn=sm-idp-signing,ou=certificates,dc=ciam-ops"
    assert [one(c, "ciamClaimName") for c in children(d, f"ou=claims,{PARTS}", "ciamClaimMap")] == ["email"]
    assert any("company (o)" in n for n in notices)                 # no user-schema record for o: named, not recorded
    service = get(d, SERVICE)
    assert one(service, "ciamBaseUrl") == "https://wam.example.test"
    assert one(service, "ciamTargetRole") == "sm-policy-server"
    assert "new integration aog-parts-exchange (saml2-sp), not in the record before: give it an owner" in notices
    assert not [e for e in subtree(d, "ou=integrations,dc=ciam-ops") if "SAMLv2SP" in (one(e, "smClass") or "")]


def test_header_responses_become_header_contracts_and_a_fixed_value_is_withheld(after):
    d, _ = after
    user = get(d, "cn=crew-portal-sm_user,ou=header-contracts,dc=ciam-ops")
    assert (one(user, "ciamHeaderName"), one(user, "ciamHeaderKind"), one(user, "ciamSetByRole"),
            one(user, "ciamHeaderValue")) == ("SM_USER", "identity", "sm-agent", "attribute uid")
    key = get(d, "cn=crew-portal-x-crew-app-key,ou=header-contracts,dc=ciam-ops")
    assert one(key, "ciamHeaderValue") == "a fixed value" and one(key, "smWithheld").startswith("Value: ")


def test_what_has_no_equivalent_is_carried_as_source_objects(after):
    d, _ = after
    carried = {one(o, "cn"): o for o in subtree(d, CARRIED, "ciamSourceObject")}
    assert sorted(carried) == ["aco-crew-aco", "cookie-crew-portal-crew-identity-crewrole",
                               "custom-scheme-badge-login", "hco-default-hco", "keys", "routing-parts-gateway",
                               "trusted-host-crew-web-1", "unknown-shift"]
    for cn, k in (("aco-crew-aco", "aco"), ("hco-default-hco", "hco"), ("trusted-host-crew-web-1", "trusted-host"),
                  ("custom-scheme-badge-login", "custom-scheme"), ("routing-parts-gateway", "routing"),
                  ("keys", "keys"), ("unknown-shift", "unknown")):
        handling, role, blocks, how = CARRY[k]
        o = carried[cn]
        assert (one(o, "ciamHandling"), one(o, "ciamTargetRole"), one(o, "ciamBlocking") == "TRUE",
                one(o, "ciamHow")) == (handling, role, blocks, how), cn
    assert values(carried["custom-scheme-badge-login"], "ciamConcerns") == (ADMIN,)
    assert values(carried["aco-crew-aco"], "ciamSourceFact") == ("Parameters CookieDomain=.example.test, "
                                                                "LogOffUri=/crew/logout",)
    assert one(carried["keys"], "ciamImportedAt") == "20260920030000Z"
    assert "CA.SM::Variable" not in KINDS and one(carried["unknown-shift"], "ciamSourceClass") == "CA.SM::Variable"


def test_no_sensitive_value_is_ever_stored_clear_or_encrypted():
    _, changes, notices = imported()
    stored = " ".join(v for c in changes for vs in c.attrs.values() for v in vs)
    assert not [s for s in SECRETS if s in stored]
    (summary,) = [n for n in notices if "withheld, never stored" in n]
    assert summary.startswith("6 sensitive setting(s) withheld") and "CLEAR TEXT" in summary and "-pass" in summary


def test_a_doctype_another_release_or_nothing_is_refused():
    text = EXPORT.read_text()
    _, changes, notices = imported(text=text.replace("<XPS ", '<!DOCTYPE XPS [<!ENTITY x "y">]><XPS ', 1))
    assert changes == () and "policy-store.xml: a DOCTYPE or entity declaration: refused, not read" in notices
    _, changes, notices = imported(text=text.replace('ProductVersion="12.8.8"', 'ProductVersion="12.52.2"'))
    assert changes == () and notices == ("the export is from SiteMinder 12.52.2; this adapter reads >=12.8,<13: "
                                         "nothing imported",)
    _, changes, _ = imported(text=text.replace('ProductVersion="12.8.8"', 'ProductVersion="12.9.1"'))
    assert changes and release("12.52") == "12.5.2" and release("12.8.08") == "12.8.08"
    _, changes, notices = imported(text="<XPS><PolicyData/></XPS>")
    assert changes == () and notices == ("no SiteMinder XPSExport objects found (*.xml with <Object> elements)",)


def test_a_link_to_an_object_the_export_doesnt_hold_is_named():
    text = EXPORT.read_text().replace("CA.SM::AuthScheme@0d-badge</XID>", "CA.SM::AuthScheme@0d-gone</XID>")
    _, _, notices = imported(text=text)
    assert any("links to CA.SM::AuthScheme@0d-gone, which the export doesn't hold" in n for n in notices)


def test_a_partner_the_record_holds_is_kept_as_it_is(after):
    held = ("dn: ou=integrations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: integrations\n",
            "dn: cn=parts,ou=integrations,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\n"
            "objectClass: ciamIntegration\ncn: parts\nciamProtocolType: saml2-sp\n"
            "ciamEntityId: https://parts.example.test/sp\nciamAcsUrl: https://parts.example.test/new-acs\n"
            "ciamServedBy: cn=sso,ou=identity-services,dc=ciam-ops\n")
    d, _, notices = imported(extra=(*EXTRA, *held))
    parts = get(d, "cn=parts,ou=integrations,dc=ciam-ops")
    assert one(parts, "ciamAcsUrl") == "https://parts.example.test/new-acs" and "smObject" in parts.classes
    assert one(parts, "ciamServedBy") == "cn=sso,ou=identity-services,dc=ciam-ops" and get(d, PARTS) is None
    assert any("which the record already holds (served by sso): kept as it is" in n for n in notices)


def test_a_re_import_changes_nothing_and_keeps_the_record_s_decisions(after):
    d, _ = after
    assert preview_import(d, "siteminder", files(), (ADAPTER,), at=AT)[0] == ()
    decided = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *EXTRA)))), (
        *imported()[1], *parse(f"dn: cn=hco-default-hco,{CARRIED}\nchangetype: modify\nreplace: ciamHandling\n"
                               "ciamHandling: review\n-\nreplace: ciamHow\nciamHow: ask the web team\n-\n")))
    assert preview_import(decided, "siteminder", files(), (ADAPTER,), at=AT)[0] == ()


def _ctx(d, src="alpha/prod", dst="beta/prod"):
    return PlanContext(d, env_model(d, src), env_model(d, dst), dt.date(2026, 11, 1), dt.date(2026, 10, 1), {}, {}, ())


APPS = "ou=protected-applications,dc=ciam-ops"
RULES = f"ou=access-rules,{APPS}"


def test_realms_rules_and_policies_are_projected_onto_the_neutral_layer(after):
    d, _ = after
    crew = get(d, f"cn=crew-portal-crew,{APPS}")
    assert (one(crew, "ciamBasePath"), one(crew, "ciamEnforcedByRole"), one(crew, "ciamSignOn"),
            one(crew, "ciamIdleTimeout"), one(crew, "ciamProjectedFrom")) == ("/crew/", "sm-agent", "form", "1800",
                                                                              CREW)
    assert values(crew, "ciamSetsHeader") == ("cn=crew-portal-sm_user,ou=header-contracts,dc=ciam-ops",
                                              "cn=crew-portal-x-crew-app-key,ou=header-contracts,dc=ciam-ops")
    assert one(crew, "ciamPublishedAs") is None and one(crew, "ciamBackendRole") is None     # not in the export
    pages = get(d, f"cn=crew-pages,{crew.dn}")
    assert (values(pages, "ciamPathPattern"), one(pages, "ciamMatchKind"), values(pages, "ciamHttpMethod"),
            values(pages, "ciamRuleRef")) == (("/*",), "wildcard", ("GET", "POST"),
                                              (f"cn=crew-portal-all-crew,{RULES}",))
    admin = get(d, f"cn=admin-pages,cn=crew-portal-crew-admin,{APPS}")
    assert (values(admin, "ciamPathPattern"), one(admin, "ciamMatchKind")) == (("^/(roster|swap)",), "regex")
    assert one(get(d, f"cn=crew-portal-crew-admin,{APPS}"), "ciamSignOn") == "custom"
    rule = get(d, f"cn=crew-portal-all-crew,{RULES}")
    assert (one(rule, "ciamEffect"), values(rule, "ciamWho"), one(rule, "ciamProjectedFrom")) == (
        "allow", ("group cn=crew,ou=groups,dc=example,dc=test",), f"cn=all-crew,ou=policies,{DOMAIN}")


def test_a_target_without_its_agents_leaves_every_realm_unprotected():
    d, _, _ = imported(extra=(*EXTRA, *SERVERS))
    found = check_protected_apps(_ctx(d))
    assert [b[1].split(" (")[0] for b in found.blockers] == ["Protected application `crew-portal-crew`",
                                                             "Protected application `crew-portal-crew-admin`"]
    assert found.blockers[0] == (WEB_ACCESS, "Protected application `crew-portal-crew` (`/crew/`) is enforced by "
                                             "`sm-agent`, which beta/prod doesn't run: its 1 resource(s), its rules "
                                             "(`crew-portal-all-crew`), its form sign-on, and the headers the "
                                             "application trusts (`SM_USER`, `X-Crew-App-Key`) stop being enforced. "
                                             "Have a product beta/prod runs protect it (its enforcing role overridden "
                                             "there), or retire it.", "**NO OWNER**")
    assert check_protected_apps(_ctx(d, "beta/prod", "alpha/prod")).blockers == ()


def test_source_objects_of_roles_the_target_doesnt_run_are_planned_by_the_core():
    d, _, _ = imported(extra=(*EXTRA, *SERVERS))
    found = check_source_objects(_ctx(d))
    assert len(found.blockers) == 1 and "custom-scheme-badge-login" in found.blockers[0][1]   # routing: no gateway
    assert sorted(a[1].split("`")[1] for a in found.actions) == [
        "aco-crew-aco", "cookie-crew-portal-crew-identity-crewrole", "hco-default-hco", "keys",
        "trusted-host-crew-web-1", "unknown-shift"]


def test_a_user_directory_binding_as_an_unrecorded_account_is_an_action():
    d, _, _ = imported(extra=(*EXTRA[2:], *SERVERS))          # no consumer record
    (action,) = check_user_directories(_ctx(d)).actions
    assert action[0] == AREA and action[1].startswith("SiteMinder's user directory `crew-directory` binds as an "
                                                      "account no directory consumer records")
    d, _, _ = imported(extra=(*EXTRA, *SERVERS))
    assert check_user_directories(_ctx(d)).actions == ()
