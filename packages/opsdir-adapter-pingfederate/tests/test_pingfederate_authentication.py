"""PingFederate authentication: plugin instances (a password credential validator on a data store, IdP adapters, an
authentication selector) linked to the objects their settings name, secrets withheld; policy contracts, the default
authentication policy's trees and a fragment linked to what they run; rendered (plugins per environment, policies
environment-neutral), imported back unchanged, and the planner's findings about what is missing."""
import datetime as dt
import json

import pytest

from opsdir.connectors.fixes import chosen
from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir.domains.federation.naming import INTEGRATIONS
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.checks import check_references
from opsdir_adapter_pingfederate.naming import (CONTRACTS, DATA_STORES, DEFAULT_POLICY, FRAGMENTS, IDP_ADAPTERS,
                                                SELECTORS, VALIDATORS, named)
from opsdir_adapter_pingfederate.admin_api import OUTPUT as REQUESTS, rendered_bodies
from opsdir_adapter_pingfederate.render import render_env
from opsdir_adapter_pingfederate.schema import FRAGMENT
import mini_estate
from support import build_directory

REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
# alpha keeps the Duo adapter's secret; beta doesn't
EXTRA = f"""dn: cn=secret-pf-duo,ou=bindings,{ALPHA}
objectClass: top
objectClass: ciamSecretRef
cn: secret-pf-duo
ciamBindingRole: pf-duo-secret
ciamRefUri: fake://secrets/alpha/pf-duo
"""


def _plugin(pid, cls, fields=(), tables=(), **more):
    return {"id": pid, "name": pid.upper(), "pluginDescriptorRef": {"id": cls},
            "configuration": {"tables": list(tables), "fields": list(fields)}, **more}


def _node(action, *below):
    return {"action": action, **({"children": list(below)} if below else {})}


def _source(adapter, context=None):
    return {"type": "AUTHN_SOURCE", **({"context": context} if context else {}),
            "authenticationSource": {"type": "IDP_ADAPTER", "sourceRef": {"id": adapter}}}


STORE = {"type": "LDAP", "id": "users", "name": "Users", "hostnames": ["ldap.example.test:1636"], "useSsl": True}
VALIDATOR = _plugin("pcv-ldap", "org.sourceid.saml20.domain.LDAPUsernamePasswordCredentialValidator",
                    fields=[{"name": "LDAP Datastore", "value": "users"},
                            {"name": "Search Filter", "value": "uid=${username}"}],
                    attributeContract={"coreAttributes": [{"name": "DN"}, {"name": "username"}]})
HTML_FORM = _plugin("htmlform", "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter",
                    fields=[{"name": "Login Template", "value": "html.form.login.template.html"}],
                    tables=[{"name": "Credential Validators", "rows": [
                        {"fields": [{"name": "Password Credential Validator Instance", "value": "pcv-ldap"}]}]}])
PARTNER_FORM = {**_plugin("htmlform-partners", "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"),
                "parentRef": {"id": "htmlform"}}
DUO = _plugin("duo", "com.pingidentity.adapters.duo.DuoSecurityAdapter",
              fields=[{"name": "Integration Key", "value": "DIXXXXXXXXXXXXXXXXXX"},
                      {"name": "Secret Key", "encryptedValue": "eyJhbGciOiJkaXIifQ..not-a-real-value"},
                      {"name": "API Hostname", "value": "api-1234.duosecurity.example"}])
SELECTOR = _plugin("by-network", "com.pingidentity.pf.selectors.cidr.CIDRAdapterSelector",
                   tables=[{"name": "Networks", "rows": [
                       {"fields": [{"name": "Network Range (CIDR notation)", "value": "10.0.0.0/8"}]}]}])
CONTRACT = {"id": "default-apc", "name": "Default", "coreAttributes": [{"name": "subject"}],
            "extendedAttributes": [{"name": "mail"}]}
WORKFORCE = {"name": "Workforce", "enabled": True, "rootNode": _node(
    {"type": "AUTHN_SELECTOR", "authenticationSelectorRef": {"id": "by-network"}},
    _node(_source("htmlform", "Yes"),
          _node({"type": "FRAGMENT", "context": "Success", "fragment": {"id": "mfa"}},
                _node({"type": "APC_MAPPING", "context": "Success",
                       "authenticationPolicyContractRef": {"id": "default-apc"}})),
          _node({"type": "DONE", "context": "Fail"})))}
LEGACY = {"name": "Legacy", "enabled": False, "rootNode": _node(_source("kerberos"))}
PARTNERS = {"name": "Partners", "enabled": True, "rootNode": _node(
    {"type": "AUTHN_SOURCE", "authenticationSource": {"type": "IDP_CONNECTION", "sourceRef": {"id": "acme-okta"}}},
    _node({"type": "APC_MAPPING", "context": "Success", "authenticationPolicyContractRef": {"id": "default-apc"}}))}
POLICY = {"failIfNoSelection": False, "trackedHttpParameters": [],
          "authnSelectionTrees": [WORKFORCE, LEGACY, PARTNERS]}
ACME = {"id": "acme-okta", "name": "Acme Okta", "entityId": "https://acme.example/okta",
        "idpBrowserSso": {"protocol": "SAML20"}}
MFA = {"id": "mfa", "name": "MFA", "rootNode": _node(_source("duo"), _node({"type": "DONE", "context": "Success"})),
       "inputs": {"id": "default-apc"}, "outputs": {"id": "default-apc"}}
SET_DUO_ROLE = tuple(parse(f"dn: {named(IDP_ADAPTERS, 'duo')}\nchangetype: modify\nreplace: pingfedCredentialRole\n"
                           "pingfedCredentialRole: pf-duo-secret\n-\n"))


def export(policy=POLICY, connections=(ACME,)):
    ops = (("/dataStores", [STORE]), ("/passwordCredentialValidators", [VALIDATOR]),
           ("/sp/idpConnections", connections),
           ("/idp/adapters", [HTML_FORM, PARTNER_FORM, DUO]), ("/authenticationSelectors", [SELECTOR]),
           ("/authenticationPolicyContracts", [CONTRACT]), ("/authenticationPolicies/default", [policy]),
           ("/authenticationPolicies/fragments", [MFA]))
    return {"data.json": json.dumps({"operations": [{"operationType": "SAVE", "resourceType": r, "items": list(items)}
                                                     for r, items in ops]})}


def records(extra=""):
    return tuple(parse(mini_estate.LDIF + "\n" + EXTRA + extra))


def imported(changes=(), files=None, extra=""):
    """(the record (with extra LDIF) after importing (then the changes), the import's change records, notices)."""
    base = build_directory(REGISTRY, records(extra))
    import_changes, notices = preview_import(base, "pingfederate/bulk", files or export(), (ADAPTER,))
    return build_directory(REGISTRY, records(extra), (*import_changes, *changes)), import_changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def _config(e, attr="pingfedConfig"):
    return json.loads(one(e, attr))


def test_plugin_instances_link_what_their_settings_name(after):
    d, _ = after
    pcv, form = get(d, named(VALIDATORS, "pcv-ldap")), get(d, named(IDP_ADAPTERS, "htmlform"))
    assert (one(pcv, "pingfedPluginKind"), one(pcv, "pingfedPluginType"), values(pcv, "pingfedUses")) == \
        ("validator", "org.sourceid.saml20.domain.LDAPUsernamePasswordCredentialValidator",
         (named(DATA_STORES, "users"),))
    assert values(form, "pingfedUses") == (named(VALIDATORS, "pcv-ldap"),)
    assert "pluginDescriptorRef" not in _config(form) and _config(pcv)["attributeContract"]["coreAttributes"][0] == \
        {"name": "DN"}
    assert one(get(d, named(IDP_ADAPTERS, "htmlform-partners")), "pingfedParent") == named(IDP_ADAPTERS, "htmlform")
    assert one(get(d, named(SELECTORS, "by-network")), "pingfedPluginKind") == "selector"


def test_a_plugins_secret_fields_are_withheld(after):
    d, notices = after
    duo = get(d, named(IDP_ADAPTERS, "duo"))
    fields = _config(duo)["configuration"]["fields"]
    assert fields[1] == {"name": "Secret Key", "value": None} and fields[2]["value"] == "api-1234.duosecurity.example"
    assert values(duo, "pingfedWithheld") == ("/configuration/fields/1/value",)
    assert "IdP adapter DUO: its secrets are withheld; set pingfedCredentialRole to the secret role that holds them" \
        in notices
    assert "not-a-real-value" not in json.dumps([dict(e.attrs) for e in d.entries.values()])


def test_the_default_policy_keeps_its_trees_in_order_linked_to_what_they_run(after):
    d, notices = after
    assert _config(get(d, DEFAULT_POLICY)) == {"failIfNoSelection": False, "trackedHttpParameters": []}
    workforce, legacy = get(d, named(DEFAULT_POLICY, "Workforce")), get(d, named(DEFAULT_POLICY, "Legacy"))
    assert (one(workforce, "pingfedPosition"), one(workforce, "pingfedEnabled"), one(legacy, "pingfedPosition"),
            one(legacy, "pingfedEnabled")) == ("0", "TRUE", "1", "FALSE")
    assert values(workforce, "pingfedUses") == (named(SELECTORS, "by-network"), named(IDP_ADAPTERS, "htmlform"),
                                                named(FRAGMENTS, "mfa"), named(CONTRACTS, "default-apc"))
    assert _config(workforce, "pingfedPolicyTree") == WORKFORCE["rootNode"] and not values(legacy, "pingfedUses")
    assert "authentication policy Legacy: runs IdP adapter `kerberos`, which neither the export nor the record has" \
        in notices


def test_contracts_and_fragments(after):
    d, _ = after
    assert _config(get(d, named(CONTRACTS, "default-apc")))["extendedAttributes"] == [{"name": "mail"}]
    mfa = get(d, named(FRAGMENTS, "mfa"))
    assert values(mfa, "pingfedUses") == (named(IDP_ADAPTERS, "duo"), named(CONTRACTS, "default-apc"))
    assert _config(mfa) == {"name": "MFA", "inputs": {"id": "default-apc"}, "outputs": {"id": "default-apc"}}


def test_a_tree_the_export_no_longer_has_is_removed():
    d, first, _ = imported()
    second, _ = preview_import(d, "pingfederate/bulk", export({**POLICY, "authnSelectionTrees": [WORKFORCE]}),
                               (ADAPTER,))
    again = build_directory(REGISTRY, records(), (*first, *second))
    assert get(again, named(DEFAULT_POLICY, "Legacy")) is None and get(again, named(DEFAULT_POLICY, "Workforce"))


def _bodies(d, env):
    return rendered_bodies(render_env(env_model(d, env), None)[REQUESTS])


def test_plugins_render_per_environment_and_policies_everywhere_the_same():
    d, _, _ = imported(SET_DUO_ROLE)
    alpha, beta = (_bodies(d, e) for e in ("alpha/prod", "beta/prod"))
    duo = {e: next(p for p in r["/idp/adapters"] if p["id"] == "duo") for e, r in (("alpha", alpha), ("beta", beta))}
    assert (duo["alpha"]["configuration"]["fields"][1]["value"],
            duo["beta"]["configuration"]["fields"][1]["value"]) == \
        ("${secret:fake://secrets/alpha/pf-duo}", "UNBOUND:pf-duo-secret")
    assert duo["alpha"]["pluginDescriptorRef"] == {"id": "com.pingidentity.adapters.duo.DuoSecurityAdapter"}
    (policy,) = alpha["/authenticationPolicies/default"]
    assert [t["name"] for t in policy["authnSelectionTrees"]] == ["Workforce", "Legacy", "Partners"]
    assert policy["authnSelectionTrees"][0] == WORKFORCE and policy["failIfNoSelection"] is False
    assert alpha["/authenticationPolicies/fragments"] == [MFA] == beta["/authenticationPolicies/fragments"]
    assert beta["/authenticationPolicies/default"] == [policy]
    assert {"/passwordCredentialValidators", "/authenticationSelectors"} <= set(alpha)


@pytest.mark.parametrize("env", ["alpha/prod", "beta/prod"])
def test_what_it_renders_imports_back_unchanged(env):
    d, _, _ = imported(SET_DUO_ROLE)
    rendered = {p: t for p, t in render_env(env_model(d, env), None).items() if p.endswith(".json")}
    again, _ = preview_import(d, "pingfederate/bulk", rendered, (ADAPTER,))
    assert again == ()


def plan(d, dst="beta/prod"):
    return check_references(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, dst), None,
                                            dt.date(2026, 10, 1), {}, {}, ()))


def test_the_planner_names_what_is_missing_and_what_the_target_lacks():
    d, _, _ = imported()
    assert [t for _, t, _ in plan(d).blockers] == [
        "IdP adapter `duo` has withheld credentials but no credential role: nothing says which secret beta/prod gives "
        "it. Set pingfedCredentialRole.",
        "Authentication policy `Legacy` names IdP adapter `kerberos`, which the record doesn't have: PingFederate "
        "refuses the configuration until it is recorded."]
    d2, _, _ = imported(SET_DUO_ROLE)
    assert [t for _, t, _ in plan(d2).blockers][0] == "IdP adapter `duo` needs role `pf-duo-secret`, which beta/prod " \
                                                      "doesn't bind."


def test_a_policy_naming_only_what_the_record_has_is_ok():
    d, _, _ = imported(SET_DUO_ROLE, export({**POLICY, "authnSelectionTrees": [WORKFORCE, PARTNERS]}))
    f = plan(d, "alpha/prod")
    assert (f.blockers, f.ok) == ((), ("PingFederate's 5 plugin instance(s), 2 authentication policy tree(s) and 0 "
                                       "OIDC policy(-ies) name only what the record has.",))


# An IdP connection a policy tree authenticates through is the partner integration carrying PingFederate's id for it
# (pingfedConnectionId): that id, not the integration's name in the record, is the link, and exactly one integration
# may carry it.
ACME_DN = f"cn=acme-okta,{INTEGRATIONS}"


def test_a_tree_through_a_recorded_idp_connection_links_it(after):
    d, _ = after
    acme = get(d, ACME_DN)
    assert ("pingfedConnection" in acme.classes, one(acme, "pingfedConnectionId")) == (True, "acme-okta")
    partners = get(d, named(DEFAULT_POLICY, "Partners"))
    assert values(partners, "pingfedUses") == (ACME_DN, named(CONTRACTS, "default-apc"))
    assert not any("Partners" in t for _, t, _ in plan(d, "alpha/prod").blockers)


def test_a_tree_through_an_unrecorded_idp_connection_is_blocked():
    d, _, notices = imported(SET_DUO_ROLE, export(connections=()))
    assert ACME_DN not in values(get(d, named(DEFAULT_POLICY, "Partners")), "pingfedUses")
    assert "authentication policy Partners: runs IdP connection `acme-okta`, which neither the export nor the record " \
           "has" in notices
    blockers = [t for _, t, _ in plan(d, "alpha/prod").blockers]
    assert "Authentication policy `Partners` names IdP connection `acme-okta`, which the record doesn't have: " \
           "PingFederate refuses the configuration until it is recorded." in blockers


def test_an_idp_connection_id_two_integrations_claim_resolves_to_neither():
    claim = tuple(parse(f"dn: cn=acme-copy,{INTEGRATIONS}\nchangetype: add\nobjectClass: top\n"
                        "objectClass: ciamObject\nobjectClass: ciamIntegration\nobjectClass: pingfedConnection\n"
                        "cn: acme-copy\n"
                        "ciamProtocolType: saml2-idp\nciamEntityId: https://copy.example/okta\n"
                        "pingfedConnectionId: acme-okta\n"))
    d, _, _ = imported((*SET_DUO_ROLE, *claim))
    found = plan(d, "alpha/prod")
    assert "Authentication policy `Partners` names IdP connection `acme-okta`, which 2 entries claim (acme-copy, " \
           "acme-okta): exactly one may carry its id, so the record must give it to one." in \
        [t for _, t, _ in found.blockers]
    (fix,) = [x for x in found.fixes if x.key == "claimants:idp-connection:acme-okta"]
    assert [(o.key, o.label) for o in fix.options] == [("acme-copy", "keep it on `acme-copy`"),
                                                       ("acme-okta", "keep it on `acme-okta`")]
    kept, _, _ = imported((*SET_DUO_ROLE, *claim, *chosen(fix, "acme-okta").records))
    assert not any("entries claim" in t for _, t, _ in plan(kept, "alpha/prod").blockers)


def test_an_idp_connection_the_record_names_differently_still_resolves():
    partner = (f"\ndn: {INTEGRATIONS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: integrations\n\n"
               f"dn: cn=acme-partner,{INTEGRATIONS}\nobjectClass: top\nobjectClass: ciamObject\n"
               "objectClass: ciamIntegration\ncn: acme-partner\nciamProtocolType: saml2-idp\n"
               "ciamEntityId: https://acme.example/okta\n")
    d, _, _ = imported(SET_DUO_ROLE, extra=partner)
    acme = f"cn=acme-partner,{INTEGRATIONS}"
    assert get(d, ACME_DN) is None and one(get(d, acme), "pingfedConnectionId") == "acme-okta"
    assert values(get(d, named(DEFAULT_POLICY, "Partners")), "pingfedUses")[0] == acme
    assert not any("Partners" in t for _, t, _ in plan(d, "alpha/prod").blockers)
