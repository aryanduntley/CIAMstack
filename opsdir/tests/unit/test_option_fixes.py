"""Fixes that are a choice: nothing is proposed or applied without one option chosen; each option, applied, resolves
the finding. Secret roles for withheld credentials (one option per secret role the target binds, never picked),
overrides aligned (run the source's value, or the shared one), and the plain fixes beside them: stray firewall rules
closed, endpoint services requiring acceptance, private endpoints no longer reaching unbound roles."""
from types import SimpleNamespace

import pytest

from opsdir.connectors.fixes import chosen
from opsdir.connectors.network import network_check
from opsdir.core.contract import Listener
from opsdir.core.directory import make_entry
from opsdir.core.findings import Fix, Option
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.infrastructure.checks import check_overrides
from opsdir.domains.network.checks import check_endpoint_services, check_private_endpoints
from opsdir.domains.pki.credentials import credential_role_fix, name_match
from network_fixtures import ALPHA, BETA, context, entry, model, rule

R1, R2, R = (LdifRecord(f"cn={n},dc=ciam-ops", "delete", {}, ()) for n in ("r1", "r2", "r"))
CHOICE = Fix("k", "A", "Do it", (), ("by hand",), ("shared risk",),
             (Option("one", "the first", (R1,), ()), Option("two", "the second", (R2,), ("its own risk",))))


def test_a_choice_needs_one_option_and_carries_its_records_and_risks():
    with pytest.raises(ValueError, match="is a choice: name one with --option \\(one, two\\)"):
        chosen(CHOICE)
    with pytest.raises(ValueError, match="is a choice"):
        chosen(CHOICE, "three")
    picked = chosen(CHOICE, "two")
    assert (picked.title, picked.records, picked.risks, picked.options) == (
        "Do it: the second", (R2,), ("shared risk", "its own risk"), ())
    plain = CHOICE._replace(options=(), records=(R,))
    assert chosen(plain) == plain
    with pytest.raises(ValueError, match="offers no options"):
        chosen(plain, "one")


def _secret(env, role):
    return entry(env, f"secret-{role}", "ciamSecretRef", ciamBindingRole=role, ciamRefUri=f"fake://{role}")


def test_credential_roles_are_offered_never_picked():
    d, alpha, beta = model(alpha=(_secret(ALPHA, "db-password"),),
                           beta=(_secret(BETA, "db-password"), _secret(BETA, "ldap-password")))
    store = make_entry("cn=hr,ou=stores,dc=ciam-ops", ("pingfedDataStore",), {})
    fix = credential_role_fix(alpha, beta, store, "pingfedCredentialRole", "Data store `hr`", "credential-role:hr")
    assert fix.records == () and [(o.key, o.label, o.risks) for o in fix.options] == [
        ("db-password", "`db-password` (fake://db-password in beta/prod)", ()),
        ("ldap-password", "`ldap-password` (fake://ldap-password in beta/prod)",
         ("alpha/prod binds no `ldap-password`: its render then lacks the secret.",))]
    assert chosen(fix, "db-password").records[0].mods == (("replace", "pingfedCredentialRole", ("db-password",)),)
    assert credential_role_fix(alpha, model()[2], store, "a", "b", "c") is None     # no secret role to offer
    hinted = credential_role_fix(alpha, beta, store, "a", "b", "c", names=("ldap-store",))
    assert [o.key for o in hinted.options] == ["ldap-password", "db-password"]       # a matching name first
    assert hinted.options[0].label.endswith(", its name matches")
    assert name_match(("grant-store",), "pf-grants-db-password") and not name_match(("grant-store",), "ds-keystore")


OVERRIDES = ("dn: cn=lockout,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\ncn: lockout\n"
             "ciamLockoutFailureCount: 5\n")


def _override(env, value):
    return (f"dn: ou=overrides,{env}\nobjectClass: top\nobjectClass: organizationalUnit\nou: overrides\n",
            f"dn: cn=lockout,ou=overrides,{env}\nobjectClass: top\nobjectClass: ciamOverride\ncn: lockout\n"
            f"ciamOverrides: cn=lockout,dc=ciam-ops\nciamOverrideAttribute: ciamLockoutFailureCount\n"
            f"ciamOverrideValue: {value}\n")


def _overrides(src=None, dst=None, changes=()):
    tree = (OVERRIDES, *(_override(ALPHA, src) if src else ()), *(_override(BETA, dst) if dst else ()))
    d, alpha, beta = model(tree=tree, changes=changes)
    return check_overrides(context(d, alpha, beta))


@pytest.mark.parametrize("src, dst, option, kinds", [
    (None, "3", "source", ["delete"]),                        # the target's override deleted: both run the shared 5
    ("10", "3", "source", ["modify"]),                        # the target's set to the source's 10
    ("10", None, "source", ["add", "add"]),                   # the target gets its own (and its ou=overrides)
])
def test_overrides_align_on_the_option_chosen(src, dst, option, kinds):
    (fix,) = _overrides(src, dst).fixes
    assert fix.key == "override:lockout:ciamLockoutFailureCount" and fix.records == ()
    records = chosen(fix, option).records
    assert [r.changetype for r in records] == kinds
    assert _overrides(src, dst, records).actions == ()


def test_running_the_shared_value_is_an_option_only_when_both_override():
    (fix,) = _overrides("10", "3").fixes
    assert [o.key for o in fix.options] == ["source", "shared"]
    assert [o.key for o in _overrides(None, "3").fixes[0].options] == ["source"]


def test_plain_fixes_close_stray_ports_require_acceptance_and_drop_unbound_reach():
    listeners = (Listener("ds", 1636, "tcp", "LDAPS", ("clients",)),)
    adapters = (SimpleNamespace(listeners=lambda m: listeners),)
    beta = (rule(BETA, "fw-ds", "10.0.0.0/8", ("1636", "23"), "ds"), rule(BETA, "fw-telnet", "10.0.0.0/8", "23", "ds"),
            entry(BETA, "es", "ciamEndpointService", ciamBindingRole="es", ciamServiceRole="sso-service"),
            entry(BETA, "pe", "ciamPrivateEndpoint", ciamBindingRole="pe", ciamPrivateService="secrets",
                  ciamReachesRole="nowhere"))
    d, alpha, beta_m = model(beta=beta)
    ctx = context(d, alpha, beta_m)
    stray = network_check(adapters, adapters)(ctx).fixes
    assert [(f.key, f.title, [r.changetype for r in f.records]) for f in stray] == [
        ("stray-rule:fw-ds", "Close ports 23 of rule `fw-ds` in beta/prod", ["modify"]),
        ("stray-rule:fw-telnet", "Close rule `fw-telnet` in beta/prod", ["delete"])]
    (accept,) = check_endpoint_services(ctx).fixes
    (reach,) = check_private_endpoints(ctx).fixes
    assert (accept.key, reach.key) == ("acceptance:es", "reaches:beta/prod:pe:nowhere")
    d, alpha, beta_m = model(beta=beta, changes=tuple(r for f in (*stray, accept, reach) for r in f.records))
    ctx = context(d, alpha, beta_m)
    assert network_check(adapters, adapters)(ctx).fixes == ()
    assert check_endpoint_services(ctx).fixes == check_private_endpoints(ctx).fixes == ()
