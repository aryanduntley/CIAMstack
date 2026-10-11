"""Risk-based sign-in policies on a threat-detection service watching identity: parsed as the record states them,
whom they cover and leave out resolved against the environment's user and group identities, report-only unless the
record says enforced, and what keeps them from being rendered named, never guessed."""
import re

import pytest

from opsdir.core.directory import get
from opsdir.domains.estate.risk_policies import (RiskPolicy, policy_advice, policy_mode, policy_problems, policy_scope,
                                                 renders, risk_policies)
from opsdir.domains.estate.naming import RISK_POLICY
from network_fixtures import ALPHA, entry, model

PEOPLE = (entry(ALPHA, "identity-admins", "ciamIdentityBinding", ciamBindingRole="identity-admins",
                ciamIdentityKind="group", ciamProviderRef="5b2c0000-0000-4000-8000-0000000000a1"),
          entry(ALPHA, "identity-break-glass", "ciamIdentityBinding", ciamBindingRole="identity-break-glass",
                ciamIdentityKind="user", ciamProviderRef="7e1d0000-0000-4000-8000-0000000000b9"),
          entry(ALPHA, "identity-pf", "ciamIdentityBinding", ciamBindingRole="identity-pf",
                ciamIdentityKind="managed-identity", ciamProviderRef="/subscriptions/s/x/id-pf"))
SERVICE = f"cn=defender,ou=bindings,{ALPHA}"


def _service(**attrs):
    base = {"ciamBindingRole": "threat-detection", "ciamSecurityKind": "threat-detection",
            "ciamSecurityCoverage": ("control-plane", "identity")}
    d, alpha, _ = model(alpha=(*PEOPLE, entry(ALPHA, "defender", "ciamSecurityService", **{**base, **attrs})))
    return alpha, get(d, SERVICE)


def test_policies_whom_they_cover_and_report_only_by_default():
    m, s = _service(ciamRiskPolicy=("sign-in medium+: mfa", "user high+: password-change"),
                    ciamPolicyCovers="identity-admins", ciamPolicyExcludes="identity-break-glass")
    assert risk_policies(s) == (RiskPolicy("sign-in", "medium", "mfa"), RiskPolicy("user", "high", "password-change"))
    scope = policy_scope(m, s)
    assert (scope.all_users, [e.dn.split(",")[0] for e in scope.covered], [e.dn.split(",")[0] for e in scope.excluded],
            scope.unknown) == (False, ["cn=identity-admins"], ["cn=identity-break-glass"], ())
    assert (policy_mode(s), policy_problems(m, s), policy_advice(m, s), renders(m, s)) == ("report-only", (), (), True)
    assert policy_mode(_service(ciamRiskPolicy="sign-in high+: block", ciamPolicyCovers="all-users",
                                ciamPolicyMode="enforced")[1]) == "enforced"


def test_what_keeps_policies_from_being_rendered_is_named():
    m, s = _service(ciamRiskPolicy="sign-in medium+: mfa")
    assert policy_problems(m, s) == ("defender: risk policies cover no one: set ciamPolicyCovers (identity roles, or "
                                     "all-users)",) and not renders(m, s)
    m, s = _service(ciamRiskPolicy="sign-in medium+: mfa", ciamPolicyCovers=("identity-pf", "nobody"))
    assert policy_problems(m, s) == ("defender: ciamPolicyCovers/ciamPolicyExcludes name no user or group identity "
                                     "of the environment: identity-pf, nobody",)
    m, s = _service(ciamPolicyCovers="all-users")
    assert policy_problems(m, s) == ("defender: whom risk policies cover is recorded but no policy (ciamRiskPolicy)",)
    m, s = _service(ciamRiskPolicy=("sign-in high+: password-change", "sign-in high+: risk-remediation"),
                    ciamPolicyCovers="all-users")
    assert policy_problems(m, s) == (
        "defender: 'sign-in high+: password-change': password-change answers a user's risk only (user high+)",
        "defender: 'sign-in high+: risk-remediation': risk-remediation answers a user's risk only (user high+)")
    m, s = _service(ciamRiskPolicy="sign-in medium+: mfa", ciamPolicyCovers="all-users",
                    ciamSecurityCoverage="network")
    assert policy_problems(m, s) == ("defender: risk policies on a service that doesn't watch identity "
                                     "(threat-detection covering identity)",)


def test_covering_everyone_without_an_exclusion_is_advice_not_a_problem():
    m, s = _service(ciamRiskPolicy="user high+: block", ciamPolicyCovers="all-users")
    assert renders(m, s) and policy_advice(m, s) == (
        "defender: risk policies cover all-users and leave no one out: exclude the break-glass accounts "
        "(ciamPolicyExcludes) so a policy can't lock everyone out",)


@pytest.mark.parametrize("bad", ["sign-in medium: mfa", "device high+: block", "user high+: allow"])
def test_a_policy_outside_the_grammar_is_refused_by_the_pattern_and_never_read(bad):
    """The store refuses it (the attribute's X-PATTERN); a snapshot holding one anyway reads no policy from it."""
    assert not re.match(RISK_POLICY, bad) and re.match(RISK_POLICY, "sign-in medium+: mfa")
    assert risk_policies(_service(ciamRiskPolicy=bad)[1]) == ()
