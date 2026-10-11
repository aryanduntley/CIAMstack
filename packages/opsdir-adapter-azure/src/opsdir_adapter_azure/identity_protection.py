"""A threat-detection service watching identity on Azure (core estate: ciamSecurityService covering identity) as
Microsoft Entra ID Protection: Defender for Cloud has no plan for identity. Pure.

  - its risk logs exported where the service's findings go (azurerm_monitor_aad_diagnostic_setting: RiskyUsers,
    UserRiskEvents, RiskyServicePrincipals, ServicePrincipalRiskEvents), to the Log Analytics workspace its findings
    role names (observability.workspace_id: the one this root renders, else its recorded ID); another destination is a
    NOTE;
  - its risk-based policies (core estate risk_policies) as Conditional Access (azuread_conditional_access_policy), one
    per policy, only when the record states them completely (whom they cover, whom they leave out, what they grant):
    users and groups by their identity bindings' object ids (ciamProviderRef), report-only
    (enabledForReportingButNotEnforced) unless the record says enforced. What keeps them from being rendered, and advice
    (no break-glass exclusion), are comments.
Entra ID P2 is needed for the risk signals and policies (Workload Identities Premium for service principals' risk);
the deploying identity needs Conditional Access rights in Microsoft Graph and the Security Administrator role (or
Contributor on /providers/Microsoft.aadiam) for the export: the planner names both (milestone 5.5e).
"""
from types import MappingProxyType
from typing import NamedTuple, Optional

from opsdir.core.directory import one, rdn_value
from opsdir.core.inventory import of_types
from opsdir.domains.estate.naming import RISK_LEVELS
from opsdir.domains.estate.risk_policies import (policy_advice, policy_mode, policy_problems, policy_scope, renders,
                                                 risk_policies)
from opsdir.domains.estate.security import findings_destination, security_services
from opsdir_format_terraform.hcl import Block, block, tf_name
from opsdir_format_terraform.state import first_block
from .observability import workspace_id

CA_POLICY, RISK_EXPORT = "azuread_conditional_access_policy", "azurerm_monitor_aad_diagnostic_setting"
RISK_CATEGORIES = ("RiskyUsers", "UserRiskEvents", "RiskyServicePrincipals", "ServicePrincipalRiskEvents")
STATES = MappingProxyType({"report-only": "enabledForReportingButNotEnforced", "enforced": "enabled"})
REPORT_ONLY = "report-only"
RISK_LEVELS_OF = MappingProxyType({"sign-in": "sign_in_risk_levels", "user": "user_risk_levels"})
MFA_STRENGTH = "/policies/authenticationStrengthPolicies/00000000-0000-0000-0000-000000000002"   # built-in MFA
# What a policy's grant requires in Conditional Access: (operator, built-in controls, authentication strength, sign-in
# frequency interval). mfa is the built-in Multifactor authentication strength (Microsoft's current how-to; it can't
# sit beside the mfa control); password change needs mfa with it (AND). Microsoft's risk remediation (authentication
# strength + riskRemediation, every time) isn't one azuread accepts yet (3.10.0): a NOTE (research note 2496).
GRANTS = MappingProxyType({"mfa": ("OR", (), MFA_STRENGTH, None), "block": ("OR", ("block",), None, None),
                           "password-change": ("AND", ("mfa", "passwordChange"), None, None)})


def watches_identity(s):
    """Whether a security service is threat detection covering identity (what Entra ID Protection realizes)."""
    return one(s, "ciamSecurityKind") == "threat-detection" and "identity" in s.attrs.get("ciamSecurityCoverage", ())


def risk_export(m, s):
    """The diagnostic setting exporting Entra ID Protection's risk logs to the workspace a service's findings go to,
    or a NOTE when they go elsewhere or nowhere."""
    cn, workspace = rdn_value(s), workspace_id(m, findings_destination(m, s))
    if not workspace:
        where = one(s, "ciamFindingsRole")
        return (f"# NOTE: {cn}: Entra ID Protection's risk logs not exported: "
                + (f"{where} is no Log Analytics workspace (ciamProviderRef)" if where else
                   "the service sends its findings nowhere (ciamFindingsRole)"),)
    return (block("resource", [RISK_EXPORT, tf_name(f"{cn}_identity_risk")], [
        ("name", f"{cn}-identity-risk"), ("log_analytics_workspace_id", workspace),
        *(("enabled_log", Block((("category", c),))) for c in RISK_CATEGORIES)]),)


def _ids(entries, kind):
    return [one(e, "ciamProviderRef") for e in entries if one(e, "ciamIdentityKind") == kind]


def _users(scope):
    included_users = ["All"] if scope.all_users else _ids(scope.covered, "user")
    return Block(tuple((k, v) for k, v in (
        ("included_users", included_users), ("included_groups", _ids(scope.covered, "group")),
        ("excluded_users", _ids(scope.excluded, "user")), ("excluded_groups", _ids(scope.excluded, "group"))) if v))


def conditional_access(m, s, policy):
    """The Conditional Access policy realizing one of a service's risk policies (RiskPolicy) in environment m."""
    cn, (operator, controls, strength, frequency) = rdn_value(s), GRANTS[policy.grant]
    levels = list(RISK_LEVELS[RISK_LEVELS.index(policy.level):])
    session = (("session_controls", Block((("sign_in_frequency_interval", frequency),))),) if frequency else ()
    return block("resource", [CA_POLICY, tf_name(f"{cn}_{policy.subject}_{policy.level}_{policy.grant}")], [
        ("display_name", f"{cn} ({m.label}): {policy.subject} risk {policy.level}+: {policy.grant}"),
        ("state", STATES[policy_mode(s)]),
        ("conditions", Block((
            ("client_app_types", ["all"]), (RISK_LEVELS_OF[policy.subject], levels),
            ("applications", Block((("included_applications", ["All"]),))),
            ("users", _users(policy_scope(m, s)))))),
        ("grant_controls", Block((("operator", operator),
                                  *((("built_in_controls", list(controls)),) if controls else ()),
                                  *((("authentication_strength_policy_id", strength),) if strength else ())))),
        *session])


def render_identity_protection(m, s):
    """HCL (and comments) for a kept security service watching identity: the risk-log export, its risk-based
    Conditional Access policies when the record states them completely, what keeps them from being rendered and advice
    as comments; () for a service that doesn't watch identity."""
    if not watches_identity(s):
        return ()
    cn, complete = rdn_value(s), renders(m, s)
    policies = tuple(conditional_access(m, s, p) for p in risk_policies(s) if p.grant in GRANTS) if complete else ()
    unexpressed = tuple(p for p in risk_policies(s) if p.grant not in GRANTS) if complete else ()
    return (f"# {cn}: identity: Microsoft Entra ID Protection (Defender for Cloud has no plan for identity); its risk "
            "signals and policies need Entra ID P2",
            *risk_export(m, s),
            *(f"# {cn}: risk policies not rendered: {p}" for p in policy_problems(m, s)),
            *(f"# {cn}: {a}" for a in (policy_advice(m, s) if policies else ())),
            *(f"# NOTE: {cn}: '{p.subject} {p.level}+: {p.grant}': not rendered: azuread can't express Microsoft's "
              "risk remediation yet; configure it in Microsoft Entra, or record password-change" for p in unexpressed),
            *policies)


def uses_azuread(m):
    """Whether environment m's root renders azuread resources: complete risk policies azuread can express on a service
    the platform team keeps (no ciamManagedBy)."""
    return any(watches_identity(s) and renders(m, s) and any(p.grant in GRANTS for p in risk_policies(s))
               for s in security_services(m) if not one(s, "ciamManagedBy"))


# ------------------------------------------------------------------ read back
# What reading identity protection gives the threat-detection service: whether it watches identity (the risk logs
# exported, or risk policies), its policies ('<subject> <level>+: <grant>'), their mode, whom they cover (all users,
# or object ids) and leave out (object ids), and what couldn't be read
IdentityRead = NamedTuple("IdentityRead", [("watched", bool), ("policies", tuple), ("mode", Optional[str]),
                                           ("all_users", bool), ("covers", tuple), ("excludes", tuple),
                                           ("notices", tuple)])
MODES = MappingProxyType({v: k for k, v in STATES.items()})
_PEOPLE = (("included_users", "user"), ("included_groups", "group"), ("excluded_users", "user"),
           ("excluded_groups", "group"))
_EVERYONE = {"all", "none", "guestsorexternalusers"}


def _policy_users(a):
    return first_block(first_block(a.get("conditions")).get("users"))


def _risk_policies(pairs):
    return [a for a in of_types(pairs, CA_POLICY)
            if any(first_block(a.get("conditions")).get(k) for k in RISK_LEVELS_OF.values())]


def policy_principals(pairs):
    """{object id: user or group} of the users and groups risk-based Conditional Access policies cover or leave out:
    principals the source reports (the IAM reader places them, so a policy's users resolve to identity roles)."""
    return {oid: kind for a in _risk_policies(pairs) for key, kind in _PEOPLE
            for oid in _policy_users(a).get(key) or () if str(oid).lower() not in _EVERYONE}


def _grant(g):
    controls = set(g.get("built_in_controls") or ())
    strength = (g.get("authentication_strength_policy_id") or "").rsplit("/", 1)[-1]
    by_controls = {frozenset({"block"}): "block", frozenset({"mfa", "passwordChange"}): "password-change",
                   frozenset({"riskRemediation"}): "risk-remediation", frozenset({"mfa"}): "mfa"}
    mfa_strength = not controls and strength == MFA_STRENGTH.rsplit("/", 1)[-1]
    return "mfa" if mfa_strength else by_controls.get(frozenset(controls))


def _texts(a):
    """(the policy's '<subject> <level>+: <grant>' texts, why it can't be read or None)."""
    conditions, name = first_block(a.get("conditions")), a.get("display_name") or a.get("id")
    grant = _grant(first_block(a.get("grant_controls")))
    found = [(subject, [lv for lv in conditions.get(key) or () if lv in RISK_LEVELS])
             for subject, key in RISK_LEVELS_OF.items() if conditions.get(key)]
    if grant is None:
        return (), f"Conditional Access policy {name}: its grant isn't one the record expresses (mfa, " \
                   "password-change, risk-remediation, block); not read"
    if len(found) > 1:
        return (), f"Conditional Access policy {name}: it needs both a sign-in's and the user's risk; not read"
    subject, levels = found[0]
    least = min(levels, key=RISK_LEVELS.index) if levels else None
    if least is None or levels and sorted(levels, key=RISK_LEVELS.index) != list(
            RISK_LEVELS[RISK_LEVELS.index(least):]):
        return (), f"Conditional Access policy {name}: its {subject} risk levels don't run from one level up; not read"
    return (f"{subject} {least}+: {grant}",), None


def identity_read(pairs):
    """IdentityRead of (azurerm/azuread type, attributes) pairs: the risk logs exported (the RiskyUsers and
    UserRiskEvents categories), the risk-based Conditional Access policies (disabled ones and those the record can't
    express named), their mode and whom they cover and leave out (the first policy's; a difference named)."""
    exported = any({"RiskyUsers", "UserRiskEvents"} <= {x.get("category") for x in a.get("enabled_log") or ()}
                   for a in of_types(pairs, RISK_EXPORT))
    policies = _risk_policies(pairs)
    live = [a for a in policies if a.get("state") in MODES]
    read = [(a, *_texts(a)) for a in live]
    kept = [(a, texts) for a, texts, why in read if texts]
    scopes = {tuple(tuple(_policy_users(a).get(k) or ()) for k, _ in _PEOPLE) for a, _ in kept}
    modes = {MODES[a["state"]] for a, _ in kept}
    first = _policy_users(kept[0][0]) if kept else {}
    everyone = any(str(u).lower() == "all" for u in first.get("included_users") or ())
    return IdentityRead(
        exported or bool(kept), tuple(t for _, texts in kept for t in texts),
        (REPORT_ONLY if len(modes) > 1 else next(iter(modes))) if modes else None, everyone,
        () if everyone else (*(first.get("included_users") or ()), *(first.get("included_groups") or ())),
        (*(first.get("excluded_users") or ()), *(first.get("excluded_groups") or ())),
        (*(f"Conditional Access policy {a.get('display_name') or a.get('id')}: disabled; not read"
           for a in policies if a not in live),
         *(why for _, _, why in read if why),
         *(("risk-based Conditional Access policies cover different users; the first one's are recorded",)
           if len(scopes) > 1 else ()),
         *(("risk-based Conditional Access policies differ in mode (enforced, report-only); recorded as report-only",)
           if len(modes) > 1 else ())))
