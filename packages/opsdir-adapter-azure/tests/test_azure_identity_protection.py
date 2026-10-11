"""Identity on Azure as Microsoft Entra ID Protection: the risk logs exported where the service's findings go, and the
risk-based Conditional Access policies the record states completely (users and groups by their object ids, the
break-glass account left out, report-only unless enforced); what keeps them from being rendered named; the azuread
provider only when a policy is rendered, in Azure Government's environment there."""
import re

from opsdir.core.directory import get, make_entry
from opsdir_adapter_azure.account import azuread_provider, required_providers
from opsdir_adapter_azure.cli import kind_of
from opsdir_adapter_azure.cli_identity import identity_items
from opsdir_adapter_azure.iam import iam_resources
from opsdir_adapter_azure.identity_protection import identity_read, render_identity_protection, uses_azuread
from opsdir_adapter_azure.security import security_notices, security_resources
from network_fixtures import ALPHA, entry, model

WORKSPACE = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/sec-logs"
ADMINS, GLASS = "5b2c0000-0000-4000-8000-0000000000a1", "7e1d0000-0000-4000-8000-0000000000b9"
RECORD = (entry(ALPHA, "security-logs", "ciamLogDestination", ciamBindingRole="security-logs",
                ciamDestinationKind="workspace", ciamProviderRef=WORKSPACE),
          entry(ALPHA, "identity-admins", "ciamIdentityBinding", ciamBindingRole="identity-admins",
                ciamIdentityKind="group", ciamProviderRef=ADMINS),
          entry(ALPHA, "identity-break-glass", "ciamIdentityBinding", ciamBindingRole="identity-break-glass",
                ciamIdentityKind="user", ciamProviderRef=GLASS))
SERVICE = f"cn=defender,ou=bindings,{ALPHA}"


def _render(**attrs):
    base = {"ciamBindingRole": "threat-detection", "ciamSecurityKind": "threat-detection",
            "ciamSecurityCoverage": ("control-plane", "identity"), "ciamFindingsRole": "security-logs"}
    d, alpha, _ = model(alpha=(*RECORD, entry(ALPHA, "defender", "ciamSecurityService", **{**base, **attrs})))
    return alpha, "\n\n".join(render_identity_protection(alpha, get(d, SERVICE)))


def test_the_risk_logs_go_where_the_findings_go():
    _, out = _render()
    assert 'resource "azurerm_monitor_aad_diagnostic_setting" "defender_identity_risk"' in out
    assert re.findall(r'category = "(\w+)"', out) == ["RiskyUsers", "UserRiskEvents", "RiskyServicePrincipals",
                                                       "ServicePrincipalRiskEvents"]
    assert "log_analytics_workspace_id = azurerm_log_analytics_workspace.security_logs.id" in out    # rendered here
    assert "azuread_conditional_access_policy" not in out
    _, nowhere = _render(ciamFindingsRole="nowhere")
    assert "# NOTE: defender: Entra ID Protection's risk logs not exported: nowhere is no Log Analytics workspace" \
        in nowhere


def test_complete_policies_render_as_report_only_conditional_access():
    m, out = _render(ciamRiskPolicy=("sign-in medium+: mfa", "user high+: password-change"),
                     ciamPolicyCovers="identity-admins", ciamPolicyExcludes="identity-break-glass")
    assert out.count('resource "azuread_conditional_access_policy"') == 2
    assert 'resource "azuread_conditional_access_policy" "defender_sign_in_medium_mfa"' in out
    assert 'display_name = "defender (alpha/prod): sign-in risk medium+: mfa"' in out
    assert out.count('state        = "enabledForReportingButNotEnforced"') == 2
    assert 'sign_in_risk_levels = ["medium", "high"]' in out and 'user_risk_levels = ["high"]' in out
    assert f'included_groups = ["{ADMINS}"]' in out and f'excluded_users  = ["{GLASS}"]' in out
    assert 'built_in_controls = ["mfa", "passwordChange"]' in out and 'operator          = "AND"' in out
    assert 'authentication_strength_policy_id = "/policies/authenticationStrengthPolicies/' \
        '00000000-0000-0000-0000-000000000002"' in out                    # mfa: the built-in MFA strength
    assert "session_controls" not in out and '"mfa"]' not in out.split("passwordChange")[0]
    assert uses_azuread(m)
    _, enforced = _render(ciamRiskPolicy="sign-in high+: block", ciamPolicyCovers="all-users",
                          ciamPolicyExcludes="identity-break-glass", ciamPolicyMode="enforced")
    assert 'state        = "enabled"' in enforced and 'included_users = ["All"]' in enforced


def test_risk_remediation_is_a_note_until_azuread_can_express_it():
    m, out = _render(ciamRiskPolicy=("user high+: risk-remediation", "sign-in medium+: mfa"),
                     ciamPolicyCovers="identity-admins", ciamPolicyExcludes="identity-break-glass")
    assert "# NOTE: defender: 'user high+: risk-remediation': not rendered: azuread can't express Microsoft's risk " \
           "remediation yet" in out
    assert out.count('resource "azuread_conditional_access_policy"') == 1 and uses_azuread(m)
    only, _ = _render(ciamRiskPolicy="user high+: risk-remediation", ciamPolicyCovers="identity-admins")
    assert not uses_azuread(only)


def test_what_keeps_policies_from_being_rendered_is_a_comment():
    m, out = _render(ciamRiskPolicy="sign-in medium+: mfa")
    assert "azuread_conditional_access_policy" not in out and not uses_azuread(m)
    assert "# defender: risk policies not rendered: defender: risk policies cover no one" in out
    _, everyone = _render(ciamRiskPolicy="user high+: block", ciamPolicyCovers="all-users")
    assert "exclude the break-glass accounts" in everyone and "azuread_conditional_access_policy" in everyone


def test_the_azuread_provider_and_its_government_environments():
    m, _ = _render()
    assert '"hashicorp/azuread"' in required_providers(azuread=True) and "azuread" not in required_providers()
    assert azuread_provider(m) == 'provider "azuread" {\n}'
    in_gov = {**m.cloud.attrs, "ciamCloudEnvironment": ("usgovernment",), "ciamRegion": ("usgovvirginia",)}
    gov = m._replace(cloud=make_entry(m.cloud.dn, m.cloud.classes, in_gov))
    dod = gov._replace(cloud=make_entry(gov.cloud.dn, gov.cloud.classes, {**gov.cloud.attrs,
                                                                          "ciamRegion": ("usdodeast",)}))
    assert 'environment = "usgovernment"' in azuread_provider(gov)
    assert 'environment = "usgovernmentl5"' in azuread_provider(dod)


# ------------------------------------------------------------------ read back
def _state_policy(name, subject_key, levels, grant, state="enabledForReportingButNotEnforced", users=None):
    return ("azuread_conditional_access_policy", {
        "id": name, "display_name": name, "state": state,
        "conditions": [{subject_key: levels, "client_app_types": ["all"],
                        "applications": [{"included_applications": ["All"]}],
                        "users": [users or {"included_groups": [ADMINS], "excluded_users": [GLASS]}]}],
        "grant_controls": [grant]})


STRENGTH = {"operator": "OR", "built_in_controls": [],
            "authentication_strength_policy_id": "/policies/authenticationStrengthPolicies/"
                                                 "00000000-0000-0000-0000-000000000002"}
EXPORT = ("azurerm_monitor_aad_diagnostic_setting", {"name": "defender-identity-risk", "enabled_log": [
    {"category": c} for c in ("RiskyUsers", "UserRiskEvents", "RiskyServicePrincipals", "ServicePrincipalRiskEvents")]})
PRICING = ("azurerm_security_center_subscription_pricing", {
    "id": "/subscriptions/s/providers/Microsoft.Security/pricings/Arm", "tier": "Standard", "resource_type": "Arm"})
STATE = (EXPORT, PRICING,
         _state_policy("p1", "sign_in_risk_levels", ["medium", "high"], STRENGTH),
         _state_policy("p2", "user_risk_levels", ["high"], {"operator": "AND",
                                                            "built_in_controls": ["mfa", "passwordChange"]}))


def test_identity_protection_reads_back_from_state():
    read = identity_read(STATE)
    assert (read.watched, read.policies, read.mode, read.all_users, read.covers, read.excludes, read.notices) == (
        True, ("sign-in medium+: mfa", "user high+: password-change"), "report-only", False, (ADMINS,), (GLASS,), ())
    (threat,) = [r for r in security_resources(STATE) if r.attrs.get("ciamSecurityKind") == ("threat-detection",)]
    assert threat.attrs["ciamSecurityCoverage"] == ("control-plane", "identity")
    assert (threat.attrs["ciamRiskPolicy"], threat.attrs["ciamPolicyMode"]) == (
        ("sign-in medium+: mfa", "user high+: password-change"), ("report-only",))
    assert (threat.links["ciamPolicyCovers"], threat.links["ciamPolicyExcludes"]) == ((ADMINS,), (GLASS,))
    principals = {r.ref: r.attrs["ciamIdentityKind"] for r in iam_resources(STATE)[0] if r.ref in (ADMINS, GLASS)}
    assert principals == {ADMINS: ("group",), GLASS: ("user",)}


def test_the_cli_reads_the_same_as_state():
    graph = [{"id": "p1", "displayName": "p1", "state": "enabledForReportingButNotEnforced",
              "conditions": {"signInRiskLevels": ["medium", "high"], "clientAppTypes": ["all"],
                             "applications": {"includeApplications": ["All"]},
                             "users": {"includeGroups": [ADMINS], "excludeUsers": [GLASS]}},
              "grantControls": {"operator": "OR", "builtInControls": [],
                                "authenticationStrength": {"id": "00000000-0000-0000-0000-000000000002"}}},
             {"id": "p2", "displayName": "p2", "state": "enabledForReportingButNotEnforced",
              "conditions": {"userRiskLevels": ["high"], "clientAppTypes": ["all"],
                             "applications": {"includeApplications": ["All"]},
                             "users": {"includeGroups": [ADMINS], "excludeUsers": [GLASS]}},
              "grantControls": {"operator": "AND", "builtInControls": ["mfa", "passwordChange"]}}]
    setting = {"id": "/providers/microsoft.aadiam/diagnosticSettings/defender-identity-risk",
               "name": "defender-identity-risk", "type": "Microsoft.Insights/diagnosticSettings",
               "logs": [{"category": c, "enabled": True} for c in ("RiskyUsers", "UserRiskEvents")]}
    items = [(kind_of(i), i) for i in (*graph, setting)]
    assert identity_read(identity_items(items))[:6] == identity_read(STATE)[:6]


def test_what_the_record_cant_express_is_named():
    pairs = (_state_policy("off", "sign_in_risk_levels", ["high"], STRENGTH, state="disabled"),
             _state_policy("odd", "sign_in_risk_levels", ["high"], {"operator": "OR",
                                                                    "built_in_controls": ["compliantDevice"]}),
             _state_policy("gap", "user_risk_levels", ["low", "high"],
                           {"operator": "OR", "built_in_controls": ["block"]}),
             _state_policy("all", "sign_in_risk_levels", ["high"], {"operator": "OR", "built_in_controls": ["block"]},
                           state="enabled", users={"included_users": ["All"]}))
    read = identity_read(pairs)
    assert (read.policies, read.mode, read.all_users, read.covers) == (("sign-in high+: block",), "enforced", True, ())
    assert read.notices == (
        "Conditional Access policy off: disabled; not read",
        "Conditional Access policy odd: its grant isn't one the record expresses (mfa, password-change, "
        "risk-remediation, block); not read",
        "Conditional Access policy gap: its user risk levels don't run from one level up; not read")
    assert security_notices((EXPORT,)) == ("Entra ID Protection (risk logs or risk policies) read, but no Defender "
                                           "for Cloud threat detection plan to record it on; not imported",)
