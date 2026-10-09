"""Suppressions on Azure: a subscription policy exemption per framework of the subscription's initiative assignment
(Waiver, Mitigated for a compensating control, expiring with the exception); Defender alert suppression rules through
the azapi add-on when the cloud allows it (pinned in the root, Azure Government's environment), a comment otherwise;
read back from state, merged per exception."""
from opsdir.core.directory import make_entry
from opsdir_adapter_azure.suppressions import azapi_provider, render_suppressions, suppression_resources, uses_azapi
from network_fixtures import ALPHA, entry, model

EXC = "cn=EXC-7,ou=exceptions,dc=ciam-ops"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"


def _tree(kind):
    return ("dn: ou=exceptions,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: exceptions\n",
            f"dn: {EXC}\nobjectClass: top\nobjectClass: ciamRiskException\ncn: EXC-7\nciamExceptionKind: {kind}\n"
            "ciamExceptionStatus: approved\nciamAffectedEnvironment: env=prod,cloud=alpha,ou=environments,dc=ciam-ops\n"
            "ciamExpiresAt: 20270331000000Z\n")


def _model(*refs, kind="risk-acceptance", add_on=False, gov=False):
    s = entry(ALPHA, "exc-EXC-7", "ciamSuppression", ciamBindingRole="suppression-EXC-7", ciamFindingRef=tuple(refs),
              ciamExceptionRef=EXC)
    _, alpha, _ = model(alpha=(s,), tree=_tree(kind))
    extra = {**({"ciamProviderAddOn": ("azapi",)} if add_on else {}),
             **({"ciamCloudEnvironment": ("usgovernment",)} if gov else {})}
    return alpha._replace(cloud=make_entry(alpha.cloud.dn, (*alpha.cloud.classes, "ciamCloudAccount"),
                                           {**alpha.cloud.attrs, **extra})) if extra else alpha


def test_policy_refs_render_an_exemption_per_framework():
    out = "\n\n".join(render_suppressions(_model("azure:policy:nist-800-171-r2/ref-a",
                                                 "azure:policy:nist-800-171-r2/ref-b",
                                                 "azure:policy:cis", kind="compensating-control")))
    assert 'resource "azurerm_subscription_policy_exemption" "exc_exc_7_nist_800_171_r2"' in out
    assert ('policy_assignment_id            = "${data.azurerm_subscription.current.id}/providers/'
            'Microsoft.Authorization/policyAssignments/ciam-nist-800-171-r2"') in out
    assert 'policy_definition_reference_ids = ["ref-a", "ref-b"]' in out and out.count('"Mitigated"') == 2
    assert 'expires_on                      = "2027-03-31T00:00:00Z"' in out and '"exception" : "EXC-7"' in out
    assert 'name                 = "exc-EXC-7-cis"' in out and 'data "azurerm_subscription" "current"' in out


def test_alert_suppression_rules_need_the_azapi_add_on():
    m = _model("azure:alerts:VM_SuspiciousActivity", kind="false-positive")
    assert render_suppressions(m)[-1].startswith("# exc-EXC-7: Defender for Cloud alert suppression rules for "
                                                 "VM_SuspiciousActivity until 2027-03-31T00:00:00Z: azurerm has no "
                                                 "resource for them")
    assert not uses_azapi(m)
    m = _model("azure:alerts:VM_SuspiciousActivity", kind="false-positive", add_on=True, gov=True)
    out = "\n\n".join(render_suppressions(m))
    assert 'type      = "Microsoft.Security/alertsSuppressionRules@2019-01-01-preview"' in out
    assert 'alertType         = "VM_SuspiciousActivity"' in out and 'reason            = "FalsePositive"' in out
    assert uses_azapi(m) and 'environment     = "usgovernment"' in azapi_provider(m)


def test_suppressions_are_read_back_merged_per_exception():
    pairs = [("azurerm_subscription_policy_exemption", {
                 "id": f"{SUB}/providers/Microsoft.Authorization/policyExemptions/exc-EXC-7-cis",
                 "name": "exc-EXC-7-cis",
                 "policy_assignment_id": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/ciam-cis",
                 "policy_definition_reference_ids": ["ref-a"], "metadata": '{"exception":"EXC-7"}'}),
             ("azapi_resource", {"id": f"{SUB}/providers/Microsoft.Security/alertsSuppressionRules/exc-EXC-7",
                                 "name": "exc-EXC-7",
                                 "type": "Microsoft.Security/alertsSuppressionRules@2019-01-01-preview",
                                 "body": {"properties": {"alertType": "IpAnomaly", "comment": "exception EXC-7"}}}),
             ("azapi_resource", {"id": "x", "name": "y", "type": "Microsoft.Storage/storageAccounts@2023-01-01"})]
    (found,) = suppression_resources(pairs)
    assert (found.name, dict(found.attrs)) == ("exc-EXC-7", {
        "ciamFindingRef": ("azure:policy:cis/ref-a", "azure:alerts:IpAnomaly"), "ciamExceptionRef": ("EXC-7",)})
