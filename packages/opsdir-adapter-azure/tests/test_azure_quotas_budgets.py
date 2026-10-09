"""Quotas and budgets on Azure. Quotas: the record-derived fetch (az account show, then per region the compute and
network usages), read into the subscription's quota catalogs with Total Regional vCPUs and the network usages as their
kinds and the region told by the path; approved increases named in comments (azurerm can't request one). Budgets:
azurerm_consumption_budget_resource_group on the environment's resource group from the budget_start_date input, a
notification per threshold to the channel's action group (100% spent and the subscription's Owners when the record
gives neither), at most five, the Azure Government note; read back from Terraform state."""
import json
import re

from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.budgets import budget_inputs, budget_resources, render_budgets
from opsdir_adapter_azure.quotas import quota_commands, quota_request_notes, read_quotas
from network_fixtures import ALPHA, entry, model

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
SUB = "00000000-0000-0000-0000-000000000001"
GROUP = f"/subscriptions/{SUB}/resourceGroups/rg-ops/providers/Microsoft.Insights/actionGroups/cost-alerts"
CHANNEL = entry(ALPHA, "cost-alerts", "ciamAlertChannel", ciamBindingRole="cost-alerts",
                ciamChannelKind="action-group", ciamProviderRef=GROUP)


def cloud(region="eastus2", gov=False):
    return LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                            ("replace", "ciamRegion", (region,)),
                                            ("replace", "ciamCloudProvider", ("azure",)),
                                            ("replace", "ciamAccountRef", (SUB,)),
                                            *((("replace", "ciamCloudEnvironment", ("usgovernment",)),) if gov
                                              else ())))


def need(cn, kind, n, **more):
    return entry(ALPHA, cn, "ciamQuotaNeed", ciamBindingRole=cn, ciamQuotaKind=kind, ciamQuotaNeeded=str(n), **more)


def budget(**more):
    return entry(ALPHA, "monthly", "ciamBudget", ciamBindingRole="budget", ciamBudgetAmount="5000",
                 **{"ciamAlertRole": "cost-alerts", **more})


def _alpha(*bindings, **cloud_args):
    d, alpha, _ = model(alpha=bindings, changes=(cloud(**cloud_args),))
    return d, alpha


def flat(blocks):
    return re.sub(r" +", " ", "\n\n".join(blocks))


def test_quota_commands_fetch_each_region_s_usages():
    d, _ = _alpha(need("cpus", "vcpus", 16))
    assert quota_commands(d) == (
        ("quotas/account.json", ("az", "account", "show", "-o", "json")),
        ("quotas/eastus2/compute.json", ("az", "vm", "list-usage", "--location", "eastus2", "-o", "json")),
        ("quotas/eastus2/network.json", ("az", "network", "list-usages", "--location", "eastus2", "-o", "json")))
    assert quota_commands(model()[0]) == ()
    assert next(i for i in ADAPTER.importers if i.name == "quotas").commands is quota_commands


def _usage(value, localized, limit, current=0, id_=None):
    return {"name": {"value": value, "localizedValue": localized}, "limit": limit, "currentValue": current,
            "unit": "Count", **({"id": id_} if id_ else {})}


def test_usages_are_read_into_the_subscription_s_catalog():
    d, _ = _alpha(need("cpus", "vcpus", 16), need("ips", "public-ips", 4),
                  entry(ALPHA, "family", "ciamQuotaNeed", ciamBindingRole="family", ciamQuotaNeeded="8",
                        ciamProviderRef="standardDSv5Family"))
    files = {"quotas/account.json": json.dumps({"id": SUB, "tenantId": "t", "name": "ops"}),
             "quotas/eastus2/compute.json": json.dumps([
                 _usage("cores", "Total Regional vCPUs", 100, 12),
                 _usage("standardDSv5Family", "Standard DSv5 Family vCPUs", 10),
                 _usage("virtualMachines", "Virtual Machines", 25000)]),
             "network.json": json.dumps([_usage("PublicIPAddresses", "Public IP Addresses", 1000, 3,
                                                      f"/subscriptions/{SUB}/providers/Microsoft.Network/locations/"
                                                      "eastus2/usages/PublicIPAddresses")]),
             "odd.json": json.dumps([_usage("x", "x", 1)])}
    imported = read_quotas(files, d, ())
    (dn, entries), = imported.groups
    assert dn == f"cn=azure:{SUB}:eastus2,ou=quotas,dc=ciam-ops"
    assert sorted((e.dn.split(",")[0], dict(e.attrs).get("ciamQuotaKind")) for e in entries[1:]) == [
        ("cn=PublicIPAddresses", ("public-ips",)), ("cn=cores", ("vcpus",)), ("cn=standardDSv5Family", None)]
    assert next(dict(e.attrs) for e in entries if e.dn.startswith("cn=cores,"))["ciamQuotaUsage"] == ("12",)
    assert "odd.json: its region can't be told (save it as <region>/compute.json); not read" in \
        imported.notices


def test_approved_increases_are_named_in_comments():
    _, alpha = _alpha(need("cpus", "vcpus", 16, ciamQuotaDecision="request"),
                      need("ips", "public-ips", 4, ciamQuotaDecision="deny"))
    note, = quota_request_notes(alpha)
    assert note.startswith(f"# Quota request (vcpus): raise it to 16 for subscription {SUB} in eastus2 through the "
                           "Quota API (`az quota update`, Microsoft.Quota)")


def test_a_budget_on_the_resource_group_alerts_the_action_group():
    _, alpha = _alpha(budget(ciamActualThreshold=("80", "100"), ciamForecastThreshold="100",
                             ciamBudgetPeriod="quarterly"), CHANNEL)
    out = flat(render_budgets(alpha))
    assert 'resource "azurerm_consumption_budget_resource_group" "monthly" {' in out
    assert "resource_group_id = data.azurerm_resource_group.main.id" in out and "amount = 5000" in out
    assert 'time_grain = "Quarterly"' in out and "start_date = var.budget_start_date" in out
    assert out.count("notification {") == 3 and out.count('"Forecasted"') == 1 and f'["{GROUP}"]' in out
    assert "Azure Government" not in out and 'variable "budget_start_date"' in budget_inputs(alpha)[0]


def test_defaults_azure_needs_and_the_government_note():
    _, alpha = _alpha(budget(ciamAlertRole="nowhere", ciamCurrency="EUR"), gov=True)
    out = flat(render_budgets(alpha))
    assert "# budget monthly: no thresholds recorded: Azure needs a notification, so it alerts at 100% spent" in out
    assert "# budget monthly: nowhere names no action group: its alerts go to the subscription's Owners" in out
    assert "# budget monthly: Azure counts it in the billing account's currency, not EUR" in out
    assert "# Azure Government: Cost Management budgets serve Enterprise Agreement and pay-as-you-go" in out
    assert 'threshold = 100' in out and 'contact_roles = ["Owner"]' in out
    _, alpha = _alpha(budget(ciamActualThreshold=("50", "60", "70", "80", "90", "100")), CHANNEL)
    out = flat(render_budgets(alpha))
    assert out.count("notification {") == 5 and "Azure takes five notifications: 100% Actual left out" in out
    _, alpha = _alpha(budget(ciamManagedBy="cn=finance,ou=owners,dc=ciam-ops"))
    assert render_budgets(alpha) == ("# Budget monthly: kept by cn=finance,ou=owners,dc=ciam-ops, not rendered here",)
    assert budget_inputs(alpha) == ()


def test_budgets_are_read_back_from_state():
    a = {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Consumption/budgets/alpha-prod-monthly",
         "name": "alpha-prod-monthly", "amount": 5000.0, "time_grain": "BillingQuarter",
         "notification": [{"operator": "GreaterThan", "threshold": 80, "threshold_type": "Actual",
                           "contact_groups": [GROUP], "enabled": True},
                          {"operator": "GreaterThan", "threshold": 100, "threshold_type": "Forecasted",
                           "contact_groups": [GROUP], "enabled": True},
                          {"operator": "EqualTo", "threshold": 50, "threshold_type": "Actual",
                           "contact_emails": ["x@example.test"]}]}
    b, = budget_resources([("azurerm_consumption_budget_resource_group", a)])
    assert (b.attrs["ciamBudgetAmount"], b.attrs["ciamBudgetPeriod"], b.attrs["ciamActualThreshold"],
            b.attrs["ciamForecastThreshold"], b.links["ciamAlertRole"], b.tags) == (
        ("5000",), ("quarterly",), ("80",), ("100",), GROUP, None)
