"""Quotas and budgets on Google Cloud. Quotas: the record-derived fetch (the project, then each region), read into the
project's per-region catalogs with the project-wide quotas as global.<metric>; approved increases as Cloud Quotas
preferences for the documented quota ids (ABANDON on destroy), others in a comment. Budgets: google_billing_budget in
the landing-zone root on the billing account, filtered to the project (by number) and the environment label, threshold
rules per threshold, updates to a notification channel or Pub/Sub topic, the provider's quota project; read back from
Terraform state."""
import json
import re

from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_gcp.adapter import ADAPTER
from opsdir_adapter_gcp.budgets import budget_notes, budget_provider_settings, budget_resources, render_budgets
from opsdir_adapter_gcp.landing import render_landing
from opsdir_adapter_gcp.quotas import quota_commands, read_quotas, render_quota_requests
from network_fixtures import ALPHA, entry, model

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
CHANNEL_ID = "projects/ciam-prod/notificationChannels/123"
CHANNEL = entry(ALPHA, "cost-alerts", "ciamAlertChannel", ciamBindingRole="cost-alerts", ciamChannelKind="email",
                ciamProviderRef=CHANNEL_ID)
TAG_POLICY = ("dn: ou=tag-policy,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: tag-policy\n",
              "dn: cn=environment,ou=tag-policy,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamTagRule\n"
              "cn: environment\nciamTagKey: Environment\nciamTagSource: environment\n")


def cloud(billing=None):
    return LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                            ("replace", "ciamRegion", ("us-east1",)),
                                            ("replace", "ciamCloudProvider", ("gcp",)),
                                            ("replace", "ciamAccountRef", ("ciam-prod",)),
                                            *((("replace", "ciamBillingAccountRef", (billing,)),) if billing else ())))


def need(cn, kind, n, **more):
    return entry(ALPHA, cn, "ciamQuotaNeed", ciamBindingRole=cn, ciamQuotaNeeded=str(n),
                 **({"ciamQuotaKind": kind} if kind else {}), **more)


def budget(**more):
    return entry(ALPHA, "monthly", "ciamBudget", ciamBindingRole="budget",
                 **{"ciamBudgetAmount": "5000.50", "ciamAlertRole": "cost-alerts", **more})


def _alpha(*bindings, tree=(), billing=None):
    d, alpha, _ = model(alpha=bindings, tree=tree, changes=(cloud(billing),))
    return d, alpha


def flat(blocks):
    return re.sub(r" +", " ", "\n\n".join(blocks))


def test_quota_commands_fetch_the_project_and_each_region():
    d, _ = _alpha(need("cpus", "vcpus", 16))
    assert quota_commands(d) == (
        ("quotas/project.json", ("gcloud", "compute", "project-info", "describe", "--format=json")),
        ("quotas/us-east1.json", ("gcloud", "compute", "regions", "describe", "us-east1", "--format=json")))
    assert quota_commands(model()[0]) == ()
    assert next(i for i in ADAPTER.importers if i.name == "quotas").commands is quota_commands


def test_quotas_are_read_with_the_project_wide_ones_in_each_region():
    d, _ = _alpha(need("cpus", "vcpus", 16), need("nets", "networks", 3), need("n2", None, 8, ciamProviderRef="N2_CPUS"))
    files = {"quotas/project.json": json.dumps({
                 "kind": "compute#project", "name": "ciam-prod",
                 "quotas": [{"metric": "NETWORKS", "limit": 15.0, "usage": 2.0},
                            {"metric": "FIREWALLS", "limit": 200.0, "usage": 9.0}]}),
             "quotas/us-east1.json": json.dumps({
                 "kind": "compute#region", "name": "us-east1",
                 "quotas": [{"metric": "CPUS", "limit": 24.0, "usage": 8.0}, {"metric": "N2_CPUS", "limit": 24.0},
                            {"metric": "DISKS_TOTAL_GB", "limit": 4096.0}]}),
             "other.json": "{}"}
    imported = read_quotas(files, d, ())
    (dn, entries), = imported.groups
    assert dn == "cn=gcp:ciam-prod:us-east1,ou=quotas,dc=ciam-ops"
    assert [(e.dn.split(",")[0], dict(e.attrs).get("ciamQuotaKind")) for e in entries[1:]] == [
        ("cn=CPUS", ("vcpus",)), ("cn=N2_CPUS", None), ("cn=global.NETWORKS", ("networks",))]
    assert imported.notices[-1] == "other.json: not `gcloud compute` project or region output; not read"


def test_approved_increases_are_quota_preferences_where_google_documents_the_id():
    _, alpha = _alpha(need("cpus", "vcpus", 16, ciamQuotaDecision="request", ciamQuotaRequested="32"),
                      need("nets", "networks", 3, ciamQuotaDecision="request"),
                      need("ips", "public-ips", 4, ciamQuotaDecision="request"))
    out = flat(render_quota_requests(alpha))
    assert 'resource "google_cloud_quotas_quota_preference" "cpus_vcpus" {' in out
    assert 'quota_id = "CPUS-per-project-region"' in out and 'region = "us-east1"' in out
    assert "preferred_value = 32" in out and 'deletion_policy = "ABANDON"' in out
    assert 'quota_id = "NETWORKS-per-project"' in out and "preferred_value = 3" in out
    assert "# Quota request (public-ips): raise IN_USE_ADDRESSES to 4 for the project in us-east1" in out


def test_a_budget_on_the_billing_account_in_the_landing_zone():
    _, alpha = _alpha(budget(ciamActualThreshold=("50", "90"), ciamForecastThreshold="100"), CHANNEL,
                      tree=TAG_POLICY, billing="0X0X0X-0X0X0X-0X0X0X")
    out = flat(render_budgets(alpha))
    assert out.startswith('data "google_project" "budgets" {\n project_id = var.project_id\n}')
    assert 'billing_account = "0X0X0X-0X0X0X-0X0X0X"' in out and 'display_name = "alpha-prod-monthly"' in out
    assert '"projects/${data.google_project.budgets.number}"' in out and 'environment = "alpha-prod"' in out
    assert 'calendar_period = "MONTH"' in out and 'units = "5000"' in out and "nanos = 500000000" in out
    assert "threshold_percent = 0.5" in out and out.count("threshold_rules {") == 3 and "FORECASTED_SPEND" in out
    assert f'monitoring_notification_channels = ["{CHANNEL_ID}"]' in out
    assert budget_provider_settings(alpha)[1] == ("user_project_override", True)
    landing = render_landing(alpha)
    assert 'resource "google_billing_budget" "monthly"' in landing["terraform/landing-zone/main.tf"]
    assert "user_project_override = true" in landing["terraform/landing-zone/providers.tf"]


def test_without_a_billing_account_or_a_channel():
    _, alpha = _alpha(budget(), CHANNEL)
    assert budget_notes(alpha) == ("# NOTE: budget monthly: not rendered: a Google Cloud budget lives on the billing "
                                     "account and the cloud names none (ciamBillingAccountRef)",)
    assert budget_provider_settings(alpha) == () and render_landing(alpha) == {}
    _, alpha = _alpha(budget(ciamAlertRole="nowhere"), billing="0X0X0X-0X0X0X-0X0X0X")
    out = flat(render_budgets(alpha))
    assert "# budget monthly: nowhere names no notification channel or Pub/Sub topic" in out
    assert "all_updates_rule" not in out


def test_budgets_are_read_back_from_state():
    a = {"name": "billingAccounts/0X0X0X-0X0X0X-0X0X0X/budgets/abc", "display_name": "alpha-prod-monthly",
         "amount": [{"specified_amount": [{"currency_code": "EUR", "units": "5000", "nanos": 500000000}]}],
         "budget_filter": [{"calendar_period": "QUARTER", "projects": ["projects/123"]}],
         "threshold_rules": [{"threshold_percent": 0.9, "spend_basis": "CURRENT_SPEND"},
                             {"threshold_percent": 1.0, "spend_basis": "FORECASTED_SPEND"}],
         "all_updates_rule": [{"monitoring_notification_channels": [CHANNEL_ID]}]}
    b, = budget_resources([("google_billing_budget", a)])
    assert (b.attrs["ciamBudgetAmount"], b.attrs["ciamCurrency"], b.attrs["ciamBudgetPeriod"],
            b.attrs["ciamActualThreshold"], b.attrs["ciamForecastThreshold"], b.links["ciamAlertRole"]) == (
        ("5000.5",), ("EUR",), ("quarterly",), ("90",), ("100",), CHANNEL_ID)
