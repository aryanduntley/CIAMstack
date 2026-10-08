"""Quotas and budgets on AWS. Quotas: the record-derived fetch (caller identity, then per region and service AWS's
defaults and the applied values), read into quota catalogs with applied values over the defaults and kinds by their
quota codes; an approved increase rendered as aws_servicequotas_service_quota. Budgets: aws_budgets_budget filtered by
the tag policy's environment tag (else the account), a notification per threshold to the channel's topic when it is
in the budget's account, GovCloud budgets through the provider aliased to the standard account; read back from
Terraform state with the topic as its channel."""
import json
import re

from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.budgets import budget_resources, needs_billing_provider, render_budgets
from opsdir_adapter_aws.inventory import pairs_resources
from opsdir_adapter_aws.quotas import quota_commands, read_quotas, render_quota_requests
from network_fixtures import ALPHA, entry, model

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
TOPIC_ARN = "arn:aws:sns:us-east-1:111122223333:cost-alerts"
TOPIC = entry(ALPHA, "cost-alerts", "ciamAlertChannel", ciamBindingRole="cost-alerts", ciamChannelKind="topic",
              ciamProviderRef=TOPIC_ARN)
TAG_POLICY = ("dn: ou=tag-policy,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: tag-policy\n",
              "dn: cn=environment,ou=tag-policy,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamTagRule\n"
              "cn: environment\nciamTagKey: Environment\nciamTagSource: environment\n")


def cloud(region="us-east-1", **attrs):
    """The change record placing the alpha cloud in region with an account (ciamCloudAccount attributes)."""
    return LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                            ("replace", "ciamRegion", (region,)), ("replace", "ciamCloudProvider", ("aws",)),
                                            *(("replace", k, (v,)) for k, v in attrs.items())))


def flat(blocks):
    """Rendered HCL with its alignment collapsed (one space around =)."""
    return re.sub(r" +", " ", "\n\n".join(blocks))


def need(cn, kind, n, **more):
    return entry(ALPHA, cn, "ciamQuotaNeed", ciamBindingRole=cn, ciamQuotaKind=kind, ciamQuotaNeeded=str(n), **more)


def budget(**more):
    return entry(ALPHA, "monthly", "ciamBudget", ciamBindingRole="budget", ciamBudgetAmount="5000",
                 ciamActualThreshold=("80", "100"), ciamForecastThreshold="100", ciamAlertRole="cost-alerts", **more)


def _alpha(*bindings, tree=(), **cloud_attrs):
    d, alpha, _ = model(alpha=bindings, tree=tree, changes=(cloud(**cloud_attrs),))
    return d, alpha


def test_quota_commands_fetch_the_services_and_regions_the_needs_name():
    d, _ = _alpha(need("cpus", "vcpus", 16), entry(ALPHA, "nlbs", "ciamQuotaNeed", ciamBindingRole="nlbs",
                                                   ciamQuotaNeeded="4", ciamProviderRef="elasticloadbalancing.L-69A177A2"),
                  ciamAccountRef="111122223333")
    assert quota_commands(d) == (
        ("quotas/caller.json", ("aws", "sts", "get-caller-identity", "--output", "json")),
        *((f"quotas/us-east-1/{s}{x}.json", ("aws", "service-quotas", c, "--service-code", s, "--region", "us-east-1",
                                              "--output", "json"))
          for s in ("ec2", "elasticloadbalancing")
          for x, c in (("-defaults", "list-aws-default-service-quotas"), ("", "list-service-quotas"))))
    assert quota_commands(model()[0]) == ()
    assert next(i for i in ADAPTER.importers if i.name == "quotas").commands is quota_commands


def _quota(code, value, account="111122223333", service="ec2", name="a quota"):
    return {"ServiceCode": service, "QuotaCode": code, "QuotaName": name, "Value": value,
            "QuotaArn": f"arn:aws:servicequotas:us-east-1:{account}:{service}/{code}"}


def test_quotas_are_read_applied_over_defaults_into_the_account_s_catalog():
    d, _ = _alpha(need("cpus", "vcpus", 16), ciamAccountRef="111122223333")
    files = {"quotas/caller.json": json.dumps({"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:user/x"}),
             "quotas/us-east-1/ec2-defaults.json": json.dumps({"Quotas": [
                 _quota("L-1216C47A", 5.0, account="", name="Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) "
                                                           "instances"), _quota("L-0263D0A3", 5.0, account="")]}),
             "quotas/us-east-1/ec2.json": json.dumps({"Quotas": [_quota("L-1216C47A", 32.0)]}),
             "notes.txt": "hello"}
    imported = read_quotas(files, d, ())
    (dn, entries), = imported.groups
    assert dn == "cn=aws:111122223333:us-east-1,ou=quotas,dc=ciam-ops"
    limit = entries[1]
    assert limit.dn.startswith("cn=ec2.L-1216C47A,") and dict(limit.attrs)["ciamQuotaValue"] == ("32",) and \
        dict(limit.attrs)["ciamQuotaKind"] == ("vcpus",)
    assert len(entries) == 2 and imported.notices[-1] == "notes.txt: not Service Quotas output; not read"


def test_an_approved_increase_is_rendered_as_a_service_quota():
    _, alpha = _alpha(need("cpus", "vcpus", 16, ciamQuotaDecision="request"),
                      need("ips", "public-ips", 4, ciamQuotaDecision="request", ciamQuotaRequested="10"),
                      need("lbs", "load-balancers", 4, ciamQuotaDecision="deny"))
    out = flat(render_quota_requests(alpha))
    assert 'resource "aws_servicequotas_service_quota" "cpus_vcpus" {' in out
    assert 'quota_code = "L-1216C47A"' in out and "value = 16" in out
    assert 'quota_code = "L-0263D0A3"' in out and "value = 10" in out
    assert "L-53DA6B97" not in out


def test_a_budget_filters_by_the_environment_tag_and_alerts_the_topic():
    _, alpha = _alpha(budget(), TOPIC, tree=TAG_POLICY, ciamAccountRef="111122223333")
    out = flat(render_budgets(alpha))
    assert 'resource "aws_budgets_budget" "monthly" {' in out and 'name = "alpha-prod-monthly"' in out
    assert 'limit_amount = "5000"' in out and 'limit_unit = "USD"' in out and '"MONTHLY"' in out
    assert '"user:Environment$alpha/prod"' in out and "activate it as a cost allocation tag" in out
    assert out.count("notification {") == 3 and out.count('"FORECASTED"') == 1 and f'["{TOPIC_ARN}"]' in out
    assert not needs_billing_provider(alpha)


def test_without_an_environment_tag_the_account_and_a_topic_elsewhere_is_noted():
    _, alpha = _alpha(budget(), TOPIC, ciamAccountRef="999988887777")
    out = flat(render_budgets(alpha))
    assert 'name = "LinkedAccount"' in out and '["999988887777"]' in out
    assert "notification {" not in out and out.startswith(
        "# NOTE: budget monthly's alerts to cost-alerts: not rendered: AWS Budgets publishes only to a topic in the "
        f"budget's account (999988887777) and {TOPIC_ARN} is elsewhere")
    _, alpha = _alpha(budget(ciamManagedBy="cn=landing-zone,ou=owners,dc=ciam-ops"), TOPIC)
    assert render_budgets(alpha) == ("# Budget monthly: kept by cn=landing-zone,ou=owners,dc=ciam-ops, not rendered "
                                     "here",)


def test_govcloud_budgets_go_through_the_standard_account():
    _, alpha = _alpha(budget(), TOPIC, region="us-gov-west-1", ciamAccountRef="222233334444")
    assert render_budgets(alpha)[0].startswith("# NOTE: budget monthly: not rendered: GovCloud's billing is managed")
    _, alpha = _alpha(budget(), TOPIC, region="us-gov-west-1", ciamAccountRef="222233334444",
                      ciamBillingAccountRef="111122223333")
    out = flat(render_budgets(alpha))
    assert "provider = aws.billing" in out and f'["{TOPIC_ARN}"]' in out and needs_billing_provider(alpha)


def test_budgets_are_read_back_from_state_with_their_topic_as_channel():
    a = {"arn": "arn:aws:budgets::111122223333:budget/alpha-prod-monthly", "name": "alpha-prod-monthly",
         "budget_type": "COST", "limit_amount": "5000.0", "limit_unit": "USD", "time_unit": "MONTHLY",
         "notification": [{"comparison_operator": "GREATER_THAN", "threshold": 80, "threshold_type": "PERCENTAGE",
                           "notification_type": "ACTUAL", "subscriber_sns_topic_arns": [TOPIC_ARN]},
                          {"comparison_operator": "GREATER_THAN", "threshold": 100, "threshold_type": "PERCENTAGE",
                           "notification_type": "FORECASTED", "subscriber_sns_topic_arns": [TOPIC_ARN]},
                          {"comparison_operator": "GREATER_THAN", "threshold": 900, "threshold_type": "ABSOLUTE_VALUE",
                           "notification_type": "ACTUAL", "subscriber_email_addresses": ["x@example.test"]}]}
    daily = {**a, "arn": "arn:aws:budgets::111122223333:budget/daily", "time_unit": "DAILY"}
    b, = budget_resources([("aws_budgets_budget", a), ("aws_budgets_budget", daily)])
    assert (b.kind, b.attrs["ciamBudgetAmount"], b.attrs["ciamBudgetPeriod"], b.attrs["ciamActualThreshold"],
            b.attrs["ciamForecastThreshold"], b.links["ciamAlertRole"]) == (
        "budget", ("5000",), ("monthly",), ("80",), ("100",), TOPIC_ARN)
    resources, _ = pairs_resources([("aws_budgets_budget", a),
                                    ("aws_sns_topic", {"arn": TOPIC_ARN, "name": "cost-alerts"})])
    assert [r.kind for r in resources] == ["channel", "budget"]
