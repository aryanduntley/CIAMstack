"""Data discovery on AWS as Amazon Macie: the account enabled, a custom data identifier per own data type, a scheduled
classification job over the S3 buckets of the stores examined (daily, weekly or monthly), findings sent by an
EventBridge rule, results exported to a KMS-encrypted bucket; stores that aren't S3 and discovery kept by someone else
in comments; GovCloud an add-on with a comment and an action; all of it read back from Terraform state."""
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.core.inventory import environment_groups, resource
from opsdir_adapter_aws.discovery import check_discovery_availability, discovery_resources, render_discovery
from opsdir_adapter_aws.inventory import pairs_resources
from network_fixtures import ALPHA, BETA, context, entry, model

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
TOPIC_ARN = "arn:aws:sns:us-east-1:111122223333:security-alerts"
KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/1234"
STORES = (entry(ALPHA, "backups", "ciamObjectStore", ciamBindingRole="ds-backups", ciamStorageRef="s3://ea-backups"),
          entry(ALPHA, "audit", "ciamObjectStore", ciamBindingRole="audit-archive", ciamStorageRef="s3://ea-audit",
                ciamEncryptedByRole="audit-key"),
          entry(ALPHA, "audit-key", "ciamKeyRef", ciamBindingRole="audit-key", ciamRefUri=f"aws-kms://{KEY_ARN}"),
          entry(ALPHA, "grants", "ciamDatabase", ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql"),
          entry(ALPHA, "security-alerts", "ciamAlertChannel", ciamBindingRole="security-alerts",
                ciamChannelKind="topic", ciamProviderRef=TOPIC_ARN))


def macie(cn="macie-weekly", days="7", **more):
    return entry(ALPHA, cn, "ciamDataDiscovery", ciamBindingRole="data-discovery",
                 ciamScansRole=("ds-backups", "pf-grants-db"),
                 ciamCustomIdentifier=("cui-marking: CUI//[A-Z-]+", "employee-id: EA[0-9]{6}"), ciamRescanDays=days,
                 ciamFindingsRole="security-alerts", ciamResultsRole="audit-archive", **more)


def _alpha(*bindings, region="us-east-1", account="111122223333"):
    change = LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                              ("replace", "ciamRegion", (region,)),
                                              *((("replace", "ciamAccountRef", (account,)),) if account else ())))
    return model(alpha=(*STORES, *bindings), changes=(change,))


def test_macie_examines_the_s3_buckets_with_the_own_data_types_and_sends_findings_and_results():
    _, alpha, _ = _alpha(macie())
    out = "\n\n".join(render_discovery(alpha))
    assert 'resource "aws_macie2_account" "macie" {' in out and 'status                       = "ENABLED"' in out
    assert 'resource "aws_macie2_custom_data_identifier" "cdi_cui_marking" {' in out
    assert 'regex      = "CUI//[A-Z-]+"' in out and 'name       = "employee-id"' in out
    assert 'resource "aws_macie2_classification_job" "macie_weekly" {' in out and 'job_type = "SCHEDULED"' in out
    assert 'weekly_schedule = "SUNDAY"' in out
    assert ("custom_data_identifier_ids = [aws_macie2_custom_data_identifier.cdi_cui_marking.id, "
            "aws_macie2_custom_data_identifier.cdi_employee_id.id]") in out
    assert 'account_id = "111122223333"' in out and 'buckets    = ["ea-backups"]' in out
    assert "# macie-weekly: Macie examines S3 only: pf-grants-db not examined here" in out
    assert '"aws.macie"' in out and '"Macie Finding"' in out and f'arn  = "{TOPIC_ARN}"' in out
    assert 'resource "aws_macie2_classification_export_configuration" "macie" {' in out
    assert 'bucket_name = "ea-audit"' in out and f'kms_key_arn = "{KEY_ARN}"' in out
    assert "GovCloud" not in out


def test_schedules_and_what_isnt_rendered():
    _, alpha, _ = _alpha(macie(days="1"))
    assert "daily_schedule = true" in "\n".join(render_discovery(alpha))
    _, alpha, _ = _alpha(macie(days="30"))
    assert "monthly_schedule = 1" in "\n".join(render_discovery(alpha))
    _, alpha, _ = _alpha(macie(), account=None)
    assert "# NOTE: data discovery macie-weekly: no classification job: the cloud records no account" in \
        "\n".join(render_discovery(alpha))
    _, alpha, _ = _alpha(entry(ALPHA, "org-macie", "ciamDataDiscovery", ciamBindingRole="data-discovery",
                               ciamManagedBy="cn=landing-zone,ou=owners,dc=ciam-ops"))
    assert render_discovery(alpha) == ("# Data discovery org-macie: kept by cn=landing-zone,ou=owners,dc=ciam-ops, "
                                       "not rendered here",)


def test_govcloud_is_an_add_on_with_an_action():
    d, alpha, beta = _alpha(macie(), region="us-gov-west-1")
    assert "# Amazon Macie in GovCloud: AWS's FedRAMP services-in-scope page marks it for US East/West only" in \
        "\n".join(render_discovery(alpha))
    f = check_discovery_availability(context(d, beta, alpha, cutover="2026-12-01"))
    assert [a[1] for a in f.actions] == [
        "alpha/prod runs data discovery (macie-weekly) in GovCloud: Amazon Macie in GovCloud: AWS's FedRAMP "
        "services-in-scope page marks it for US East/West only and no GovCloud endpoint was found (2026-10-08): "
        "rendered as an add-on, confirm it is offered before applying."]
    d, alpha, beta = _alpha(macie())
    assert check_discovery_availability(context(d, beta, alpha)).actions == ()


STATE = [("aws_macie2_account", {"id": "111122223333", "status": "ENABLED"}),
         ("aws_macie2_custom_data_identifier", {"id": "cdi-1", "name": "cui-marking", "regex": "CUI//[A-Z-]+"}),
         ("aws_macie2_classification_job", {
             "id": "job-1", "job_type": "SCHEDULED", "name": "macie-weekly",
             "schedule_frequency": [{"daily_schedule": False, "weekly_schedule": "SUNDAY", "monthly_schedule": 0}],
             "custom_data_identifier_ids": ["cdi-1"],
             "s3_job_definition": [{"bucket_definitions": [{"account_id": "111122223333",
                                                            "buckets": ["ea-backups"]}]}]}),
         ("aws_macie2_classification_job", {"id": "job-2", "job_type": "ONE_TIME", "name": "once"}),
         ("aws_macie2_classification_export_configuration", {
             "id": "us-east-1", "s3_destination": [{"bucket_name": "ea-audit", "kms_key_arn": KEY_ARN}]}),
         ("aws_cloudwatch_event_rule", {"name": "macie-weekly-findings", "event_pattern":
                                        '{"source":["aws.macie"],"detail-type":["Macie Finding"]}'}),
         ("aws_cloudwatch_event_target", {"rule": "macie-weekly-findings", "arn": TOPIC_ARN}),
         ("aws_sns_topic", {"arn": TOPIC_ARN, "name": "security-alerts", "tags_all": {"Role": "security-alerts"}})]


def test_macie_is_read_back_from_state():
    (r,) = discovery_resources(STATE)
    assert (r.kind, r.ref, r.name) == ("discovery", "job-1", "macie-weekly")
    assert dict(r.attrs) == {"ciamRescanDays": ("7",), "ciamCustomIdentifier": ("cui-marking: CUI//[A-Z-]+",)}
    assert dict(r.links) == {"ciamScansRole": ("arn:aws:s3:::ea-backups",), "ciamFindingsRole": TOPIC_ARN,
                             "ciamResultsRole": "arn:aws:s3:::ea-audit"}
    d, *_ = model()
    resources, _ = pairs_resources(STATE)
    stores = (resource("storage", "arn:aws:s3:::ea-backups", {"ciamStorageRef": "s3://ea-backups"},
                       name="ea-backups", role="ds-backups"),
              resource("storage", "arn:aws:s3:::ea-audit", {"ciamStorageRef": "s3://ea-audit"}, name="ea-audit",
                       role="audit-archive"))
    groups, _ = environment_groups(d, "alpha/prod", (*stores, *resources))
    (placed,) = [dict(e.attrs) for _, entries in groups for e in entries if "ciamDataDiscovery" in e.classes]
    assert placed["ciamBindingRole"] == ("data-discovery",) and placed["ciamScansRole"] == ("ds-backups",)
    assert placed["ciamResultsRole"] == ("audit-archive",) and placed["ciamFindingsRole"] == ("security-alerts",)
