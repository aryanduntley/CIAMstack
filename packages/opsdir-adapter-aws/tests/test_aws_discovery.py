"""Data discovery on AWS as Amazon Macie: the account enabled, a custom data identifier per own data type, a scheduled
classification job over the S3 buckets of the stores examined (daily, weekly or monthly), findings sent by an
EventBridge rule, results exported to a KMS-encrypted bucket; stores that aren't S3 and discovery kept by someone else
in comments; an interval Macie's schedule doesn't offer exactly as an EventBridge Scheduler schedule and a Lambda
starting one-time jobs once due; GovCloud not rendered, with an action (a blocker for restricted data); all of it read
back from Terraform state."""
from opsdir.core.directory import make_entry
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.core.inventory import environment_groups, resource
import datetime as dt
import runpy
import sys
from types import SimpleNamespace

from opsdir.domains.estate.discovery import rescan_due
from opsdir_adapter_aws.discovery import (check_discovery_availability, discovery_resources, handler_script,
                                          render_discovery)
from opsdir_adapter_aws.inventory import pairs_resources
from opsdir_adapter_aws.rendered_state import rendered_states
from opsdir_format_terraform.hcl import TfBlock, block
from opsdir_format_terraform.state import read_state
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
                 ciamCustomIdentifier=("cui-marking: CUI//[A-Z-]+", "employee-id: EA[0-9]{6}"),
                 **({"ciamRescanDays": days} if days else {}),
                 ciamFindingsRole="security-alerts", ciamResultsRole="audit-archive", **more)


def _alpha(*bindings, region="us-east-1", account="111122223333"):
    change = LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                              ("replace", "ciamRegion", (region,)),
                                              *((("replace", "ciamAccountRef", (account,)),) if account else ())))
    return model(alpha=(*STORES, *bindings), changes=(change,))


def test_macie_examines_the_s3_buckets_with_the_own_data_types_and_sends_findings_and_results():
    _, alpha, _ = _alpha(macie())
    out, files = _out(alpha)
    assert files == {}
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


def _out(m):
    hcl, files = render_discovery(m)
    return "\n\n".join(hcl), files


def test_schedules_and_what_isnt_rendered():
    _, alpha, _ = _alpha(macie(days="1"))
    assert "daily_schedule = true" in _out(alpha)[0]
    _, alpha, _ = _alpha(macie(days=None))
    assert 'weekly_schedule = "SUNDAY"' in _out(alpha)[0]                # no interval recorded: weekly
    _, alpha, _ = _alpha(macie(), account=None)
    assert "# NOTE: data discovery macie-weekly: no classification job: the cloud records no account" in _out(alpha)[0]
    _, alpha, _ = _alpha(entry(ALPHA, "org-macie", "ciamDataDiscovery", ciamBindingRole="data-discovery",
                               ciamManagedBy="cn=landing-zone,ou=owners,dc=ciam-ops"))
    assert render_discovery(alpha) == (("# Data discovery org-macie: kept by cn=landing-zone,ou=owners,dc=ciam-ops, "
                                        "not rendered here",), {})


def test_govcloud_renders_nothing_and_gives_an_action():
    d, alpha, beta = _alpha(macie(), region="us-gov-west-1")
    assert render_discovery(alpha) == ((
        "# Amazon Macie isn't offered in GovCloud: AWS's General Reference lists no GovCloud endpoint for it and its "
        "FedRAMP services-in-scope page marks it for US East/West only: not rendered: data discovery macie-weekly (the "
        "planner names the gap)",), {})
    f = check_discovery_availability(context(d, beta, alpha, cutover="2026-12-01"))
    assert [a[1] for a in f.actions] == [
        "alpha/prod runs data discovery (macie-weekly) in GovCloud: Amazon Macie isn't offered in GovCloud: AWS's "
        "General Reference lists no GovCloud endpoint for it and its FedRAMP services-in-scope page marks it for US "
        "East/West only: not rendered."]
    d, alpha, beta = _alpha(macie())
    f = check_discovery_availability(context(d, beta, alpha))
    assert f.actions == () and f.ok == ("alpha/prod's data discovery `macie-weekly` examines its stores every 7 "
                                        "days: Macie's own weekly classification job.",)


def test_an_interval_macie_doesnt_offer_is_a_scheduler_starting_one_time_jobs():
    d, alpha, beta = _alpha(macie(days="3"))
    out, files = _out(alpha)
    assert "aws_macie2_classification_job" not in out and "monthly_schedule" not in out     # never rounded
    fn = "ciam-prod-macie-macie-weekly"
    assert ("# macie-weekly: every 3 days: Macie's schedule runs daily or weekly, so EventBridge Scheduler invokes "
            f"{fn}") in out
    assert 'resource "aws_scheduler_schedule" "macie_weekly" {' in out
    assert 'schedule_expression = "rate(1 day)"' in out and 'mode = "OFF"' in out
    assert "arn      = aws_lambda_function.macie_weekly.arn" in out
    assert "role_arn = aws_iam_role.macie_weekly_scheduler.arn" in out
    assert 'runtime          = "python3.14"' in out and 'handler          = "handler.handler"' in out
    assert 'source_code_hash = data.archive_file.macie_weekly.output_base64sha256' in out
    assert 'RESCAN_DAYS                = "3"' in out and 'BUCKETS                    = "ea-backups"' in out
    assert ('CUSTOM_DATA_IDENTIFIER_IDS = "${aws_macie2_custom_data_identifier.cdi_cui_marking.id},'
            '${aws_macie2_custom_data_identifier.cdi_employee_id.id}"') in out
    assert '"RescanDays" = "3"' in out or 'RescanDays = "3"' in out
    # least privilege: jobs in the account and region, its own log group; the scheduler only invokes the function
    assert "arn:aws:macie2:us-east-1:111122223333:classification-job/*" in out
    assert f"log-group:/aws/lambda/{fn}:*" in out
    assert "schedule-group/default" in out and f"arn:aws:lambda:us-east-1:111122223333:function:{fn}" in out
    assert list(files) == [f"terraform/discovery/{fn}/handler.py"]
    assert check_discovery_availability(context(d, beta, alpha)).ok == (
        f"alpha/prod's data discovery `macie-weekly` examines its stores every 3 days: EventBridge Scheduler invokes "
        f"{fn} daily, which starts a one-time classification job once 3 days have passed since the last successful "
        "one.",)


def test_govcloud_discovery_blocks_where_the_data_is_restricted():
    d, alpha, beta = _alpha(macie(), region="us-gov-west-1")
    held = alpha._replace(env=make_entry(alpha.env.dn, (*alpha.env.classes, "ciamEnvironmentPlacement"),
                                         {**alpha.env.attrs, "ciamDataClassification": ("restricted",)}))
    f = check_discovery_availability(context(d, beta, held, cutover="2026-12-01"))
    assert f.actions == () and len(f.blockers) == 1
    assert f.blockers[0][1].startswith("alpha/prod runs data discovery (macie-weekly) in GovCloud: Amazon Macie")
    assert f.blockers[0][1].endswith("; its data is classified restricted: this blocks the move.")


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


def test_the_scheduler_reads_back_from_the_state_its_render_would_record():
    job = "arn:aws:macie2:us-east-1:111122223333:classification-job/3ce0"
    d, alpha, _ = _alpha(macie(days="3", ciamProviderRef=job))
    provider = block(*TfBlock("provider", ("aws",), (("region", "us-east-1"),
                                                      ("allowed_account_ids", ("111122223333",)))))
    states = rendered_states({"alpha/prod/main.tf": _out(alpha)[0] + "\n\n" + provider}, d, "alpha/prod")
    found, problem = read_state(states["alpha/prod/terraform.tfstate"])
    assert problem is None
    pairs = [(r.type, r.attributes) for r in found if r.mode == "managed"]
    (r,) = discovery_resources(pairs)
    assert (r.ref, r.name) == (job, "macie-weekly")                  # the function realizes the binding
    assert dict(r.attrs)["ciamRescanDays"] == ("3",)
    assert dict(r.attrs)["ciamCustomIdentifier"] == ("cui-marking: CUI//[A-Z-]+", "employee-id: EA[0-9]{6}")
    assert dict(r.links)["ciamScansRole"] == ("arn:aws:s3:::ea-backups",)
    resources, _ = pairs_resources(pairs)
    assert [x.kind for x in resources if x.kind == "job"] == []      # the scheduler's function is no job binding


class _Macie:
    """A stand-in for boto3's macie2 client: jobs as (status, error code, last run start)."""
    def __init__(self, jobs):
        self.jobs, self.created = {f"j{i}": j for i, j in enumerate(jobs)}, []

    def list_classification_jobs(self, filterCriteria, nextToken=None):
        assert filterCriteria["includes"][0] == {"key": "name", "comparator": "STARTS_WITH",
                                                  "values": ["macie-weekly:"]}
        return {"items": [{"jobId": i, "jobStatus": s, "lastRunErrorStatus": {"code": e}}
                          for i, (s, e, _) in self.jobs.items()]}

    def describe_classification_job(self, jobId):
        return {"lastRunTime": self.jobs[jobId][2]}

    def create_classification_job(self, **kw):
        self.created.append(kw)
        return {"jobId": "new"}


def _run(m, s, jobs, monkeypatch, tmp_path):
    script = tmp_path / "handler.py"
    script.write_text(handler_script(m, s))
    macie = _Macie(jobs)
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda name: macie))
    for k, v in {"JOB_NAME": "macie-weekly", "RESCAN_DAYS": "3", "ACCOUNT_ID": "111122223333",
                 "BUCKETS": "ea-backups", "CUSTOM_DATA_IDENTIFIER_IDS": "cdi-1,cdi-2"}.items():
        monkeypatch.setenv(k, v)
    module = runpy.run_path(str(script))
    return module, module["handler"]({}, None), macie.created


def test_the_function_starts_a_job_only_when_due(monkeypatch, tmp_path):
    _, alpha, _ = _alpha(macie(days="3"))
    (s,) = [x for x in alpha.bindings if "ciamDataDiscovery" in x.classes]
    now = dt.datetime.now(dt.timezone.utc)
    module, result, created = _run(alpha, s, (), monkeypatch, tmp_path)        # nothing has run yet
    assert result == {"started": "new"} and created[0]["jobType"] == "ONE_TIME"
    assert created[0]["name"].startswith("macie-weekly:") and created[0]["customDataIdentifierIds"] == ["cdi-1",
                                                                                                       "cdi-2"]
    assert created[0]["s3JobDefinition"] == {"bucketDefinitions": [{"accountId": "111122223333",
                                                                     "buckets": ["ea-backups"]}]}
    recent = [("COMPLETE", "NONE", now - dt.timedelta(days=2)), ("COMPLETE", "ERROR", now - dt.timedelta(days=9))]
    assert _run(alpha, s, recent, monkeypatch, tmp_path)[2] == []
    failed_since = [("COMPLETE", "NONE", now - dt.timedelta(days=3)), ("COMPLETE", "ERROR", now)]
    assert len(_run(alpha, s, failed_since, monkeypatch, tmp_path)[2]) == 1     # a failed run doesn't count
    running = [("COMPLETE", "NONE", now - dt.timedelta(days=9)), ("RUNNING", "NONE", now)]
    assert _run(alpha, s, running, monkeypatch, tmp_path)[1] == {"started": None, "why": "a job is unfinished"}
    # the function's rule is core estate discovery's (rescan_due), case for case
    for last, today, days in ((None, dt.date(2026, 10, 1), 3), (dt.date(2026, 10, 1), dt.date(2026, 10, 3), 3),
                              (dt.date(2026, 10, 1), dt.date(2026, 10, 4), 3),
                              (dt.date(2026, 9, 1), dt.date(2026, 10, 1), 30)):
        assert module["due"](last, today, days) == rescan_due(last, today, days)

