"""CloudWatch Logs forwarded on to a SIEM (milestone 109, task 573): a log group whose binding forwards to a Splunk or
Elastic index is subscribed to a Firehose stream that reads the index's credential from Secrets Manager (never in the
render or state) and keeps undeliverable events in S3; what can't be rendered is a blocker note; the SIEM team's step
is an action; the core's check names forwarding to something that isn't a SIEM index."""
from types import SimpleNamespace

from opsdir.core.contract import PlanContext
from opsdir.domains.observability.siem import check_siem
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_aws.siem_forwarding import render_siem_forwarding, siem_forwarding_notes
from network_fixtures import ALPHA, entry, model

GROUP_ARN = "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/security"
SECRET = "aws-sm://arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/hec-AbCdEf"


def _records(keeper_index="ciam_security", storage="s3://ciam-siem-failed/firehose", intake="https://hec.example.test"):
    return (entry(ALPHA, "security-logs", "ciamLogDestination", ciamBindingRole="security-logs",
                  ciamDestinationKind="log-group", ciamProviderRef=GROUP_ARN, ciamRetentionDays="30",
                  ciamForwardsToRole="siem", **({"ciamStorageRef": storage} if storage else {})),
            entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                  ciamProviderRef=keeper_index, ciamRetentionDays="90", ciamCredentialRole="siem-intake",
                  **({"ciamIntakeUrl": intake} if intake else {})),
            entry(ALPHA, "siem-intake", "ciamSecretRef", ciamBindingRole="siem-intake", ciamRefUri=SECRET))


def _services(keeper):
    return SimpleNamespace(siem_keeper=lambda m, b: keeper)


def _render(keeper="splunk", **kw):
    _, m, _ = model(alpha=_records(**kw))
    return "\n\n".join(as_text(render_siem_forwarding(m, _services(keeper)))), m


def test_a_log_group_forwarded_to_splunk_is_a_firehose_stream_reading_its_token_by_reference():
    text, _ = _render()
    for line in ('resource "aws_kinesis_firehose_delivery_stream" "security_logs"', 'destination = "splunk"',
                 'hec_endpoint      = "https://hec.example.test"', 'hec_endpoint_type = "Raw"',
                 's3_backup_mode    = "FailedEventsOnly"',
                 "secret_arn = data.aws_secretsmanager_secret.siem_intake.arn",
                 'bucket_arn = "arn:aws:s3:::ciam-siem-failed"', 'prefix     = "firehose/"',
                 'type = "Decompression"', 'resource "aws_cloudwatch_log_subscription_filter" "security_logs"',
                 "log_group_name  = aws_cloudwatch_log_group.security_logs.name", 'filter_pattern  = ""',
                 "destination_arn = aws_kinesis_firehose_delivery_stream.security_logs.arn",
                 '\\"Service\\":\\"logs.amazonaws.com\\"', '\\"Action\\":[\\"firehose:PutRecord\\"'):
        assert line in text, line
    assert "hec_token" not in text and "secretsmanager:GetSecretValue" in text


def test_an_elastic_index_is_an_http_endpoint_and_the_team_is_told_which_key_the_secret_holds():
    text, m = _render("elastic")
    assert 'destination = "http_endpoint"' in text and 'name           = "Elastic"' in text
    assert 's3_backup_mode = "FailedDataOnly"' in text and "access_key" not in text
    (action,) = siem_forwarding_notes(m, _services("elastic"))
    assert action.severity == "action" and '{"api_key": ...}' in action.text


def test_what_cant_be_rendered_is_a_blocker_naming_what_is_missing():
    text, m = _render("prometheus", storage=None, intake=None)
    assert "aws_kinesis_firehose_delivery_stream" not in text
    (blocker,) = siem_forwarding_notes(m, _services("prometheus"))
    assert blocker.severity == "blocker"
    for what in ("Splunk or Elastic adapter keeps", "an intake URL", "where undeliverable events go"):
        assert what in blocker.text, what


def test_the_core_check_names_forwarding_to_something_that_isnt_a_siem_index():
    bad = entry(ALPHA, "audit", "ciamLogDestination", ciamBindingRole="audit", ciamDestinationKind="log-group",
                ciamProviderRef=GROUP_ARN, ciamForwardsToRole="nowhere")
    d, m, beta = model(alpha=(bad,))
    texts = [t for _, t, _, _ in check_siem(PlanContext(d, m, beta, None, None, {}, {}, ())).actions]
    assert texts == ["alpha/prod's log destination `audit` forwards its logs to `nowhere`, which alpha/prod doesn't "
                     "bind: nothing is forwarded. Bind the role to the SIEM's index (a log destination of kind "
                     "siem-index)."]


def test_cloudformation_deploys_the_stream_and_subscription_natively_without_a_token():
    from opsdir_format_terraform.hcl import TfFile, tf_block
    from opsdir_adapter_aws.cfn_types import cloudformation_files
    from opsdir_adapter_aws.observability import render_log_groups
    _, m, _ = model(alpha=_records())
    data = tf_block("data", ["aws_secretsmanager_secret", "siem_intake"], [("arn", SECRET.split("://", 1)[1])])
    root = TfFile("", (data, *render_log_groups(m), *render_siem_forwarding(m, _services("splunk"))))
    files = cloudformation_files(SimpleNamespace(dn=m.dn, label="alpha/prod"), {"terraform/main.tf": root}, "x")
    template = files["cloudformation/template.yaml"]
    template = template if isinstance(template, str) else template.text
    for line in ("Type: AWS::KinesisFirehose::DeliveryStream", "SplunkDestinationConfiguration:",
                 "SecretsManagerConfiguration:", "Type: AWS::Logs::SubscriptionFilter",
                 "DeliveryStreamType: DirectPut"):
        assert line in template, line
    assert "HECToken" not in template
