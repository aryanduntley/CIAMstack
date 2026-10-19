"""CloudWatch Logs pulled into Splunk from S3 through SQS (task 129d, note 3538 item 2): the estate setting
aws-siem-delivery chooses it per log destination or index (an environment's entry first), Firehose push staying the
default; the pull renders Firehose to S3, the queue and its dead-letter queue, the policy letting the bucket send, one
notification per bucket and the read-only role the Splunk Add-on for AWS assumes (trusted by the principal
aws-siem-pull-principal names: no credential); CloudFormation writes them natively, the notification into a bucket the
template holds or else kept in Terraform; what the owners do are actions, what is missing a blocker."""
from types import SimpleNamespace

from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import TfFile, as_text
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.cfn_types import cloudformation_files
from opsdir_adapter_aws.observability import render_log_groups
from opsdir_adapter_aws.siem_forwarding import DELIVERY, render_siem_forwarding, siem_forwarding_notes
from opsdir_adapter_aws.siem_pull import (MAX_RECEIVES, PRINCIPAL, VISIBILITY_SECONDS, queue_name, queue_url,
                                          reader_role_arn, reader_role_name, render_siem_pull, siem_pull_notes)
from opsdir_adapter_aws.storage import render_object_stores
from network_fixtures import ALPHA, entry, model

GROUP_ARN = "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/security"
SPLUNK_ROLE = "arn:aws:iam::444455556666:role/splunk-addon"
KEY = "arn:aws:kms:us-east-1:111122223333:key/abcd"


def _cloud(region="us-east-1"):
    return LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {}, (
        ("add", "objectClass", ("ciamCloudAccount",)), ("replace", "ciamAccountRef", ("111122223333",)),
        ("replace", "ciamRegion", (region,))))


def _setting(name, value):
    return (f"dn: cn={name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamEstateSetting\ncn: {name}\n"
            f"ciamEstateValue: {value}\n")


def _group(cn, storage="s3://ciam-siem-logs/cloudwatch", group=GROUP_ARN):
    return entry(ALPHA, cn, "ciamLogDestination", ciamBindingRole=cn, ciamDestinationKind="log-group",
                 ciamProviderRef=group, ciamRetentionDays="30", ciamForwardsToRole="siem",
                 **({"ciamStorageRef": storage} if storage else {}))


INDEX = entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
              ciamProviderRef="ciam_security", ciamRetentionDays="90")
STORE = (entry(ALPHA, "siem-logs", "ciamObjectStore", ciamBindingRole="siem-logs", ciamStorageRef="s3://ciam-siem-logs",
               ciamStorageVersioning="TRUE", ciamEncryptedByRole="siem-key"),
         entry(ALPHA, "siem-key", "ciamKeyRef", ciamBindingRole="siem-key", ciamRefUri=f"aws-kms://{KEY}"))


def _model(delivery="siem=s3-sqs", principal=f"siem={SPLUNK_ROLE}", records=None, region="us-east-1"):
    tree = tuple(_setting(s.name, v) for s, v in ((DELIVERY, delivery), (PRINCIPAL, principal)) if v)
    _, m, _ = model(alpha=records or (_group("security-logs"), INDEX), tree=tree, changes=(_cloud(region),))
    return m


def _services(keeper="splunk"):
    return SimpleNamespace(siem_keeper=lambda m, b: keeper)


def _text(blocks):
    return "\n\n".join(as_text(blocks))


def test_firehose_push_stays_the_default_and_the_setting_chooses_the_pull():
    pushed = _model(delivery=None)
    assert render_siem_pull(pushed, _services()) == ()
    (push,) = siem_forwarding_notes(pushed, _services())       # the push's (it needs an intake and a credential)
    assert push.severity == "blocker" and "an intake URL on siem" in push.text
    m = _model()
    assert render_siem_forwarding(m, _services()) == () and siem_forwarding_notes(m, _services()) == ()
    text = _text(render_siem_pull(m, _services()))
    for line in ('destination = "extended_s3"', 'bucket_arn          = "arn:aws:s3:::ciam-siem-logs"',
                 'prefix              = "cloudwatch/security-logs/"',
                 'error_output_prefix = "cloudwatch/security-logs-failed/"', 'type = "Decompression"',
                 'type = "AppendDelimiterToRecord"',
                 'resource "aws_cloudwatch_log_subscription_filter" "security_logs"',
                 'resource "aws_sqs_queue" "security_logs_dlq"', f"visibility_timeout_seconds = {VISIBILITY_SECONDS}",
                 '\\"maxReceiveCount\\":' + str(MAX_RECEIVES), "sqs_managed_sse_enabled",
                 '\\"Service\\":\\"s3.amazonaws.com\\"', '\\"aws:SourceArn\\":\\"arn:aws:s3:::ciam-siem-logs\\"',
                 'resource "aws_s3_bucket_notification" "siem_ciam_siem_logs"', 'bucket = "ciam-siem-logs"',
                 'filter_prefix = "cloudwatch/security-logs/"', f'\\"AWS\\":\\"{SPLUNK_ROLE}\\"',
                 '\\"sqs:ReceiveMessage\\"', '\\"arn:aws:s3:::ciam-siem-logs/cloudwatch/security-logs/*\\"'):
        assert line in text, line
    assert "hec_token" not in text and "secretsmanager" not in text and "sqs:SendMessage\\\",\\\"sqs" not in text
    assert "kms:" not in text


def test_an_environments_own_entry_and_the_log_destinations_role_come_first():
    m = _model(delivery="siem=s3-sqs, alpha/prod:siem=firehose")
    assert render_siem_pull(m, _services()) == ()
    m = _model(delivery="alpha/prod:siem=firehose, security-logs=s3-sqs, alpha/prod:security-logs=s3-sqs")
    assert render_siem_pull(m, _services())


def test_the_names_the_splunk_adapter_reads_back():
    m = _model()
    b = next(e for e in m.bindings if e.dn.startswith("cn=security-logs,"))
    assert queue_name(m, b) == "ciam-prod-security-logs-siem"
    assert reader_role_name(m, b) == "ciam-prod-security-logs-siem-reader"
    assert queue_url(m, b) == "https://sqs.us-east-1.amazonaws.com/111122223333/ciam-prod-security-logs-siem"
    assert reader_role_arn(m, b) == "arn:aws:iam::111122223333:role/ciam-prod-security-logs-siem-reader"


def test_the_teams_steps_are_actions_naming_role_principal_queue_and_bucket():
    m = _model()
    notes = siem_pull_notes(m, _services())
    team, bucket, encryption, replay = notes
    assert team.severity == "action"
    for what in ("Splunk Add-on for AWS", "https://sqs.us-east-1.amazonaws.com/111122223333/ciam-prod-security-logs-siem",
                 "arn:aws:iam::111122223333:role/ciam-prod-security-logs-siem-reader", SPLUNK_ROLE,
                 "s3://ciam-siem-logs/cloudwatch/security-logs/", "no credential"):
        assert what in team.text, what
    assert any("8.3.0" in h for h in team.how) and any("ciam-prod-security-logs-siem-reader" in h for h in team.how)
    assert bucket.severity == "action" and "replaces any other notifications" in bucket.text
    assert encryption.severity == "note" and "ciamEncryptedByRole" in encryption.text
    assert replay.severity == "note" and "ciam-prod-security-logs-siem-dlq" in replay.text


def test_a_bucket_the_stack_keeps_is_the_resource_with_its_key():
    m = _model(records=(_group("security-logs"), INDEX, *STORE))
    text = _text(render_siem_pull(m, _services()))
    assert "bucket = aws_s3_bucket.siem_logs.id" in text and f'kms_key_arn         = "{KEY}"' in text
    assert '\\"kms:Decrypt\\",\\"kms:GenerateDataKey\\"' in text and '\\"DecryptLogObjects\\"' in text
    assert [n.severity for n in siem_pull_notes(m, _services())] == ["action", "note"]


def test_cloudformation_writes_the_notification_into_a_bucket_it_holds_else_terraform_keeps_it():
    def translated(m):
        blocks = (*render_object_stores(m), *render_log_groups(m), *render_siem_pull(m, _services()))
        files = cloudformation_files(SimpleNamespace(dn=m.dn, label="alpha/prod"),
                                     {"terraform/main.tf": TfFile("main.tf", blocks)}, "x")
        return files["cloudformation/template.yaml"], files
    template, files = translated(_model(records=(_group("security-logs"), INDEX, *STORE)))
    for line in ("Type: AWS::SQS::Queue", "Type: AWS::SQS::QueuePolicy", "ExtendedS3DestinationConfiguration:",
                 "AWSKMSKeyARN: " + KEY, "NotificationConfiguration:", "QueueConfigurations:",
                 "Value: cloudwatch/security-logs/", "- Type: AppendDelimiterToRecord\n"):
        assert line in template, line
    assert "Parameters: []" not in template
    template, files = translated(_model())
    assert "NotificationConfiguration" not in template and "Type: AWS::SQS::Queue" in template
    side = files["cloudformation/terraform/main.tf"]
    assert any(b.labels == ("aws_s3_bucket_notification", "siem_ciam_siem_logs") for b in side.items
               if hasattr(b, "labels"))


def test_forwardings_to_one_bucket_share_its_one_notification():
    other = "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/audit"
    m = _model(records=(_group("security-logs"), _group("audit-logs", group=other), INDEX))
    blocks = render_siem_pull(m, _services())
    (notification,) = (b for b in blocks if getattr(b, "labels", ())[:1] == ("aws_s3_bucket_notification",))
    text = _text((notification,))
    assert text.count("queue {") == 2 and "cloudwatch/audit-logs/" in text and "cloudwatch/security-logs/" in text


def test_what_cant_be_pulled_is_a_blocker_naming_what_is_missing():
    m = _model(principal="siem=not-an-arn", records=(_group("security-logs", storage=None), INDEX))
    assert "aws_sqs_queue" not in _text(render_siem_pull(m, _services("elastic")))
    (blocker,) = siem_pull_notes(m, _services("elastic"))
    assert blocker.severity == "blocker"
    for what in ("Splunk adapter keeps", "the bucket its logs land in", "aws-siem-pull-principal"):
        assert what in blocker.text, what


def test_a_delivery_the_setting_doesnt_know_is_a_blocker_and_a_malformed_part_a_note():
    m = _model(delivery="siem=kafka, nonsense")
    (blocker,) = siem_forwarding_notes(m, _services())
    assert blocker.severity == "blocker" and "it says `kafka`" in blocker.text
    (note,) = siem_pull_notes(m, _services())
    assert note.severity == "note" and "aws-siem-delivery" in note.text and "nonsense" in note.text


def test_govcloud_names_the_addons_s3_host_and_what_fips_doesnt_establish():
    m = _model(region="us-gov-west-1")
    text = _text(render_siem_pull(m, _services()))
    assert "arn:aws-us-gov:s3:::ciam-siem-logs" in text
    notes = siem_pull_notes(m, _services())
    assert any(n.severity == "action" and "S3 Host Name" in n.text for n in notes)
    assert any("FIPS" in n.text and "Firehose" in n.text for n in notes)


def test_the_adapter_declares_the_settings():
    assert {DELIVERY, PRINCIPAL} <= set(ADAPTER.settings)
