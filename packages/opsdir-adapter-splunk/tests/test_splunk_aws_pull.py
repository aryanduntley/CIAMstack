"""The Splunk Add-on for AWS's SQS-based S3 inputs (task 129d) for the forwardings the AWS adapter pulls from S3 through
SQS: a stanza per forwarding in the opsdir_ciam_aws app, with the queue, its region, the add-on's role entry and the
index (fields as the add-on's 8.3.0 documentation names them), its account entry when the estate setting names it;
what the Splunk team does is an action, a cloud without account or region a blocker; the queue and role names are the
AWS adapter's."""
import pytest

from opsdir.connectors.registry import services
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_splunk.adapter import ADAPTER
from opsdir_adapter_splunk.aws_pull import (ADDON_ACCOUNT, ADDON_VERSION, AWS_INPUTS, SOURCETYPE, aws_pull_notes,
                                            input_stanzas, pull_inputs)
from opsdir_adapter_splunk.conf import read_conf, setting
from opsdir_adapter_splunk.render import render
from network_fixtures import ALPHA, entry, model

GROUP_ARN = "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/security"
SPLUNK_ROLE = "arn:aws:iam::444455556666:role/splunk-addon"
STACK = (f"dn: cn=siem,ou=stack,{ALPHA}\nobjectClass: top\nobjectClass: ciamStackComponent\ncn: siem\n"
         "ciamStackRole: siem\nciamAdapter: splunk\nciamAdapterVersion: >=0.1,<1\n"
         "ciamAdapterSource: https://example.test/splunk\n")
RECORDS = (entry(ALPHA, "security-logs", "ciamLogDestination", ciamBindingRole="security-logs",
                 ciamDestinationKind="log-group", ciamProviderRef=GROUP_ARN, ciamForwardsToRole="siem",
                 ciamStorageRef="s3://ciam-siem-logs/cloudwatch"),
           entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
                 ciamProviderRef="ciam_security", ciamRetentionDays="90"))


def _setting(name, value):
    return (f"dn: cn={name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamEstateSetting\ncn: {name}\n"
            f"ciamEstateValue: {value}\n")


def _cloud(provider="aws", account=True):
    return LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {}, (
        ("replace", "ciamCloudProvider", (provider,)), ("replace", "ciamRegion", ("us-east-1",)),
        *((("add", "objectClass", ("ciamCloudAccount",)), ("replace", "ciamAccountRef", ("111122223333",)))
          if account else ())))


def _model(delivery="siem=s3-sqs", account_entry=None, **cloud):
    tree = (STACK, _setting("aws-siem-delivery", delivery), _setting("aws-siem-pull-principal", f"siem={SPLUNK_ROLE}"),
            *((_setting(ADDON_ACCOUNT.name, account_entry),) if account_entry else ()))
    _, m, _ = model(alpha=RECORDS, tree=tree, changes=(_cloud(**cloud),))
    return m


def test_a_pulled_forwarding_is_an_sqs_based_s3_input_for_its_index():
    m = _model(account_entry="splunk-hf")
    files = render(m, services())
    text = files[AWS_INPUTS]
    assert "Splunk Add-on for AWS inputs" in text
    ((name, _),) = stanzas = read_conf(text)
    assert name == "aws_sqs_based_s3://ciam-prod-security-logs-siem"
    for key, value in (("aws_account", "splunk-hf"), ("aws_iam_role", "ciam-prod-security-logs-siem-reader"),
                       ("sqs_queue_url", "https://sqs.us-east-1.amazonaws.com/111122223333/ciam-prod-security-logs-siem"),
                       ("sqs_queue_region", "us-east-1"), ("s3_file_decoder", "CustomLogs"), ("sourcetype", SOURCETYPE),
                       ("index", "ciam_security"), ("using_dlq", "1"), ("sqs_batch_size", "10")):
        assert setting(stanzas[0], key) == value, key
    actions = [n for n in aws_pull_notes(m) if n.severity == "action"]
    assert len(actions) == 2 and any(ADDON_VERSION in h for h in actions[0].how)
    assert SOURCETYPE in actions[1].how[0]


def test_without_the_account_setting_the_input_names_none_and_an_action_says_so():
    m = _model()
    ((_, pairs),) = input_stanzas(m)
    assert "aws_account" not in dict(pairs)
    assert any(ADDON_ACCOUNT.name in h for n in aws_pull_notes(m) for h in n.how)


def test_only_aws_forwardings_mapped_to_the_pull_are_inputs():
    assert pull_inputs(_model(delivery="siem=firehose")) == ()
    assert pull_inputs(_model(provider="azure")) == ()
    assert AWS_INPUTS not in render(_model(delivery="siem=firehose"), services())


def test_a_cloud_without_its_account_is_a_blocker_not_an_input():
    m = _model(account=False)
    assert input_stanzas(m) == ()
    (blocker,) = aws_pull_notes(m)
    assert blocker.severity == "blocker" and "ciamAccountRef" in blocker.text


def test_the_queue_and_role_are_named_as_the_aws_adapter_names_them():
    pull = pytest.importorskip("opsdir_adapter_aws.siem_pull")
    m = _model()
    (x,) = pull_inputs(m)
    assert (x.queue, x.url, x.role) == (pull.queue_name(m, x.destination), pull.queue_url(m, x.destination),
                                        pull.reader_role_name(m, x.destination))


def test_the_adapter_declares_the_app_and_the_setting():
    assert ADDON_ACCOUNT in ADAPTER.settings
    assert any(AWS_INPUTS.startswith(pattern.split("*", 1)[0]) for pattern, _ in ADAPTER.formats)
