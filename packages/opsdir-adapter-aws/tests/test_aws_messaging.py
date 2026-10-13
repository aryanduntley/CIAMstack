"""AWS messaging: SES domain identities read as sending identities (DKIM status, SPF and DMARC from the domain's Route
53 TXT records), and SQS queues, SNS topics, EventBridge buses and Kinesis streams as stream carriers, from Terraform
state; an identity for a single address and the default event bus are left out. The AWS CLI's outputs of the same
resources read as the same record (tags saved by name; an SES identity saved by name, its ARN in the environment's
account)."""
import json

from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.inventory import state_resources


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("aws_sesv2_email_identity", "domain", {"arn": "arn:ses:example.test", "email_identity": "example.test",
                                            "dkim_signing_attributes": [{"status": "SUCCESS"}],
                                            "tags": {"Role": "mail-sending"}}),
    ("aws_sesv2_email_identity", "address", {"arn": "arn:ses:ops", "email_identity": "ops@example.test"}),
    ("aws_route53_record", "spf", {"name": "example.test", "type": "TXT",
                                   "records": ["v=spf1 include:amazonses.com ~all"]}),
    ("aws_route53_record", "dmarc", {"name": "_dmarc.example.test.", "type": "TXT",
                                     "records": ["v=DMARC1; p=reject"]}),
    ("aws_sqs_queue", "crm", {"arn": "arn:sqs:crm", "name": "ciam-crm", "tags": {"Role": "crm-queue"}}),
    ("aws_cloudwatch_event_bus", "audit", {"arn": "arn:events:bus/audit", "name": "ciam-audit"}),
    ("aws_cloudwatch_event_bus", "default", {"arn": "arn:events:bus/default", "name": "default"}))


def test_a_domain_identity_with_what_its_dns_says():
    resources, _ = state_resources(STATE)
    (ses,) = [r for r in resources if r.kind == "sending"]
    assert (ses.ref, ses.name, ses.role) == ("arn:ses:example.test", "ses-example.test", "mail-sending")
    assert ses.attrs == {"ciamSenderDomain": ("example.test",), "ciamDkimVerified": ("TRUE",),
                         "ciamSpfAuthorized": ("TRUE",), "ciamDmarcPolicy": ("reject",)}


def test_queues_and_buses_carry_streams():
    resources, _ = state_resources(STATE)
    streams = {r.ref: (r.attrs["ciamStreamKind"], r.role) for r in resources if r.kind == "stream"}
    assert streams == {"arn:sqs:crm": (("queue",), "crm-queue"), "arn:events:bus/audit": (("bus",), None)}


ACCOUNT = "111122223333"
QUEUE, BUS = f"arn:aws:sqs:us-east-1:{ACCOUNT}:ciam-crm", f"arn:aws:events:us-east-1:{ACCOUNT}:event-bus/ciam-audit"
PARTNER = "aws.partner/example.com/123/audit"
STREAM = f"arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/ciam-logs"
DOMAIN = f"arn:aws:ses:us-east-1:{ACCOUNT}:identity/example.test"
LIVE = _state(
    ("aws_sqs_queue", "crm", {"arn": QUEUE, "name": "ciam-crm", "tags": {"Role": "crm-queue"}}),
    ("aws_sqs_queue", "dlq", {"arn": f"arn:aws:sqs:us-east-1:{ACCOUNT}:ciam-crm-dlq", "name": "ciam-crm-dlq"}),
    ("aws_cloudwatch_event_bus", "audit", {"arn": BUS, "name": "ciam-audit", "tags": {"Role": "audit-bus"}}),
    ("aws_cloudwatch_event_bus", "partner", {"arn": f"arn:aws:events:us-east-1:{ACCOUNT}:event-bus/{PARTNER}",
                                             "name": PARTNER}),
    ("aws_cloudwatch_event_bus", "default", {"arn": f"arn:aws:events:us-east-1:{ACCOUNT}:event-bus/default",
                                             "name": "default"}),
    ("aws_kinesis_stream", "logs", {"arn": STREAM, "name": "ciam-logs", "tags": {"Role": "log-stream"}}),
    ("aws_sesv2_email_identity", "domain", {"arn": DOMAIN, "email_identity": "example.test",
                                            "dkim_signing_attributes": [{"status": "SUCCESS"}],
                                            "tags": {"Role": "mail-sending"}}))
CLI = {
    "vpcs.json": {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]},
    "subnets.json": {"Subnets": [{"SubnetId": "subnet-a", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24",
                                  "SubnetArn": f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/subnet-a"}]},
    "queues/ciam-crm.json": {"QueueArn": QUEUE},                                        # projected
    "queues/ciam-crm-dlq.json": {"Attributes": {"QueueArn": f"arn:aws:sqs:us-east-1:{ACCOUNT}:ciam-crm-dlq"}},  # raw
    "queue-tags/ciam-crm.json": {"Tags": {"Role": "crm-queue"}},
    "queue-tags/ciam-crm-dlq.json": {"Tags": None},                                     # no tags, projected
    "event-buses.json": {"EventBuses": [
        {"Name": "default", "Arn": f"arn:aws:events:us-east-1:{ACCOUNT}:event-bus/default"},
        {"Name": "ciam-audit", "Arn": BUS, "Policy": "{}"},
        {"Name": PARTNER, "Arn": f"arn:aws:events:us-east-1:{ACCOUNT}:event-bus/{PARTNER}"}]},
    "event-bus-tags/ciam-audit.json": {"Tags": [{"Key": "Role", "Value": "audit-bus"}]},
    "event-bus-tags/aws.partner%2Fexample.com%2F123%2Faudit.json": {"Tags": []},
    "streams.json": {"StreamNames": ["ciam-logs", "old"], "HasMoreStreams": False, "StreamSummaries": [
        {"StreamName": "ciam-logs", "StreamARN": STREAM, "StreamStatus": "ACTIVE"},
        {"StreamName": "old", "StreamARN": f"arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/old",
         "StreamStatus": "DELETING"}]},
    "stream-tags/ciam-logs.json": {"Tags": [{"Key": "Role", "Value": "log-stream"}]},
    "email-identities/example.test.json": {"IdentityType": "DOMAIN", "DkimAttributes": {"Status": "SUCCESS"},
                                           "Tags": [{"Key": "Role", "Value": "mail-sending"}]}}
KINDS = ("stream", "sending")


def _cli(outputs=None):
    return cli_resources({p: json.dumps(doc) for p, doc in (outputs or CLI).items()})


def test_the_cli_reads_the_same_messaging_as_state():
    resources, notices = _cli()
    cli = {r.ref: r for r in resources if r.kind in KINDS}
    assert cli == {r.ref: r for r in state_resources(LIVE)[0] if r.kind in KINDS}
    assert len(cli) == 6 and cli[DOMAIN].attrs["ciamDkimVerified"] == ("TRUE",)
    assert not [n for n in notices if "not an AWS CLI output" in n]       # every file is recognized


def test_ses_identities_without_the_environments_arn_are_named():
    resources, notices = _cli({p: d for p, d in CLI.items() if p != "subnets.json"})
    assert not [r for r in resources if r.kind == "sending"]
    assert any(n.startswith("sesv2: 1 identity(ies) without an ARN") for n in notices)
