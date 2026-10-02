"""AWS messaging: SES domain identities read as sending identities (DKIM status, SPF and DMARC from the domain's Route
53 TXT records), and SQS queues, SNS topics, EventBridge buses and Kinesis streams as stream carriers, from Terraform
state; an identity for a single address and the default event bus are left out."""
import json

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
