"""Messaging that CloudFormation stacks declare, normalized to the Terraform attribute names the shared mapping reads
(opsdir_adapter_aws.inventory: stream carriers, sending identities). Properties come resolved (Ref to physical IDs,
Fn::GetAtt where it follows from one). Pure.

  AWS::SQS::Queue          -> aws_sqs_queue (its Ref is its URL; its ARN from Fn::GetAtt Arn)
  AWS::SNS::Topic          -> aws_sns_topic (its Ref is its ARN)
  AWS::Events::EventBus    -> aws_cloudwatch_event_bus (its Ref is its name; its ARN from Fn::GetAtt Arn)
  AWS::Kinesis::Stream     -> aws_kinesis_stream (its Ref is its name; its ARN from Fn::GetAtt Arn)
  AWS::SES::EmailIdentity  -> aws_sesv2_email_identity (its Ref is the identity; its ARN in the stack's account)
A template doesn't hold whether SES has verified an identity's DKIM (Fn::GetAtt gives only its DNS tokens): that
attribute keeps the record's value. Ref values and ARN formats: AWS's CloudFormation template reference and Service
Authorization Reference (research notes 2712, 2713).
"""
from .cloudformation_values import stack_arn, tag_map

MESSAGING_TYPES = ("AWS::SQS::Queue", "AWS::SNS::Topic", "AWS::Events::EventBus", "AWS::Kinesis::Stream",
                   "AWS::SES::EmailIdentity")
NAMES = {"AWS::SQS::Queue": ("aws_sqs_queue", "QueueName"), "AWS::SNS::Topic": ("aws_sns_topic", "TopicName"),
         "AWS::Events::EventBus": ("aws_cloudwatch_event_bus", "Name"),
         "AWS::Kinesis::Stream": ("aws_kinesis_stream", "Name")}


def _last(pid):
    """A queue's name from its URL, a topic's from its ARN, a stream's from its Ref (its name); a bus's Name is
    required."""
    return str(pid).replace(":", "/").rsplit("/", 1)[-1] if pid else None


def _carriers(declared, names):
    return [(tf, {"arn": names.get(f"{lid}.Arn") or (pid if str(pid).startswith("arn:") else None),
                  "name": p.get(name) or _last(pid), "tags": tag_map(p.get("Tags"))})
            for lid, t, p, _, pid in declared if t in NAMES for tf, name in (NAMES[t],)]


def _identities(declared, names):
    return [("aws_sesv2_email_identity", {"arn": stack_arn(names, "ses", f"identity/{identity}"),
                                          "email_identity": identity, "tags": tag_map(p.get("Tags"))})
            for _, t, p, _, pid in declared if t == "AWS::SES::EmailIdentity"
            for identity in (p.get("EmailIdentity") or pid,)]


def messaging_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of the queues, topics, event buses, data streams and SES identities
    among a stack's declared resources ((logical ID, type, resolved properties, raw properties, physical ID), ...);
    names: what references resolve to ('<logical ID>.Arn', the stack's pseudo parameters)."""
    return [*_carriers(declared, names), *_identities(declared, names)]
