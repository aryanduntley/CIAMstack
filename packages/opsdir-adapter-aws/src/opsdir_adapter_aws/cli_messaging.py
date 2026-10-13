"""The messaging outputs of the AWS CLI, normalized to the attribute names of the matching Terraform resources
(opsdir_adapter_aws.inventory reads both: stream carriers, sending identities). Pure. SNS topics are read with the
monitoring outputs (cli_monitor.py).

  sqs get-queue-attributes --attribute-names QueueArn
                                          QueueArn (projected), or  -> aws_sqs_queue (its name from its ARN)
                                          Attributes {QueueArn}
  sqs list-queue-tags                     Tags (a map)              -> a queue's tags; the output doesn't name the
                                                                       queue: save it as queue-tags/<queue name>.json
  events list-event-buses                 EventBuses                -> aws_cloudwatch_event_bus
  events list-tags-for-resource           Tags                      -> a bus's tags; save it as event-bus-tags/<bus
                                                                       name, percent-encoded>.json
  kinesis list-streams                    StreamSummaries           -> aws_kinesis_stream (deleting ones skipped)
  kinesis list-tags-for-resource          Tags                      -> a stream's tags; save it as stream-tags/<stream
                                                                       name>.json
  sesv2 get-email-identity                DkimAttributes            -> aws_sesv2_email_identity (its DKIM status, tags);
                                                                       the output doesn't name the identity: save it
                                                                       as email-identities/<identity>.json. Its ARN
                                                                       is in the environment's partition, region and
                                                                       account (cli_outputs.home_of): the output
                                                                       holds none
"""
from .cli_outputs import documents, folder_tags, home_of, items, named, tags_of, under

KEYS = ("QueueArn", "EventBuses", "StreamSummaries", "DkimAttributes")
TAGS = ("queue-tags", "event-bus-tags", "stream-tags")


def is_messaging_tags(path):
    """Whether a file is a queue's, event bus's or stream's tags (saved under queue-tags/, event-bus-tags/ or
    stream-tags/)."""
    return any(under(path, t) for t in TAGS)


def _queues(outs):
    tags = folder_tags(outs, "queue-tags")
    arns = [*(doc.get("QueueArn") for _, doc in documents(outs, "QueueArn")),
            *(doc["Attributes"].get("QueueArn") for _, doc in documents(outs, "Attributes")
              if isinstance(doc.get("Attributes"), dict))]
    return [("aws_sqs_queue", {"arn": arn, "name": name, "tags": tags.get(name, {})})
            for arn in dict.fromkeys(a for a in arns if a) for name in (arn.rsplit(":", 1)[-1],)]


def _buses(outs):
    tags = folder_tags(outs, "event-bus-tags")
    return [("aws_cloudwatch_event_bus", {"arn": b.get("Arn"), "name": b.get("Name"),
                                          "tags": tags.get(b.get("Name"), {})})
            for b in items(outs, "EventBuses") if b.get("Arn")]


def _streams(outs):
    tags = folder_tags(outs, "stream-tags")
    return [("aws_kinesis_stream", {"arn": s.get("StreamARN"), "name": s.get("StreamName"),
                                    "tags": tags.get(s.get("StreamName"), {})})
            for s in items(outs, "StreamSummaries") if s.get("StreamARN") and s.get("StreamStatus") != "DELETING"]


def _identities(outs):
    """(pairs, notices): SES identities; without an ARN of the environment's to place them by, they are named."""
    found = [(named(p), doc) for p, doc in documents(outs, "DkimAttributes") if under(p, "email-identities")]
    home = home_of(outs)
    if found and not home:
        return [], (f"sesv2: {len(found)} identity(ies) without an ARN of the environment's (no subnets listed) to "
                    f"tell their ARNs by; not read",)
    return [("aws_sesv2_email_identity", {
                "arn": f"arn:{home[0]}:ses:{home[1]}:{home[2]}:identity/{name}", "email_identity": name,
                "dkim_signing_attributes": [{"status": (doc.get("DkimAttributes") or {}).get("Status")}],
                "tags": tags_of(doc.get("Tags"))})
            for name, doc in found], ()


def messaging_pairs(outs):
    """(pairs, notices): the SQS queues, EventBridge buses, Kinesis streams and SES identities, with their tags."""
    identities, notices = _identities(outs)
    return [*_queues(outs), *_buses(outs), *_streams(outs), *identities], notices
