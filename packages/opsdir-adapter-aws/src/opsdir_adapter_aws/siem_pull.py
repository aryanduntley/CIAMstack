"""CloudWatch Logs pulled into Splunk from S3 through SQS, the alternative to Firehose pushing to the index's intake
(user decision 2026-10-19, note 3538 item 2; decision 3301 keeps the push the default; research m109b section 1: "S3
alternative ... where replay and role-based collection dominate"). Pure.

A forwarding the estate setting aws-siem-delivery maps to s3-sqs (siem_forwarding.delivery), from a log group this
environment renders to an index the Splunk adapter keeps, is rendered as:
  aws_cloudwatch_log_subscription_filter (+ role)  as for the push (siem_forwarding.subscription)
  aws_kinesis_firehose_delivery_stream             extended_s3: the CloudWatch Logs hop to S3 the research says
                                                   notifications alone don't make, to the log destination's
                                                   ciamStorageRef (s3://bucket[/prefix]) under <prefix>/<role>/
                                                   (failures under <prefix>/<role>-failed/, outside what the queue
                                                   hears of), the envelope decompressed (AWS's Decompression
                                                   processor, as the push does) one per line (AppendDelimiterToRecord);
                                                   objects encrypted with the bucket's key when the record names one
  aws_iam_role (+ policy)                          what Firehose assumes: the bucket (and its key)
  aws_sqs_queue (+ dead-letter queue)              standard (the add-on takes no FIFO queue), SQS-managed encryption,
                                                   14 days' retention, visibility 5 minutes (the add-on asks for 5 or
                                                   more), a redrive policy sending a message received 5 times to the
                                                   dead-letter queue (the add-on asks for one)
  aws_sqs_queue_policy                             S3 may send to the queue, for this bucket (and account) only
  aws_s3_bucket_notification                       the bucket's object-created events under the prefix to the queue:
                                                   one resource per bucket, every pulled forwarding to it a queue block
  aws_iam_role (+ policy)                          the read-only role the add-on assumes: receive, delete and change
                                                   visibility of the queue's messages (and read both queues'
                                                   attributes: the add-on checks the dead-letter queue), get the
                                                   objects under the prefix, decrypt with the bucket's key when the
                                                   record names it; trusted by the one principal the estate setting
                                                   aws-siem-pull-principal names for the forwarding (the Splunk team's
                                                   identity: no credential in the render or the state)
The permissions follow the add-on's SQS-based S3 documentation (Splunk Add-on for AWS 8.3.0, read 2026-10-18), least
privilege: its sample's sqs:SendMessage and sqs:ListQueues on every resource aren't granted.

The bucket is the one the record names: an object store the stack keeps (ciamObjectStore naming it in ciamStorageRef,
rendered with its encryption by storage.py) is referred to as the resource, so CloudFormation writes the notification
into the bucket; any other is referred to by name, and the notification (which CloudFormation can only write on a
bucket its template holds) stays Terraform. What a person does is a render note: the Splunk team binds the role in the
add-on and creates the input (the Splunk adapter renders it), the bucket's keeper keeps its other notifications, and
in GovCloud the add-on's S3 host name; a forwarding the render can't express (an index the Splunk adapter doesn't keep,
no bucket, no principal, a log group someone else keeps) is a blocker.
"""
import re

from opsdir.core.contract import Setting
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import of_class
from opsdir.core.notes import note, note_comment
from opsdir.domains.observability.realized import keeper_of
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import account_id, govcloud, partition
from .observability import group_name
from .siem_forwarding import (AREA, DELIVERY, PULL, SPLUNK, STREAM, bucket_statement, chosen_for, delivery,
                              forwarded, iam_policy, s3_location, service_trust, setting_notes, stream_name,
                              stream_tags, subscription)
from .storage import bucket_of, key_arn, kept_buckets

PRINCIPAL = Setting("aws-siem-pull-principal", "string", None,
                    "Who may assume the read-only role the Splunk Add-on for AWS pulls a forwarding's logs from S3 "
                    "with (aws-siem-delivery s3-sqs): comma-separated <role>=<IAM principal ARN> (the identity the "
                    "add-on runs as: its EC2 instance role, or the role or user the Splunk team configures in it), "
                    "the role a log destination's or a SIEM index's binding role (the log destination's first); "
                    "<cloud>/<environment>:<role> for one environment (before the estate's)")
ADDON, ADDON_VERSION = "Splunk Add-on for AWS", "8.3.0"     # the version whose SQS-based S3 documentation it follows
VISIBILITY_SECONDS = 300            # the add-on: "Set your SQS visibility timeout to 5 minutes or longer"
RETENTION_SECONDS = 1209600         # SQS's longest retention (14 days): an outage of the add-on loses no message
MAX_RECEIVES = 5                    # receives before a message moves to the dead-letter queue
QUEUE, QUEUE_POLICY, NOTIFICATION = "aws_sqs_queue", "aws_sqs_queue_policy", "aws_s3_bucket_notification"
_PRINCIPAL = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:(root|role/.+|user/.+)$")


def queue_name(m, b):
    """The SQS queue the add-on pulls log destination b's forwarding from: the stream's name in SQS's characters."""
    return re.sub(r"[^A-Za-z0-9_-]", "-", stream_name(m, b))


def reader_role_name(m, b):
    """The IAM role the add-on assumes to pull log destination b's forwarding: <queue>-reader, at most 64."""
    return f"{queue_name(m, b)}-reader"[:64]


def queue_url(m, b):
    """The queue's URL (https://sqs.<region>.amazonaws.com/<account>/<queue>) when the cloud records its region and
    account, else None."""
    region, account = one(m.cloud, "ciamRegion"), account_id(m)
    return f"https://sqs.{region}.amazonaws.com/{account}/{queue_name(m, b)}" if region and account else None


def reader_role_arn(m, b):
    """The reader role's ARN when the cloud records its account, else None."""
    account = account_id(m)
    return f"arn:{partition(m)}:iam::{account}:role/{reader_role_name(m, b)}" if account else None


def pull_location(b):
    """(bucket, prefix) Firehose delivers log destination b's logs to and the queue hears of: its ciamStorageRef's
    bucket, under <its prefix>/<b's role>/; None when it names no S3 location."""
    found = s3_location(one(b, "ciamStorageRef"))
    if found is None:
        return None
    bucket, prefix = found
    return bucket, f"{prefix.strip('/') + '/' if prefix.strip('/') else ''}{one(b, 'ciamBindingRole')}/"


def principal(m, b, to):
    """The IAM principal ARN aws-siem-pull-principal names for the forwarding of b to to, or None (also when what it
    names isn't one)."""
    found = chosen_for(m, PRINCIPAL, b, to)
    return found if found and _PRINCIPAL.match(found) else None


def bucket_store(m, bucket):
    """The object store of environment m whose ciamStorageRef names bucket, or None."""
    return next((s for s in of_class(m, "ciamObjectStore") if bucket_of(one(s, "ciamStorageRef")) == bucket), None)


def bucket_key(m, bucket):
    """The KMS key ARN the record says bucket is encrypted with (its object store's ciamEncryptedByRole), or None."""
    store = bucket_store(m, bucket)
    return key_arn(m, store)[0] if store is not None else None


def pulled(m, services):
    """(log destination, SIEM index, keeper) of environment m's forwardings delivered by s3-sqs."""
    return tuple(x for x in forwarded(m, services) if delivery(m, x[0], x[1]) == PULL)


def lacking(m, b, to, keeper):
    """What a pulled forwarding of log destination b to index to (kept by adapter keeper) lacks to be rendered, in
    words."""
    return tuple(why for why, missing in (
        ("its log group isn't rendered here (someone else keeps it, or its ciamProviderRef isn't a log group ARN)",
         keeper_of(m, b) is not None or group_name(b) is None),
        (f"an index this environment's Splunk adapter keeps (the {ADDON} pulls from S3; it's "
         f"{keeper or 'kept by none'})", keeper != SPLUNK),
        (f"the bucket its logs land in (ciamStorageRef s3://bucket[/prefix] on {rdn_value(b)})",
         pull_location(b) is None),
        (f"who the add-on runs as (aws-siem-pull-principal naming an IAM principal ARN for {rdn_value(b)} or "
         f"{rdn_value(to)})", principal(m, b, to) is None)) if missing)


def _blocked(m, b, to, keeper):
    return note(AREA, "blocker", f"log destination {rdn_value(b)}",
                f"not forwarded to {rdn_value(to)} through S3 and SQS: it needs {'; '.join(lacking(m, b, to, keeper))}",
                ("Record what is missing, or deliver by Firehose push (map it to firehose in aws-siem-delivery)",),
                b.dn, m.label)


def _notified(m, bucket):
    """What a bucket's notification names it by: the stack's own object store resource (CloudFormation then writes
    the notification into the bucket), else its name."""
    store = next((s for s in kept_buckets(m) if bucket_of(one(s, "ciamStorageRef")) == bucket), None)
    return ref(f"aws_s3_bucket.{tf_name(rdn_value(store))}.id") if store is not None else bucket


def _pull(m, b, to):
    n = tf_name(rdn_value(b))
    bucket, prefix = pull_location(b)
    key = bucket_key(m, bucket)
    p, account = partition(m), account_id(m)
    queue_arn, dlq_arn = f"${{{QUEUE}.{n}.arn}}", f"${{{QUEUE}.{n}_dlq.arn}}"
    kms = [{"Sid": "EncryptLogObjects", "Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
            "Resource": [key]}] if key else []
    source = {"ArnLike": {"aws:SourceArn": f"arn:{p}:s3:::{bucket}"},
              **({"StringEquals": {"aws:SourceAccount": account}} if account else {})}
    reader = [
        {"Sid": "ReceiveNotifications", "Effect": "Allow",
         "Action": ["sqs:ChangeMessageVisibility", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl",
                    "sqs:ReceiveMessage"], "Resource": [queue_arn]},
        {"Sid": "CheckDeadLetters", "Effect": "Allow", "Action": ["sqs:GetQueueAttributes", "sqs:GetQueueUrl"],
         "Resource": [dlq_arn]},
        {"Sid": "ReadLogObjects", "Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
         "Resource": [f"arn:{p}:s3:::{bucket}/{prefix}*"]},
        *([{"Sid": "DecryptLogObjects", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": [key]}]
          if key else [])]
    gzip = Block((("parameter_name", "CompressionFormat"), ("parameter_value", "GZIP")))
    processors = (("processors", Block((("type", "Decompression"), ("parameters", gzip)))),
                  ("processors", Block((("type", "AppendDelimiterToRecord"),))))
    return (
        tf_block("resource", ["aws_iam_role", f"{n}_firehose"], [
            ("name", f"{stream_name(m, b)}-firehose"[:64]),
            ("assume_role_policy", service_trust("firehose.amazonaws.com"))]),
        tf_block("resource", ["aws_iam_role_policy", f"{n}_firehose"], [
            ("name", "siem-delivery-s3"), ("role", ref(f"aws_iam_role.{n}_firehose.id")),
            ("policy", iam_policy([bucket_statement(m, bucket, "DeliverLogObjects"), *kms]))]),
        tf_block("resource", [STREAM, n], [
            ("name", stream_name(m, b)), ("destination", "extended_s3"),
            ("extended_s3_configuration", Block((
                ("role_arn", ref(f"aws_iam_role.{n}_firehose.arn")), ("bucket_arn", f"arn:{p}:s3:::{bucket}"),
                ("prefix", prefix), ("error_output_prefix", f"{prefix.rstrip('/')}-failed/"),
                *((("kms_key_arn", key),) if key else ()),
                ("processing_configuration", Block((("enabled", True), *processors)))))),
            ("tags", stream_tags(b))]),
        *subscription(m, b),
        tf_block("resource", [QUEUE, f"{n}_dlq"], [
            ("name", f"{queue_name(m, b)}-dlq"), ("message_retention_seconds", RETENTION_SECONDS),
            ("sqs_managed_sse_enabled", True), ("tags", stream_tags(b))]),
        tf_block("resource", [QUEUE, n], [
            ("name", queue_name(m, b)), ("visibility_timeout_seconds", VISIBILITY_SECONDS),
            ("message_retention_seconds", RETENTION_SECONDS), ("sqs_managed_sse_enabled", True),
            ("redrive_policy", f'{{"deadLetterTargetArn":"{dlq_arn}","maxReceiveCount":{MAX_RECEIVES}}}'),
            ("tags", stream_tags(b))]),
        tf_block("resource", [QUEUE_POLICY, n], [
            ("queue_url", ref(f"{QUEUE}.{n}.id")),
            ("policy", iam_policy([{"Sid": "BucketNotifications", "Effect": "Allow",
                                    "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sqs:SendMessage",
                                    "Resource": queue_arn, "Condition": source}]))]),
        tf_block("resource", ["aws_iam_role", f"{n}_reader"], [
            ("name", reader_role_name(m, b)),
            ("assume_role_policy", iam_policy([{"Effect": "Allow", "Principal": {"AWS": principal(m, b, to)},
                                                "Action": "sts:AssumeRole"}])),
            ("tags", stream_tags(b))]),
        tf_block("resource", ["aws_iam_role_policy", f"{n}_reader"], [
            ("name", "siem-pull"), ("role", ref(f"aws_iam_role.{n}_reader.id")), ("policy", iam_policy(reader))]))


def _notifications(m, rendered):
    """One aws_s3_bucket_notification per bucket the rendered forwardings land in (S3 keeps one notification
    configuration per bucket), a queue block per forwarding, stamped with the first forwarding's entry."""
    buckets = tuple(dict.fromkeys(pull_location(b)[0] for b, _ in rendered))
    return tuple(x for bucket in buckets for mine in ((tuple(b for b, _ in rendered
                                                             if pull_location(b)[0] == bucket)),)
                 for x in from_entry(mine[0].dn, (tf_block("resource", [NOTIFICATION, f"siem_{tf_name(bucket)}"], [
                     ("bucket", _notified(m, bucket)),
                     *(("queue", Block((("queue_arn", ref(f"{QUEUE}.{tf_name(rdn_value(b))}.arn")),
                                        ("events", ["s3:ObjectCreated:*"]),
                                        ("filter_prefix", pull_location(b)[1])))) for b in mine),
                     ("depends_on", [ref(f"{QUEUE_POLICY}.{tf_name(rdn_value(b))}") for b in mine])]),)))


def render_siem_pull(m, services):
    """HCL (and comments) for environment m's forwardings pulled from S3 through SQS, each stamped with its log
    destination's entry, then the buckets' notifications; one it can't render as its blocker note's comment."""
    found = pulled(m, services)
    rendered = tuple((b, to) for b, to, keeper in found if not lacking(m, b, to, keeper))
    return (*(x for b, to, keeper in found for x in from_entry(b.dn, (
                (comment(note_comment(_blocked(m, b, to, keeper))),) if lacking(m, b, to, keeper)
                else _pull(m, b, to)))),
            *_notifications(m, rendered))


def _where(m, b):
    url = queue_url(m, b)
    return f"queue {queue_name(m, b)}" + (f" ({url})" if url else "")


def _rendered_notes(m, b, to):
    """A rendered pulled forwarding's notes: what the Splunk team binds in the add-on (an action), the bucket's
    notification configuration when the stack doesn't keep the bucket (an action), its encryption when the record
    doesn't say (a note), the dead-letter queue (a note), and GovCloud's endpoints (an action, a note)."""
    bucket, prefix = pull_location(b)
    role = reader_role_arn(m, b) or f"role {reader_role_name(m, b)} (this account)"
    who = f"log destination {rdn_value(b)} forwarding"
    return (
        note(AREA, "action", who,
             f"the {ADDON} pulls {rdn_value(to)}'s logs from {_where(m, b)}, reading s3://{bucket}/{prefix}, as "
             f"{role}, which only {principal(m, b, to)} may assume: no credential is in the render or the state",
             (f"Ask the Splunk team to install the {ADDON} (the input assumes {ADDON_VERSION}) where its inputs run "
              "(a heavy forwarder, or Splunk Cloud's Inputs Data Manager)",
              f"In the add-on, add an IAM role entry named {reader_role_name(m, b)} for {role} and use it from an "
              f"account entry that authenticates as {principal(m, b, to)} (its EC2 instance role or that identity)",
              "Create the SQS-based S3 input the Splunk adapter renders for it (or in the add-on's UI with its "
              "values)"), b.dn, m.label),
        *((note(AREA, "action", who,
                f"the render's aws_s3_bucket_notification is the whole notification configuration of {bucket}, "
                "which this stack doesn't keep: applying it replaces any other notifications the bucket sends",
                (f"Ask the keeper of {bucket} whether it sends other notifications; if so, add them to that resource, "
                 "or have the stack keep the bucket (an object store in the record)",), b.dn, m.label),)
          if bucket_store(m, bucket) not in kept_buckets(m) else ()),
        *((note(AREA, "note", who,
                f"how {bucket} encrypts isn't in the record (no object store naming it with ciamEncryptedByRole): "
                "objects land with the bucket's default encryption, and no KMS permission is rendered for Firehose "
                "or the reader role",
                (f"Record {bucket} as an object store with its key role if a customer managed key encrypts it",),
                b.dn, m.label),) if bucket_key(m, bucket) is None else ()),
        note(AREA, "note", who,
             f"a notification the add-on fails to process {MAX_RECEIVES} times moves to {queue_name(m, b)}-dlq "
             f"(kept 14 days); the objects stay in s3://{bucket}/{prefix} to be replayed", (), b.dn, m.label),
        *((note(AREA, "action", who,
                f"in GovCloud, Splunk documents adding the GovCloud S3 endpoint in the {ADDON}'s S3 Host Name field; "
                "whether the add-on reaches SQS, S3 and STS through FIPS endpoints isn't established",
                ("Ask the Splunk team to set the input's S3 host name to the GovCloud endpoint, and confirm with "
                 "Splunk which endpoints the add-on uses if FIPS-validated endpoints are required",), b.dn, m.label),
           note(AREA, "note", who,
                "in GovCloud, whether Firehose reaches S3 through FIPS endpoints isn't established (AWS documents "
                "Firehose there with no differences)", (), b.dn, m.label)) if govcloud(m) else ()))


def siem_pull_notes(m, services):
    """The render notes of environment m's forwardings pulled from S3 through SQS: what in the delivery settings
    isn't read (siem_forwarding.setting_notes), a blocker for each the render can't express, the notes of each
    rendered (_rendered_notes)."""
    return (*setting_notes(m, services, (DELIVERY, PRINCIPAL)),
            *(n for b, to, keeper in pulled(m, services) for n in (
                (_blocked(m, b, to, keeper),) if lacking(m, b, to, keeper) else _rendered_notes(m, b, to))))
