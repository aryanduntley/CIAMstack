"""CloudWatch Logs forwarded on to a SIEM (core observability: a log destination's ciamForwardsToRole, milestone 109,
decision 3301; research docs/research m109b). Pure.

A log group this environment renders (observability.render_log_groups) whose binding forwards to a SIEM index is
subscribed to an Amazon Data Firehose delivery stream that pushes its logs to the index's intake (ciamIntakeUrl):
  aws_cloudwatch_log_subscription_filter   every event of the group (empty pattern) to the stream, through a role
                                           CloudWatch Logs assumes (firehose:PutRecord and PutRecordBatch on the
                                           stream; trust limited to this account's log groups when the cloud records
                                           its account and region)
  aws_kinesis_firehose_delivery_stream     splunk (an index the Splunk adapter keeps: HEC endpoint type Raw, the
                                           CloudWatch envelope decompressed, kept whole) or http_endpoint (an index
                                           the Elastic adapter keeps: Elastic's Firehose intake), the credential read
                                           by Firehose from the Secrets Manager secret the index's ciamCredentialRole
                                           references (secrets_manager_configuration: no token in the render or the
                                           Terraform state; the secret holds {"hec_token": ...} for Splunk,
                                           {"api_key": ...} for Elastic), events it can't deliver kept in the S3
                                           location the log group's ciamStorageRef names
  aws_iam_role (+ policy)                  what Firehose assumes: the secret (and its customer managed key when the
                                           secret binding records one: ciamEncryptedByRole), the backup bucket
What a person does is a render note: the SIEM team puts the credential in the secret (and, for Splunk, turns on
indexer acknowledgment for the HEC token Firehose uses). A forwarding the render can't express (no intake URL, no
credential or backup location, a credential that isn't an aws-sm:// reference, an index no adapter here keeps as
Splunk or Elastic, a log group someone else keeps) is a blocker note instead.
"""
import json
import re

from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.core.notes import note, note_comment
from opsdir.domains.observability.realized import keeper_of
from opsdir.domains.observability.siem import forwardings, is_siem
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import account_id, govcloud, partition
from .observability import LOG_GROUP, group_name

STREAM = "aws_kinesis_firehose_delivery_stream"
FILTER = "aws_cloudwatch_log_subscription_filter"
AREA = "Logs"
SPLUNK, ELASTIC = "splunk", "elastic"          # the SIEM adapters whose intake Firehose delivers to natively
SECRET_KEYS = {SPLUNK: "hec_token", ELASTIC: "api_key"}     # the secret's JSON key Firehose reads (AWS's formats)
CREDENTIALS = {SPLUNK: "HEC token (indexer acknowledgment on)", ELASTIC: "API key"}


def _policy(statements):
    return json.dumps({"Version": "2012-10-17", "Statement": statements}, separators=(",", ":"))


def _trust(service, condition=None):
    return _policy([{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole",
                     **({"Condition": condition} if condition else {})}])


def _name(m, b):
    """The stream's name: ciam-<env>-<destination>-siem in Firehose's characters, at most 64."""
    return re.sub(r"[^A-Za-z0-9_.-]", "-", f"ciam-{rdn_value(m.env)}-{rdn_value(b)}-siem")[:64]


def _bucket(location):
    """(bucket, prefix) of an s3:// location, or None."""
    if not (location or "").startswith("s3://") or len(location) <= 5:
        return None
    bucket, _, prefix = location[5:].partition("/")
    return bucket, prefix


def _secret(m, to):
    """The aws-sm:// secret binding the index's ciamCredentialRole names, or None."""
    s = one_role(m, one(to, "ciamCredentialRole") or "")
    return s if s is not None and (one(s, "ciamRefUri") or "").startswith("aws-sm://") else None


def lacking(m, b, to, keeper):
    """What a forwarding of log destination b to index to (kept by adapter keeper) lacks to be rendered, in words."""
    return tuple(why for why, missing in (
        ("its log group isn't rendered here (someone else keeps it, or its ciamProviderRef isn't a log group ARN)",
         keeper_of(m, b) is not None or group_name(b) is None),
        (f"an index this environment's Splunk or Elastic adapter keeps (it's {keeper or 'kept by none'})",
         keeper not in SECRET_KEYS),
        (f"an intake URL on {rdn_value(to)} (ciamIntakeUrl, https)", not (one(to, "ciamIntakeUrl") or "")
         .startswith("https://")),
        (f"a credential on {rdn_value(to)} (ciamCredentialRole naming an aws-sm:// secret reference)",
         _secret(m, to) is None),
        (f"where undeliverable events go (ciamStorageRef s3://bucket[/prefix] on {rdn_value(b)})",
         _bucket(one(b, "ciamStorageRef")) is None)) if missing)


def _destination(m, to, keeper, role, backup, secret):
    """The stream's destination block: Splunk HEC or Elastic's http endpoint, with the secret and the backup."""
    bucket, prefix = backup
    s3 = ("s3_configuration", Block((("role_arn", ref(f"aws_iam_role.{role}.arn")),
                                     ("bucket_arn", f"arn:{partition(m)}:s3:::{bucket}"),
                                     *((("prefix", prefix.rstrip("/") + "/"),) if prefix else ()))))
    secrets = ("secrets_manager_configuration", Block((
        ("enabled", True), ("secret_arn", ref(f"data.aws_secretsmanager_secret.{tf_name(secret)}.arn")),
        ("role_arn", ref(f"aws_iam_role.{role}.arn")))))
    if keeper == SPLUNK:
        return ("splunk_configuration", Block((
            ("hec_endpoint", one(to, "ciamIntakeUrl")), ("hec_endpoint_type", "Raw"),
            ("s3_backup_mode", "FailedEventsOnly"), s3, secrets,
            ("processing_configuration", Block((("enabled", True), ("processors", Block((
                ("type", "Decompression"), ("parameters", Block((("parameter_name", "CompressionFormat"),
                                                                 ("parameter_value", "GZIP")))))))))))))
    return ("http_endpoint_configuration", Block((
        ("url", one(to, "ciamIntakeUrl")), ("name", "Elastic"), ("role_arn", ref(f"aws_iam_role.{role}.arn")),
        ("s3_backup_mode", "FailedDataOnly"), s3, secrets,
        ("request_configuration", Block((("content_encoding", "GZIP"),))))))


def _forward(m, b, to, keeper):
    n, group = tf_name(rdn_value(b)), f"{LOG_GROUP}.{tf_name(rdn_value(b))}"
    secret_binding = _secret(m, to)
    secret_role = one(secret_binding, "ciamBindingRole")
    bucket, prefix = _bucket(one(b, "ciamStorageRef"))
    key = one_role(m, one(secret_binding, "ciamEncryptedByRole") or "")
    key_arn = (one(key, "ciamRefUri") or "").split("://", 1)[-1] if key is not None else None
    region, account = one(m.cloud, "ciamRegion"), account_id(m)
    source = ({"ArnLike": {"aws:SourceArn": f"arn:{partition(m)}:logs:{region}:{account}:*"}}
              if region and account else None)
    stream_arn = f"${{{STREAM}.{n}.arn}}"
    firehose = [
        {"Sid": "ReadIntakeCredential", "Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
         "Resource": [f"${{data.aws_secretsmanager_secret.{tf_name(secret_role)}.arn}}"]},
        *([{"Sid": "DecryptIntakeCredential", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": [key_arn]}]
          if key_arn else []),
        {"Sid": "KeepUndelivered", "Effect": "Allow",
         "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket",
                    "s3:ListBucketMultipartUploads", "s3:PutObject"],
         "Resource": [f"arn:{partition(m)}:s3:::{bucket}", f"arn:{partition(m)}:s3:::{bucket}/*"]}]
    return (
        tf_block("resource", ["aws_iam_role", f"{n}_firehose"], [
            ("name", f"{_name(m, b)}-firehose"[:64]), ("assume_role_policy", _trust("firehose.amazonaws.com"))]),
        tf_block("resource", ["aws_iam_role_policy", f"{n}_firehose"], [
            ("name", "siem-delivery"), ("role", ref(f"aws_iam_role.{n}_firehose.id")), ("policy", _policy(firehose))]),
        tf_block("resource", [STREAM, n], [
            ("name", _name(m, b)), ("destination", "splunk" if keeper == SPLUNK else "http_endpoint"),
            _destination(m, to, keeper, f"{n}_firehose", (bucket, prefix), secret_role),
            ("tags", {"BindingRole": one(b, "ciamBindingRole"), "ForwardsTo": one(b, "ciamForwardsToRole")})]),
        tf_block("resource", ["aws_iam_role", f"{n}_to_firehose"], [
            ("name", f"{_name(m, b)}-logs"[:64]), ("assume_role_policy", _trust("logs.amazonaws.com", source))]),
        tf_block("resource", ["aws_iam_role_policy", f"{n}_to_firehose"], [
            ("name", "siem-subscription"), ("role", ref(f"aws_iam_role.{n}_to_firehose.id")),
            ("policy", _policy([{"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                                 "Resource": [stream_arn]}]))]),
        tf_block("resource", [FILTER, n], [
            ("name", f"to-{one(b, 'ciamForwardsToRole')}"), ("log_group_name", ref(f"{group}.name")),
            ("filter_pattern", ""), ("destination_arn", ref(f"{STREAM}.{n}.arn")),
            ("role_arn", ref(f"aws_iam_role.{n}_to_firehose.arn"))]))


def _ours(m, services):
    """(log destination, SIEM index, keeper) of environment m's forwardings to a SIEM index."""
    return tuple((b, to, services.siem_keeper(m, to) if services else None) for b, to in forwardings(m)
                 if to is not None and is_siem(to) and one(b, "ciamDestinationKind") == "log-group")


def render_siem_forwarding(m, services):
    """HCL (and comments) for environment m's log groups forwarded on to a SIEM index, each stamped with its log
    destination's entry; a forwarding it can't render as its blocker note's comment."""
    return tuple(x for b, to, keeper in _ours(m, services) for x in from_entry(b.dn, (
        (comment(note_comment(_blocked(m, b, to, keeper))),) if lacking(m, b, to, keeper)
        else _forward(m, b, to, keeper))))


def _blocked(m, b, to, keeper):
    return note(AREA, "blocker", f"log destination {rdn_value(b)}",
                f"not forwarded to {rdn_value(to)}: it needs {'; '.join(lacking(m, b, to, keeper))}",
                ("Record what is missing, or ship the logs to the SIEM another way (its forwarder or agent)",),
                b.dn, m.label)


def siem_forwarding_notes(m, services):
    """The render notes of environment m's forwardings: a blocker for each the render can't express; for each
    rendered, the credential the SIEM team puts in the secret (and in GovCloud, that the FIPS endpoint Firehose itself
    uses for the secret and the intake isn't established)."""
    return tuple(n for b, to, keeper in _ours(m, services) for n in (
        (_blocked(m, b, to, keeper),) if lacking(m, b, to, keeper) else (
            note(AREA, "action", f"log destination {rdn_value(b)} forwarding",
                 f"Firehose reads the credential for {rdn_value(to)} from {one(_secret(m, to), 'ciamRefUri')}: "
                 f"the secret must hold {{\"{SECRET_KEYS[keeper]}\": ...}}",
                 (f"Ask the SIEM team to store the {CREDENTIALS[keeper]} in that secret, in the stream's region",),
                 b.dn, m.label),
            *((note(AREA, "note", f"log destination {rdn_value(b)} forwarding",
                    "in GovCloud, whether Firehose reaches the secret and the intake through FIPS endpoints isn't "
                    "established (AWS documents Firehose there with no differences)",
                    ("Confirm with AWS if the intake must be reached over FIPS-validated endpoints",), b.dn, m.label),)
              if govcloud(m) else ()))))
