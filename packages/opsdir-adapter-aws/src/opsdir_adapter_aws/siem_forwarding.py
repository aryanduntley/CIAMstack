"""CloudWatch Logs forwarded on to a SIEM (core observability: a log destination's ciamForwardsToRole, milestone 109,
decision 3301; research docs/research m109b). Pure.

A log group this environment renders (observability.render_log_groups) whose binding forwards to a SIEM index is
subscribed to an Amazon Data Firehose delivery stream that pushes its logs to the index's intake (ciamIntakeUrl):
  aws_cloudwatch_log_subscription_filter   every event of the group (empty pattern) to the stream, through a role
                                           CloudWatch Logs assumes (firehose:PutRecord and PutRecordBatch on the
                                           stream; trust limited to this account's log groups when the cloud records
                                           its account and region)
  aws_kinesis_firehose_delivery_stream     splunk (an index the Splunk adapter keeps: HEC endpoint type Raw at its
                                           Firehose endpoint, the CloudWatch envelope decompressed, kept whole) or
                                           http_endpoint (an index the Elastic adapter keeps: Elastic's Firehose
                                           intake), the credential read
                                           by Firehose from the Secrets Manager secret the index's ciamCredentialRole
                                           references (secrets_manager_configuration: no token in the render or the
                                           Terraform state; the secret holds {"hec_token": ...} for Splunk,
                                           {"api_key": ...} for Elastic), events it can't deliver kept in the S3
                                           location the log group's ciamStorageRef names
  aws_iam_role (+ policy)                  what Firehose assumes: the secret (and its customer managed key when the
                                           secret binding records one: ciamEncryptedByRole), the backup bucket
A Splunk index's Firehose endpoint isn't always its HEC (splunk_firehose_endpoint; research task 593: Splunk's
"Configure Amazon Kinesis Firehose" and "Set up and use HTTP Event Collector in Splunk Web"): Splunk Cloud Platform on
AWS takes Firehose at https://http-inputs-firehose-<stack>.splunkcloud.com:443 while its HEC is
http-inputs-<stack>.splunkcloud.com, so that endpoint is derived from the intake URL (one that already names a
Firehose host is used as it is); Splunk documents none for its other stacks (Google Cloud, Azure, FedRAMP on AWS
GovCloud: http-inputs.<stack>, trials), so for those the stack's Firehose endpoint must be recorded as the index's
ciamStreamIntakeUrl (where it takes a delivery stream's logs when that isn't its intake URL), else a blocker; any other
host is Splunk Enterprise's, sent to as the intake URL names it, Firehose taking the URL without a path. An index that
records ciamStreamIntakeUrl is sent to there as recorded (a note names it), whatever its intake URL, Elastic's too.

What a person does is a render note: the SIEM team puts the credential in the secret (and, for Splunk, turns on
indexer acknowledgment for the HEC token Firehose uses); for Splunk Enterprise, the load balancer Firehose needs in
front of the HEC. A forwarding the render can't express (no intake URL, no credential or backup location, a
credential that isn't an aws-sm:// reference, an index no adapter here keeps as Splunk or Elastic, a Splunk Cloud
stack with no documented Firehose endpoint and none recorded, a log group someone else keeps, a delivery the estate
setting names that isn't one) is a blocker note instead.

That push is the default delivery. The estate setting aws-siem-delivery (DELIVERY) chooses per log destination or
SIEM index, and per environment, the other: s3-sqs, pulled by the Splunk Add-on for AWS from S3 through an SQS queue
(siem_pull renders it; this module leaves those forwardings to it).
"""
import json
import re
from urllib.parse import urlsplit

from opsdir.core.contract import Setting
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.core.notes import note, note_comment
from opsdir.core.settings import setting_mapping
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
# Splunk Cloud Platform's domains; on AWS its HEC host is http-inputs-<stack>.splunkcloud.com and Firehose's
# http-inputs-firehose-<stack>.splunkcloud.com, on port 443 (Splunk's documented forms)
SPLUNK_CLOUD = ("splunkcloud.com", "splunkcloudgc.com")
_HEC_HOST = re.compile(r"^http-inputs-(?P<stack>[a-z0-9][a-z0-9-]*)\.splunkcloud\.com$")
FIREHOSE_HOST, FIREHOSE_PORT = "http-inputs-firehose-{}.splunkcloud.com", 443
DERIVED, AS_RECORDED, ENTERPRISE, UNDOCUMENTED = "derived", "as-recorded", "enterprise", "undocumented"
STREAM_INTAKE = "stream-intake"         # the index's ciamStreamIntakeUrl, as recorded
# How a forwarding is delivered (user decision 2026-10-19, note 3538; decision 3301 keeps Firehose push the default):
# pushed by Firehose to the index's intake, or pulled by the Splunk Add-on for AWS from S3 through an SQS queue
# (siem_pull: where replay matters, research m109b section 1)
FIREHOSE, PULL = "firehose", "s3-sqs"
DELIVERIES = (FIREHOSE, PULL)
DELIVERY = Setting("aws-siem-delivery", "string", None,
                   "How CloudWatch log groups forwarded on to a SIEM index get there, where not by Firehose pushing "
                   f"to the index's intake (the default): comma-separated <role>=<{'|'.join(DELIVERIES)}>, the role "
                   "a log destination's or a SIEM index's binding role (the log destination's first); "
                   "<cloud>/<environment>:<role> for one environment (before the estate's). s3-sqs: Firehose "
                   "delivers to S3, whose object notifications feed an SQS queue the Splunk Add-on for AWS pulls "
                   "from (replay; no intake credential)")


def iam_policy(statements):
    """An IAM policy document of statements, as compact JSON text."""
    return json.dumps({"Version": "2012-10-17", "Statement": statements}, separators=(",", ":"))


def service_trust(service, condition=None):
    """The trust policy letting an AWS service assume a role (under a condition when given)."""
    return iam_policy([{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole",
                        **({"Condition": condition} if condition else {})}])


def stream_name(m, b):
    """The stream's name: ciam-<env>-<destination>-siem in Firehose's characters, at most 64."""
    return re.sub(r"[^A-Za-z0-9_.-]", "-", f"ciam-{rdn_value(m.env)}-{rdn_value(b)}-siem")[:64]


def s3_location(location):
    """(bucket, prefix) of an s3:// location, or None."""
    if not (location or "").startswith("s3://") or len(location) <= 5:
        return None
    bucket, _, prefix = location[5:].partition("/")
    return bucket, prefix


def _secret(m, to):
    """The aws-sm:// secret binding the index's ciamCredentialRole names, or None."""
    s = one_role(m, one(to, "ciamCredentialRole") or "")
    return s if s is not None and (one(s, "ciamRefUri") or "").startswith("aws-sm://") else None


def _splunk_cloud(url):
    host = (urlsplit(url or "").hostname or "").lower()
    return any(host == d or host.endswith(f".{d}") for d in SPLUNK_CLOUD)


def stream_intake(to):
    """The https URL a SIEM index takes a delivery stream's logs at when it records one (ciamStreamIntakeUrl), or
    None."""
    url = one(to, "ciamStreamIntakeUrl") or ""
    return url if url.startswith("https://") else None


def splunk_firehose_endpoint(intake, stream=None):
    """(the URL Firehose sends a Splunk index's events to, how it was found) from its https stream intake URL
    (ciamStreamIntakeUrl: STREAM_INTAKE, as recorded) or else its intake URL (ciamIntakeUrl): DERIVED for Splunk
    Cloud Platform on AWS's HEC host (its Firehose host, port 443), AS_RECORDED for a host naming firehose,
    UNDOCUMENTED (None) for Splunk Cloud's other stacks, ENTERPRISE for any other host (the URL's scheme, host and
    port: Firehose takes no path); (None, None) for no https URL."""
    if (stream or "").startswith("https://"):
        return stream, STREAM_INTAKE
    parts = urlsplit(intake or "")
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host:
        return None, None
    origin = f"https://{parts.netloc}"
    found = _HEC_HOST.match(host)
    if found and not found["stack"].startswith("firehose-"):
        return f"https://{FIREHOSE_HOST.format(found['stack'])}:{FIREHOSE_PORT}", DERIVED
    if _splunk_cloud(intake):
        return (origin, AS_RECORDED) if "firehose" in host.split(".", 1)[0] else (None, UNDOCUMENTED)
    return origin, ENTERPRISE


def _splunk_endpoint(to):
    return splunk_firehose_endpoint(one(to, "ciamIntakeUrl"), stream_intake(to))


def _intake(to):
    """Where Firehose sends an Elastic index's logs: its stream intake URL, else its intake URL."""
    return stream_intake(to) or one(to, "ciamIntakeUrl")


def lacking(m, b, to, keeper):
    """What a forwarding of log destination b to index to (kept by adapter keeper) lacks to be rendered, in words."""
    chosen = delivery(m, b, to)
    return tuple(why for why, missing in (
        (f"a delivery aws-siem-delivery knows ({' or '.join(DELIVERIES)}; it says `{chosen}`)",
         chosen not in DELIVERIES),
        ("its log group isn't rendered here (someone else keeps it, or its ciamProviderRef isn't a log group ARN)",
         keeper_of(m, b) is not None or group_name(b) is None),
        (f"an index this environment's Splunk or Elastic adapter keeps (it's {keeper or 'kept by none'})",
         keeper not in SECRET_KEYS),
        (f"an intake URL on {rdn_value(to)} (ciamIntakeUrl, or ciamStreamIntakeUrl for the stream; https)",
         not (_intake(to) or "").startswith("https://")),
        (f"the stack's Firehose endpoint recorded as ciamStreamIntakeUrl on {rdn_value(to)}: Splunk documents one "
         f"only for Splunk Cloud Platform on AWS (http-inputs-firehose-<stack>.splunkcloud.com), not for this stack's "
         f"{_host(to)} (its HEC), so ask Splunk for the stack's Firehose endpoint",
         keeper == SPLUNK and _splunk_endpoint(to)[1] == UNDOCUMENTED),
        (f"a credential on {rdn_value(to)} (ciamCredentialRole naming an aws-sm:// secret reference)",
         _secret(m, to) is None),
        (f"where undeliverable events go (ciamStorageRef s3://bucket[/prefix] on {rdn_value(b)})",
         s3_location(one(b, "ciamStorageRef")) is None)) if missing)


def _host(to):
    return urlsplit(one(to, "ciamIntakeUrl") or "").hostname or ""


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
            ("hec_endpoint", _splunk_endpoint(to)[0]), ("hec_endpoint_type", "Raw"),
            ("s3_backup_mode", "FailedEventsOnly"), s3, secrets,
            ("processing_configuration", Block((("enabled", True), ("processors", Block((
                ("type", "Decompression"), ("parameters", Block((("parameter_name", "CompressionFormat"),
                                                                 ("parameter_value", "GZIP")))))))))))))
    return ("http_endpoint_configuration", Block((
        ("url", _intake(to)), ("name", "Elastic"), ("role_arn", ref(f"aws_iam_role.{role}.arn")),
        ("s3_backup_mode", "FailedDataOnly"), s3, secrets,
        ("request_configuration", Block((("content_encoding", "GZIP"),))))))


def bucket_statement(m, bucket, sid):
    """The IAM statement letting Firehose write to an S3 bucket (AWS's Firehose S3 permissions: research m109b)."""
    return {"Sid": sid, "Effect": "Allow",
            "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket",
                       "s3:ListBucketMultipartUploads", "s3:PutObject"],
            "Resource": [f"arn:{partition(m)}:s3:::{bucket}", f"arn:{partition(m)}:s3:::{bucket}/*"]}


def subscription(m, b):
    """HCL subscribing log destination b's log group to the delivery stream rendered for it (every event: an empty
    pattern), through a role CloudWatch Logs assumes: firehose:PutRecord and PutRecordBatch on the stream, its trust
    limited to this account's log groups when the cloud records its account and region."""
    n, group = tf_name(rdn_value(b)), f"{LOG_GROUP}.{tf_name(rdn_value(b))}"
    region, account = one(m.cloud, "ciamRegion"), account_id(m)
    source = ({"ArnLike": {"aws:SourceArn": f"arn:{partition(m)}:logs:{region}:{account}:*"}}
              if region and account else None)
    return (
        tf_block("resource", ["aws_iam_role", f"{n}_to_firehose"], [
            ("name", f"{stream_name(m, b)}-logs"[:64]),
            ("assume_role_policy", service_trust("logs.amazonaws.com", source))]),
        tf_block("resource", ["aws_iam_role_policy", f"{n}_to_firehose"], [
            ("name", "siem-subscription"), ("role", ref(f"aws_iam_role.{n}_to_firehose.id")),
            ("policy", iam_policy([{"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                                    "Resource": [f"${{{STREAM}.{n}.arn}}"]}]))]),
        tf_block("resource", [FILTER, n], [
            ("name", f"to-{one(b, 'ciamForwardsToRole')}"), ("log_group_name", ref(f"{group}.name")),
            ("filter_pattern", ""), ("destination_arn", ref(f"{STREAM}.{n}.arn")),
            ("role_arn", ref(f"aws_iam_role.{n}_to_firehose.arn"))]))


def _forward(m, b, to, keeper):
    n = tf_name(rdn_value(b))
    secret_binding = _secret(m, to)
    secret_role = one(secret_binding, "ciamBindingRole")
    bucket, prefix = s3_location(one(b, "ciamStorageRef"))
    key = one_role(m, one(secret_binding, "ciamEncryptedByRole") or "")
    key_arn = (one(key, "ciamRefUri") or "").split("://", 1)[-1] if key is not None else None
    firehose = [
        {"Sid": "ReadIntakeCredential", "Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
         "Resource": [f"${{data.aws_secretsmanager_secret.{tf_name(secret_role)}.arn}}"]},
        *([{"Sid": "DecryptIntakeCredential", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": [key_arn]}]
          if key_arn else []),
        bucket_statement(m, bucket, "KeepUndelivered")]
    return (
        tf_block("resource", ["aws_iam_role", f"{n}_firehose"], [
            ("name", f"{stream_name(m, b)}-firehose"[:64]),
            ("assume_role_policy", service_trust("firehose.amazonaws.com"))]),
        tf_block("resource", ["aws_iam_role_policy", f"{n}_firehose"], [
            ("name", "siem-delivery"), ("role", ref(f"aws_iam_role.{n}_firehose.id")),
            ("policy", iam_policy(firehose))]),
        tf_block("resource", [STREAM, n], [
            ("name", stream_name(m, b)), ("destination", "splunk" if keeper == SPLUNK else "http_endpoint"),
            _destination(m, to, keeper, f"{n}_firehose", (bucket, prefix), secret_role),
            ("tags", stream_tags(b))]),
        *subscription(m, b))


def stream_tags(b):
    """The tags of what a forwarding renders: its log destination's binding role and the index's role."""
    return {"BindingRole": one(b, "ciamBindingRole"), "ForwardsTo": one(b, "ciamForwardsToRole")}


def chosen_for(m, setting, b, to):
    """What a mapping setting (<role>=<value>, ...) gives the forwarding of log destination b to index to: the value
    of the first of <environment label>:<b's role>, <environment label>:<to's role>, b's role, to's role it maps
    (an environment's own entry before the estate's), or None."""
    pairs, _ = setting_mapping(m.d, setting)
    found = {k: v for k, v in reversed(pairs)}      # the first a role is mapped to, as setting_mapping reads them
    roles = (one(b, "ciamBindingRole"), one(to, "ciamBindingRole"))
    keys = (*(f"{m.label}:{r}" for r in roles if r), *(r for r in roles if r))
    return next((found[k] for k in keys if k in found), None)


def delivery(m, b, to):
    """How the forwarding of log destination b to index to is delivered: what aws-siem-delivery maps it to (FIREHOSE,
    PULL, or the unknown text it says), FIREHOSE when it maps nothing."""
    return chosen_for(m, DELIVERY, b, to) or FIREHOSE


def forwarded(m, services):
    """(log destination, SIEM index, keeper) of environment m's forwardings to a SIEM index, whatever their
    delivery."""
    return tuple((b, to, services.siem_keeper(m, to) if services else None) for b, to in forwardings(m)
                 if to is not None and is_siem(to) and one(b, "ciamDestinationKind") == "log-group")


def _ours(m, services):
    """(log destination, SIEM index, keeper) of environment m's forwardings this module renders: all but those
    pulled from S3 (siem_pull)."""
    return tuple(x for x in forwarded(m, services) if delivery(m, x[0], x[1]) != PULL)


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


def _endpoint_notes(m, b, to, keeper):
    """A rendered forwarding's endpoint notes: a recorded stream intake URL it sends to (a note; to a Splunk host
    outside Splunk Cloud, what Firehose needs of Splunk Enterprise too), where a derived Firehose endpoint departs
    from the intake URL (a note), what Firehose needs of a Splunk Enterprise intake (an action)."""
    stream = stream_intake(to)
    recorded = (note(AREA, "note", f"log destination {rdn_value(b)} forwarding",
                     f"Firehose sends to {stream}, the delivery-stream intake {rdn_value(to)} records "
                     "(ciamStreamIntakeUrl), as recorded", (), b.dn, m.label),) if stream else ()
    if keeper != SPLUNK:
        return recorded
    url, how = _splunk_endpoint(to)
    if how == STREAM_INTAKE:
        return (*recorded, *(() if _splunk_cloud(url) else (_enterprise(m, b, to, url, "stream intake URL"),)))
    if how == DERIVED:
        return (note(AREA, "note", f"log destination {rdn_value(b)} forwarding",
                     f"Firehose sends to {url}, Splunk Cloud Platform's Firehose endpoint for the stack whose HEC "
                     f"{rdn_value(to)}'s intake URL names ({_host(to)})", (), b.dn, m.label),)
    if how == ENTERPRISE:
        return (_enterprise(m, b, to, url, "intake URL"),)
    return ()


def _enterprise(m, b, to, url, which):
    """The action naming what Firehose needs of a Splunk Enterprise HEC it sends to at url (the index's `which`)."""
    return note(AREA, "action", f"log destination {rdn_value(b)} forwarding",
                f"Firehose sends to {url} ({rdn_value(to)}'s {which}) as Splunk Enterprise's HEC: Firehose needs it "
                "behind a Classic or Application Load Balancer, over HTTPS with a certificate a trusted CA signed for "
                "that host (self-signed isn't accepted), with duration-based sticky sessions",
                ("Ask the Splunk team to put the HEC behind such a load balancer (Classic: cookie expiration disabled; "
                 f"Application: stickiness duration 7 days) and record its URL as {rdn_value(to)}'s "
                 "ciamStreamIntakeUrl (collectors keep sending to the HEC at ciamIntakeUrl), or confirm the "
                 f"{which} already names it",), b.dn, m.label)


def siem_forwarding_notes(m, services):
    """The render notes of environment m's forwardings: a blocker for each the render can't express; for each
    rendered, the credential the SIEM team puts in the secret, the index's endpoint notes (_endpoint_notes), and
    in GovCloud, that the FIPS endpoint Firehose itself uses for the secret and the intake isn't established."""
    return tuple(n for b, to, keeper in _ours(m, services) for n in (
        (_blocked(m, b, to, keeper),) if lacking(m, b, to, keeper) else (
            note(AREA, "action", f"log destination {rdn_value(b)} forwarding",
                 f"Firehose reads the credential for {rdn_value(to)} from {one(_secret(m, to), 'ciamRefUri')}: "
                 f"the secret must hold {{\"{SECRET_KEYS[keeper]}\": ...}}",
                 (f"Ask the SIEM team to store the {CREDENTIALS[keeper]} in that secret, in the stream's region",),
                 b.dn, m.label),
            *_endpoint_notes(m, b, to, keeper),
            *((note(AREA, "note", f"log destination {rdn_value(b)} forwarding",
                    "in GovCloud, whether Firehose reaches the secret and the intake through FIPS endpoints isn't "
                    "established (AWS documents Firehose there with no differences)",
                    ("Confirm with AWS if the intake must be reached over FIPS-validated endpoints",), b.dn, m.label),)
              if govcloud(m) else ()))))


def setting_notes(m, services, settings):
    """A note per malformed part of the estate settings (mapping Settings) that choose how environment m's
    forwardings are delivered, when it forwards any: the part isn't read."""
    if not forwarded(m, services):
        return ()
    return tuple(note(AREA, "note", f"setting {s.name}", f"{problem}: that part isn't read",
                      (f"Correct the estate setting {s.name} (comma-separated <role>=<value>)",), None, m.label)
                 for s in settings for problem in setting_mapping(m.d, s)[1])
