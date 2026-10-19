"""The Splunk Add-on for AWS's SQS-based S3 inputs for the forwardings the AWS adapter delivers through S3 and SQS
instead of Firehose pushing to the index (user decision 2026-10-19, note 3538 item 2: opsdir-adapter-aws siem_pull).
Pure.

A log group of an AWS environment forwarded to a Splunk index this add-on keeps (core siem.forwardings), which the
AWS adapter's estate setting aws-siem-delivery maps to s3-sqs and whose aws-siem-pull-principal names who the add-on
runs as, is pulled by the add-on: Firehose writes the log group's events to S3, the bucket's notifications go to an
SQS queue, and the add-on, assuming a read-only role, reads each notified object into the index. Rendered for the add-on
in an app of its own (opsdir_ciam_aws: installed where the add-on runs its inputs, not with opsdir_ciam on the indexers
and search heads), inputs.conf: a [aws_sqs_based_s3://<queue>] stanza per forwarding, with the fields of the add-on's
SQS-based S3 documentation (version 8.3.0, the one the stanza assumes: research m109b section 1 cites the page):
  aws_account        the add-on's account entry (estate setting splunk-aws-addon-account; left out when unset: an
                     action names it)
  aws_iam_role       the add-on's IAM role entry, named as the AWS adapter names the reader role
  sqs_queue_url      https://sqs.<region>.amazonaws.com/<account>/<queue>, sqs_queue_region its region
  s3_file_decoder    CustomLogs (the add-on has no CloudWatch Logs decoder for these objects), sourcetype
                     ciam:aws:cloudwatchlogs: each line an object holds is one CloudWatch Logs envelope (JSON), its
                     events in logEvents
  sqs_batch_size 10, interval 300, using_dlq 1 (the add-on's defaults), index, disabled 0

The settings and names are the AWS adapter's (aws-siem-delivery, aws-siem-pull-principal: <role>=<value>, an
environment's <cloud>/<environment>:<role> before the estate's; the queue and role names from the stream's), read here
by name so this add-on needs no AWS package. What the Splunk team still does is a render note: install the app and the
add-on, bind the role (the AWS adapter's action names it), split the envelopes into events (props.conf and
transforms.conf: CustomLogs doesn't parse), set the account; a forwarding whose cloud records no account or region (no
queue URL) is a blocker.
"""
import re
from collections import namedtuple

from opsdir.core.contract import Setting
from opsdir.core.directory import one, rdn_value
from opsdir.core.notes import note
from opsdir.core.settings import recorded_setting, setting_pairs, setting_value
from opsdir.domains.observability.siem import forwardings
from .naming import index_name

AWS_DELIVERY, AWS_PRINCIPAL = "aws-siem-delivery", "aws-siem-pull-principal"    # the AWS adapter's settings
PULL = "s3-sqs"
ADDON, ADDON_VERSION = "Splunk Add-on for AWS", "8.3.0"     # the version whose SQS-based S3 documentation it follows
AWS_APP = "opsdir_ciam_aws"                         # the app holding the add-on's inputs, where the add-on runs
AWS_APP_DIR = f"splunk/apps/{AWS_APP}/default"
AWS_INPUTS = f"{AWS_APP_DIR}/inputs.conf"
ADDON_ACCOUNT = Setting("splunk-aws-addon-account", "string", None,
                        f"The account entry (its name) in the {ADDON} that the SQS-based S3 inputs opsdir renders "
                        "use: the EC2 instance role or IAM identity the AWS adapter's aws-siem-pull-principal names, "
                        "which assumes each forwarding's read-only role")
SOURCETYPE = "ciam:aws:cloudwatchlogs"        # the envelopes' own: not _json, which other inputs use
DEFAULTS = (("sqs_batch_size", "10"), ("s3_file_decoder", "CustomLogs"), ("sourcetype", SOURCETYPE),
            ("interval", "300"), ("using_dlq", "1"))
_PRINCIPAL = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:(root|role/.+|user/.+)$")

# One forwarding the add-on pulls: its log destination and index, the queue's name and URL (None when the cloud
# records no account or region), its region, and the add-on's IAM role entry name.
PullInput = namedtuple("PullInput", ("destination", "index", "queue", "url", "region", "role"))


def mapped(m, name, b, to):
    """What the AWS adapter's mapping setting `name` gives the forwarding of log destination b to index to, as the
    AWS adapter reads it (siem_forwarding.chosen_for): <environment label>:<role> before <role>, b's role before
    to's, the first a key is mapped to; or None."""
    pairs, _ = setting_pairs(recorded_setting(m.d, name))
    found = {k: v for k, v in reversed(pairs)}
    roles = tuple(r for r in (one(b, "ciamBindingRole"), one(to, "ciamBindingRole")) if r)
    return next((found[k] for k in (*(f"{m.label}:{r}" for r in roles), *roles) if k in found), None)


def queue_name(m, b):
    """The SQS queue the AWS adapter renders for log destination b's pulled forwarding (siem_pull.queue_name: the
    delivery stream's name, ciam-<environment>-<destination>-siem, in SQS's characters)."""
    stream = re.sub(r"[^A-Za-z0-9_.-]", "-", f"ciam-{rdn_value(m.env)}-{rdn_value(b)}-siem")[:64]
    return re.sub(r"[^A-Za-z0-9_-]", "-", stream)


def _pull_input(m, b, to):
    region, account = one(m.cloud, "ciamRegion"), one(m.cloud, "ciamAccountRef")
    queue = queue_name(m, b)
    return PullInput(b, to, queue, f"https://sqs.{region}.amazonaws.com/{account}/{queue}" if region and account
                     else None, region, f"{queue}-reader"[:64])


def pull_inputs(m):
    """Environment m's PullInputs: its log groups (on AWS) forwarded to a Splunk index, mapped to s3-sqs, with a
    principal and an S3 location recorded (what the AWS adapter renders them from)."""
    return tuple(_pull_input(m, b, to) for b, to in forwardings(m)
                 if m.provider == "aws" and index_name(to) is not None
                 and one(b, "ciamDestinationKind") == "log-group" and mapped(m, AWS_DELIVERY, b, to) == PULL
                 and _PRINCIPAL.match(mapped(m, AWS_PRINCIPAL, b, to) or "")
                 and (one(b, "ciamStorageRef") or "").startswith("s3://"))


def input_stanza(x, account):
    """The add-on's inputs.conf stanza pulling PullInput x into its index, with the add-on's account entry when
    known."""
    return (f"aws_sqs_based_s3://{x.queue}",
            (*((("aws_account", account),) if account else ()), ("aws_iam_role", x.role),
             ("sqs_queue_url", x.url), ("sqs_queue_region", x.region), *DEFAULTS,
             ("index", index_name(x.index)), ("disabled", "0")))


def input_stanzas(m):
    """The stanzas of environment m's rendered PullInputs (those with a queue URL)."""
    account = setting_value(m.d, ADDON_ACCOUNT)
    return tuple(input_stanza(x, account) for x in pull_inputs(m) if x.url)


def aws_pull_notes(m):
    """The render notes of environment m's PullInputs: a blocker for each without a queue URL; when any is rendered,
    installing the app and the add-on, the account entry when splunk-aws-addon-account isn't set (actions), and
    splitting the envelopes into events (an action)."""
    found = pull_inputs(m)
    rendered = tuple(x for x in found if x.url)
    return (
        *(note("Logs", "blocker", f"Splunk input {x.queue}",
               f"{rdn_value(x.destination)}'s logs pulled into {index_name(x.index)} from S3 through SQS: no input "
               "rendered, the cloud records no account or region (ciamAccountRef, ciamRegion), so the queue's URL "
               "isn't known", ("Record the cloud's account and region",), x.destination.dn, m.label)
          for x in found if not x.url),
        *((note("Logs", "action", f"Splunk app {AWS_APP}",
                f"rendered for where the {ADDON} runs its inputs: SQS-based S3 inputs for "
                f"{', '.join(x.queue for x in rendered)} (fields as the add-on's {ADDON_VERSION} documentation names "
                "them)",
                (f"Install the {ADDON} {ADDON_VERSION} or later and the app on the heavy forwarder running it, or "
                 "create the inputs in the add-on's UI with these values (Splunk Cloud: its Inputs Data Manager)",
                 "Bind each input's IAM role entry as the AWS adapter's render note says"), None, m.label),
           *((note("Logs", "action", f"Splunk app {AWS_APP}",
                   f"the inputs name no aws_account: the {ADDON}'s account entry is the Splunk team's",
                   (f"Set the estate setting {ADDON_ACCOUNT.name} to the account entry's name and re-render, or "
                    "choose it on each input in the add-on",), None, m.label),)
             if not setting_value(m.d, ADDON_ACCOUNT) else ()),
           note("Logs", "action", f"Splunk app {AWS_APP}",
                "the CustomLogs decoder doesn't parse: each event the inputs index is one CloudWatch Logs envelope "
                "(JSON: logGroup, logStream, and the log events in logEvents)",
                (f"Have the Splunk team set how sourcetype {SOURCETYPE} is read (props.conf: KV_MODE = json for "
                 "its fields at search time, or transforms.conf splitting logEvents into events)",), None, m.label))
          if rendered else ()))
