"""Data discovery on AWS (core estate: ciamDataDiscovery) as Amazon Macie. Pure.

Rendered in the platform's own root, for each data discovery the platform team keeps (one someone else keeps is named
in a comment): Macie for the account (aws_macie2_account, enabled, findings published every fifteen minutes), an
aws_macie2_custom_data_identifier per own data type (its name and regular expression), and a scheduled
aws_macie2_classification_job over the S3 buckets of the object stores it examines, in the account the cloud records,
with those identifiers. A store that isn't an S3 bucket is named in a comment (Macie examines S3 only). Its findings go
where ciamFindingsRole says through an EventBridge rule (source aws.macie, detail-type Macie Finding), as the security
services' do; its detailed results to the S3 bucket of the object store ciamResultsRole names
(aws_macie2_classification_export_configuration, with that store's KMS key, which Macie requires).

How often is the record's ciamRescanDays, never rounded (core estate discovery: rescan_plan). Macie's own schedule runs
daily or weekly (monthly is a day of the month, not every 30 days): 1 or 7 days (or none recorded: weekly) is the
scheduled job's. Any other interval is a scheduler: an EventBridge Scheduler schedule (aws_scheduler_schedule, daily)
invokes a Lambda function (aws_lambda_function, python3.14, terraform/discovery/<name>/handler.py zipped by the archive
provider) that starts a ONE_TIME classification job over the same buckets and identifiers, named '<service>:<UTC time>',
once that many calendar days have passed since the last successful one (COMPLETE, lastRunErrorStatus NONE; nothing
while one is unfinished), the rule of core estate discovery's rescan_due. Least privilege: the function's role may
create and describe classification jobs, list them, and write its own log group; the scheduler's role (trusted by
scheduler.amazonaws.com for the account's default schedule group) may only invoke the function. The function's
environment and tags (Realizes, RescanDays) say what it runs, so the reader recovers the interval; the plan names which
mechanism applies (check_discovery_availability's OK line).

In GovCloud (a us-gov- region) nothing is rendered for Macie, only a comment, and the check gives an action, or a
blocker where the environment's data is restricted (as for a missing data discovery): AWS's General Reference lists no
GovCloud endpoint for Amazon Macie and its FedRAMP services-in-scope page marks it for US East/West only (research note
2492, decision 2493).

Read back from Terraform state: aws_macie2_classification_job (its buckets as the stores examined, its schedule as
days, its custom identifiers by name and regular expression from aws_macie2_custom_data_identifier), or the scheduler's
function (tag RescanDays; its environment's buckets, interval and identifier ids), with the EventBridge rule's target
for aws.macie as the findings destination and the export configuration's bucket as the results destination -> data
discovery (kind discovery). The function isn't read as a job binding (inventory)."""
import json
import re

from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.findings import findings, responsible
from opsdir.core.formats import PYTHON
from opsdir.core.inventory import of_types, resource
from opsdir.core.manifest import header
from opsdir.domains.estate.discovery import (custom_identifiers, destination, discovery_services, rescan_line,
                                             rescan_plan)
from opsdir.domains.estate.naming import RESTRICTED
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from opsdir_format_terraform.state import blocks
from .account import account_id
from .account import govcloud, partition
from .security import findings_routes, findings_routing
from .storage import bucket_of, key_arn

ACCOUNT, IDENTIFIER, JOB = "aws_macie2_account", "aws_macie2_custom_data_identifier", "aws_macie2_classification_job"
EXPORT = "aws_macie2_classification_export_configuration"
MACIE = "macie"
GOVCLOUD_NOTE = ("Amazon Macie isn't offered in GovCloud: AWS's General Reference lists no GovCloud endpoint for it "
                 "and its FedRAMP services-in-scope page marks it for US East/West only: not rendered")
DAYS = {"daily_schedule": 1, "weekly_schedule": 7, "monthly_schedule": 30}
OFFERED = (1, 7)                    # what Macie's own schedule honours exactly: daily, weekly
SCHEDULE, FUNCTION = "aws_scheduler_schedule", "aws_lambda_function"
RUNTIME = "python3.14"              # the newest GA Lambda Python runtime (research note 2511)
RESCAN_TAG = "RescanDays"

HANDLER = '''"""Starts a one-time Amazon Macie classification job for data discovery JOB_NAME once RESCAN_DAYS calendar
days (UTC) have passed since the last successful one; nothing while one of its jobs is unfinished. Its jobs are named
'<JOB_NAME>:<UTC time>'. EventBridge Scheduler invokes it daily."""
import datetime as dt
import os
import uuid

import boto3

NAME, DAYS = os.environ["JOB_NAME"], int(os.environ["RESCAN_DAYS"])
ACCOUNT = os.environ["ACCOUNT_ID"]
BUCKETS = [b for b in os.environ["BUCKETS"].split(",") if b]
IDENTIFIERS = [i for i in os.environ.get("CUSTOM_DATA_IDENTIFIER_IDS", "").split(",") if i]
FINISHED = {"COMPLETE", "CANCELLED"}


def due(last_success, today, days):
    """Nothing has succeeded yet, or days calendar days have passed since the last success."""
    return last_success is None or (today - last_success).days >= days


def _jobs(macie):
    criteria = {"includes": [{"key": "name", "comparator": "STARTS_WITH", "values": [f"{NAME}:"]},
                             {"key": "jobType", "comparator": "EQ", "values": ["ONE_TIME"]}]}
    token = None
    while True:
        page = macie.list_classification_jobs(filterCriteria=criteria, **({"nextToken": token} if token else {}))
        yield from page.get("items", [])
        token = page.get("nextToken")
        if not token:
            return


def _succeeded(job):
    return job.get("jobStatus") == "COMPLETE" and (job.get("lastRunErrorStatus") or {}).get("code") == "NONE"


def handler(event, context):
    macie = boto3.client("macie2")
    jobs = list(_jobs(macie))
    if any(j.get("jobStatus") not in FINISHED for j in jobs):
        return {"started": None, "why": "a job is unfinished"}
    runs = [macie.describe_classification_job(jobId=j["jobId"]).get("lastRunTime") for j in jobs if _succeeded(j)]
    last = max((t.astimezone(dt.timezone.utc).date() for t in runs if t), default=None)
    now = dt.datetime.now(dt.timezone.utc)
    if not due(last, now.date(), DAYS):
        return {"started": None, "last_success": str(last)}
    job = macie.create_classification_job(
        clientToken=str(uuid.uuid4()), jobType="ONE_TIME", name=f"{NAME}:{now:%Y-%m-%dT%H:%M:%SZ}",
        s3JobDefinition={"bucketDefinitions": [{"accountId": ACCOUNT, "buckets": BUCKETS}]},
        **({"customDataIdentifierIds": IDENTIFIERS} if IDENTIFIERS else {}))
    return {"started": job["jobId"]}
'''


def _kept(m):
    return [s for s in discovery_services(m) if not one(s, "ciamManagedBy")]


def _schedule(days):
    """The classification job's schedule_frequency for examining every days, one Macie offers (OFFERED; None:
    weekly)."""
    return (("daily_schedule", True),) if days == 1 else (("weekly_schedule", "SUNDAY"),)


def function_name(m, s):
    """The scheduler's Lambda function for data discovery s of environment m (letters, digits, - and _; up to 64)."""
    return re.sub(r"[^A-Za-z0-9_-]", "-", f"ciam-{rdn_value(m.env)}-macie-{rdn_value(s)}")[:64]


def _json(doc):
    return json.dumps(doc, separators=(",", ":"))


def _scheduled(m, s, ids, days, buckets, account):
    """The scheduler for data discovery s examining buckets every days: its schedule, function, package and roles."""
    cn, fn, n = rdn_value(s), function_name(m, s), tf_name(rdn_value(s))       # blocks named after the binding
    part, region = partition(m), one(m.cloud, "ciamRegion") or ""
    lambda_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                             "Principal": {"Service": "lambda.amazonaws.com"}}]}
    runs = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["macie2:CreateClassificationJob", "macie2:DescribeClassificationJob"],
         "Resource": f"arn:{part}:macie2:{region}:{account}:classification-job/*"},
        {"Effect": "Allow", "Action": "macie2:ListClassificationJobs", "Resource": "*"},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:{part}:logs:{region}:{account}:log-group:/aws/lambda/{fn}:*"}]}
    scheduler_trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "scheduler.amazonaws.com"},
        "Condition": {"StringEquals": {"aws:SourceAccount": account,
                                       "aws:SourceArn": f"arn:{part}:scheduler:{region}:{account}:"
                                                        "schedule-group/default"}}}]}
    invokes = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "lambda:InvokeFunction",
        "Resource": f"arn:{part}:lambda:{region}:{account}:function:{fn}"}]}
    # a quoted template (the ids joined by commas), written as is
    ident = ",".join(f"${{{IDENTIFIER}.{ids[x][0]}.id}}" for x, _ in custom_identifiers(s))
    return (comment(f"{cn}: every {days} days: Macie's schedule runs daily or weekly, so EventBridge Scheduler invokes "
                    f"{fn} daily and it starts a one-time classification job once {days} days have passed since the "
                    "last successful one"),
            tf_block("data", ["archive_file", n], [
                ("type", "zip"), ("source_dir", f"${{path.module}}/discovery/{fn}"),
                ("output_path", f"${{path.module}}/.build/{fn}.zip")]),
            tf_block("resource", ["aws_iam_role", n], [("name", fn), ("assume_role_policy", _json(lambda_trust))]),
            tf_block("resource", ["aws_iam_role_policy", n], [
                ("name", "macie-jobs"), ("role", ref(f"aws_iam_role.{n}.id")), ("policy", _json(runs))]),
            tf_block("resource", [FUNCTION, n], [
                ("function_name", fn), ("role", ref(f"aws_iam_role.{n}.arn")), ("runtime", RUNTIME),
                ("handler", "handler.handler"), ("timeout", 60),
                ("filename", ref(f"data.archive_file.{n}.output_path")),
                ("source_code_hash", ref(f"data.archive_file.{n}.output_base64sha256")),
                ("environment", Block((("variables", {
                    "JOB_NAME": cn, "RESCAN_DAYS": str(days), "ACCOUNT_ID": account, "BUCKETS": ",".join(buckets),
                    **({"CUSTOM_DATA_IDENTIFIER_IDS": ref(f'"{ident}"')} if ident else {})}),))),
                ("tags", {"Realizes": cn, RESCAN_TAG: str(days)}),
                ("depends_on", [ref(f"{ACCOUNT}.{MACIE}")])]),
            tf_block("resource", ["aws_iam_role", f"{n}_scheduler"], [
                ("name", f"{fn}-scheduler"[:64]), ("assume_role_policy", _json(scheduler_trust))]),
            tf_block("resource", ["aws_iam_role_policy", f"{n}_scheduler"], [
                ("name", "invoke"), ("role", ref(f"aws_iam_role.{n}_scheduler.id")), ("policy", _json(invokes))]),
            tf_block("resource", [SCHEDULE, n], [
                ("name", fn), ("schedule_expression", "rate(1 day)"),
                ("flexible_time_window", Block((("mode", "OFF"),))),
                ("target", Block((("arn", ref(f"{FUNCTION}.{n}.arn")),
                                  ("role_arn", ref(f"aws_iam_role.{n}_scheduler.arn")))))]))


def handler_script(m, s):
    """The scheduler function's Python source, with its do-not-edit header."""
    return header(m, f"Lambda function {function_name(m, s)}: one-time Macie jobs for data discovery {rdn_value(s)}",
                  PYTHON) + HANDLER


def _stores(m, s):
    """(S3 bucket names of the stores discovery s examines, the roles that aren't S3 buckets)."""
    found = [(r, b) for r in values(s, "ciamScansRole")
             for b in (next((x for x in m.bindings if one(x, "ciamBindingRole") == r), None),)]
    buckets = [bucket_of(one(b, "ciamStorageRef")) if b is not None and is_kind(m.d, b, "ciamObjectStore") else None
               for _, b in found]
    return [x for x in buckets if x], [r for (r, _), x in zip(found, buckets) if not x]


def _identifiers(services):
    """{name: (terraform name, regular expression)} of the own data types the services look for."""
    return {n: (tf_name(f"cdi_{n}"), rx) for s in services for n, rx in custom_identifiers(s)}


def _job(m, s, ids):
    cn, n = rdn_value(s), tf_name(rdn_value(s))
    buckets, others = _stores(m, s)
    account = account_id(m)
    notes = (*((comment(f"{cn}: Macie examines S3 only: {', '.join(others)} not examined here"),) if others else ()),)
    if not buckets:
        return (*notes, comment(f"NOTE: data discovery {cn}: no classification job: it examines no S3 bucket here"))
    if account is None:
        return (*notes, comment(f"NOTE: data discovery {cn}: no classification job: the cloud records no account "
                                "(ciamAccountRef)"))
    plan = rescan_plan(s, OFFERED)
    if plan is not None and not plan.native:
        return (*notes, *_scheduled(m, s, ids, plan.days, buckets, account))
    return (*notes, tf_block("resource", [JOB, n], [
        ("job_type", "SCHEDULED"), ("name", cn), ("schedule_frequency", Block(_schedule(plan and plan.days))),
        *((("custom_data_identifier_ids", [ref(f"{IDENTIFIER}.{ids[x][0]}.id") for x, _ in custom_identifiers(s)]),)
          if custom_identifiers(s) else ()),
        ("s3_job_definition", Block((("bucket_definitions", Block((("account_id", account),
                                                                   ("buckets", buckets)))),))),
        ("depends_on", [ref(f"{ACCOUNT}.{MACIE}")])]))


def _export(m, services):
    """The classification export configuration to the first results store, or a note (one per account)."""
    s = next((x for x in services if one(x, "ciamResultsRole")), None)
    if s is None:
        return ()
    dest = destination(m, s, "ciamResultsRole")
    bucket = bucket_of(one(dest, "ciamStorageRef")) if dest is not None and is_kind(m.d, dest, "ciamObjectStore") \
        else None
    key = key_arn(m, dest)[0] if bucket else None
    if bucket is None or key is None:
        why = "it isn't an S3 bucket here" if bucket is None else "its store has no KMS key (Macie requires one)"
        return (comment(f"NOTE: data discovery {rdn_value(s)}'s results to {one(s, 'ciamResultsRole')}: not rendered: "
                        f"{why}"),)
    return (tf_block("resource", [EXPORT, MACIE], [
        ("s3_destination", Block((("bucket_name", bucket), ("key_prefix", f"macie/{rdn_value(m.env)}/"),
                                  ("kms_key_arn", key)))),
        ("depends_on", [ref(f"{ACCOUNT}.{MACIE}")])]),)


def _uses_scheduler(m, s):
    plan = rescan_plan(s, OFFERED)
    return plan is not None and not plan.native and bool(_stores(m, s)[0]) and account_id(m) is not None


def render_discovery(m):
    """(HCL and comments, {path: script}) for environment m's data discovery (whoever keeps each service): the
    scheduler functions' sources. Each service's blocks are stamped with its entry, and what the account shares (Macie
    itself, custom data identifiers, the findings export) with the first service's (the render places them by
    keeper)."""
    kept = discovery_services(m)
    if not kept:
        return (), {}
    first, ids = kept[0].dn, _identifiers(kept)
    if govcloud(m):
        return from_entry(first, (comment(f"{GOVCLOUD_NOTE}: data discovery {', '.join(rdn_value(s) for s in kept)} "
                                          "(the planner names the gap)"),)), {}
    scripts = {f"terraform/discovery/{function_name(m, s)}/handler.py": handler_script(m, s)
               for s in kept if _uses_scheduler(m, s)}
    return (*from_entry(first, (
                tf_block("resource", [ACCOUNT, MACIE], [("finding_publishing_frequency", "FIFTEEN_MINUTES"),
                                                        ("status", "ENABLED")]),
                *(tf_block("resource", [IDENTIFIER, tf], [("name", n), ("regex", rx),
                                                          ("depends_on", [ref(f"{ACCOUNT}.{MACIE}")])])
                  for n, (tf, rx) in ids.items()))),
            *(x for s in kept for x in from_entry(s.dn, (*_job(m, s, ids), *findings_routing(m, s, "data-discovery")))),
            *from_entry(first, _export(m, kept))), scripts


def _rescan_lines(m, kept):
    """The plan's lines naming how each kept service's interval is honoured: Macie's schedule or the scheduler."""
    plans = [(s, rescan_plan(s, OFFERED)) for s in kept]
    return tuple(rescan_line(m, s, plan, f"Macie's own {'daily' if plan.days == 1 else 'weekly'} classification job",
                             f"EventBridge Scheduler invokes {function_name(m, s)} daily, which starts a one-time "
                             f"classification job once {plan.days} days have passed since the last successful one")
                 for s, plan in plans if plan is not None)


def check_discovery_availability(ctx):
    """For a GovCloud target that records data discovery the platform keeps: an action, a blocker where its data is
    restricted (see the module); elsewhere, how each kept service's interval is honoured (OK lines)."""
    kept = _kept(ctx.dst)
    if not kept:
        return findings()
    if not govcloud(ctx.dst):
        return findings(ok=_rescan_lines(ctx.dst, kept))
    restricted = one(ctx.dst.env, "ciamDataClassification") == RESTRICTED
    text = f"{ctx.dst.label} runs data discovery ({', '.join(rdn_value(s) for s in kept)}) in GovCloud: {GOVCLOUD_NOTE}"
    owner = responsible(ctx.d, ctx.dst.env)
    if restricted:
        return findings(blockers=[("Data discovery", f"{text}; its data is classified {RESTRICTED}: this blocks the "
                                                     "move.", owner)])
    return findings(actions=[("Data discovery", f"{text}.", owner, ctx.cutover)])


# ------------------------------------------------------------------ read back
def _days(job):
    sched = (job.get("schedule_frequency") or [{}])[0] or {}
    return next((DAYS[k] for k in ("daily_schedule", "weekly_schedule", "monthly_schedule") if sched.get(k)), None)


def _buckets(job):
    defs = ((job.get("s3_job_definition") or [{}])[0] or {}).get("bucket_definitions") or ()
    return tuple(dict.fromkeys(f"arn:aws:s3:::{b}" for d in defs for b in d.get("buckets") or ()))


def is_rescan_function(a):
    """Whether a Lambda function's attributes are a data discovery scheduler's (tagged RescanDays): the inventory
    doesn't read it as a job."""
    return bool((a.get("tags") or a.get("tags_all") or {}).get(RESCAN_TAG))


def _scheduled_resources(pairs, ids, links):
    """Data discovery from the scheduler functions: their environment's buckets, interval and identifier ids."""
    def read(a):
        env = next((b.get("variables") or {} for b in blocks(a.get("environment"))), {})
        tags = a.get("tags") or a.get("tags_all") or {}
        return resource("discovery", a.get("arn"), {
            "ciamRescanDays": int(env.get("RESCAN_DAYS") or tags[RESCAN_TAG]),
            "ciamCustomIdentifier": tuple(ids[i] for i in (env.get("CUSTOM_DATA_IDENTIFIER_IDS") or "").split(",")
                                          if i in ids)},
            links={"ciamScansRole": tuple(f"arn:aws:s3:::{b}" for b in (env.get("BUCKETS") or "").split(",") if b),
                   **links}, name=env.get("JOB_NAME") or tags.get("Realizes"))
    return tuple(read(a) for a in of_types(pairs, FUNCTION) if a.get("arn") and is_rescan_function(a))


def discovery_resources(pairs):
    """Data discovery of (Terraform resource type, attributes) pairs."""
    ids = {a.get("id"): f"{a.get('name')}: {a.get('regex')}" for a in of_types(pairs, IDENTIFIER)
           if a.get("id") and a.get("name") and a.get("regex")}
    routes = findings_routes(pairs)
    export = next((((e.get("s3_destination") or [{}])[0] or {}).get("bucket_name") for e in of_types(pairs, EXPORT)),
                  None)
    links = {"ciamFindingsRole": routes.get("aws.macie"),
             "ciamResultsRole": f"arn:aws:s3:::{export}" if export else None}
    return (*_scheduled_resources(pairs, ids, links), *(resource("discovery", a.get("arn") or a.get("id"), {
        "ciamRescanDays": _days(a),
        "ciamCustomIdentifier": tuple(ids[i] for i in a.get("custom_data_identifier_ids") or () if i in ids)},
        links={"ciamScansRole": _buckets(a), **links}, name=a.get("name") or "macie")
        for a in of_types(pairs, JOB) if (a.get("arn") or a.get("id")) and a.get("job_type") == "SCHEDULED"))
