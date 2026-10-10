"""Data discovery on AWS (core estate: ciamDataDiscovery) as Amazon Macie. Pure.

Rendered in the platform's own root, for each data discovery the platform team keeps (one someone else keeps is named
in a comment): Macie for the account (aws_macie2_account, enabled, findings published every fifteen minutes), an
aws_macie2_custom_data_identifier per own data type (its name and regular expression), and a scheduled
aws_macie2_classification_job over the S3 buckets of the object stores it examines, in the account the cloud records,
daily, weekly or monthly by ciamRescanDays (1; up to 7; more), with those identifiers. A store that isn't an S3 bucket
is named in a comment (Macie examines S3 only). Its findings go where ciamFindingsRole says through an EventBridge rule
(source aws.macie, detail-type Macie Finding), as the security services' do; its detailed results to the S3 bucket of
the object store ciamResultsRole names (aws_macie2_classification_export_configuration, with that store's KMS key,
which Macie requires).

In GovCloud (a us-gov- region) Macie is rendered as an add-on with a comment, and the check gives an action: AWS's
FedRAMP services-in-scope page marks Amazon Macie for US East/West only, and no GovCloud endpoint was found for it
(2026-10-08; AWS states no availability either way).

Read back from Terraform state: aws_macie2_classification_job (its buckets as the stores examined, its schedule as
days, its custom identifiers by name and regular expression from aws_macie2_custom_data_identifier), with the
EventBridge rule's target for aws.macie as the findings destination and the export configuration's bucket as the
results destination -> data discovery (kind discovery)."""
from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.findings import findings, responsible
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.discovery import custom_identifiers, destination, discovery_services
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .account import account_id
from .account import govcloud
from .security import findings_routes, findings_routing
from .storage import bucket_of, key_arn

ACCOUNT, IDENTIFIER, JOB = "aws_macie2_account", "aws_macie2_custom_data_identifier", "aws_macie2_classification_job"
EXPORT = "aws_macie2_classification_export_configuration"
MACIE = "macie"
GOVCLOUD_NOTE = ("Amazon Macie in GovCloud: AWS's FedRAMP services-in-scope page marks it for US East/West only and "
                 "no GovCloud endpoint was found (2026-10-08): rendered as an add-on, confirm it is offered before "
                 "applying")
DAYS = {"daily_schedule": 1, "weekly_schedule": 7, "monthly_schedule": 30}


def _keeper(m, s):
    holder = get(m.d, one(s, "ciamManagedBy"))
    return rdn_value(holder) if holder is not None else one(s, "ciamManagedBy")


def _kept(m):
    return [s for s in discovery_services(m) if not one(s, "ciamManagedBy")]


def _schedule(days):
    """The classification job's schedule_frequency for examining every days (None: weekly)."""
    d = int(days) if days is not None else 7
    return (("daily_schedule", True),) if d <= 1 else (("weekly_schedule", "SUNDAY"),) if d <= 7 else \
        (("monthly_schedule", 1),)


def _stores(m, s):
    """(S3 bucket names of the stores discovery s examines, the roles that aren't S3 buckets)."""
    found = [(r, b) for r in values(s, "ciamScansRole")
             for b in (next((x for x in m.bindings if one(x, "ciamBindingRole") == r), None),)]
    buckets = [bucket_of(one(b, "ciamStorageRef")) if b is not None and is_kind(m.d, b, "ciamObjectStore") else None
               for _, b in found]
    return [x for x in buckets if x], [r for (r, _), x in zip(found, buckets) if not x]


def _identifiers(m):
    """{name: (terraform name, regular expression)} of the own data types the kept services look for."""
    return {n: (tf_name(f"cdi_{n}"), rx) for s in _kept(m) for n, rx in custom_identifiers(s)}


def _job(m, s, ids):
    cn, n = rdn_value(s), tf_name(rdn_value(s))
    buckets, others = _stores(m, s)
    account = account_id(m)
    notes = (*((f"# {cn}: Macie examines S3 only: {', '.join(others)} not examined here",) if others else ()),)
    if not buckets:
        return (*notes, f"# NOTE: data discovery {cn}: no classification job: it examines no S3 bucket here")
    if account is None:
        return (*notes, f"# NOTE: data discovery {cn}: no classification job: the cloud records no account "
                        "(ciamAccountRef)")
    return (*notes, block("resource", [JOB, n], [
        ("job_type", "SCHEDULED"), ("name", cn), ("schedule_frequency", Block(_schedule(one(s, "ciamRescanDays")))),
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
        return (f"# NOTE: data discovery {rdn_value(s)}'s results to {one(s, 'ciamResultsRole')}: not rendered: {why}",)
    return (block("resource", [EXPORT, MACIE], [
        ("s3_destination", Block((("bucket_name", bucket), ("key_prefix", f"macie/{rdn_value(m.env)}/"),
                                  ("kms_key_arn", key)))),
        ("depends_on", [ref(f"{ACCOUNT}.{MACIE}")])]),)


def render_discovery(m):
    """HCL (and comments) for environment m's data discovery."""
    kept, ids = _kept(m), _identifiers(m)
    notes = tuple(f"# Data discovery {rdn_value(s)}: kept by {_keeper(m, s)}, not rendered here"
                  for s in discovery_services(m) if one(s, "ciamManagedBy"))
    if not kept:
        return notes
    return (*notes, *((f"# {GOVCLOUD_NOTE}",) if govcloud(m) else ()),
            block("resource", [ACCOUNT, MACIE], [("finding_publishing_frequency", "FIFTEEN_MINUTES"),
                                                 ("status", "ENABLED")]),
            *(block("resource", [IDENTIFIER, tf], [("name", n), ("regex", rx),
                                                   ("depends_on", [ref(f"{ACCOUNT}.{MACIE}")])])
              for n, (tf, rx) in ids.items()),
            *(x for s in kept for x in (*_job(m, s, ids), *findings_routing(m, s, "data-discovery"))),
            *_export(m, kept))


def check_discovery_availability(ctx):
    """An action for a GovCloud target that records data discovery the platform keeps (see the module)."""
    kept = _kept(ctx.dst)
    if not kept or not govcloud(ctx.dst):
        return findings()
    return findings(actions=[("Data discovery", f"{ctx.dst.label} runs data discovery "
                              f"({', '.join(rdn_value(s) for s in kept)}) in GovCloud: {GOVCLOUD_NOTE}.",
                              responsible(ctx.d, ctx.dst.env), ctx.cutover)])


# ------------------------------------------------------------------ read back
def _days(job):
    sched = (job.get("schedule_frequency") or [{}])[0] or {}
    return next((DAYS[k] for k in ("daily_schedule", "weekly_schedule", "monthly_schedule") if sched.get(k)), None)


def _buckets(job):
    defs = ((job.get("s3_job_definition") or [{}])[0] or {}).get("bucket_definitions") or ()
    return tuple(dict.fromkeys(f"arn:aws:s3:::{b}" for d in defs for b in d.get("buckets") or ()))


def discovery_resources(pairs):
    """Data discovery of (Terraform resource type, attributes) pairs."""
    ids = {a.get("id"): f"{a.get('name')}: {a.get('regex')}" for a in of_types(pairs, IDENTIFIER)
           if a.get("id") and a.get("name") and a.get("regex")}
    routes = findings_routes(pairs)
    export = next((((e.get("s3_destination") or [{}])[0] or {}).get("bucket_name") for e in of_types(pairs, EXPORT)),
                  None)
    return tuple(resource("discovery", a.get("arn") or a.get("id"), {
        "ciamRescanDays": _days(a),
        "ciamCustomIdentifier": tuple(ids[i] for i in a.get("custom_data_identifier_ids") or () if i in ids)},
        links={"ciamScansRole": _buckets(a), "ciamFindingsRole": routes.get("aws.macie"),
               "ciamResultsRole": f"arn:aws:s3:::{export}" if export else None},
        name=a.get("name") or "macie")
        for a in of_types(pairs, JOB) if (a.get("arn") or a.get("id")) and a.get("job_type") == "SCHEDULED")
