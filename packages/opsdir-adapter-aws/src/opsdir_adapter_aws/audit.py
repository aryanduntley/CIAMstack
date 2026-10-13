"""Control-plane audit trails on AWS (core observability: ciamAuditTrail) as CloudTrail trails. Pure.

Rendered for every trail, stamped with its entry (placed by its keeper: governance.keepers) as an aws_cloudtrail
delivering to the S3 bucket of the object store its ciamLogDestinationRole names: all regions (with global services'
events), log file integrity validation. The bucket must let CloudTrail write (s3:GetBucketAcl on it, s3:PutObject under
AWSLogs/<account>/ and, for an organization trail, AWSLogs/<organization>/, for this trail only): a bucket this render
creates gets that policy; one that exists or someone else keeps is told in a NOTE (its policy is theirs).
- An organization trail (ciamAuditScope organization, milestone 5.7b) is made from the organization's management
  account (provider aws.management) and kept with the landing zone (its organization origin); the environment's own
  root says who enables it.
- Data events (ciamAuditEvents data-read / data-write) are logged with advanced event selectors for the data resources
  the trail names (ciamAuditResourceRole), else the environment's own (decision 2777): S3 objects of each bucket but the
  trail's own (logging writes to it would log themselves). Databases have no data events (queries aren't API calls)
  and Secrets Manager's reads are management events: both said so. With selectors, management events are logged by a
  selector of their own when the trail records control-plane.
- A log group the trail also streams to (ciamAuditStreamRole) gets CloudTrail's delivery role: trusted by CloudTrail,
  allowed to create the trail's log streams (its account's prefix, and the organization's) and put events in them.

Read back from Terraform state: aws_cloudtrail -> audit trail (kind audit): organization or account, the activity its
event selectors record (none: control-plane, CloudTrail's default), all regions, integrity validation, where its
records go (its bucket, or its CloudWatch log group) as the role of that object store or log destination, and the log
group it also streams to. Which data resources its selectors name isn't read (the record keeps ciamAuditResourceRole:
none named means the environment's own, which a read can't tell from a list).
"""
import json

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.governance.keepers import organization_line, organization_origin, organization_wide
from opsdir.domains.observability.audit import audit_trails, data_resources, trail_destination, trail_stream
from opsdir.domains.observability.naming import AUDIT_EVENTS
from opsdir.domains.observability.realized import keeper_of
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import MANAGEMENT, account_id, management_account, partition
from .observability import LOG_GROUP, group_name
from .storage import bucket_of, described_buckets
from .tags import state_tags

TRAIL_TYPE = "aws_cloudtrail"
SERVICE = "cloudtrail.amazonaws.com"


def _name(trail):
    ref = one(trail, "ciamProviderRef") or ""
    return ref.rsplit("trail/", 1)[1] if "trail/" in ref else rdn_value(trail)


def organization_ref(m):
    """The AWS organization ID (o-...) of environment m's cloud (its ciamOrganizationRef, an ID or the organization's
    ARN), or None."""
    ref_ = (one(m.cloud, "ciamOrganizationRef") or "").rsplit("/", 1)[-1]
    return ref_ if ref_.startswith("o-") else None


def _recorded_arn(t):
    ref_ = one(t, "ciamProviderRef") or ""
    return ref_ if ref_.startswith("arn:") and ":cloudtrail:" in ref_ else None


def _owner(m, t):
    """The account a trail is made in: the one its recorded ARN names, else the organization's management account for
    an organization trail, else the environment's."""
    if _recorded_arn(t):
        return _recorded_arn(t).split(":")[4]
    return management_account(m) if organization_wide(t) else account_id(m)


def trail_arn(m, t):
    """The ARN a trail of environment m has (its ciamProviderRef when that is one) or will have (the delivery policies'
    aws:SourceArn), or None without the account it is made in."""
    owner = _owner(m, t)
    if _recorded_arn(t):
        return _recorded_arn(t)
    return f"arn:{partition(m)}:cloudtrail:{one(m.cloud, 'ciamRegion')}:{owner}:trail/{_name(t)}" if owner else None


def _statement(sid, action, resource_, conditions):
    return {"Sid": sid, "Effect": "Allow", "Principal": {"Service": SERVICE}, "Action": action,
            "Resource": resource_, "Condition": {"StringEquals": conditions}}


def delivery_statements(m, t, bucket):
    """The bucket policy statements CloudTrail needs to deliver trail t's records to bucket (AWS's documented form):
    s3:GetBucketAcl on the bucket, s3:PutObject under AWSLogs/<account>/ and, for an organization trail,
    AWSLogs/<organization>/, each for this trail only (aws:SourceArn)."""
    arn, source = f"arn:{partition(m)}:s3:::{bucket}", {"aws:SourceArn": trail_arn(m, t)}
    write = {**source, "s3:x-amz-acl": "bucket-owner-full-control"}
    org = organization_ref(m) if organization_wide(t) else None
    return (_statement("AWSCloudTrailAclCheck", "s3:GetBucketAcl", arn, source),
            _statement("AWSCloudTrailWrite", "s3:PutObject", f"{arn}/AWSLogs/{_owner(m, t)}/*", write),
            *((_statement("AWSCloudTrailOrganizationWrite", "s3:PutObject", f"{arn}/AWSLogs/{org}/*", write),)
              if org else ()))


def _policy_note(m, t, dest, bucket, why):
    lines = "; ".join(f"{s['Action']} on {s['Resource']}" for s in delivery_statements(m, t, bucket))
    return comment(f"NOTE: audit trail {rdn_value(t)}: bucket {bucket} ({rdn_value(dest)}) must let {SERVICE} {lines}"
                   f" (s3:x-amz-acl bucket-owner-full-control on writes; aws:SourceArn {trail_arn(m, t)}): its policy "
                   f"isn't rendered: {why}")


def _bucket_policy(m, t, dest, bucket):
    """(items, depends_on): the trail's bucket's delivery policy when this render creates the bucket, else a NOTE
    naming the statements its policy must hold (an existing bucket's policy, or one someone else keeps, isn't ours to
    replace); nothing without the trail's account."""
    if trail_arn(m, t) is None:
        return (comment(f"NOTE: audit trail {rdn_value(t)}: its bucket's delivery policy isn't rendered: the record "
                        "names no account it is made in"),), ()
    if dest.dn not in {b.dn for b in described_buckets(m)}:
        return (_policy_note(m, t, dest, bucket, "the record doesn't describe the bucket"),), ()
    if one(dest, "ciamProviderRef"):
        return (_policy_note(m, t, dest, bucket, "the bucket exists already (ciamProviderRef)"),), ()
    n = tf_name(rdn_value(t))
    policy = json.dumps({"Version": "2012-10-17", "Statement": list(delivery_statements(m, t, bucket))},
                        separators=(",", ":"))
    return (tf_block("resource", ["aws_s3_bucket_policy", f"{n}_delivery"], [
        ("bucket", ref(f"aws_s3_bucket.{tf_name(rdn_value(dest))}.id")), ("policy", policy)]),), \
        (ref(f"aws_s3_bucket_policy.{n}_delivery"),)


def _selector(name, *fields):
    return ("advanced_event_selector", Block((("name", name), *(("field_selector", Block(f)) for f in fields))))


def _data_selectors(m, t, dest):
    """(advanced_event_selector body items, comment lines) for trail t's data events: S3 objects of each bucket it
    logs (its own destination left out), what has no data events said once per kind."""
    events = set(values(t, "ciamAuditEvents"))
    data = [e for e in ("data-read", "data-write") if e in events]
    if not data:
        return (), ()
    named = data_resources(m, t)
    found = [b for b in named if dest is None or b.dn != dest.dn]
    buckets = sorted({bucket_of(one(b, "ciamStorageRef")) for b in found if is_kind(m.d, b, "ciamObjectStore")
                      and bucket_of(one(b, "ciamStorageRef"))})
    databases = [rdn_value(b) for b in found if is_kind(m.d, b, "ciamDatabase")]
    secrets = [b for b in found if is_kind(m.d, b, "ciamSecretRef")]
    read_only = () if len(data) == 2 else ((("field", "readOnly"), ("equals", ["true" if data == ["data-read"] else
                                                                              "false"])),)
    selectors = ((_selector(f"{' and '.join(data)} on S3 objects",
                            (("field", "eventCategory"), ("equals", ["Data"])),
                            (("field", "resources.type"), ("equals", ["AWS::S3::Object"])), *read_only,
                            (("field", "resources.ARN"),
                             ("starts_with", [f"arn:{partition(m)}:s3:::{b}/" for b in buckets]))),) if buckets else ())
    several = len(databases) > 1
    notes = (*((f"{', '.join(data)} events: database{'s' if several else ''} {', '.join(databases)} "
                f"{'have' if several else 'has'} none (queries aren't API calls CloudTrail records)",)
               if databases else ()),
             *((f"{', '.join(data)} events: reading the {len(secrets)} secret{'s' if len(secrets) > 1 else ''} is a "
                "Secrets Manager management event, recorded with control-plane",) if secrets else ()),
             *((f"{', '.join(data)} events: no data resource to log"
                + (" but the trail's own bucket (logging its writes would log themselves)" if named else ""),)
               if not (buckets or databases or secrets) else ()))
    if not selectors:
        return (), notes
    management = ((_selector("Management events", (("field", "eventCategory"), ("equals", ["Management"]))),)
                  if "control-plane" in events else ())
    return (*management, *selectors), notes


def _stream(m, t, n):
    """(trail arguments, items) of streaming trail t's records to the log group its ciamAuditStreamRole names: the
    group's ARN, and CloudTrail's delivery role allowed to create the trail's log streams and put events in them."""
    b = trail_stream(m, t)
    if b is None:
        return (), ()
    name, arn = group_name(b), (one(b, "ciamProviderRef") or "").removesuffix(":*")
    if one(b, "ciamDestinationKind") != "log-group" or name is None:
        return (), (comment(f"NOTE: audit trail {rdn_value(t)}: streams only to a CloudWatch log group (its "
                            f"ciamAuditStreamRole {rdn_value(b)} isn't one with a log group ARN): not streamed"),)
    rendered = keeper_of(m, b) is None
    group = f"${{{LOG_GROUP}.{tf_name(rdn_value(b))}.arn}}" if rendered else arn
    org = organization_ref(m) if organization_wide(t) else None
    streams = [f"{arn}:log-stream:{_owner(m, t)}_CloudTrail_*", *([f"{arn}:log-stream:{org}_*"] if org else [])]
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": SERVICE},
                                                     "Action": "sts:AssumeRole"}]}
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "AWSCloudTrailCreateLogStream", "Effect": "Allow", "Action": ["logs:CreateLogStream"],
         "Resource": streams},
        {"Sid": "AWSCloudTrailPutLogEvents", "Effect": "Allow", "Action": ["logs:PutLogEvents"], "Resource": streams}]}
    provider = (("provider", ref(f"aws.{MANAGEMENT}")),) if organization_wide(t) else ()
    return ((("cloud_watch_logs_group_arn", f"{group}:*"),
             ("cloud_watch_logs_role_arn", ref(f"aws_iam_role.{n}_logs.arn"))),
            (tf_block("resource", ["aws_iam_role", f"{n}_logs"], [
                *provider, ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(t)}-cloudtrail-logs"[:64]),
                ("assume_role_policy", json.dumps(trust, separators=(",", ":")))]),
             tf_block("resource", ["aws_iam_role_policy", f"{n}_logs"], [
                 *provider, ("name", "cloudtrail-logs"), ("role", ref(f"aws_iam_role.{n}_logs.id")),
                 ("policy", json.dumps(policy, separators=(",", ":")))])))


def _trail(m, t):
    cn, dest, n = rdn_value(t), trail_destination(m, t), tf_name(rdn_value(t))
    bucket = bucket_of(one(dest, "ciamStorageRef")) if dest is not None and is_kind(m.d, dest, "ciamObjectStore") \
        else None
    if bucket is None:
        why = ("its records go to a CloudWatch log group, but CloudTrail keeps them in an S3 bucket "
               "(ciamLogDestinationRole an object store; a log group it also streams to is its ciamAuditStreamRole)"
               if dest is not None else "no object store here keeps its records (ciamLogDestinationRole)")
        return (comment(f"NOTE: audit trail {cn}: not rendered: {why}"),)
    if organization_wide(t) and management_account(m) is None:
        return (comment(f"NOTE: audit trail {cn}: not rendered: an organization trail is made from the "
                        "organization's management account, which the record doesn't name (ciamManagementRef)"),)
    everywhere = one(t, "ciamAllRegions") == "TRUE"
    selectors, notes = _data_selectors(m, t, dest)
    streamed, stream_items = _stream(m, t, n)
    policy, after = _bucket_policy(m, t, dest, bucket)
    return (*policy, *stream_items, tf_block("resource", [TRAIL_TYPE, n], [
        *((("provider", ref(f"aws.{MANAGEMENT}")),) if organization_wide(t) else ()),
        *(("#", line) for line in notes),
        ("name", _name(t)), ("s3_bucket_name", bucket),
        ("is_multi_region_trail", everywhere), ("include_global_service_events", everywhere),
        ("enable_log_file_validation", one(t, "ciamIntegrityValidation") == "TRUE"),
        *((("is_organization_trail", True),) if organization_wide(t) else ()), *streamed, *selectors,
        *((("depends_on", list(after)),) if after else ())]))


def _placed(m, t):
    """A trail's items stamped for placement: an organization trail with its organization origin (kept with the landing
    zone) and a line in the environment's own render saying who enables it; any other with its entry. A bucket policy
    goes with its bucket."""
    dest = trail_destination(m, t)
    items = tuple(x._replace(origin=dest.dn) if getattr(x, "labels", ())[:1] == ("aws_s3_bucket_policy",) else x
                  for x in _trail(m, t))
    if not organization_wide(t):
        return from_entry(t.dn, items)
    return (*from_entry(organization_origin(t.dn), items), comment(organization_line(m, t)))


def render_trails(m):
    """HCL (and comments) for environment m's control-plane audit trails."""
    return tuple(x for t in audit_trails(m) for x in _placed(m, t))


def _flag(v):
    return None if v is None else "TRUE" if v else "FALSE"


def _basic(s):
    rw, data = s.get("read_write_type") or "All", bool(s.get("data_resource"))
    return (*(("control-plane",) if s.get("include_management_events", True) else ()),
            *(("data-read",) if data and rw in ("All", "ReadOnly") else ()),
            *(("data-write",) if data and rw in ("All", "WriteOnly") else ()))


def _advanced(s):
    fields = {f.get("field"): tuple(f.get("equals") or ()) for f in s.get("field_selector") or ()}
    category, read_only = fields.get("eventCategory", ()), fields.get("readOnly", ())
    reads, writes = "false" not in read_only, "true" not in read_only
    return (*(("control-plane",) if "Management" in category else ()),
            *(("data-read",) if "Data" in category and reads else ()),
            *(("data-write",) if "Data" in category and writes else ()))


def trail_events(a):
    """The activity a trail's state says it records: from its event selectors (basic or advanced), else
    control-plane (what a trail without selectors logs)."""
    basic, advanced = a.get("event_selector") or (), a.get("advanced_event_selector") or ()
    found = {e for s in basic for e in _basic(s)} | {e for s in advanced for e in _advanced(s)}
    return tuple(e for e in AUDIT_EVENTS if e in found) if basic or advanced \
        else ("control-plane",)


def _group(a):
    return (a.get("cloud_watch_logs_group_arn") or "").removesuffix(":*") or None


def _destination(a):
    if a.get("s3_bucket_name"):
        return f"arn:aws:s3:::{a['s3_bucket_name']}"
    return _group(a)


def trail_resources(pairs):
    """CloudTrail trails of (Terraform resource type, attributes) pairs, as audit trails."""
    return tuple(resource("audit", a.get("arn"), {
        "ciamAuditScope": "organization" if a.get("is_organization_trail") else "account",
        "ciamAuditEvents": trail_events(a), "ciamAllRegions": _flag(a.get("is_multi_region_trail")),
        "ciamIntegrityValidation": _flag(a.get("enable_log_file_validation"))},
        links={"ciamLogDestinationRole": _destination(a),
               "ciamAuditStreamRole": _group(a) if a.get("s3_bucket_name") else None}, name=a.get("name"),
        role=tagged_role(state_tags(a)), tags=state_tags(a))
        for a in of_types(pairs, TRAIL_TYPE) if a.get("arn"))
