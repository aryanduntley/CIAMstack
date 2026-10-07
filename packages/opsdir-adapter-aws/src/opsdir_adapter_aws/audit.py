"""Control-plane audit trails on AWS (core observability: ciamAuditTrail) as CloudTrail trails. Pure.

Rendered in the platform's own root: each trail the platform team keeps (no ciamManagedBy) as an aws_cloudtrail
delivering to the S3 bucket of the object store its ciamLogDestinationRole names: all regions (with global services'
events), log file integrity validation, the organization's trail when its scope is organization. Not rendered, and
said so: a trail someone else keeps (an organization trail the landing zone keeps: named with its keeper), a trail
whose records go to a CloudWatch log group (that delivery also needs a role CloudTrail assumes), and data events (a
trail logs data events only for the resources its event selectors name, which the record doesn't say).

Read back from Terraform state: aws_cloudtrail -> audit trail (kind audit): organization or account, the activity its
event selectors record (none: control-plane, CloudTrail's default), all regions, integrity validation, and where its
records go (its bucket, or its CloudWatch log group) as the role of that object store or log destination.
"""
from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.observability.audit import audit_trails, trail_destination, trail_keeper
from opsdir.domains.observability.naming import AUDIT_EVENTS
from opsdir_format_terraform.hcl import block, tf_name
from .storage import bucket_of
from .tags import state_tags

TRAIL_TYPE = "aws_cloudtrail"


def _name(trail):
    ref = one(trail, "ciamProviderRef") or ""
    return ref.rsplit("trail/", 1)[1] if "trail/" in ref else rdn_value(trail)


def _trail(m, t):
    cn, keeper, dest = rdn_value(t), trail_keeper(m, t), trail_destination(m, t)
    if keeper is not None:
        return (f"# Audit trail {cn} ({one(t, 'ciamAuditScope')}): kept by {rdn_value(keeper)}, not rendered here",)
    bucket = bucket_of(one(dest, "ciamStorageRef")) if dest is not None and is_kind(m.d, dest, "ciamObjectStore") \
        else None
    if bucket is None:
        why = ("its records go to a CloudWatch log group, a delivery that also needs a role CloudTrail assumes"
               if dest is not None else "no object store here keeps its records (ciamLogDestinationRole)")
        return (f"# NOTE: audit trail {cn}: not rendered: {why}",)
    data = [e for e in values(t, "ciamAuditEvents") if e != "control-plane"]
    everywhere = one(t, "ciamAllRegions") == "TRUE"
    return (block("resource", [TRAIL_TYPE, tf_name(cn)], [
        *((("#", f"{', '.join(data)} events: log them with event selectors naming the resources (not rendered)"),)
          if data else ()),
        ("name", _name(t)), ("s3_bucket_name", bucket),
        ("is_multi_region_trail", everywhere), ("include_global_service_events", everywhere),
        ("enable_log_file_validation", one(t, "ciamIntegrityValidation") == "TRUE"),
        *((("is_organization_trail", True),) if one(t, "ciamAuditScope") == "organization" else ())]),)


def render_trails(m):
    """HCL (and comments) for environment m's control-plane audit trails."""
    return tuple(x for t in audit_trails(m) for x in _trail(m, t))


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


def _destination(a):
    if a.get("s3_bucket_name"):
        return f"arn:aws:s3:::{a['s3_bucket_name']}"
    group = a.get("cloud_watch_logs_group_arn") or ""
    return group.removesuffix(":*") or None


def trail_resources(pairs):
    """CloudTrail trails of (Terraform resource type, attributes) pairs, as audit trails."""
    return tuple(resource("audit", a.get("arn"), {
        "ciamAuditScope": "organization" if a.get("is_organization_trail") else "account",
        "ciamAuditEvents": trail_events(a), "ciamAllRegions": _flag(a.get("is_multi_region_trail")),
        "ciamIntegrityValidation": _flag(a.get("enable_log_file_validation"))},
        links={"ciamLogDestinationRole": _destination(a)}, name=a.get("name"),
        role=tagged_role(state_tags(a)), tags=state_tags(a))
        for a in of_types(pairs, TRAIL_TYPE) if a.get("arn"))
