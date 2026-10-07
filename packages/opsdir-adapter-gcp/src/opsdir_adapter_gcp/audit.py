"""Control-plane audit trails on Google Cloud (core observability: ciamAuditTrail) as log sinks exporting Cloud Audit
Logs. Pure.

Cloud Audit Logs record who did what in a project (Admin Activity: always on, every region; Data Access: off until an
audit config turns it on, for every service at once); Google keeps Admin Activity 400 days in the built-in _Required
bucket. A sink exports them where the record says, for as long as that keeps them.

Rendered in the platform's own root, for each trail the platform team keeps (no ciamManagedBy):
  google_logging_project_sink (account scope), or google_logging_organization_sink with include_children on the
  organization an input names (organization scope): filter logName:"cloudaudit.googleapis.com" (every audit log), a
  unique writer identity, and the destination its ciamLogDestinationRole names: an object store's bucket
  (storage.googleapis.com/<bucket>, with google_storage_bucket_iam_member granting the sink's writer identity
  roles/storage.objectCreator) or a log bucket (logging.googleapis.com/<its ciamProviderRef>)
  data-read / data-write: google_project_iam_audit_config (google_organization_iam_audit_config) for allServices
  with DATA_READ / DATA_WRITE
Not rendered, and said so: a trail someone else keeps (named with its keeper), another destination. Google keeps no
digest of audit logs: integrity is a bucket whose retention policy is locked (ciamStorageImmutability compliance), noted
when the trail asks for integrity validation without one.

Read back from (google type, attributes) pairs (Terraform state as it is; Cloud Asset Inventory's LogSink assets and
`gcloud logging sinks list` normalized to it, sink_attributes): google_logging_project_sink, _organization_sink and
_folder_sink whose filter covers Cloud Audit Logs (none: every log) -> audit trail (kind audit): account scope for a
project's sink, organization for one including its children; control-plane when it exports Admin Activity, data-read
and data-write when it exports Data Access and an audit config on its parent turns them on
(google_*_iam_audit_config, or an IAM policy's auditConfigs); every region; where its records go (its bucket, or its
log bucket) as that object store's or log destination's role. Disabled sinks and the built-in _Required and _Default
sinks are not trails.
"""
import json
import re
from urllib.parse import unquote

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.domains.observability.audit import (PROTECTED, audit_trails, store_protection, trail_destination,
                                               trail_keeper)
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .names import resource_id
from .storage import bucket_of, kept_buckets

FILTER = 'logName:"cloudaudit.googleapis.com"'
SINKS = (("google_logging_project_sink", "projects"), ("google_logging_organization_sink", "organizations"),
         ("google_logging_folder_sink", "folders"))
CONFIGS = (("google_project_iam_audit_config", "projects", "project"),
           ("google_organization_iam_audit_config", "organizations", "org_id"),
           ("google_folder_iam_audit_config", "folders", "folder"))
DATA_LOGS = (("data-read", "DATA_READ"), ("data-write", "DATA_WRITE"))
ORGANIZATION = "organization_id"


def _name(trail):
    pref = one(trail, "ciamProviderRef") or ""
    return pref.rsplit("/sinks/", 1)[-1] if "/sinks/" in pref else rdn_value(trail)


def _destination(m, n, sink, dest):
    """(destination, grants, notes) of the destination of sink (its Terraform address), or None when a sink can't
    export to it."""
    if is_kind(m.d, dest, "ciamObjectStore") and bucket_of(one(dest, "ciamStorageRef")):
        bucket = bucket_of(one(dest, "ciamStorageRef"))
        name = ref(f"google_storage_bucket.{tf_name(rdn_value(dest))}.name") \
            if dest.dn in {b.dn for b in kept_buckets(m)} else bucket
        return (f"storage.googleapis.com/{bucket}", (block("resource", ["google_storage_bucket_iam_member", n], [
            ("bucket", name), ("role", "roles/storage.objectCreator"),
            ("member", ref(f"{sink}.writer_identity"))]),), ())
    pref = one(dest, "ciamProviderRef") or ""
    if is_kind(m.d, dest, "ciamLogDestination") and "/buckets/" in pref:
        return (f"logging.googleapis.com/{pref}", (), (
            f"# {rdn_value(dest)}: a log bucket in another project needs roles/logging.bucketWriter for the sink's "
            "writer identity",))
    return None


def _data(n, org, events):
    logs = [log for e, log in DATA_LOGS if e in events]
    if not logs:
        return ()
    kind, parent = (("google_organization_iam_audit_config", ("org_id", ref(f"var.{ORGANIZATION}"))) if org
                    else ("google_project_iam_audit_config", ("project", ref("var.project_id"))))
    return (block("resource", [kind, n], [parent, ("service", "allServices"),
                                          *(("audit_log_config", Block((("log_type", log),))) for log in logs)]),)


def _trail(m, t):
    cn, keeper, dest = rdn_value(t), trail_keeper(m, t), trail_destination(m, t)
    if keeper is not None:
        return (f"# Audit trail {cn} ({one(t, 'ciamAuditScope')}): kept by {rdn_value(keeper)}, not rendered here",)
    n = tf_name(cn)
    org = one(t, "ciamAuditScope") == "organization"
    sink = f"google_logging_{'organization' if org else 'project'}_sink"
    found = _destination(m, n, f"{sink}.{n}", dest) if dest is not None else None
    if found is None:
        why = ("no bucket or log bucket here keeps its records (ciamLogDestinationRole)" if dest is None else
               f"a sink exports to a bucket, a log bucket, BigQuery or Pub/Sub, and {rdn_value(dest)} is none of those")
        return (f"# NOTE: audit trail {cn}: not rendered: {why}",)
    destination, grants, notes = found
    unlocked = one(t, "ciamIntegrityValidation") == "TRUE" and store_protection(m, t) < PROTECTED
    return (*notes, block("resource", [sink, n], [
        *((("#", "integrity: Google keeps no digest of audit logs; keep them in a bucket whose retention policy is "
                 "locked (ciamStorageImmutability compliance)"),) if unlocked else ()),
        ("name", _name(t)),
        *((("org_id", ref(f"var.{ORGANIZATION}")), ("include_children", True)) if org else ()),
        ("destination", destination), ("filter", FILTER), ("unique_writer_identity", True)]),
        *grants,
        *_data(n, org, values(t, "ciamAuditEvents")))


def render_trails(m):
    """HCL (and comments) for environment m's control-plane audit trails; the organization input once, when an
    organization sink is rendered."""
    out = tuple(x for t in audit_trails(m) for x in _trail(m, t))
    org = any(f"var.{ORGANIZATION}" in x for x in out)
    return ((block("variable", [ORGANIZATION], [
        ("type", ref("string")), ("description", "The organization whose audit logs the organization sink exports")]),)
        if org else ()) + out


# ------------------------------------------------------------------ read back
def _logs(filter_):
    """The audit logs a sink's filter exports ('activity', 'data_access'): every one when it has no filter or names
    Cloud Audit Logs without naming which; none when it doesn't name them."""
    f = unquote(filter_ or "")
    if not f.strip():
        return {"activity", "data_access"}
    if "cloudaudit.googleapis.com" not in f:
        return set()
    named = {x for x in ("activity", "data_access") if f"cloudaudit.googleapis.com/{x}" in f}
    return named or {"activity", "data_access"}


def _parent(sink_id):
    """The parent of a sink (projects/p, organizations/o, folders/f) from its resource name."""
    parts = resource_id(sink_id or "").split("/sinks/", 1)[0]
    return parts if re.fullmatch(r"(projects|organizations|folders)/[^/]+", parts) else None


def _policy_configs(a):
    try:
        return json.loads(a.get("policy_data") or "{}").get("auditConfigs") or ()
    except ValueError:
        return ()


def audit_configs(pairs):
    """{parent: {log type turned on}} of the Data Access audit configs among (google type, attributes) pairs: the
    google_*_iam_audit_config resources and IAM policies' auditConfigs (any service)."""
    def parent(collection, v):
        return v if str(v).startswith(f"{collection}/") else f"{collection}/{v}"
    found = [*((parent(collection, a.get(key)), c.get("log_type"))
               for t, collection, key in CONFIGS for a in of_types(pairs, t) for c in a.get("audit_log_config") or ()),
             *((resource_id(a.get("resource") or "") or f"projects/{a.get('project')}", c.get("logType"))
               for t in ("google_cai_iam_policy", "google_project_iam_policy") for a in of_types(pairs, t)
               for cfg in _policy_configs(a) for c in cfg.get("auditLogConfigs") or ())]
    return {p: {log for q, log in found if q == p} for p, _ in found}


def trail_events(a, configs):
    """The activity a sink exports: control-plane with Admin Activity, data reads and writes with Data Access when an
    audit config on its parent turns them on."""
    logs, on = _logs(a.get("filter")), configs.get(_parent(a.get("id")), set())
    return (*(("control-plane",) if "activity" in logs else ()),
            *(e for e, log in DATA_LOGS if "data_access" in logs and log in on))


def _link(destination):
    service, _, path = (destination or "").partition(".googleapis.com/")
    return path.split("/", 1)[0] if service == "storage" else path if service == "logging" else None


def trail_resources(pairs):
    """Log sinks exporting Cloud Audit Logs among (google type, attributes) pairs, as audit trails."""
    configs = audit_configs(pairs)
    return tuple(resource("audit", resource_id(a["id"]), {
        "ciamAuditScope": "organization" if collection != "projects" and a.get("include_children") else "account",
        "ciamAuditEvents": trail_events(a, configs), "ciamAllRegions": "TRUE"},
        links={"ciamLogDestinationRole": _link(a.get("destination"))}, name=a.get("name"))
        for t, collection in SINKS for a in of_types(pairs, t)
        if a.get("id") and not a.get("disabled") and not (a.get("name") or "").startswith("_")
        and _logs(a.get("filter")))


def sink_attributes(d, parent):
    """(google type, attributes) of a LogSink as Cloud Asset Inventory or gcloud prints it, under its parent
    (projects/p, organizations/o or folders/f)."""
    collection = (parent or "projects/").split("/", 1)[0]
    kind = next((t for t, c in SINKS if c == collection), SINKS[0][0])
    return kind, {"id": f"{parent}/sinks/{d.get('name')}", "name": d.get("name"), "destination": d.get("destination"),
                  "filter": d.get("filter"), "disabled": d.get("disabled", False),
                  "include_children": d.get("includeChildren", False), "writer_identity": d.get("writerIdentity")}


def sink_parent(origin):
    """A LogSink's parent: from its Cloud Asset Inventory name (//logging.googleapis.com/<parent>/sinks/<name>), else
    from the file gcloud's list was saved as (<project>.json, organizations-<id>.json, folders-<id>.json)."""
    if origin.startswith("//"):
        return _parent(origin)
    stem = origin.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    kind, _, rest = stem.partition("-")
    return f"{kind}/{rest}" if kind in ("organizations", "folders") and rest else f"projects/{stem}"
