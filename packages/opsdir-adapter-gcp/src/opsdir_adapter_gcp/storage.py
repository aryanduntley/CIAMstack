"""Google Cloud: the object stores (Cloud Storage buckets, gs://<bucket>) an environment uses, rendered as Terraform and
read back. Pure.

Rendered into the stack's main.tf, for each bucket the record describes and the stack keeps (one naming ciamManagedBy
is someone else's: a comment names them and what to ask them for); a bucket the record only references stays a
reference (the backup target's data source):

  google_storage_bucket in the environment's region: uniform bucket-level access, public access prevention (enforced
  when blocked), versioning, a retention policy (its days in seconds; locked for compliance, unlocked for governance),
  the default KMS key of its key role (the Cloud Storage service agent needs Encrypter/Decrypter on it: a comment),
  a lifecycle rule per recorded rule (SetStorageClass to NEARLINE, COLDLINE or ARCHIVE for cool, cold, archive;
  Delete; noncurrent versions by days since they became noncurrent), labels role and managed_by
  an import block when its provider ref is recorded
  Cloud Storage has no bucket-to-bucket replication setting: a copy to its replica (a Storage Transfer Service job, or
  a dual-region location instead) is a comment

Read back from (google type, attributes) pairs, Terraform state as it is or Cloud Asset Inventory and gcloud
normalized to it (bucket_attributes): versioning, retention, key, lifecycle, public access prevention. A setting a
source doesn't report is left as the record has it.
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND, bound, of_class
from opsdir.core.inventory import of_types, resource
from opsdir.domains.data.storage import (LifecycleRule, depth_summary, has_depth, kept_store, lifecycle_rules,
                                         lifecycle_value)
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from opsdir_format_terraform.state import first_block
from .names import REGION, label

CLASSES = {"cool": "NEARLINE", "cold": "COLDLINE", "archive": "ARCHIVE"}
_NEUTRAL = {"NEARLINE": "cool", "COLDLINE": "cold", "ARCHIVE": "archive"}
DAY = 86400


def bucket_of(uri):
    """The bucket of a gs:// storage reference (gs://bucket/prefix -> bucket), else None."""
    return uri[len("gs://"):].split("/", 1)[0] if (uri or "").startswith("gs://") else None


def kept_buckets(m):
    """Environment m's object stores in Cloud Storage whose settings the stack renders: described by the record, kept
    by the stack."""
    return tuple(b for b in of_class(m, "ciamObjectStore")
                 if bucket_of(one(b, "ciamStorageRef")) and kept_store(b))


# ------------------------------------------------------------------ render
def _key(m, b):
    role = one(b, "ciamEncryptedByRole")
    uri = bound(m, role, "ciamRefUri") if role else None
    if uri is None:
        return (), ()
    if uri.startswith(UNBOUND):
        return (), (("#", f"{uri}: no key binding for role {role} in this environment"),)
    return ((f"# {rdn_value(b)}: the Cloud Storage service agent (service-<project number>@gs-project-accounts.iam."
             "gserviceaccount.com) needs roles/cloudkms.cryptoKeyEncrypterDecrypter on its key",),
            (("encryption", Block((("default_kms_key_name", uri.split("://", 1)[1]),))),))


def _rule(r):
    condition = (("days_since_noncurrent_time", r.days), ("with_state", "ARCHIVED")) if r.noncurrent \
        else (("age", r.days),)
    action = (("type", "Delete"),) if r.action == "delete" else \
        (("type", "SetStorageClass"), ("storage_class", CLASSES[r.action]))
    return "lifecycle_rule", Block((("condition", Block(condition)), ("action", Block(action))))


def _bucket(m, b):
    n, bucket = tf_name(rdn_value(b)), bucket_of(one(b, "ciamStorageRef"))
    mode, days = one(b, "ciamStorageImmutability"), one(b, "ciamStorageLockDays")
    versioning, public = one(b, "ciamStorageVersioning"), one(b, "ciamStoragePublicBlocked")
    notes, body = _key(m, b)
    return (*notes,
            *((f"# {rdn_value(b)}: copied to {one(b, 'ciamStorageReplicaRef')}: Cloud Storage has no bucket-to-bucket "
               "replication setting; a Storage Transfer Service job (or a dual-region location) does it: not rendered",)
              if one(b, "ciamStorageReplicaRef") else ()),
            block("resource", ["google_storage_bucket", n], [
                ("name", bucket), ("location", REGION), ("uniform_bucket_level_access", True),
                *((("public_access_prevention", "enforced" if public == "TRUE" else "inherited"),) if public else ()),
                *((("versioning", Block((("enabled", versioning == "TRUE"),))),) if versioning else ()),
                *((("retention_policy", Block((("retention_period", int(days or 1) * DAY),
                                                ("is_locked", mode == "compliance")))),)
                  if mode in ("governance", "compliance") else ()),
                *body, *(_rule(r) for r in lifecycle_rules(b)),
                ("labels", {"role": label(one(b, "ciamBindingRole")), "managed_by": "opsdir"})]),
            *((import_block(f"google_storage_bucket.{n}", bucket),) if adopted(b) else ()))


def render_object_stores(m):
    """HCL for environment m's object stores in Cloud Storage the record describes: comments naming who keeps the
    others and what to ask them for, then those the stack keeps."""
    described = [b for b in of_class(m, "ciamObjectStore") if bucket_of(one(b, "ciamStorageRef")) and has_depth(b)]
    return (*(f"# Object store '{rdn_value(b)}' (role {one(b, 'ciamBindingRole')}) is kept by {kept_by(m, b)}: not "
              f"rendered here. Ask them for: {depth_summary(b)}" for b in described if not owned(b)),
            *(x for b in kept_buckets(m) for x in _bucket(m, b)))


# ------------------------------------------------------------------ read back
def _cli_rule(r):
    action, condition = r.get("action") or {}, r.get("condition") or {}
    state = "ARCHIVED" if condition.get("isLive") is False else condition.get("withState")
    return {"action": [{"type": action.get("type"), "storage_class": action.get("storageClass")}],
            "condition": [{"age": condition.get("age"),
                           "days_since_noncurrent_time": condition.get("daysSinceNoncurrentTime"),
                           "with_state": state}]}


def bucket_attributes(d):
    """A bucket as Cloud Asset Inventory (storage#bucket) or `gcloud storage buckets describe` prints it, as
    google_storage_bucket's attributes."""
    retention = d.get("retentionPolicy") or d.get("retention_policy") or {}
    period = retention.get("retentionPeriod") or retention.get("retention_period")
    lifecycle = d.get("lifecycle") or d.get("lifecycle_config")
    versioning = (d.get("versioning") or {}).get("enabled") if "versioning" in d else d.get("versioning_enabled")
    key = (d.get("encryption") or {}).get("defaultKmsKeyName") or d.get("default_kms_key")
    public = (d.get("iamConfiguration") or {}).get("publicAccessPrevention") or d.get("public_access_prevention")
    return {"name": d.get("name") or (d.get("storage_url") or "")[5:].rstrip("/"), "labels": d.get("labels") or {},
            **({"versioning": [{"enabled": versioning is True}]} if versioning is not None else {}),
            **({"retention_policy": [{"retention_period": int(period), "is_locked": (
                retention.get("isLocked") or retention.get("is_locked")) is True}]} if period else {}),
            **({"encryption": [{"default_kms_key_name": key}]} if key else {}),
            **({"lifecycle_rule": [_cli_rule(r) for r in lifecycle.get("rule") or ()]} if lifecycle else {}),
            **({"public_access_prevention": public} if public else {})}


def _rules(a):
    """The ciamStorageLifecycle values of a bucket's lifecycle rules."""
    out = []
    for r in a.get("lifecycle_rule") or ():
        action, condition = first_block(r.get("action")), first_block(r.get("condition"))
        noncurrent = bool(condition.get("days_since_noncurrent_time")) or condition.get("with_state") == "ARCHIVED"
        days = condition.get("days_since_noncurrent_time") or condition.get("age")
        what = "delete" if action.get("type") == "Delete" else _NEUTRAL.get(action.get("storage_class"))
        if days and what:
            out.append(LifecycleRule(noncurrent, int(days), what))
    return sorted(dict.fromkeys(lifecycle_value(r) for r in out))


def object_store_resources(pairs):
    """Storage resources of (google type, attributes) pairs: Cloud Storage buckets with their versioning, retention,
    key, lifecycle and public access prevention."""
    def one_bucket(a):
        retention = first_block(a.get("retention_policy"))
        period = retention.get("retention_period")
        versioning = first_block(a.get("versioning"))
        public = a.get("public_access_prevention")
        labels = a.get("labels") or {}
        return resource("storage", a.get("name"), {
            "ciamStorageRef": f"gs://{a.get('name')}",
            "ciamStorageVersioning": ("TRUE" if versioning.get("enabled") else "FALSE") if versioning else None,
            "ciamStorageImmutability": ("compliance" if retention.get("is_locked") else "governance")
            if period else None,
            "ciamStorageLockDays": -(-int(period) // DAY) if period else None,
            "ciamStorageLifecycle": _rules(a) if "lifecycle_rule" in a else None,
            "ciamStoragePublicBlocked": ("TRUE" if public == "enforced" else "FALSE") if public else None},
            links={"ciamEncryptedByRole": first_block(a.get("encryption")).get("default_kms_key_name") or None},
            name=a.get("name"), role=labels.get("role") or labels.get("bindingrole") or None)
    return tuple(one_bucket(a) for a in of_types(pairs, "google_storage_bucket") if a.get("name"))
