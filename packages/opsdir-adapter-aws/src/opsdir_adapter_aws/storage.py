"""AWS: the object stores (S3 buckets) an environment uses, rendered as Terraform and read back. Pure.

Rendered into the stack's main.tf, for each object store whose record says how it keeps what it holds
(opsdir.domains.data.storage) and that the stack keeps (one naming ciamManagedBy is someone else's: a comment names
them); a store the record only references stays a reference (the backup target's data source):

  aws_s3_bucket (Object Lock enabled when its objects are locked: only possible when the bucket is created) with its
  versioning, its default Object Lock retention (GOVERNANCE or COMPLIANCE, days), SSE-KMS with the key of its key role
  (S3 bucket keys on), the public access block (all four settings), one lifecycle rule (transitions to STANDARD_IA,
  GLACIER_IR or DEEP_ARCHIVE for cool, cold, archive; expiration; the same for noncurrent versions) and replication to
  its replica's bucket (the replication role an input; KMS-encrypted objects re-encrypted with the replica's key, an
  input too), each as its own resource
  an import block when its provider ref is recorded (the bucket's name: the settings are written over)

Read back from (Terraform type, attributes) pairs, Terraform state as it is or the CLI normalized to it
(cli_storage.py): aws_s3_bucket and the aws_s3_bucket_versioning, _object_lock_configuration,
_server_side_encryption_configuration, _public_access_block, _lifecycle_configuration and _replication_configuration
of each. A setting a source doesn't report is left as the record has it.
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND, bound, of_class
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.data.storage import (LifecycleRule, depth_summary, has_depth, kept_store, lifecycle_rules,
                                         lifecycle_value)
from opsdir.domains.network.plumbing import adopted
from opsdir.domains.network.stack import kept_by, owned
from opsdir_format_terraform.hcl import Block, block, import_block, ref, tf_name
from opsdir_format_terraform.state import blocks
from .network import binding_tags

TIERS = {"cool": "STANDARD_IA", "cold": "GLACIER_IR", "archive": "DEEP_ARCHIVE"}
_NEUTRAL_TIERS = {"STANDARD_IA": "cool", "ONEZONE_IA": "cool", "INTELLIGENT_TIERING": "cool", "GLACIER_IR": "cold",
                  "GLACIER": "archive", "DEEP_ARCHIVE": "archive"}
MODES = {"governance": "GOVERNANCE", "compliance": "COMPLIANCE"}
PUBLIC_BLOCK = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")


def bucket_of(uri):
    """The bucket of an s3:// storage reference (s3://bucket/prefix -> bucket), else None."""
    return uri[len("s3://"):].split("/", 1)[0] if (uri or "").startswith("s3://") else None


def kept_buckets(m):
    """Environment m's object stores on S3 whose settings the stack renders: described by the record, kept by the
    stack."""
    return tuple(b for b in of_class(m, "ciamObjectStore")
                 if bucket_of(one(b, "ciamStorageRef")) and kept_store(b))


# ------------------------------------------------------------------ render
def _key_arn(m, b):
    role = one(b, "ciamEncryptedByRole")
    uri = bound(m, role, "ciamRefUri") if role else None
    if uri is None:
        return None, ()
    if uri.startswith(UNBOUND):
        return None, (f"# {uri}: no key binding for role {role} in this environment",)
    return uri.split("://", 1)[1], ()


def _lifecycle(rules):
    """The one lifecycle rule's body: transitions and expiration of current objects, then of noncurrent versions (the
    earliest delete when several are recorded)."""
    def body(noncurrent):
        days = "noncurrent_days" if noncurrent else "days"
        mine = [r for r in rules if r.noncurrent == noncurrent]
        delete = min((r.days for r in mine if r.action == "delete"), default=None)
        prefix = "noncurrent_version_" if noncurrent else ""
        return (*((f"{prefix}transition", Block(((days, r.days), ("storage_class", TIERS[r.action]))))
                  for r in mine if r.action in TIERS),
                *(((f"{prefix}expiration", Block(((days, delete),))),) if delete is not None else ()))
    return (("id", "ciam"), ("status", "Enabled"), ("filter", Block(())), *body(False), *body(True))


def _bucket(m, b):
    n, cn, bucket = tf_name(rdn_value(b)), rdn_value(b), bucket_of(one(b, "ciamStorageRef"))
    target = ref(f"aws_s3_bucket.{n}.id")
    mode, days = one(b, "ciamStorageImmutability"), one(b, "ciamStorageLockDays")
    locked = mode in MODES
    versioning = one(b, "ciamStorageVersioning")
    key, key_note = _key_arn(m, b)
    rules, replica = lifecycle_rules(b), bucket_of(one(b, "ciamStorageReplicaRef"))
    public = one(b, "ciamStoragePublicBlocked")
    notes = (*key_note,
             *((f"# {cn}: Object Lock needs versioning: it is turned on with the lock",)
               if locked and versioning != "TRUE" else ()),
             *((f"# {cn}: its replica {one(b, 'ciamStorageReplicaRef')} isn't an S3 bucket: replication not rendered",)
               if one(b, "ciamStorageReplicaRef") and not replica else ()))
    enabled = versioning == "TRUE" or locked or bool(replica)
    status = "Enabled" if enabled else "Suspended" if versioning == "FALSE" else None
    return (*notes,
            block("resource", ["aws_s3_bucket", n], [("bucket", bucket),
                                                     *((("object_lock_enabled", True),) if locked else ()),
                                                     ("tags", binding_tags(b))]),
            *((block("resource", ["aws_s3_bucket_versioning", n], [
                ("bucket", target), ("versioning_configuration", Block((("status", status),)))]),) if status else ()),
            *((block("resource", ["aws_s3_bucket_object_lock_configuration", n], [
                ("bucket", target), ("rule", Block((("default_retention", Block((
                    ("mode", MODES[mode]), ("days", int(days or 1))))),))),
                ("depends_on", [ref(f"aws_s3_bucket_versioning.{n}")])]),) if locked else ()),
            *((block("resource", ["aws_s3_bucket_server_side_encryption_configuration", n], [
                ("bucket", target), ("rule", Block((
                    ("apply_server_side_encryption_by_default", Block((("sse_algorithm", "aws:kms"),
                                                                       ("kms_master_key_id", key)))),
                    ("bucket_key_enabled", True))))]),) if key else ()),
            *((block("resource", ["aws_s3_bucket_public_access_block", n], [
                ("bucket", target), *((k, public == "TRUE") for k in PUBLIC_BLOCK)]),) if public else ()),
            *((block("resource", ["aws_s3_bucket_lifecycle_configuration", n], [
                ("bucket", target), ("rule", Block(_lifecycle(rules))),
                *((("depends_on", [ref(f"aws_s3_bucket_versioning.{n}")]),) if status else ())]),) if rules else ()),
            *(_replication(b, n, target, replica, key) if replica else ()),
            *((import_block(f"aws_s3_bucket.{n}", bucket),) if adopted(b) else ()))


def _replication(b, n, target, replica, key):
    role, replica_key = f"{n}_replication_role_arn", f"{n}_replica_kms_key_arn"
    rule = (("id", "ciam"), ("status", "Enabled"), ("filter", Block(())),
            ("delete_marker_replication", Block((("status", "Enabled"),))),
            *((("source_selection_criteria", Block((("sse_kms_encrypted_objects",
                                                     Block((("status", "Enabled"),))),))),) if key else ()),
            ("destination", Block((("bucket", f"arn:aws:s3:::{replica}"),
                                   *((("encryption_configuration", Block((
                                       ("replica_kms_key_id", ref(f"var.{replica_key}")),))),) if key else ())))))
    return (block("variable", [role], [("type", ref("string")), ("description", (
                f"The IAM role S3 replicates bucket {rdn_value(b)} to {replica} with"))]),
            *((block("variable", [replica_key], [("type", ref("string")), ("description", (
                f"The KMS key ARN objects are re-encrypted with in {replica}"))]),) if key else ()),
            block("resource", ["aws_s3_bucket_replication_configuration", n], [
                ("bucket", target), ("role", ref(f"var.{role}")), ("rule", Block(rule)),
                ("depends_on", [ref(f"aws_s3_bucket_versioning.{n}")])]))


def render_object_stores(m):
    """HCL for environment m's object stores the record describes: comments naming who keeps the others and what to
    ask them for, then those the stack keeps."""
    described = [b for b in of_class(m, "ciamObjectStore") if bucket_of(one(b, "ciamStorageRef")) and has_depth(b)]
    return (*(f"# Object store '{rdn_value(b)}' (role {one(b, 'ciamBindingRole')}) is kept by {kept_by(m, b)}: not "
              f"rendered here. Ask them for: {depth_summary(b)}" for b in described if not owned(b)),
            *(x for b in kept_buckets(m) for x in _bucket(m, b)))


# ------------------------------------------------------------------ read back
def _by_bucket(pairs, kind):
    return {a.get("bucket"): a for a in of_types(pairs, kind) if a.get("bucket")}


def _first(v):
    found = blocks(v)
    return found[0] if found else {}


def _lock(a):
    retention = _first(_first(a.get("rule")).get("default_retention"))
    days = retention.get("days") or (retention.get("years") or 0) * 365 or None
    mode = (retention.get("mode") or "").lower()
    return {"ciamStorageImmutability": mode if mode in MODES else "none",
            "ciamStorageLockDays": days if mode in MODES else None}


def _rules(a):
    """The ciamStorageLifecycle values of a lifecycle configuration's enabled rules."""
    out = []
    for r in blocks(a.get("rule")):
        if (r.get("status") or "Enabled") != "Enabled":
            continue
        for noncurrent, prefix, days in ((False, "", "days"), (True, "noncurrent_version_", "noncurrent_days")):
            out += [LifecycleRule(noncurrent, int(t[days]), _NEUTRAL_TIERS[t.get("storage_class")])
                    for t in blocks(r.get(f"{prefix}transition")) if t.get(days)
                    and t.get("storage_class") in _NEUTRAL_TIERS]
            out += [LifecycleRule(noncurrent, int(e[days]), "delete") for e in blocks(r.get(f"{prefix}expiration"))
                    if e.get(days)]
    return sorted(dict.fromkeys(lifecycle_value(r) for r in out))


def _replica(a):
    rule = next((r for r in blocks(a.get("rule")) if (r.get("status") or "Enabled") == "Enabled"), {})
    arn = _first(rule.get("destination")).get("bucket") or ""
    return f"s3://{arn.rsplit(':', 1)[-1]}" if arn else None


def object_store_resources(pairs):
    """Storage resources of (Terraform type, attributes) pairs: S3 buckets, with what their settings resources say."""
    def settings(kind):
        return _by_bucket(pairs, f"aws_s3_bucket_{kind}")
    versioning, lock, sse = settings("versioning"), settings("object_lock_configuration"), \
        settings("server_side_encryption_configuration")
    public, lifecycle, replication = settings("public_access_block"), settings("lifecycle_configuration"), \
        settings("replication_configuration")

    def one_bucket(a):
        name = a.get("bucket")
        v = (_first(versioning[name].get("versioning_configuration")).get("status")
             if name in versioning else None)
        default = _first(_first(sse.get(name, {}).get("rule")).get("apply_server_side_encryption_by_default"))
        return resource("storage", a.get("arn") or name, {
            "ciamStorageRef": f"s3://{name}",
            "ciamStorageVersioning": {"Enabled": "TRUE", "Suspended": "FALSE", "Disabled": "FALSE"}.get(v),
            **(_lock(lock[name]) if name in lock else {}),
            "ciamStoragePublicBlocked": ("TRUE" if all(public[name].get(k) is True for k in PUBLIC_BLOCK) else "FALSE")
            if name in public else None,
            "ciamStorageLifecycle": _rules(lifecycle[name]) if name in lifecycle else None,
            "ciamStorageReplicaRef": _replica(replication[name]) if name in replication else None},
            links={"ciamEncryptedByRole": default.get("kms_master_key_id")
                   if default.get("sse_algorithm") in ("aws:kms", "aws:kms:dsse") else None},
            name=name, role=tagged_role(a.get("tags") or a.get("tags_all") or {}))
    return tuple(one_bucket(a) for a in of_types(pairs, "aws_s3_bucket") if a.get("bucket"))
