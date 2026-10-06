"""The S3 bucket settings the AWS CLI reports, normalized to the attribute names of the matching Terraform resources
(opsdir_adapter_aws.storage reads both). Pure. None of these outputs names its bucket, so each is saved under a folder
saying what it is, named after the bucket, and recognized by that folder (lifecycle rules have the same top-level key
as EventBridge's list-rules; a bucket that never had versioning prints {}):

  s3api get-bucket-versioning                 bucket-versioning/<bucket>.json     -> aws_s3_bucket_versioning
  s3api get-object-lock-configuration         bucket-object-lock/<bucket>.json    -> aws_s3_bucket_object_lock_
                                                                                     configuration
  s3api get-bucket-encryption                 bucket-encryption/<bucket>.json     -> aws_s3_bucket_server_side_
                                                                                     encryption_configuration
  s3api get-public-access-block               bucket-public-access/<bucket>.json  -> aws_s3_bucket_public_access_block
  s3api get-bucket-lifecycle-configuration    bucket-lifecycle/<bucket>.json      -> aws_s3_bucket_lifecycle_
                                                                                     configuration
  s3api get-bucket-replication                bucket-replication/<bucket>.json    -> aws_s3_bucket_replication_
                                                                                     configuration
"""
from .cli_outputs import stem

FOLDERS = ("bucket-versioning", "bucket-object-lock", "bucket-encryption", "bucket-public-access", "bucket-lifecycle",
           "bucket-replication")
_PUBLIC = (("BlockPublicAcls", "block_public_acls"), ("BlockPublicPolicy", "block_public_policy"),
           ("IgnorePublicAcls", "ignore_public_acls"), ("RestrictPublicBuckets", "restrict_public_buckets"))


def storage_folder(path):
    """The bucket-settings folder an output is saved under (its recognized kind), else None."""
    folder = path.rsplit("/", 2)[-2] if "/" in path else ""
    return folder if folder in FOLDERS else None


def _rule(r):
    """A lifecycle rule as the CLI prints it, as Terraform's rule block."""
    return {"status": r.get("Status"),
            "transition": [{"days": t.get("Days"), "storage_class": t.get("StorageClass")}
                           for t in r.get("Transitions") or ()],
            "expiration": [{"days": e["Days"]} for e in (r.get("Expiration") or None,) if e and e.get("Days")],
            "noncurrent_version_transition": [{"noncurrent_days": t.get("NoncurrentDays"),
                                               "storage_class": t.get("StorageClass")}
                                              for t in r.get("NoncurrentVersionTransitions") or ()],
            "noncurrent_version_expiration": [{"noncurrent_days": e["NoncurrentDays"]}
                                              for e in (r.get("NoncurrentVersionExpiration") or None,)
                                              if e and e.get("NoncurrentDays")]}


def _pair(kind, bucket, doc):
    if kind == "bucket-versioning":
        return "aws_s3_bucket_versioning", {"bucket": bucket, "versioning_configuration": [
            {"status": doc.get("Status") or "Disabled"}]}
    if kind == "bucket-object-lock":
        retention = ((doc.get("ObjectLockConfiguration") or {}).get("Rule") or {}).get("DefaultRetention") or {}
        return "aws_s3_bucket_object_lock_configuration", {"bucket": bucket, "rule": [{"default_retention": [
            {"mode": retention.get("Mode"), "days": retention.get("Days"), "years": retention.get("Years")}]}]}
    if kind == "bucket-encryption":
        rules = (doc.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or ()
        return "aws_s3_bucket_server_side_encryption_configuration", {"bucket": bucket, "rule": [
            {"apply_server_side_encryption_by_default": [{
                "sse_algorithm": (r.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm"),
                "kms_master_key_id": (r.get("ApplyServerSideEncryptionByDefault") or {}).get("KMSMasterKeyID")}],
             "bucket_key_enabled": r.get("BucketKeyEnabled")} for r in rules]}
    if kind == "bucket-public-access":
        block = doc.get("PublicAccessBlockConfiguration") or {}
        return "aws_s3_bucket_public_access_block", {"bucket": bucket, **{t: block.get(c) for c, t in _PUBLIC}}
    if kind == "bucket-lifecycle":
        return "aws_s3_bucket_lifecycle_configuration", {"bucket": bucket,
                                                         "rule": [_rule(r) for r in doc.get("Rules") or ()]}
    config = doc.get("ReplicationConfiguration") or {}
    return "aws_s3_bucket_replication_configuration", {"bucket": bucket, "role": config.get("Role"), "rule": [
        {"status": r.get("Status"), "destination": [{"bucket": (r.get("Destination") or {}).get("Bucket")}]}
        for r in config.get("Rules") or ()]}


def storage_pairs(outs):
    """(Terraform type, attributes) pairs of the bucket-settings outputs ((path, kind, document), ...)."""
    return [_pair(k, stem(p), doc) for p, k, doc in outs if k in FOLDERS]
