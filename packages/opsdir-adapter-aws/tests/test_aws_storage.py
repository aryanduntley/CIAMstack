"""Object stores on AWS: a bucket the record describes and the stack keeps is rendered with its versioning, Object
Lock, SSE-KMS, public access block, lifecycle and replication (role and replica key as inputs), adopted when it exists;
one someone else keeps is named; one the record only references stays a data source. Read back from Terraform state
and the CLI (each setting saved by bucket under its folder), what it renders reading back as recorded."""
import json

from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.inventory import state_resources
from opsdir_adapter_aws.storage import kept_buckets, render_object_stores
from network_fixtures import ALPHA, entry, model

KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/k-1"
STORE = dict(ciamBindingRole="backup-target", ciamStorageRef="s3://alpha-backups", ciamRetentionDays="35",
             ciamStorageVersioning="TRUE", ciamStorageImmutability="compliance", ciamStorageLockDays="35",
             ciamEncryptedByRole="db-key", ciamStoragePublicBlocked="TRUE", ciamStorageReplicaRef="s3://alpha-backups-dr",
             ciamStorageLifecycle=("30 cold", "400 delete", "noncurrent 30 delete"))
KEY = entry(ALPHA, "key-db", "ciamKeyRef", ciamBindingRole="db-key", ciamRefUri=f"aws-kms://{KEY_ARN}")


def _render(*records):
    return "\n\n".join(render_object_stores(model(alpha=records)[1]))


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": "x", "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, a in resources]})


def test_a_kept_bucket_with_every_setting():
    out = _render(KEY, entry(ALPHA, "backup", "ciamBackupTarget", **STORE, ciamProviderRef="alpha-backups"))
    for text in ('resource "aws_s3_bucket" "backup"', 'bucket              = "alpha-backups"',
                 "object_lock_enabled = true", 'status = "Enabled"', 'mode = "COMPLIANCE"', "days = 35",
                 'sse_algorithm     = "aws:kms"', f'kms_master_key_id = "{KEY_ARN}"', "bucket_key_enabled = true",
                 "restrict_public_buckets = true", 'storage_class = "GLACIER_IR"', "days = 400",
                 "noncurrent_days = 30", 'variable "backup_replication_role_arn"',
                 'variable "backup_replica_kms_key_arn"', 'bucket = "arn:aws:s3:::alpha-backups-dr"',
                 "replica_kms_key_id = var.backup_replica_kms_key_arn", "role   = var.backup_replication_role_arn",
                 'to = aws_s3_bucket.backup', 'id = "alpha-backups"'):
        assert text in out, text


def test_lock_without_versioning_turns_it_on_and_others_buckets_are_named():
    out = _render(entry(ALPHA, "store", "ciamObjectStore", ciamBindingRole="exports", ciamStorageRef="s3://b",
                        ciamStorageImmutability="governance", ciamStorageLockDays="7"))
    assert "# store: Object Lock needs versioning: it is turned on with the lock" in out
    assert 'mode = "GOVERNANCE"' in out and 'status = "Enabled"' in out and "import" not in out
    kept = _render(entry(ALPHA, "store", "ciamObjectStore", ciamBindingRole="exports", ciamStorageRef="s3://b",
                         ciamStorageVersioning="TRUE", ciamManagedBy="cn=storage-team,ou=owners,dc=ciam-ops"))
    assert kept == "# Object store 'store' (role exports) is kept by cn=storage-team,ou=owners,dc=ciam-ops: not " \
                   "rendered here. Ask them for: versioning"
    assert _render(entry(ALPHA, "store", "ciamObjectStore", ciamBindingRole="exports", ciamStorageRef="s3://b")) == ""


def test_a_backup_bucket_the_stack_renders_is_kept_and_one_only_referenced_is_not():
    """A kept bucket replaces the backup target's data source in main.tf (terraform._references)."""
    referenced = entry(ALPHA, "backup", "ciamBackupTarget", ciamBindingRole="backup-target",
                       ciamStorageRef="s3://alpha-backups")
    described = entry(ALPHA, "backup", "ciamBackupTarget", ciamBindingRole="backup-target",
                      ciamStorageRef="s3://alpha-backups", ciamStorageVersioning="TRUE")
    assert kept_buckets(model(alpha=(referenced,))[1]) == ()
    (kept,) = kept_buckets(model(alpha=(described,))[1])
    assert kept.dn.startswith("cn=backup,")


STATE = (("aws_s3_bucket", {"bucket": "alpha-backups", "arn": "arn:aws:s3:::alpha-backups", "object_lock_enabled": True,
                            "tags": {"Role": "backup-target"}}),
         ("aws_s3_bucket_versioning", {"bucket": "alpha-backups", "versioning_configuration": [{"status": "Enabled"}]}),
         ("aws_s3_bucket_object_lock_configuration", {"bucket": "alpha-backups", "rule": [
             {"default_retention": [{"mode": "COMPLIANCE", "days": 35, "years": None}]}]}),
         ("aws_s3_bucket_server_side_encryption_configuration", {"bucket": "alpha-backups", "rule": [
             {"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": KEY_ARN}],
              "bucket_key_enabled": True}]}),
         ("aws_s3_bucket_public_access_block", {"bucket": "alpha-backups", "block_public_acls": True,
                                                "block_public_policy": True, "ignore_public_acls": True,
                                                "restrict_public_buckets": True}),
         ("aws_s3_bucket_lifecycle_configuration", {"bucket": "alpha-backups", "rule": [
             {"id": "ciam", "status": "Enabled", "transition": [{"days": 30, "storage_class": "GLACIER_IR"}],
              "expiration": [{"days": 400}], "noncurrent_version_expiration": [{"noncurrent_days": 30}]},
             {"id": "off", "status": "Disabled", "expiration": [{"days": 1}]}]}),
         ("aws_s3_bucket_replication_configuration", {"bucket": "alpha-backups", "role": "arn:aws:iam::1:role/r",
                                                      "rule": [{"status": "Enabled", "destination": [
                                                          {"bucket": "arn:aws:s3:::alpha-backups-dr"}]}]}))
READ = {"ciamStorageRef": ("s3://alpha-backups",), "ciamStorageVersioning": ("TRUE",),
        "ciamStorageImmutability": ("compliance",), "ciamStorageLockDays": ("35",),
        "ciamStoragePublicBlocked": ("TRUE",), "ciamStorageReplicaRef": ("s3://alpha-backups-dr",),
        "ciamStorageLifecycle": ("30 cold", "400 delete", "noncurrent 30 delete")}


def test_a_bucket_is_read_back_from_state_with_its_settings():
    resources, _ = state_resources(_state(*STATE))
    (store,) = (r for r in resources if r.kind == "storage")
    assert (store.ref, store.role) == ("arn:aws:s3:::alpha-backups", "backup-target")
    assert store.attrs == READ and store.links == {"ciamEncryptedByRole": KEY_ARN}
    (bare,) = (r for r in state_resources(_state(STATE[0]))[0] if r.kind == "storage")
    assert bare.attrs == {"ciamStorageRef": ("s3://alpha-backups",)}      # settings unreported: left as recorded


def test_the_cli_outputs_read_the_same_and_lifecycle_rules_are_not_eventbridge_rules():
    texts = {
        "buckets.json": json.dumps({"Buckets": [{"Name": "alpha-backups"}]}),
        "bucket-versioning/alpha-backups.json": json.dumps({"Status": "Enabled"}),
        "bucket-versioning/never.json": json.dumps({}),
        "bucket-object-lock/alpha-backups.json": json.dumps({"ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 35}}}}),
        "bucket-encryption/alpha-backups.json": json.dumps({"ServerSideEncryptionConfiguration": {"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": KEY_ARN},
             "BucketKeyEnabled": True}]}}),
        "bucket-public-access/alpha-backups.json": json.dumps({"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True}}),
        "bucket-lifecycle/alpha-backups.json": json.dumps({"Rules": [
            {"ID": "ciam", "Status": "Enabled", "Filter": {},
             "Transitions": [{"Days": 30, "StorageClass": "GLACIER_IR"}],
             "Expiration": {"Days": 400}, "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}]}),
        "bucket-replication/alpha-backups.json": json.dumps({"ReplicationConfiguration": {
            "Role": "arn:aws:iam::1:role/r", "Rules": [{"Status": "Enabled",
                                                       "Destination": {"Bucket": "arn:aws:s3:::alpha-backups-dr"}}]}})}
    resources, notices = cli_resources(texts)
    (store,) = (r for r in resources if r.kind == "storage")
    assert store.attrs == READ and store.links == {"ciamEncryptedByRole": KEY_ARN}
    assert not any(r.kind == "job" for r in resources) and not any("not read" in n and "bucket-" in n for n in notices)


def test_what_it_renders_reads_back_as_recorded():
    """The settings a render writes, as the state holds them, read back to the record's values."""
    resources, _ = state_resources(_state(*STATE))
    (store,) = (r for r in resources if r.kind == "storage")
    recorded = {k: (v,) if isinstance(v, str) else v for k, v in STORE.items()
                if k not in ("ciamBindingRole", "ciamEncryptedByRole", "ciamRetentionDays")}
    assert {k: store.attrs[k] for k in recorded} == recorded
