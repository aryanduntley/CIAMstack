"""Object stores on Google Cloud: a bucket the record describes and the stack keeps is rendered with uniform access,
public access prevention, versioning, a retention policy (locked for compliance), its default KMS key and a lifecycle
rule per recorded rule, adopted when it exists; its copy to another bucket a Storage Transfer Service replication job
(Cloud Storage has no replication setting), to anything else a comment; one someone else keeps is named with what to
ask for. Read back from Terraform state, Cloud Asset Inventory and gcloud (the replica an enabled transfer job copies
it to), what it renders reading back as recorded."""
import json

from opsdir_adapter_gcp.cli import cli_resources
from opsdir_adapter_gcp.inventory import state_resources
from opsdir_adapter_gcp.storage import kept_buckets, render_object_stores
from network_fixtures import ALPHA, entry, model

KEY = "projects/p/locations/us-central1/keyRings/ciam/cryptoKeys/disk"
STORE = dict(ciamBindingRole="backup-target", ciamStorageRef="gs://alpha-backups", ciamRetentionDays="35",
             ciamStorageVersioning="TRUE", ciamStorageImmutability="compliance", ciamStorageLockDays="35",
             ciamEncryptedByRole="disk-encryption", ciamStoragePublicBlocked="TRUE",
             ciamStorageReplicaRef="gs://alpha-backups-dr",
             ciamStorageLifecycle=("30 cold", "400 delete", "noncurrent 30 delete"))
KEY_ENTRY = entry(ALPHA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri=f"gcp-kms://{KEY}")


def _render(*records):
    return "\n\n".join(render_object_stores(model(alpha=records)[1]))


def _flat(text):
    return " ".join(text.split())


def test_a_kept_bucket_with_every_setting_and_its_copy_named():
    out = _flat(_render(KEY_ENTRY, entry(ALPHA, "backup", "ciamBackupTarget", **STORE,
                                         ciamProviderRef="alpha-backups")))
    for text in ('resource "google_storage_bucket" "backup"', 'name = "alpha-backups"', "location = var.region",
                 "uniform_bucket_level_access = true", 'public_access_prevention = "enforced"',
                 "versioning { enabled = true }", "retention_period = 3024000", "is_locked = true",
                 f'default_kms_key_name = "{KEY}"', "condition { age = 30 }",
                 'action { type = "SetStorageClass" storage_class = "COLDLINE" }', "condition { age = 400 }",
                 'action { type = "Delete" }', 'days_since_noncurrent_time = 30 with_state = "ARCHIVED"',
                 'role = "backup-target"', "copied to gs://alpha-backups-dr", "gs-project-accounts",
                 "to = google_storage_bucket.backup", 'id = "alpha-backups"',
                 'resource "google_storage_transfer_job" "backup_copy"',
                 "gcs_data_source { bucket_name = google_storage_bucket.backup.name }",
                 'gcs_data_sink { bucket_name = "alpha-backups-dr" }', 'overwrite_when = "DIFFERENT"',
                 "storage-transfer-service", "roles/pubsub.editor"):
        assert _flat(text) in out, text


def test_a_copy_under_a_prefix_or_to_something_else():
    prefixed = _flat(_render(entry(ALPHA, "backup", "ciamBackupTarget",
                                   **{**STORE, "ciamStorageReplicaRef": "gs://dr-bucket/ds/"})))
    assert 'gcs_data_sink { bucket_name = "dr-bucket" path = "ds/" }' in prefixed
    other = _render(entry(ALPHA, "backup", "ciamBackupTarget", **{**STORE, "ciamStorageReplicaRef": "s3://elsewhere"}))
    assert "# backup: its replica s3://elsewhere isn't a Cloud Storage bucket: the copy is not rendered" in other
    assert "google_storage_transfer_job" not in other


def test_others_buckets_are_named_and_references_left_alone():
    out = _render(entry(ALPHA, "store", "ciamObjectStore", ciamBindingRole="exports", ciamStorageRef="gs://b",
                        ciamStorageImmutability="governance", ciamStorageLockDays="7",
                        ciamManagedBy="cn=storage-team,ou=owners,dc=ciam-ops"))
    assert out == ("# Object store 'store' (role exports) is kept by cn=storage-team,ou=owners,dc=ciam-ops: "
                   "not rendered here. Ask them for: governance lock 7 days")
    referenced = entry(ALPHA, "backup", "ciamBackupTarget", ciamBindingRole="backup-target",
                       ciamStorageRef="gs://alpha-backups")
    assert _render(referenced) == "" and kept_buckets(model(alpha=(referenced,))[1]) == ()


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": "x", "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": a}]} for t, a in resources]})


BUCKET = {"name": "alpha-backups", "labels": {"role": "backup-target", "managed_by": "opsdir"},
          "versioning": [{"enabled": True}], "retention_policy": [{"retention_period": 3024000, "is_locked": True}],
          "encryption": [{"default_kms_key_name": KEY}], "public_access_prevention": "enforced",
          "lifecycle_rule": [
              {"condition": [{"age": 30}], "action": [{"type": "SetStorageClass", "storage_class": "COLDLINE"}]},
              {"condition": [{"age": 400}], "action": [{"type": "Delete"}]},
              {"condition": [{"days_since_noncurrent_time": 30, "with_state": "ARCHIVED"}],
               "action": [{"type": "Delete"}]}]}
READ = {"ciamStorageRef": ("gs://alpha-backups",), "ciamStorageVersioning": ("TRUE",),
        "ciamStorageImmutability": ("compliance",), "ciamStorageLockDays": ("35",),
        "ciamStorageLifecycle": ("30 cold", "400 delete", "noncurrent 30 delete"),
        "ciamStoragePublicBlocked": ("TRUE",)}


JOB = {"name": "transferJobs/123", "status": "ENABLED", "replication_spec": [{
    "gcs_data_source": [{"bucket_name": "alpha-backups"}], "gcs_data_sink": [{"bucket_name": "alpha-backups-dr"}]}]}


def test_the_replica_is_the_sink_of_an_enabled_transfer_job():
    def replica(*jobs):
        resources, _ = state_resources(_state(("google_storage_bucket", BUCKET), *jobs))
        return next(r for r in resources if r.kind == "storage").attrs.get("ciamStorageReplicaRef")
    assert replica(("google_storage_transfer_job", JOB)) == ("gs://alpha-backups-dr",)
    assert replica(("google_storage_transfer_job", {**JOB, "status": "DISABLED"})) is None
    scheduled = {"name": "transferJobs/9", "transfer_spec": [{
        "gcs_data_source": [{"bucket_name": "alpha-backups"}],
        "gcs_data_sink": [{"bucket_name": "dr", "path": "ds/"}]}]}
    assert replica(("google_storage_transfer_job", scheduled)) == ("gs://dr/ds",)


def test_a_transfer_job_from_the_asset_inventory_or_gcloud():
    data = {"name": "transferJobs/123", "status": "ENABLED", "projectId": "p",
            "replicationSpec": {"gcsDataSource": {"bucketName": "alpha-backups"},
                                "gcsDataSink": {"bucketName": "alpha-backups-dr"}}}
    bucket = {"kind": "storage#bucket", "name": "alpha-backups"}
    asset = {"name": "//storagetransfer.googleapis.com/projects/p/transferJobs/123",
             "assetType": "storagetransfer.googleapis.com/TransferJob", "resource": {"version": "v1", "data": data}}
    for texts in ({"assets.jsonl": json.dumps(asset) + "\n", "buckets.json": json.dumps([bucket])},
                  {"transfer-jobs.json": json.dumps([data]), "buckets.json": json.dumps([bucket])}):
        resources, notices = cli_resources(texts)
        (store,) = (r for r in resources if r.kind == "storage")
        assert store.attrs["ciamStorageReplicaRef"] == ("gs://alpha-backups-dr",), texts
        assert not [n for n in notices if "transfer" in n.lower()], notices


def test_a_bucket_is_read_back_from_state():
    resources, _ = state_resources(_state(("google_storage_bucket", BUCKET)))
    (store,) = (r for r in resources if r.kind == "storage")
    assert (store.ref, store.role) == ("alpha-backups", "backup-target")
    assert store.attrs == READ and store.links == {"ciamEncryptedByRole": KEY}
    (bare,) = (r for r in state_resources(_state(("google_storage_bucket", {"name": "b"})))[0] if r.kind == "storage")
    assert bare.attrs == {"ciamStorageRef": ("gs://b",)}


def test_the_asset_inventory_reads_the_same():
    asset = {"name": "//storage.googleapis.com/alpha-backups", "assetType": "storage.googleapis.com/Bucket",
             "resource": {"version": "v1", "data": {
                 "kind": "storage#bucket", "name": "alpha-backups", "labels": {"role": "backup-target"},
                 "versioning": {"enabled": True}, "retentionPolicy": {"retentionPeriod": "3024000", "isLocked": True},
                 "encryption": {"defaultKmsKeyName": KEY},
                 "iamConfiguration": {"publicAccessPrevention": "enforced",
                                      "uniformBucketLevelAccess": {"enabled": True}},
                 "lifecycle": {"rule": [
                     {"action": {"type": "SetStorageClass", "storageClass": "COLDLINE"}, "condition": {"age": 30}},
                     {"action": {"type": "Delete"}, "condition": {"age": 400}},
                     {"action": {"type": "Delete"}, "condition": {"daysSinceNoncurrentTime": 30, "isLive": False}}]}}}}
    resources, _ = cli_resources({"assets.jsonl": json.dumps(asset) + "\n"})
    (store,) = (r for r in resources if r.kind == "storage")
    assert store.attrs == READ and store.links == {"ciamEncryptedByRole": KEY}


def test_what_it_renders_reads_back_as_recorded():
    resources, _ = state_resources(_state(("google_storage_bucket", BUCKET), ("google_storage_transfer_job", JOB)))
    (store,) = (r for r in resources if r.kind == "storage")
    recorded = {k: (v,) if isinstance(v, str) else v for k, v in STORE.items()
                if k not in ("ciamBindingRole", "ciamEncryptedByRole", "ciamRetentionDays")}
    assert {k: store.attrs[k] for k in recorded} == recorded
