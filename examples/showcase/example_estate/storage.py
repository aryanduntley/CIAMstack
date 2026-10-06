"""Object storage fixture data: how each environment's backup bucket keeps the directory backups (BACKUP below, used by
infrastructure: SOURCE / STANDBY), and the target's backup container approved change CHG-2017 adds. Each is the
attributes of the environment's ciamBackupTarget beyond its location and retention, rendered by the cloud adapters into
the stack's own Terraform and read back from what each cloud reports (cloud.py).

  source   S3 with versioning, Object Lock in compliance mode for 35 days (the backups' retention: nobody, the
           account's root included, can delete one sooner), the platform's KMS key, the public access block,
           backups moved to Glacier Instant Retrieval after 30 days and deleted after 90, old versions after 7, and
           replication to a bucket in us-west-2
  standby  Cloud Storage the same way, but for the copy (Cloud Storage has no bucket-to-bucket replication; the standby
           is itself the second copy)
  stage    a bucket the record only references (stage is rebuilt; its backups are a convenience)
  target   none until CHG-2017, which adds a container in a storage account the stack keeps

Planted for the planner to find, once CHG-2017 adds the target's container (it was set up from the stage template):
  - no immutability policy: a backup can be deleted or overwritten before its retention ends
  - nothing copies it to another region
"""
LIFECYCLE = ["30 cold", "90 delete", "noncurrent 7 delete"]
PROTECTED = {"ciamStorageVersioning": "TRUE", "ciamStorageImmutability": "compliance", "ciamStorageLockDays": "35",
             "ciamEncryptedByRole": "disk-encryption", "ciamStoragePublicBlocked": "TRUE",
             "ciamStorageLifecycle": LIFECYCLE}
BACKUP = {
    "source": {**PROTECTED, "ciamStorageReplicaRef": "s3://example-aero-ciam-prod-ds-backups-usw2",
               "ciamProviderRef": "arn:aws:s3:::example-aero-ciam-prod-ds-backups"},
    "standby": {**PROTECTED, "ciamProviderRef": "example-aero-ciam-standby-ds-backups"},
}
