"""Disk fixture data, per environment (VOLUMES below, used by infrastructure: SOURCE / TARGET / STANDBY and stage):
PingDS's data volume, the disk each directory server keeps its database on (/opt/ds/db), as a volume every server of
role ds has (volume-ds-data), and the snapshot policy that copies it (snapshots-daily). Each is (object class, cn,
binding role, attributes), rendered by the cloud adapters into the stack's own Terraform and read back from what each
cloud reports (cloud_aws, cloud_azure, cloud_gcp). Encryption is recorded explicitly (TRUE), as each cloud reports
it.

  source   500 GB io2 with 6000 provisioned IOPS, encrypted with the platform's key; snapshotted daily at 03:00 UTC by
           a Lifecycle Manager policy the stack adopted, each snapshot kept 7 days and copied to us-west-2 (the disk
           key is a multi-region key replicated there, so the copy's key is its replica)
  stage    its own 100 GB gp3 disk, no snapshots (stage is rebuilt): it drops production's snapshot policy
  target   Premium SSD v2 with 6000 IOPS and 250 MB/s
  standby  500 GB pd-ssd (its n2 machines don't take Hyperdisk), snapshotted daily at 03:00 UTC by a snapshot
           schedule kept 7 days and stored in us-east1

Planted for the planner to find (the target was set up from a sandbox template):
  - the data volume is 256 GB where the source's is 500 GB: what PingDS keeps on it doesn't fit (a blocker)
  - no snapshot policy: a lost or damaged disk can't be restored from a snapshot
Approved change CHG-2018 makes the volume 500 GB; the snapshot policy stays open (Azure's scheduled disk snapshots are
Azure Backup's, in a Backup vault: milestone 4.10 task 5).
"""
from .common import owner

ROLE, POLICY, KEY = "volume-ds-data", "snapshots-daily", "disk-encryption"
DATA = {"ciamTargetRole": "ds", "ciamVolumeKind": "data", "ciamMountPath": "/opt/ds/db", "ciamVolumeEncrypted": "TRUE",
        "ciamEncryptedByRole": KEY, "ciamOwner": owner("ciam-platform")}
DAILY = {"ciamRetentionDays": "7", "ciamSnapshotEveryHours": "24", "ciamSnapshotAt": "03:00",
         "ciamSnapshotConsistency": "crash", "ciamOwner": owner("ciam-platform")}
VOLUMES = {
    "source": (
        ("ciamVolume", "vol-ds-data", ROLE,
         {**DATA, "ciamVolumeSizeGb": "500", "ciamVolumeClass": "provisioned", "ciamIops": "6000",
          "ciamSnapshotPolicyRole": POLICY}),
        ("ciamSnapshotPolicy", "snapshots-daily", POLICY,
         {**DAILY, "ciamCopyRegion": "us-west-2", "ciamProviderRef": "policy-0c1a2b3d4e5f60718"}),
    ),
    "stage": (
        ("ciamVolume", "vol-ds-data-stage", ROLE, {**DATA, "ciamVolumeSizeGb": "100", "ciamVolumeClass": "ssd"}),
    ),
    "target": (
        ("ciamVolume", "vol-ds-data", ROLE,
         {**DATA, "ciamVolumeSizeGb": "256", "ciamVolumeClass": "provisioned", "ciamIops": "6000",
          "ciamThroughputMb": "250"}),
    ),
    "standby": (
        ("ciamVolume", "vol-ds-data", ROLE,
         {**DATA, "ciamVolumeSizeGb": "500", "ciamVolumeClass": "ssd", "ciamSnapshotPolicyRole": POLICY}),
        ("ciamSnapshotPolicy", "snapshots-daily", POLICY,
         {**DAILY, "ciamCopyRegion": "us-east1",
          "ciamProviderRef": "projects/example-aero-ciam-standby/regions/us-central1/resourcePolicies/"
                             "ciam-prod-snapshots-daily"}),
    ),
}
