"""Disks and snapshot schedules on Google Cloud: a role's boot volume on each instance's boot_disk (size, type,
labels, key), each data volume a disk in the instance's zone attached by its device name, snapshot policies as
resource policies with a daily or hourly schedule, retention and one storage location, attached to the disks that
follow them (boot disks by the instance's name). Read back from Terraform state and Cloud Asset Inventory / gcloud."""
import json

from opsdir.core.environment import servers_with_role
from opsdir_adapter_gcp.cli import cli_resources
from opsdir_adapter_gcp.inventory import state_resources
from opsdir_adapter_gcp.volumes import boot_disk, render_snapshot_policies, server_volumes
from network_fixtures import BETA, entry, model

KEY = "projects/p/locations/us-central1/keyRings/ciam/cryptoKeys/disk"
KEY_ENTRY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri=f"gcp-kms://{KEY}")
BOOT = entry(BETA, "vol-ds-boot", "ciamVolume", ciamBindingRole="volume-ds-boot", ciamTargetRole="ds",
             ciamVolumeKind="boot", ciamVolumeSizeGb="50", ciamVolumeClass="ssd",
             ciamSnapshotPolicyRole="snapshots-daily")
DATA = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
             ciamVolumeKind="data", ciamMountPath="/opt/ds/db", ciamVolumeSizeGb="200", ciamVolumeClass="provisioned",
             ciamIops="6000", ciamThroughputMb="250", ciamSnapshotPolicyRole="snapshots-daily")
POLICY = entry(BETA, "snapshots-daily", "ciamSnapshotPolicy", ciamBindingRole="snapshots-daily",
               ciamRetentionDays="7", ciamSnapshotAt="03:00", ciamCopyRegion="us-east1",
               ciamProviderRef="projects/p/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily")


def _m(*records):
    return model(beta=records)[2]


def _flat(text):
    return " ".join(text.split())


def _ds1(m):
    return servers_with_role(m, "ds")[0]


def test_the_boot_volume_sets_the_boot_disk():
    m = _m(KEY_ENTRY, BOOT, DATA, POLICY)
    notes, disk = boot_disk(m, _ds1(m), f"gcp-kms://{KEY}")
    params = dict(dict(disk.body)["initialize_params"].body)
    assert notes == () and params["size"] == 50 and params["type"] == "pd-ssd"
    assert params["labels"] == {"volume": "vol-ds-boot", "role": "volume-ds-boot", "managed_by": "opsdir"}
    assert dict(disk.body)["kms_key_self_link"] == KEY
    plain = _m(KEY_ENTRY)
    assert dict(boot_disk(plain, _ds1(plain), f"gcp-kms://{KEY}")[1].body) == {
        "initialize_params": dict(boot_disk(plain, _ds1(plain), f"gcp-kms://{KEY}")[1].body)["initialize_params"],
        "kms_key_self_link": KEY}


def test_a_data_volume_is_an_attached_disk_and_both_follow_their_schedule():
    m = _m(KEY_ENTRY, BOOT, DATA, POLICY)
    out = _flat("\n\n".join(server_volumes(m, _ds1(m))))
    for text in ('resource "google_compute_disk" "ds_1_vol_ds_data"', 'name = "ds-1-vol-ds-data"', 'zone = "zone-a"',
                 'type = "hyperdisk-balanced"', "size = 200", "provisioned_iops = 6000", "provisioned_throughput = 250",
                 f'disk_encryption_key {{ kms_key_self_link = "{KEY}" }}', 'snapshot_policy = "snapshots-daily"',
                 'resource "google_compute_attached_disk" "ds_1_vol_ds_data"', 'device_name = "vol-ds-data"',
                 "instance = google_compute_instance.ds_1.id", "# vol-ds-data: hyperdisk-balanced needs a machine "
                 "series that takes Hyperdisk",
                 'resource "google_compute_disk_resource_policy_attachment" "ds_1_boot"',
                 "disk = google_compute_instance.ds_1.name",
                 'resource "google_compute_disk_resource_policy_attachment" "ds_1_vol_ds_data"',
                 "name = google_compute_resource_policy.snapshots_daily.name"):
        assert _flat(text) in out, text


def test_a_snapshot_policy_is_a_resource_policy_with_its_schedule():
    out = _flat("\n\n".join(render_snapshot_policies(_m(KEY_ENTRY, POLICY))))
    for text in ('resource "google_compute_resource_policy" "snapshots_daily"', 'name = "ciam-prod-snapshots-daily"',
                 'daily_schedule { days_in_cycle = 1 start_time = "03:00" }', "max_retention_days = 7",
                 'on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"', 'storage_locations = ["us-east1"]',
                 "guest_flush = false", 'policy = "snapshots-daily" role = "snapshots-daily"',
                 'to = google_compute_resource_policy.snapshots_daily '
                 'id = "projects/p/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily"'):
        assert _flat(text) in out, text
    hourly = entry(BETA, "snapshots-often", "ciamSnapshotPolicy", ciamBindingRole="snapshots-often",
                   ciamRetentionDays="2", ciamSnapshotEveryHours="6", ciamSnapshotAt="03:30",
                   ciamSnapshotConsistency="application", ciamCopyRegion=("us-east1", "us-west1"))
    out = _flat("\n\n".join(render_snapshot_policies(_m(hourly))))
    assert 'hourly_schedule { hours_in_cycle = 6 start_time = "03:00" }' in out and "guest_flush = true" in out
    assert "starts schedules on the hour: 03:00, not 03:30" in out and "us-west1 not rendered" in out
    rare = entry(BETA, "snapshots-rare", "ciamSnapshotPolicy", ciamBindingRole="snapshots-rare",
                 ciamRetentionDays="30", ciamSnapshotEveryHours="48")
    assert "not every 48 hours: not rendered" in "\n".join(render_snapshot_policies(_m(rare)))


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}",
         "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


INSTANCE = ("google_compute_instance", {
    "id": "projects/p/zones/us-central1-a/instances/ds-1", "name": "ds-1", "labels": {"role": "ds"},
    "boot_disk": [{"source": "projects/p/zones/us-central1-a/disks/ds-1", "kms_key_self_link": KEY,
                   "initialize_params": [{"size": 50, "type": "pd-ssd",
                                          "labels": {"volume": "vol-ds-boot", "role": "volume-ds-boot"}}]}]})
DISK = ("google_compute_disk", {"id": "projects/p/zones/us-central1-a/disks/ds-1-vol-ds-data",
                                "name": "ds-1-vol-ds-data",
                                "size": 200, "type": "hyperdisk-balanced", "provisioned_iops": 6000,
                                "provisioned_throughput": 250, "disk_encryption_key": [{"kms_key_self_link": KEY}],
                                "labels": {"volume": "vol-ds-data", "role": "volume-ds-data"}})
ATTACHED = ("google_compute_attached_disk", {"disk": DISK[1]["id"], "instance": INSTANCE[1]["id"]})
SCHEDULE = ("google_compute_resource_policy", {
    "id": "projects/p/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily",
    "name": "ciam-prod-snapshots-daily", "region": "us-central1",
    "snapshot_schedule_policy": [{"schedule": [{"daily_schedule": [{"days_in_cycle": 1, "start_time": "03:00"}]}],
                                  "retention_policy": [{"max_retention_days": 7}],
                                  "snapshot_properties": [{"storage_locations": ["us-east1"], "guest_flush": False,
                                                           "labels": {"policy": "snapshots-daily",
                                                                      "role": "snapshots-daily"}}]}]})
POLICY_ON_DISK = ("google_compute_disk_resource_policy_attachment",
                  {"name": "ciam-prod-snapshots-daily", "disk": "ds-1-vol-ds-data", "zone": "us-central1-a"})
POLICY_ON_BOOT = ("google_compute_disk_resource_policy_attachment",
                  {"name": "ciam-prod-snapshots-daily", "disk": "ds-1", "zone": "us-central1-a"})


def _by(resources):
    return {(r.kind, r.ref): r for r in resources}


def test_disks_boot_disks_and_schedules_are_read_back_from_state():
    by = _by(state_resources(_state(INSTANCE, DISK, ATTACHED, SCHEDULE, POLICY_ON_DISK, POLICY_ON_BOOT))[0])
    ref = "projects/p/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily"
    data = by[("volume", "vol-ds-data")]
    assert data.attrs == {"ciamVolumeKind": ("data",), "ciamVolumeSizeGb": ("200",),
                          "ciamVolumeClass": ("provisioned",),
                          "ciamIops": ("6000",), "ciamThroughputMb": ("250",), "ciamVolumeEncrypted": ("TRUE",),
                          "ciamTargetRole": ("ds",)}
    assert data.links == {"ciamEncryptedByRole": KEY, "ciamSnapshotPolicyRole": ref}
    boot = by[("volume", "vol-ds-boot")]
    assert boot.attrs["ciamVolumeKind"] == ("boot",) and boot.attrs["ciamVolumeSizeGb"] == ("50",)
    assert boot.links == {"ciamEncryptedByRole": KEY, "ciamSnapshotPolicyRole": ref}
    policy = by[("snapshot-policy", ref)]
    assert policy.attrs == {"ciamRetentionDays": ("7",), "ciamSnapshotEveryHours": ("24",),
                            "ciamSnapshotAt": ("03:00",),
                            "ciamCopyRegion": ("us-east1",), "ciamSnapshotConsistency": ("crash",)}
    assert policy.role == "snapshots-daily" and policy.name == "snapshots-daily"      # by its snapshots' label policy


def test_the_asset_inventory_reads_the_same_and_names_an_unlabelled_data_disk():
    base = "https://www.googleapis.com/compute/v1/projects/p"
    instance = {"kind": "compute#instance", "name": "ds-1", "selfLink": f"{base}/zones/us-central1-a/instances/ds-1",
                "labels": {"role": "ds"}, "zone": f"{base}/zones/us-central1-a",
                "disks": [{"boot": True, "source": f"{base}/zones/us-central1-a/disks/ds-1"}]}
    boot = {"kind": "compute#disk", "name": "ds-1", "selfLink": f"{base}/zones/us-central1-a/disks/ds-1",
            "sizeGb": "50", "type": f"{base}/zones/us-central1-a/diskTypes/pd-ssd",
            "diskEncryptionKey": {"kmsKeyName": f"{KEY}/cryptoKeyVersions/1"},
            "labels": {"volume": "vol-ds-boot", "role": "volume-ds-boot"}, "users": [instance["selfLink"]],
            "resourcePolicies": [f"{base}/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily"]}
    data = {"kind": "compute#disk", "name": "ds-1-vol-ds-data", "selfLink": f"{base}/zones/us-central1-a/disks/ds-1-d",
            "sizeGb": "200", "type": f"{base}/zones/us-central1-a/diskTypes/hyperdisk-balanced",
            "provisionedIops": "6000", "labels": {"volume": "vol-ds-data", "role": "volume-ds-data"},
            "users": [instance["selfLink"]]}
    bare = {"kind": "compute#disk", "name": "scratch", "selfLink": f"{base}/zones/us-central1-a/disks/scratch",
            "sizeGb": "10", "users": [instance["selfLink"]]}
    policy = {"kind": "compute#resourcePolicy", "name": "ciam-prod-snapshots-daily",
              "region": f"{base}/regions/us-central1",
              "selfLink": f"{base}/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily",
              "snapshotSchedulePolicy": {"schedule": {"hourlySchedule": {"hoursInCycle": 6, "startTime": "03:00"}},
                                         "retentionPolicy": {"maxRetentionDays": 7},
                                         "snapshotProperties": {"storageLocations": ["us-central1"], "guestFlush": True,
                                                                "labels": {"role": "snapshots-daily"}}}}
    resources, notices = cli_resources({"gcloud.json": json.dumps([instance, boot, data, bare, policy])})
    by = _by(resources)
    ref = "projects/p/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily"
    assert by[("volume", "vol-ds-boot")].attrs["ciamVolumeKind"] == ("boot",)
    assert by[("volume", "vol-ds-boot")].links == {"ciamEncryptedByRole": KEY, "ciamSnapshotPolicyRole": ref}
    assert by[("volume", "vol-ds-data")].attrs["ciamIops"] == ("6000",)
    assert by[("snapshot-policy", ref)].attrs == {"ciamRetentionDays": ("7",), "ciamSnapshotEveryHours": ("6",),
                                                   "ciamSnapshotAt": ("03:00",),
                                                   "ciamSnapshotConsistency": ("application",)}
    assert by[("snapshot-policy", ref)].name == "ciam-prod-snapshots-daily"     # no label policy: its own name
    assert "disk scratch (ds-1) carries no label volume: which of the record's volumes it is can't be told; not " \
           "recorded" in notices
