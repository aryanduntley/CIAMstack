"""Compute groups on Google Cloud (5.8): an instance template with the role's disks (labelled volume and role, keyed,
following their snapshot schedule), its network tag and service account, a regional managed instance group in the zones
it spans (its first size, then its autoscaler's), the named port its services reach; an adopted one imported. The
template's disks read back as the role's volumes from Terraform state and Cloud Asset Inventory."""
import json

from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_gcp.cli import cli_resources
from opsdir_adapter_gcp.compute_groups import render_groups
from opsdir_adapter_gcp.inventory import state_resources
from network_fixtures import BETA, entry, model

KEY = "projects/p/locations/us-central1/keyRings/ciam/cryptoKeys/disk"
KEY_ENTRY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri=f"gcp-kms://{KEY}")
BOOT = entry(BETA, "vol-app-boot", "ciamVolume", ciamBindingRole="volume-app-boot", ciamTargetRole="app",
             ciamVolumeKind="boot", ciamVolumeSizeGb="50", ciamVolumeClass="ssd")
DATA = entry(BETA, "vol-app-data", "ciamVolume", ciamBindingRole="volume-app-data", ciamTargetRole="app",
             ciamVolumeKind="data", ciamVolumeSizeGb="200", ciamVolumeClass="provisioned", ciamIops="6000",
             ciamThroughputMb="250", ciamSnapshotPolicyRole="snapshots-daily")
POLICY = entry(BETA, "snapshots-daily", "ciamSnapshotPolicy", ciamBindingRole="snapshots-daily",
               ciamRetentionDays="7", ciamSnapshotAt="03:00")
IMAGE = "projects/p/global/images/app"
GROUP = entry(BETA, "mig-app", "ciamComputeGroup", ciamBindingRole="compute-app", ciamTargetRole="app",
              ciamImageRef=IMAGE, ciamInstanceSize="n2-standard-2", ciamMinSize="2", ciamMaxSize="4",
              ciamDesiredSize="2", ciamSpansZone=("us-central1-a", "us-central1-b"), ciamSubnetRole="subnet-web")


def _flat(text):
    return " ".join(text.split())


def _render(*records, ports=None):
    m = model(beta=records)[2]
    return _flat("\n\n".join(as_text(render_groups(m, f"gcp-kms://{KEY}", (), ports or {}))))


def test_a_group_is_an_instance_template_with_its_roles_disks_and_a_regional_managed_instance_group():
    out = _render(KEY_ENTRY, BOOT, DATA, POLICY, GROUP, ports={"app": (443, 443)})
    for text in ('resource "google_compute_instance_template" "mig_app" { name_prefix = "ciam-prod-mig-app-" '
                 'machine_type = "n2-standard-2" tags = ["ciam-prod-app"]',
                 f'disk {{ boot = true auto_delete = true source_image = "{IMAGE}" disk_type = "pd-ssd" '
                 f'disk_size_gb = 50 disk_encryption_key {{ kms_key_self_link = "{KEY}" }} labels = {{ '
                 'volume = "vol-app-boot" role = "volume-app-boot" managed_by = "opsdir" } }',
                 'disk { boot = false auto_delete = true device_name = "vol-app-data" disk_type = "hyperdisk-balanced" '
                 "disk_size_gb = 200 provisioned_iops = 6000 provisioned_throughput = 250 resource_policies = "
                 "[google_compute_resource_policy.snapshots_daily.id]",
                 "# NOTE: vol-app-data: hyperdisk-balanced needs a machine series that takes Hyperdisk",
                 "network_interface { subnetwork = data.google_compute_subnetwork.subnet_web.self_link }",
                 'labels = { role = "app" bindingrole = "compute-app" managed_by = "opsdir" }',
                 'resource "google_compute_region_instance_group_manager" "mig_app" { name = "ciam-prod-mig-app" '
                 'region = var.region base_instance_name = "ciam-prod-mig-app" version { instance_template = '
                 'google_compute_instance_template.mig_app.id } distribution_policy_zones = ["us-central1-a", '
                 '"us-central1-b"] target_size = 2 named_port { name = "ciam" port = 443 } lifecycle { '
                 "ignore_changes = [target_size] } }",
                 'resource "google_compute_region_autoscaler" "mig_app" { name = "ciam-prod-mig-app-autoscaler" '
                 "region = var.region target = google_compute_region_instance_group_manager.mig_app.id "
                 "autoscaling_policy { min_replicas = 2 max_replicas = 4 } }"):
        assert _flat(text) in out, text
    assert "import" not in out and "resource_manager_tags" not in out          # VPC rules: the network tag


def test_an_adopted_group_is_imported_and_its_autoscaler_said():
    ref = "projects/p/regions/us-central1/instanceGroupManagers/legacy-app"
    adopted = entry(BETA, "mig-app", "ciamComputeGroup", ciamBindingRole="compute-app", ciamTargetRole="app",
                    ciamProviderRef=ref, ciamMinSize="1", ciamMaxSize="2")
    out = _render(KEY_ENTRY, adopted)
    assert 'name = "legacy-app"' in out and "target_size = 1" in out
    assert _flat(f'import {{ to = google_compute_region_instance_group_manager.mig_app id = "{ref}" }}') in out
    assert "# NOTE: mig-app: exists: an autoscaler it already has must be imported by hand" in out


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}",
         "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


POLICY_STATE = ("google_compute_resource_policy", {
    "id": "projects/p/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily",
    "name": "ciam-prod-snapshots-daily",
    "snapshot_schedule_policy": [{"schedule": [{"daily_schedule": [{"days_in_cycle": 1, "start_time": "03:00"}]}],
                                  "retention_policy": [{"max_retention_days": 7}]}]})
TEMPLATE = ("google_compute_instance_template", {
    "id": "projects/p/global/instanceTemplates/ciam-prod-mig-app-1", "name": "ciam-prod-mig-app-1",
    "machine_type": "n2-standard-2", "labels": {"role": "app", "bindingrole": "compute-app"},
    "disk": [{"boot": True, "source_image": IMAGE, "disk_type": "pd-ssd", "disk_size_gb": 50,
              "disk_encryption_key": [{"kms_key_self_link": KEY}],
              "labels": {"volume": "vol-app-boot", "role": "volume-app-boot"}},
             {"boot": False, "device_name": "vol-app-data", "disk_type": "hyperdisk-balanced", "disk_size_gb": 200,
              "provisioned_iops": 6000, "provisioned_throughput": 250,
              "resource_policies": [POLICY_STATE[1]["id"]], "disk_encryption_key": [{"kms_key_self_link": KEY}],
              "labels": {"volume": "vol-app-data", "role": "volume-app-data"}}]})


def _volumes(resources):
    return {r.ref: (r.attrs, r.links, r.role) for r in resources if r.kind == "volume"}


def test_a_templates_disks_read_back_as_the_roles_volumes():
    found = _volumes(state_resources(_state(POLICY_STATE, TEMPLATE))[0])
    assert found == {
        "vol-app-boot": ({"ciamVolumeKind": ("boot",), "ciamVolumeSizeGb": ("50",), "ciamVolumeClass": ("ssd",),
                          "ciamVolumeEncrypted": ("TRUE",), "ciamTargetRole": ("app",)},
                         {"ciamEncryptedByRole": KEY}, "volume-app-boot"),
        "vol-app-data": ({"ciamVolumeKind": ("data",), "ciamVolumeSizeGb": ("200",),
                          "ciamVolumeClass": ("provisioned",), "ciamIops": ("6000",), "ciamThroughputMb": ("250",),
                          "ciamVolumeEncrypted": ("TRUE",), "ciamTargetRole": ("app",)},
                         {"ciamEncryptedByRole": KEY, "ciamSnapshotPolicyRole": POLICY_STATE[1]["id"]},
                         "volume-app-data")}


def test_the_asset_inventory_reads_a_templates_disks_the_same():
    api = "https://www.googleapis.com/compute/v1/projects/p"
    template = {"kind": "compute#instanceTemplate", "name": "ciam-prod-mig-app-1",
                "selfLink": f"{api}/global/instanceTemplates/ciam-prod-mig-app-1",
                "properties": {"machineType": "n2-standard-2", "labels": {"role": "app", "bindingrole": "compute-app"},
                               "disks": [
                                   {"boot": True, "diskEncryptionKey": {"kmsKeyName": KEY}, "initializeParams": {
                                       "sourceImage": f"{api}/global/images/app", "diskType": "pd-ssd",
                                       "diskSizeGb": "50", "labels": TEMPLATE[1]["disk"][0]["labels"]}},
                                   {"boot": False, "deviceName": "vol-app-data",
                                    "diskEncryptionKey": {"kmsKeyName": KEY}, "initializeParams": {
                                        "diskType": "hyperdisk-balanced", "diskSizeGb": "200",
                                        "provisionedIops": 6000, "provisionedThroughput": 250,
                                        "resourcePolicies": [f"{api}/regions/us-central1/resourcePolicies/"
                                                             "ciam-prod-snapshots-daily"],
                                        "labels": TEMPLATE[1]["disk"][1]["labels"]}}]}}
    policy = {"kind": "compute#resourcePolicy", "name": "ciam-prod-snapshots-daily",
              "region": f"{api}/regions/us-central1",
              "selfLink": f"{api}/regions/us-central1/resourcePolicies/ciam-prod-snapshots-daily",
              "snapshotSchedulePolicy": {"schedule": {"dailySchedule": {"daysInCycle": 1, "startTime": "03:00"}},
                                         "retentionPolicy": {"maxRetentionDays": 7}}}
    cai = _volumes(cli_resources({"gcloud.json": json.dumps([template, policy])})[0])
    assert cai == _volumes(state_resources(_state(POLICY_STATE, TEMPLATE))[0])
