"""Disks and snapshot policies on AWS: a role's boot volume on each instance's root_block_device, each data volume an
EBS volume in the server's zone with its attachment (tagged so Lifecycle Manager finds it), each snapshot policy the
stack keeps a Lifecycle Manager policy (interval, start, retention, encrypted cross-region copies with the disk key's
replica or an input); others' named. Read back from Terraform state and the CLI."""
import json

from opsdir.core.environment import servers_with_role
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.inventory import state_resources
from opsdir_adapter_aws.volumes import render_snapshot_policies, root_block_device, server_volumes
from network_fixtures import BETA, entry, model

ARN = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234"
KEY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri=f"aws-kms://{ARN}",
            ciamReplicaRegion="us-west-2")
BOOT = entry(BETA, "vol-ds-boot", "ciamVolume", ciamBindingRole="volume-ds-boot", ciamTargetRole="ds",
             ciamVolumeKind="boot", ciamVolumeSizeGb="50", ciamVolumeClass="ssd", ciamThroughputMb="250")
DATA = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
             ciamVolumeKind="data", ciamMountPath="/opt/ds/db", ciamVolumeSizeGb="200", ciamVolumeClass="provisioned",
             ciamIops="6000", ciamSnapshotPolicyRole="snapshots-daily")
POLICY = entry(BETA, "snapshots-daily", "ciamSnapshotPolicy", ciamBindingRole="snapshots-daily",
               ciamRetentionDays="7", ciamSnapshotAt="03:00", ciamCopyRegion=("us-west-2", "eu-west-1"),
               ciamProviderRef="policy-0123456789abcdef0")


def _m(*records):
    return model(beta=records)[2]


def _flat(text):
    return " ".join(text.split())


def _blocks(m):
    (ds1, _) = servers_with_role(m, "ds")
    root = root_block_device(m, ds1, "aws-kms://" + ARN)
    return root, _flat("\n\n".join(server_volumes(m, ds1))), _flat("\n\n".join(render_snapshot_policies(m)))


def test_the_boot_volume_is_the_root_block_device_and_a_data_volume_an_attached_ebs_volume():
    root, volumes, _ = _blocks(_m(KEY, BOOT, DATA, POLICY))
    assert root[0] == "root_block_device"
    assert dict(root[1].body)["volume_size"] == 50 and dict(root[1].body)["volume_type"] == "gp3"
    assert dict(root[1].body)["throughput"] == 250 and dict(root[1].body)["kms_key_id"] == ARN
    for text in ('resource "aws_ebs_volume" "ds_1_vol_ds_data"', 'availability_zone = "zone-a"', "size = 200",
                 'type = "io2"', "iops = 6000", "encrypted = true", f'kms_key_id = "{ARN}"',
                 'SnapshotPolicy = "snapshots-daily"', 'Server = "ds-1"', 'Volume = "vol-ds-data"',
                 'resource "aws_volume_attachment" "ds_1_vol_ds_data"', 'device_name = "/dev/sdf"',
                 "volume_id = aws_ebs_volume.ds_1_vol_ds_data.id", "instance_id = aws_instance.ds_1.id",
                 "# ds-1 mounts vol-ds-data at /opt/ds/db (its own configuration, not Terraform)"):
        assert _flat(text) in volumes, text


def test_without_a_boot_volume_the_root_disk_is_encrypted_with_the_disk_key():
    root, volumes, policies = _blocks(_m(KEY))
    assert dict(root[1].body) == {"encrypted": True, "kms_key_id": ARN}
    assert volumes == "" and policies == ""


def test_an_unencrypted_or_unbound_key_volume_is_rendered_as_recorded_and_said():
    off = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
                ciamVolumeKind="data", ciamVolumeEncrypted="FALSE")
    _, volumes, _ = _blocks(_m(KEY, off))
    assert "encrypted = false" in volumes and "kms_key_id" not in volumes
    other = entry(BETA, "vol-ds-data", "ciamVolume", ciamBindingRole="volume-ds-data", ciamTargetRole="ds",
                  ciamVolumeKind="data", ciamEncryptedByRole="data-key")
    _, unbound, _ = _blocks(_m(KEY, other))
    assert "# vol-ds-data: UNBOUND:data-key: no key binding for role data-key in this environment" in unbound


def test_a_snapshot_policy_is_a_lifecycle_manager_policy_with_encrypted_copies():
    _, _, policies = _blocks(_m(KEY, BOOT, DATA, POLICY))
    for text in ('variable "dlm_execution_role_arn"', 'resource "aws_dlm_lifecycle_policy" "snapshots_daily"',
                 "execution_role_arn = var.dlm_execution_role_arn", 'resource_types = ["VOLUME"]',
                 'target_tags = { SnapshotPolicy = "snapshots-daily" }',
                 'create_rule { interval = 24 interval_unit = "HOURS" times = ["03:00"] }',
                 'retain_rule { interval = 7 interval_unit = "DAYS" }',
                 'target = "us-west-2" encrypted = true cmk_arn = "arn:aws:kms:us-west-2:111122223333:key/mrk-1234"',
                 'target = "eu-west-1" encrypted = true cmk_arn = var.snapshots_daily_eu_west_1_kms_key_arn',
                 'variable "snapshots_daily_eu_west_1_kms_key_arn"',
                 'to = aws_dlm_lifecycle_policy.snapshots_daily id = "policy-0123456789abcdef0"'):
        assert _flat(text) in policies, text


def test_an_interval_lifecycle_manager_cannot_take_and_others_policies_are_named():
    odd = entry(BETA, "snapshots-odd", "ciamSnapshotPolicy", ciamBindingRole="snapshots-odd",
                ciamRetentionDays="7", ciamSnapshotEveryHours="48")
    theirs = entry(BETA, "snapshots-team", "ciamSnapshotPolicy", ciamBindingRole="snapshots-team",
                   ciamRetentionDays="30", ciamManagedBy="cn=storage-team,ou=owners,dc=ciam-ops")
    out = "\n".join(render_snapshot_policies(_m(odd, theirs)))
    assert "# Snapshot policy 'snapshots-odd': Lifecycle Manager snapshots every 1, 2, 3, 4, 6, 8, 12 or 24 hours, " \
           "not 48: not rendered" in out
    assert "# Snapshot policy 'snapshots-team' (role snapshots-team) is kept by cn=storage-team,ou=owners,dc=ciam-ops" \
        in out


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}", "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


def _instance(n, role="ds", root=None):
    return ("aws_instance", {"id": f"i-{n}", "tags": {"Name": n, "Role": role},
                             "root_block_device": [root] if root else []})


def _ebs(n, server, size=200, **extra):
    return [("aws_ebs_volume", {"id": f"vol-{n}", "size": size, "type": "io2", "iops": 6000, "encrypted": True,
                                "kms_key_id": ARN, "tags": {"Volume": "vol-ds-data", "Role": "volume-ds-data",
                                                            "SnapshotPolicy": "snapshots-daily", **extra}}),
            ("aws_volume_attachment", {"volume_id": f"vol-{n}", "instance_id": f"i-{server}", "device_name": "/dev/sdf"})]


DLM_POLICY = ("aws_dlm_lifecycle_policy", {
    "id": "policy-0123456789abcdef0", "state": "ENABLED", "tags": {"Name": "snapshots-daily", "Role": "snapshots-daily"},
    "policy_details": [{"resource_types": ["VOLUME"], "target_tags": {"SnapshotPolicy": "snapshots-daily"},
                        "schedule": [{"name": "snapshots-daily",
                                      "create_rule": [{"interval": 24, "interval_unit": "HOURS", "times": ["03:00"]}],
                                      "retain_rule": [{"interval": 1, "interval_unit": "WEEKS"}],
                                      "cross_region_copy_rule": [{"target": "us-west-2", "encrypted": True}]}]}]})
ROOT = {"volume_size": 50, "volume_type": "gp3", "throughput": 250, "encrypted": True, "kms_key_id": ARN,
        "tags": {"Volume": "vol-ds-boot", "Role": "volume-ds-boot"}}


def _by(resources):
    return {(r.kind, r.ref): r for r in resources}


def test_volumes_boot_disks_and_lifecycle_policies_are_read_back_from_state():
    resources, notices = state_resources(_state(_instance("ds-1", root=ROOT), _instance("ds-2", root=ROOT),
                                                *_ebs("a", "ds-1"), *_ebs("b", "ds-2", size=300), DLM_POLICY))
    by = _by(resources)
    data = by[("volume", "vol-ds-data")]
    assert (data.name, data.role) == ("vol-ds-data", "volume-ds-data")
    assert data.attrs == {"ciamVolumeKind": ("data",), "ciamVolumeSizeGb": ("200",), "ciamVolumeClass": ("provisioned",),
                          "ciamIops": ("6000",), "ciamVolumeEncrypted": ("TRUE",), "ciamTargetRole": ("ds",)}
    assert data.links == {"ciamEncryptedByRole": ARN, "ciamSnapshotPolicyRole": "policy-0123456789abcdef0"}
    boot = by[("volume", "vol-ds-boot")]
    assert boot.attrs == {"ciamVolumeKind": ("boot",), "ciamVolumeSizeGb": ("50",), "ciamVolumeClass": ("ssd",),
                          "ciamThroughputMb": ("250",), "ciamVolumeEncrypted": ("TRUE",), "ciamTargetRole": ("ds",)}
    policy = by[("snapshot-policy", "policy-0123456789abcdef0")]
    assert policy.attrs == {"ciamRetentionDays": ("7",), "ciamSnapshotEveryHours": ("24",), "ciamSnapshotAt": ("03:00",),
                            "ciamCopyRegion": ("us-west-2",), "ciamSnapshotConsistency": ("crash",)}
    assert policy.role == "snapshots-daily"
    assert "volume vol-ds-data: ds-2's disk is 300 GB, the others' 200; recorded as 200" in notices


def test_untagged_disks_count_policies_and_unencrypted_roots_are_named():
    bare = ("aws_ebs_volume", {"id": "vol-x", "size": 10, "type": "gp3", "encrypted": False, "tags": {}})
    attach = ("aws_volume_attachment", {"volume_id": "vol-x", "instance_id": "i-web-1"})
    stray = ("aws_ebs_volume", {"id": "vol-elsewhere", "size": 10, "type": "gp3", "tags": {}})
    counted = ("aws_dlm_lifecycle_policy", {"id": "policy-1", "tags": {"Name": "by-count"}, "policy_details": [{
        "schedule": [{"name": "s", "create_rule": [{"interval": 12, "interval_unit": "HOURS"}],
                      "retain_rule": [{"count": 10}]}]}]})
    off = ("aws_dlm_lifecycle_policy", {"id": "policy-2", "state": "DISABLED", "tags": {"Name": "paused"},
                                        "policy_details": [{"schedule": [{"name": "p"}]}]})
    _, notices = state_resources(_state(_instance("web-1", "web", {"encrypted": False}), bare, attach, stray,
                                        counted, off))
    assert "EBS volume vol-x (web-1) carries no tag Volume: which of the record's volumes it is can't be told; not " \
           "recorded" in notices
    assert not [n for n in notices if "vol-elsewhere" in n]
    assert "root disk of web-1 is not encrypted" in notices
    assert "snapshot policy by-count: keeps 10 snapshots, not a number of days; retention not read" in notices
    assert "snapshot policy paused: disabled; not read" in notices


def test_the_cli_reads_the_same():
    texts = {
        "vpcs.json": json.dumps({"Vpcs": [{"VpcId": "vpc-1"}]}),
        "instances.json": json.dumps({"Reservations": [{"Instances": [{
            "InstanceId": "i-ds-1", "VpcId": "vpc-1", "RootDeviceName": "/dev/xvda",
            "Tags": [{"Key": "Name", "Value": "ds-1"}, {"Key": "Role", "Value": "ds"}],
            "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-root"}},
                                    {"DeviceName": "/dev/sdf", "Ebs": {"VolumeId": "vol-a"}}]}]}]}),
        "volumes.json": json.dumps({"Volumes": [
            {"VolumeId": "vol-root", "Size": 50, "VolumeType": "gp3", "Throughput": 250, "Encrypted": True,
             "KmsKeyId": ARN, "Tags": [{"Key": "Volume", "Value": "vol-ds-boot"}, {"Key": "Role", "Value": "volume-ds-boot"}]},
            {"VolumeId": "vol-a", "Size": 200, "VolumeType": "io2", "Iops": 6000, "Encrypted": True, "KmsKeyId": ARN,
             "Attachments": [{"InstanceId": "i-ds-1", "Device": "/dev/sdf", "State": "attached"}],
             "Tags": [{"Key": "Volume", "Value": "vol-ds-data"}, {"Key": "Role", "Value": "volume-ds-data"},
                      {"Key": "SnapshotPolicy", "Value": "snapshots-daily"}]}]}),
        "dlm-policies/policy-0123456789abcdef0.json": json.dumps({"Policy": {
            "PolicyId": "policy-0123456789abcdef0", "State": "ENABLED",
            "Tags": {"Name": "snapshots-daily", "Role": "snapshots-daily"},
            "PolicyDetails": {"ResourceTypes": ["VOLUME"], "TargetTags": [{"Key": "SnapshotPolicy", "Value": "snapshots-daily"}],
                              "Schedules": [{"Name": "snapshots-daily",
                                             "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
                                             "RetainRule": {"Interval": 7, "IntervalUnit": "DAYS"},
                                             "CrossRegionCopyRules": [{"Target": "us-west-2", "Encrypted": True}]}]}}})}
    resources, notices = cli_resources(texts)
    by = _by(resources)
    assert by[("volume", "vol-ds-boot")].attrs["ciamVolumeSizeGb"] == ("50",)
    assert by[("volume", "vol-ds-data")].links["ciamSnapshotPolicyRole"] == "policy-0123456789abcdef0"
    assert by[("snapshot-policy", "policy-0123456789abcdef0")].attrs["ciamRetentionDays"] == ("7",)
    assert not [r for r in resources if r.kind.startswith("aws_organizations")]
    assert not [n for n in notices if "dlm-policies" in n or "Policy" in n], notices


def test_what_it_renders_reads_back_as_recorded():
    m = _m(KEY, BOOT, DATA, POLICY)
    ds1, _ = servers_with_role(m, "ds")
    root = dict(root_block_device(m, ds1, "aws-kms://" + ARN)[1].body)
    data = {**dict((k, v) for k, v in (("size", 200), ("type", "io2"), ("iops", 6000), ("encrypted", True),
                                       ("kms_key_id", ARN)))}
    rendered = [_instance("ds-1", root={**root, "tags": root["tags"]}),
                ("aws_ebs_volume", {"id": "vol-a", **data, "tags": {"Volume": "vol-ds-data", "Role": "volume-ds-data",
                                                                    "SnapshotPolicy": "snapshots-daily"}}),
                ("aws_volume_attachment", {"volume_id": "vol-a", "instance_id": "i-ds-1"}), DLM_POLICY]
    by = _by(state_resources(_state(*rendered))[0])
    assert by[("volume", "vol-ds-boot")].attrs["ciamVolumeClass"] == ("ssd",)
    assert by[("volume", "vol-ds-data")].attrs["ciamVolumeClass"] == ("provisioned",)
