"""Compute groups on AWS (5.8): a launch template with the role's disks (the boot volume at the AMI's root device,
data volumes at /dev/sdf ..., instances tagged with the disks they get, every disk tagged with the group and its one
snapshot policy) and an autoscaling group in the group's subnets; an adopted group imported by name. The template's
disks read back as the role's volumes from Terraform state and the CLI."""
import json

from opsdir.core.environment import UNBOUND
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.compute_groups import render_groups
from opsdir_adapter_aws.inventory import state_resources
from network_fixtures import BETA, entry, model

ARN = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234"
KEY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri=f"aws-kms://{ARN}")
BOOT = entry(BETA, "vol-app-boot", "ciamVolume", ciamBindingRole="volume-app-boot", ciamTargetRole="app",
             ciamVolumeKind="boot", ciamVolumeSizeGb="50", ciamVolumeClass="ssd", ciamThroughputMb="250",
             ciamSnapshotPolicyRole="snapshots-daily")
DATA = entry(BETA, "vol-app-data", "ciamVolume", ciamBindingRole="volume-app-data", ciamTargetRole="app",
             ciamVolumeKind="data", ciamMountPath="/opt/app/data", ciamVolumeSizeGb="200",
             ciamVolumeClass="provisioned", ciamIops="6000", ciamSnapshotPolicyRole="snapshots-daily")
POLICY = entry(BETA, "snapshots-daily", "ciamSnapshotPolicy", ciamBindingRole="snapshots-daily",
               ciamRetentionDays="7")
GROUP = entry(BETA, "asg-app", "ciamComputeGroup", ciamBindingRole="compute-app", ciamTargetRole="app",
              ciamImageRef="ami-0abc", ciamInstanceSize="m6i.large", ciamMinSize="2", ciamMaxSize="4",
              ciamSubnetRole=("subnet-ds", "subnet-web"), ciamMetadataTokens="TRUE")
ADOPTED = entry(BETA, "asg-app", "ciamComputeGroup", ciamBindingRole="compute-app", ciamTargetRole="app",
                ciamProviderRef="arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:1:"
                                "autoScalingGroupName/legacy-app", ciamMinSize="1", ciamMaxSize="2")


def _flat(text):
    return " ".join(text.split())


def _render(*records, target_groups=None):
    m = model(beta=records)[2]
    return _flat("\n\n".join(as_text(render_groups(m, f"aws-kms://{ARN}", (), target_groups or {}))))


def test_a_group_is_a_launch_template_with_its_roles_disks_and_an_autoscaling_group_in_its_subnets():
    out = _render(KEY, BOOT, DATA, POLICY, GROUP,
                  target_groups={"app": ("${aws_lb_target_group.svc_app_443.arn}",)})
    for text in ('data "aws_ami" "asg_app" { filter { name = "image-id" values = ["ami-0abc"] } }',
                 'resource "aws_launch_template" "asg_app" { name = "ciam-prod-asg-app" image_id = "ami-0abc" '
                 'instance_type = "m6i.large" vpc_security_group_ids = [aws_security_group.app.id] '
                 'metadata_options { http_endpoint = "enabled" http_tokens = "required" }',
                 "# asg-app's instances mount vol-app-data at /opt/app/data (their own configuration, not Terraform)",
                 "block_device_mappings { device_name = data.aws_ami.asg_app.root_device_name ebs { volume_size = 50 "
                 f'volume_type = "gp3" throughput = 250 encrypted = true kms_key_id = "{ARN}" '
                 "delete_on_termination = true } }",
                 'block_device_mappings { device_name = "/dev/sdf" ebs { volume_size = 200 volume_type = "io2" '
                 f'iops = 6000 encrypted = true kms_key_id = "{ARN}" ' "delete_on_termination = true } }",
                 'resource_type = "instance" tags = { Name = "ciam-prod-asg-app" Role = "app" BindingRole = '
                 '"compute-app" BootVolume = "vol-app-boot" DataVolumes = "sdf=vol-app-data" ManagedBy = "opsdir" }',
                 'resource_type = "volume" tags = { Group = "asg-app" SnapshotPolicy = "snapshots-daily" '
                 'ManagedBy = "opsdir" }',
                 'resource "aws_autoscaling_group" "asg_app" { name = "ciam-prod-asg-app" min_size = 2 max_size = 4 '
                 "vpc_zone_identifier = [data.aws_subnet.subnet_ds.id, data.aws_subnet.subnet_web.id] "
                 "launch_template { id = aws_launch_template.asg_app.id version = "
                 "aws_launch_template.asg_app.latest_version } target_group_arns = "
                 '[aws_lb_target_group.svc_app_443.arn] health_check_type = "ELB"',
                 'tag { key = "BindingRole" value = "compute-app" propagate_at_launch = false }'):
        assert _flat(text) in out, text
    assert "import" not in out and "desired_capacity" not in out


def test_an_adopted_group_is_imported_by_name_and_its_disks_without_one_policy_untagged():
    other = entry(BETA, "vol-app-data", "ciamVolume", ciamBindingRole="volume-app-data", ciamTargetRole="app",
                  ciamVolumeKind="data", ciamSnapshotPolicyRole="snapshots-weekly")
    weekly = entry(BETA, "snapshots-weekly", "ciamSnapshotPolicy", ciamBindingRole="snapshots-weekly",
                   ciamRetentionDays="28")
    out = _render(KEY, BOOT, other, POLICY, weekly, ADOPTED)
    assert _flat('import { to = aws_autoscaling_group.asg_app id = "legacy-app" }') in out
    assert 'name = "legacy-app"' in out and f"{UNBOUND}asg-app-image" in out
    assert "vpc_zone_identifier = \"UNBOUND:asg-app-subnets\"" in out
    assert "# asg-app's disks don't all name one snapshot policy (snapshots-daily, snapshots-weekly); a launch " \
           "template tags them alike, so none is tagged SnapshotPolicy" in out
    assert 'tags = { Group = "asg-app" ManagedBy = "opsdir" }' in out


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": f"r{i}", "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for i, (t, a) in enumerate(resources)]})


TEMPLATE = {"id": "lt-0123", "name": "ciam-prod-asg-app", "latest_version": 1, "image_id": "ami-0abc",
            "instance_type": "m6i.large",
            "block_device_mappings": [
                {"device_name": "/dev/xvda", "ebs": [{"volume_size": 50, "volume_type": "gp3", "throughput": 250,
                                                       "encrypted": True, "kms_key_id": ARN}]},
                {"device_name": "/dev/sdf", "ebs": [{"volume_size": 200, "volume_type": "io2", "iops": 6000,
                                                      "encrypted": True, "kms_key_id": ARN}]}],
            "tag_specifications": [
                {"resource_type": "instance", "tags": {"Role": "app", "BootVolume": "vol-app-boot",
                                                       "DataVolumes": "sdf=vol-app-data"}},
                {"resource_type": "volume", "tags": {"Group": "asg-app", "SnapshotPolicy": "snapshots-daily"}}]}
DLM = ("aws_dlm_lifecycle_policy", {
    "id": "policy-1", "state": "ENABLED", "tags": {"Name": "snapshots-daily"},
    "policy_details": [{"target_tags": {"SnapshotPolicy": "snapshots-daily"},
                        "schedule": [{"name": "s", "create_rule": [{"interval": 24, "interval_unit": "HOURS"}],
                                      "retain_rule": [{"interval": 7, "interval_unit": "DAYS"}]}]}]})


def _volumes(resources):
    return {r.ref: (r.attrs, r.links) for r in resources if r.kind == "volume"}


def test_a_launch_templates_disks_read_back_as_the_roles_volumes():
    resources, _ = state_resources(_state(("aws_launch_template", TEMPLATE), DLM))
    assert _volumes(resources) == {
        "vol-app-data": ({"ciamVolumeKind": ("data",), "ciamVolumeSizeGb": ("200",),
                          "ciamVolumeClass": ("provisioned",), "ciamIops": ("6000",), "ciamVolumeEncrypted": ("TRUE",),
                          "ciamTargetRole": ("app",)},
                         {"ciamEncryptedByRole": ARN, "ciamSnapshotPolicyRole": "policy-1"}),
        "vol-app-boot": ({"ciamVolumeKind": ("boot",), "ciamVolumeSizeGb": ("50",), "ciamVolumeClass": ("ssd",),
                          "ciamThroughputMb": ("250",), "ciamVolumeEncrypted": ("TRUE",), "ciamTargetRole": ("app",)},
                         {"ciamEncryptedByRole": ARN})}


def test_the_cli_reads_a_templates_disks_the_same():
    version = {"LaunchTemplateId": "lt-0123", "LaunchTemplateName": "ciam-prod-asg-app", "VersionNumber": 1,
               "LaunchTemplateData": {
                   "ImageId": "ami-0abc", "InstanceType": "m6i.large",
                   "BlockDeviceMappings": [
                       {"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 50, "VolumeType": "gp3", "Throughput": 250,
                                                           "Encrypted": True, "KmsKeyId": ARN}},
                       {"DeviceName": "/dev/sdf", "Ebs": {"VolumeSize": 200, "VolumeType": "io2", "Iops": 6000,
                                                          "Encrypted": True, "KmsKeyId": ARN}}],
                   "TagSpecifications": [
                       {"ResourceType": "instance", "Tags": [{"Key": "Role", "Value": "app"},
                                                             {"Key": "BootVolume", "Value": "vol-app-boot"},
                                                             {"Key": "DataVolumes", "Value": "sdf=vol-app-data"}]},
                       {"ResourceType": "volume", "Tags": [{"Key": "Group", "Value": "asg-app"}]}]}}
    group = {"AutoScalingGroupARN": "arn:asg", "AutoScalingGroupName": "ciam-prod-asg-app", "MinSize": 2,
             "MaxSize": 4, "LaunchTemplate": {"LaunchTemplateId": "lt-0123", "Version": "$Latest"},
             "Tags": [{"Key": "Role", "Value": "app"}]}
    resources, _ = cli_resources({"autoscaling-groups.json": json.dumps({"AutoScalingGroups": [group]}),
                                  "launch-templates/lt-0123-$Latest.json":
                                      json.dumps({"LaunchTemplateVersions": [version]})})
    found = _volumes(resources)
    state = _volumes(state_resources(_state(("aws_launch_template", {
        **TEMPLATE, "tag_specifications": [TEMPLATE["tag_specifications"][0],
                                           {"resource_type": "volume", "tags": {"Group": "asg-app"}}]})))[0])
    assert found == state and set(found) == {"vol-app-boot", "vol-app-data"}
