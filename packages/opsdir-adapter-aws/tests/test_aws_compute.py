"""AWS compute: autoscaling groups read as compute groups (the server role they run, scale, zones from their subnets,
the launch template's image, instance type and metadata tokens) and EKS clusters as clusters (version, add-ons, node
groups), from Terraform state; the AWS CLI's outputs of the same resources read as the same record (the launch
template version a group uses, groups and clusters outside the listed VPC counted, not read)."""
import json

from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.inventory import state_resources

ASG = "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:x:autoScalingGroupName/ciam-prod-pf"
EKS = "arn:aws:eks:us-east-1:111122223333:cluster/ciam-prod"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("aws_subnet", "a", {"id": "subnet-a", "cidr_block": "10.0.1.0/24", "availability_zone": "us-east-1a"}),
    ("aws_subnet", "b", {"id": "subnet-b", "cidr_block": "10.0.2.0/24", "availability_zone": "us-east-1b"}),
    ("aws_launch_template", "pf", {"id": "lt-0123", "name": "ciam-prod-pf", "image_id": "ami-0abc",
                                   "instance_type": "m6i.xlarge", "metadata_options": [{"http_tokens": "optional"}]}),
    ("aws_autoscaling_group", "pf", {"arn": ASG, "name": "ciam-prod-pf", "min_size": 2, "max_size": 4,
                                     "desired_capacity": 2, "vpc_zone_identifier": ["subnet-a", "subnet-b"],
                                     "launch_template": [{"id": "lt-0123", "version": "$Latest"}],
                                     "tag": [{"key": "Role", "value": "pf", "propagate_at_launch": True}]}),
    ("aws_autoscaling_group", "untagged", {"arn": "arn:asg:untagged", "name": "untagged", "min_size": 1,
                                           "max_size": 1, "availability_zones": ["us-east-1c"]}),
    ("aws_eks_cluster", "main", {"arn": EKS, "name": "ciam-prod", "version": "1.30",
                                 "vpc_config": [{"subnet_ids": ["subnet-a", "subnet-b"]}]}),
    ("aws_eks_node_group", "system", {"cluster_name": "ciam-prod", "node_group_name": "system",
                                      "instance_types": ["m6i.large"],
                                      "scaling_config": [{"min_size": 2, "max_size": 5, "desired_size": 3}]}),
    ("aws_eks_addon", "cni", {"cluster_name": "ciam-prod", "addon_name": "vpc-cni", "addon_version": "v1.18.1"}),
    ("aws_eks_addon", "ebs", {"cluster_name": "ciam-prod", "addon_name": "aws-ebs-csi-driver"}))


def _by_kind(kind):
    resources, _ = state_resources(STATE)
    return {r.ref: r for r in resources if r.kind == kind}


def test_an_autoscaling_group_is_a_compute_group_with_its_launch_template():
    pf = _by_kind("compute")[ASG]
    assert (pf.name, pf.role) == ("ciam-prod-pf", "compute-pf")
    assert pf.attrs == {"ciamTargetRole": ("pf",), "ciamImageRef": ("ami-0abc",), "ciamInstanceSize": ("m6i.xlarge",),
                        "ciamMinSize": ("2",), "ciamMaxSize": ("4",), "ciamDesiredSize": ("2",),
                        "ciamSpansZone": ("us-east-1a", "us-east-1b"), "ciamMetadataTokens": ("FALSE",)}


def test_an_untagged_group_has_no_role_and_its_own_zones():
    untagged = _by_kind("compute")["arn:asg:untagged"]
    assert untagged.role is None and untagged.attrs["ciamSpansZone"] == ("us-east-1c",)


def test_an_eks_cluster_with_its_node_groups_and_addons():
    eks = _by_kind("cluster")[EKS]
    assert (eks.name, eks.role) == ("ciam-prod", "cluster")
    assert eks.attrs == {"ciamClusterVersion": ("1.30",), "ciamClusterAddon": ("aws-ebs-csi-driver", "vpc-cni v1.18.1"),
                         "ciamNodePool": ("system: m6i.large, 2-5",), "ciamSpansZone": ("us-east-1a", "us-east-1b")}
    assert eks.links == {"ciamSubnetRole": ("subnet-a", "subnet-b")}      # its node groups' subnets


VPC = "vpc-0abc"
CLI = {
    "vpcs.json": {"Vpcs": [{"VpcId": VPC, "CidrBlock": "10.0.0.0/16"}]},
    "subnets.json": {"Subnets": [{"SubnetId": "subnet-a", "VpcId": VPC, "CidrBlock": "10.0.1.0/24",
                                  "AvailabilityZone": "us-east-1a"},
                                 {"SubnetId": "subnet-b", "VpcId": VPC, "CidrBlock": "10.0.2.0/24",
                                  "AvailabilityZone": "us-east-1b"}]},
    "autoscaling-groups.json": {"AutoScalingGroups": [
        {"AutoScalingGroupARN": ASG, "AutoScalingGroupName": "ciam-prod-pf", "MinSize": 2, "MaxSize": 4,
         "DesiredCapacity": 2, "VPCZoneIdentifier": "subnet-a,subnet-b", "AvailabilityZones": ["us-east-1a"],
         "LaunchTemplate": {"LaunchTemplateId": "lt-0123", "LaunchTemplateName": "ciam-prod-pf", "Version": "$Latest"},
         "Tags": [{"Key": "Role", "Value": "pf", "PropagateAtLaunch": True}]},
        {"AutoScalingGroupARN": "arn:asg:elsewhere", "AutoScalingGroupName": "elsewhere", "MinSize": 1, "MaxSize": 1,
         "VPCZoneIdentifier": "subnet-other"}]},
    "launch-templates/lt-0123-$Latest.json": {"LaunchTemplateVersions": [
        {"LaunchTemplateId": "lt-0123", "LaunchTemplateName": "ciam-prod-pf", "VersionNumber": 3,
         "LaunchTemplateData": {"ImageId": "ami-0abc", "InstanceType": "m6i.xlarge",
                                "MetadataOptions": {"HttpTokens": "optional"}}},
        {"LaunchTemplateId": "lt-0123", "LaunchTemplateName": "ciam-prod-pf", "VersionNumber": 2,
         "DefaultVersion": True, "LaunchTemplateData": {"ImageId": "ami-0old", "InstanceType": "m5.xlarge"}}]},
    "eks/ciam-prod.json": {"cluster": {"arn": EKS, "name": "ciam-prod", "version": "1.30", "status": "ACTIVE",
                                       "resourcesVpcConfig": {"vpcId": VPC, "subnetIds": ["subnet-a", "subnet-b"]}}},
    "eks/ciam-prod-nodegroup-system.json": {"nodegroup": {
        "clusterName": "ciam-prod", "nodegroupName": "system", "instanceTypes": ["m6i.large"],
        "scalingConfig": {"minSize": 2, "maxSize": 5, "desiredSize": 3}}},
    "eks/ciam-prod-addon-vpc-cni.json": {"addon": {"clusterName": "ciam-prod", "addonName": "vpc-cni",
                                                   "addonVersion": "v1.18.1"}},
    "eks/ciam-prod-addon-aws-ebs-csi-driver.json": {"addon": {"clusterName": "ciam-prod",
                                                              "addonName": "aws-ebs-csi-driver"}}}


def _cli(outputs=None):
    return cli_resources({p: json.dumps(doc) for p, doc in (outputs or CLI).items()})


def test_the_cli_reads_the_same_compute_groups_and_clusters_as_state():
    resources, notices = _cli()
    state = {r.ref: r for r in state_resources(STATE)[0] if r.kind in ("compute", "cluster")}
    cli = {r.ref: r for r in resources if r.kind in ("compute", "cluster")}
    assert cli == {ref: state[ref] for ref in (ASG, EKS)}
    assert "aws_autoscaling_group (1): outside the listed VPCs (vpc-0abc); not read" in notices


def test_a_group_reads_the_template_version_it_uses():
    group = CLI["autoscaling-groups.json"]["AutoScalingGroups"][0]
    pinned = {**CLI, "autoscaling-groups.json": {"AutoScalingGroups": [
        {**group, "LaunchTemplate": {**group["LaunchTemplate"], "Version": "$Default"}}]}}
    pf = next(r for r in _cli(pinned)[0] if r.ref == ASG)
    assert (pf.attrs["ciamImageRef"], pf.attrs["ciamInstanceSize"]) == (("ami-0old",), ("m5.xlarge",))
    assert "ciamMetadataTokens" not in pf.attrs
    unlisted = {**pinned, "launch-templates/lt-0123-$Latest.json": {"LaunchTemplateVersions": []}}
    resources, notices = _cli(unlisted)
    assert "ciamImageRef" not in next(r for r in resources if r.ref == ASG).attrs
    assert ("autoscaling group ciam-prod-pf: launch template lt-0123 version $Default is not listed (ec2 "
            "describe-launch-template-versions); its image and instance type not read") in notices
