"""AWS compute: autoscaling groups read as compute groups (the server role they run, scale, zones from their subnets,
the launch template's image, instance type and metadata tokens) and EKS clusters as clusters (version, add-ons, node
groups), from Terraform state."""
import json

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
