"""Compute groups as CloudFormation stacks declare them, normalized to the Terraform attribute names the shared mapping
reads (opsdir_adapter_aws.inventory compute groups, volumes.volume_resources a template's disks), through the CLI's
normalizers (cli_compute: the properties have the CLI's shapes). Properties come resolved. Pure.

  AWS::AutoScaling::AutoScalingGroup  -> aws_autoscaling_group (its ARN when the physical ID is one, else its name)
  AWS::EC2::LaunchTemplate            -> aws_launch_template (its LaunchTemplateData: image, type, metadata tokens,
                                         EBS disks, tag specifications)
  AWS::EKS::Cluster                   -> aws_eks_cluster (its Ref is its name; its ARN from Fn::GetAtt Arn)
  AWS::EKS::Nodegroup                 -> aws_eks_node_group (its name given, else the last part of its Ref,
                                         '<cluster>/<node group>')
  AWS::EKS::Addon                     -> aws_eks_addon (its Ref is '<cluster>|<add-on>'; no ARN read)
A template doesn't hold what EKS chooses when it is left out (a cluster's version, a node group's generated name
when its Ref doesn't carry it): those attributes keep the record's values.
"""
from .cli_compute import addon_pair, cluster_pair, group_pair, node_group_pair, template_pair
from .cloudformation_values import number, tag_map

COMPUTE_TYPES = ("AWS::AutoScaling::AutoScalingGroup", "AWS::EC2::LaunchTemplate", "AWS::EKS::Cluster",
                 "AWS::EKS::Nodegroup", "AWS::EKS::Addon")


def _arn_or_none(pid):
    return pid if str(pid).startswith("arn:") else None


def _last(pid):
    """The last part of a Ref that joins its cluster's name and its own ('cluster/name', 'cluster|name')."""
    return str(pid).replace("|", "/").rsplit("/", 1)[-1] if pid and not str(pid).startswith("arn:") else None


def _eks(declared, names):
    """aws_eks_* pairs of a stack's clusters, node groups and add-ons, in the shapes describe-* prints."""
    return [*(cluster_pair({"arn": names.get(f"{lid}.Arn"), "name": p.get("Name") or pid,
                            "version": p.get("Version"),
                            "resourcesVpcConfig": {"subnetIds": (p.get("ResourcesVpcConfig") or {}).get("SubnetIds")},
                            "tags": tag_map(p.get("Tags"))})
              for lid, t, p, _, pid in declared if t == "AWS::EKS::Cluster"),
            *(node_group_pair({"nodegroupArn": _arn_or_none(pid), "clusterName": p.get("ClusterName"),
                               "nodegroupName": p.get("NodegroupName") or _last(pid),
                               "instanceTypes": p.get("InstanceTypes"), "subnets": p.get("Subnets"),
                               "scalingConfig": {k[0].lower() + k[1:]: number(v)
                                                 for k, v in (p.get("ScalingConfig") or {}).items()},
                               "tags": tag_map(p.get("Tags"))})
              for _, t, p, _, pid in declared if t == "AWS::EKS::Nodegroup"),
            *(addon_pair({"addonArn": _arn_or_none(pid), "clusterName": p.get("ClusterName"),
                          "addonName": p.get("AddonName"), "addonVersion": p.get("AddonVersion"),
                          "tags": tag_map(p.get("Tags"))})
              for _, t, p, _, pid in declared if t == "AWS::EKS::Addon")]


def compute_stack_pairs(declared, names):
    """(Terraform type, attributes) pairs of a stack's autoscaling groups, launch templates and EKS clusters (declared:
    (logical id, type, resolved properties, raw properties, physical id) of its created resources; names: what
    references resolve to, '<logical id>.LatestVersionNumber' and '<logical id>.Arn' when known)."""
    return [*(group_pair({**p, "AutoScalingGroupARN": pid if str(pid).startswith("arn:") else None,
                          "AutoScalingGroupName": p.get("AutoScalingGroupName") or pid,
                          **{k: number(p[k]) for k in ("MinSize", "MaxSize", "DesiredCapacity") if p.get(k)
                             is not None}})
              for _, t, p, _, pid in declared if t == "AWS::AutoScaling::AutoScalingGroup"),
            *(template_pair({"LaunchTemplateId": pid, "LaunchTemplateName": p.get("LaunchTemplateName"),
                             "VersionNumber": names.get(f"{lid}.LatestVersionNumber"),
                             "LaunchTemplateData": p.get("LaunchTemplateData")})
              for lid, t, p, _, pid in declared if t == "AWS::EC2::LaunchTemplate"),
            *_eks(declared, names)]
