"""Compute groups as CloudFormation stacks declare them, normalized to the Terraform attribute names the shared mapping
reads (opsdir_adapter_aws.inventory compute groups, volumes.volume_resources a template's disks), through the CLI's
normalizers (cli_compute: the properties have the CLI's shapes). Properties come resolved. Pure.

  AWS::AutoScaling::AutoScalingGroup  -> aws_autoscaling_group (its ARN when the physical ID is one, else its name)
  AWS::EC2::LaunchTemplate            -> aws_launch_template (its LaunchTemplateData: image, type, metadata tokens,
                                         EBS disks, tag specifications)
"""
from .cli_compute import group_pair, template_pair
from .cloudformation_values import number

COMPUTE_TYPES = ("AWS::AutoScaling::AutoScalingGroup", "AWS::EC2::LaunchTemplate")


def compute_stack_pairs(declared, names):
    """(Terraform type, attributes) pairs of a stack's autoscaling groups and launch templates (declared: (logical id,
    type, resolved properties, raw properties, physical id) of its created resources; names: what references resolve
    to, '<logical id>.LatestVersionNumber' when known)."""
    return [*(group_pair({**p, "AutoScalingGroupARN": pid if str(pid).startswith("arn:") else None,
                          "AutoScalingGroupName": p.get("AutoScalingGroupName") or pid,
                          **{k: number(p[k]) for k in ("MinSize", "MaxSize", "DesiredCapacity") if p.get(k)
                             is not None}})
              for _, t, p, _, pid in declared if t == "AWS::AutoScaling::AutoScalingGroup"),
            *(template_pair({"LaunchTemplateId": pid, "LaunchTemplateName": p.get("LaunchTemplateName"),
                             "VersionNumber": names.get(f"{lid}.LatestVersionNumber"),
                             "LaunchTemplateData": p.get("LaunchTemplateData")})
              for lid, t, p, _, pid in declared if t == "AWS::EC2::LaunchTemplate")]
