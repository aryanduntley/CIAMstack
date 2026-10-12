"""The compute group and EKS outputs of the AWS CLI, normalized to the attribute names of the matching Terraform
resources (opsdir_adapter_aws.inventory reads both). Pure.

  autoscaling describe-auto-scaling-groups  AutoScalingGroups       -> aws_autoscaling_group (its launch template, from
                                                                       the group or its mixed instances policy)
  ec2 describe-launch-template-versions     LaunchTemplateVersions  -> aws_launch_template: the version a group uses
                                                                       ($Latest, $Default or its number)
  eks describe-cluster                      cluster                 -> aws_eks_cluster
  eks describe-nodegroup                    nodegroup               -> aws_eks_node_group
  eks describe-addon                        addon                   -> aws_eks_addon
Groups and clusters carry the VPC they sit in (a group's from its subnets, as describe-subnets lists them; a cluster's
from its VPC configuration), so the reader keeps the environment's only.
"""
from .cli_outputs import documents, items

KEYS = ("AutoScalingGroups", "LaunchTemplateVersions", "cluster", "nodegroup", "addon")


def launch_template_ref(g):
    """{id, name, version} of the launch template a group launches from (its own, else its mixed instances policy's)."""
    spec = g.get("LaunchTemplate") or ((g.get("MixedInstancesPolicy") or {}).get("LaunchTemplate") or {}).get(
        "LaunchTemplateSpecification") or {}
    return {"id": spec.get("LaunchTemplateId"), "name": spec.get("LaunchTemplateName"), "version": spec.get("Version")}


def _uses(version, ref):
    """Whether a listed template version is the one a group's reference names."""
    if not (version.get("LaunchTemplateId") == ref["id"] if ref["id"]
            else version.get("LaunchTemplateName") == ref["name"]):
        return False
    wanted = str(ref["version"] or "$Default")
    return (version.get("DefaultVersion") is True if wanted == "$Default"
            else wanted == "$Latest" or str(version.get("VersionNumber")) == wanted)


def _used_version(versions, ref):
    """The listed version a group's reference names ($Latest: the highest listed), else None."""
    matching = [v for v in versions if _uses(v, ref)]
    return max(matching, key=lambda v: v.get("VersionNumber") or 0) if matching else None


def _template(version):
    data = version.get("LaunchTemplateData") or {}
    tokens = (data.get("MetadataOptions") or {}).get("HttpTokens")
    return ("aws_launch_template", {"id": version.get("LaunchTemplateId"), "name": version.get("LaunchTemplateName"),
                                    "latest_version": version.get("VersionNumber"), "image_id": data.get("ImageId"),
                                    "instance_type": data.get("InstanceType"),
                                    "metadata_options": [{"http_tokens": tokens}] if tokens else []})


def _templates(groups, versions):
    """(template pairs, notices): the version each group uses, one per template; a template groups use at different
    versions is read at the first group's, and a group whose version isn't listed is named."""
    used = [(g.get("AutoScalingGroupName"), ref, _used_version(versions, ref))
            for g in groups for ref in (launch_template_ref(g),) if ref["id"] or ref["name"]]
    found = [v for _, _, v in used if v is not None]
    chosen = {t: next(v for v in found if v.get("LaunchTemplateId") == t)          # the first group's version
              for t in dict.fromkeys(v.get("LaunchTemplateId") for v in found)}
    return ([_template(v) for v in chosen.values()],
            (*(f"autoscaling group {name}: launch template {ref['id'] or ref['name']} version "
               f"{ref['version'] or '$Default'} is not listed (ec2 describe-launch-template-versions); its image and "
               f"instance type not read" for name, ref, v in used if v is None),
             *(f"autoscaling group {name}: uses launch template {v.get('LaunchTemplateId')} version "
               f"{v.get('VersionNumber')}, another group version {first.get('VersionNumber')}; read at that one"
               for name, _, v in used if v is not None for first in (chosen[v.get("LaunchTemplateId")],)
               if v.get("VersionNumber") != first.get("VersionNumber"))))


def _groups(groups, vpc_of_subnet):
    def subnets(g):
        return [s.strip() for s in (g.get("VPCZoneIdentifier") or "").split(",") if s.strip()]

    def group(g):
        ref = launch_template_ref(g)
        return ("aws_autoscaling_group", {
            "arn": g.get("AutoScalingGroupARN"), "name": g.get("AutoScalingGroupName"), "min_size": g.get("MinSize"),
            "max_size": g.get("MaxSize"), "desired_capacity": g.get("DesiredCapacity"),
            "vpc_zone_identifier": subnets(g), "availability_zones": g.get("AvailabilityZones") or [],
            "vpc_id": next((vpc_of_subnet[s] for s in subnets(g) if s in vpc_of_subnet), None),
            "launch_template": [ref] if ref["id"] or ref["name"] else [],
            "tag": [{"key": t.get("Key"), "value": t.get("Value"), "propagate_at_launch": t.get("PropagateAtLaunch")}
                    for t in g.get("Tags") or () if t.get("Key")]})
    return [group(g) for g in groups if g.get("Status") != "Delete in progress"]


def _eks(outs):
    clusters = [doc["cluster"] for _, doc in documents(outs, "cluster") if isinstance(doc["cluster"], dict)]
    nodegroups = [doc["nodegroup"] for _, doc in documents(outs, "nodegroup") if isinstance(doc["nodegroup"], dict)]
    addons = [doc["addon"] for _, doc in documents(outs, "addon") if isinstance(doc["addon"], dict)]
    return [*(("aws_eks_cluster", {"arn": c.get("arn"), "name": c.get("name"), "version": c.get("version"),
                                   "vpc_id": (c.get("resourcesVpcConfig") or {}).get("vpcId"),
                                   "vpc_config": [{"subnet_ids": (c.get("resourcesVpcConfig") or {}).get("subnetIds")
                                                   or []}], "tags": c.get("tags") or {}})
              for c in clusters if c.get("status") != "DELETING"),
            *(("aws_eks_node_group", {"arn": n.get("nodegroupArn"), "cluster_name": n.get("clusterName"),
                                      "node_group_name": n.get("nodegroupName"),
                                      "instance_types": n.get("instanceTypes") or [],
                                      "subnet_ids": n.get("subnets") or [],
                                      "scaling_config": [{"min_size": scale.get("minSize"),
                                                          "max_size": scale.get("maxSize"),
                                                          "desired_size": scale.get("desiredSize")}],
                                      "tags": n.get("tags") or {}})
              for n in nodegroups if n.get("status") != "DELETING" for scale in (n.get("scalingConfig") or {},)),
            *(("aws_eks_addon", {"arn": a.get("addonArn"), "cluster_name": a.get("clusterName"),
                                 "addon_name": a.get("addonName"), "addon_version": a.get("addonVersion"),
                                 "tags": a.get("tags") or {}})
              for a in addons if a.get("status") != "DELETING")]


def compute_pairs(outs):
    """(pairs, notices): the autoscaling groups with the launch template versions they use, and the EKS clusters with
    their node groups and add-ons."""
    groups = items(outs, "AutoScalingGroups")
    templates, notices = _templates(groups, items(outs, "LaunchTemplateVersions"))
    vpc_of_subnet = {s.get("SubnetId"): s.get("VpcId") for s in items(outs, "Subnets")}
    return [*_groups(groups, vpc_of_subnet), *templates, *_eks(outs)], notices

