"""The EBS and Data Lifecycle Manager outputs of the AWS CLI, normalized to the attribute names of the matching
Terraform resources (opsdir_adapter_aws.volumes reads both). Pure.

  ec2 describe-volumes                  Volumes           -> aws_ebs_volume and its aws_volume_attachment(s); an
                                                             instance's root volume (describe-instances names it:
                                                             the mapping at its RootDeviceName) is that instance's
                                                             root_block_device instead
  dlm get-lifecycle-policy              Policy            -> aws_dlm_lifecycle_policy; IAM's get-policy has the same
                                                             key: save it as dlm-policies/<policy id>.json
"""
from .cli_outputs import documents, items, tags_of

KEYS = ("Volumes",)
DLM = "dlm-policies"            # the folder Lifecycle Manager policies are saved under, and their outputs' key


def is_dlm_output(path):
    """Whether a file is a Lifecycle Manager policy (saved under dlm-policies/)."""
    return path.startswith(f"{DLM}/") or f"/{DLM}/" in path


def _root_volumes(outs):
    """{volume id: instance id} of the instances' root volumes."""
    return {m["Ebs"]["VolumeId"]: i.get("InstanceId")
            for r in items(outs, "Reservations") for i in r.get("Instances") or ()
            for m in i.get("BlockDeviceMappings") or ()
            if m.get("DeviceName") == i.get("RootDeviceName") and (m.get("Ebs") or {}).get("VolumeId")}


def _disk(v):
    return {"iops": v.get("Iops"), "throughput": v.get("Throughput"), "encrypted": v.get("Encrypted"),
            "kms_key_id": v.get("KmsKeyId"), "tags": tags_of(v.get("Tags"))}


def root_devices(outs):
    """{instance id: its root_block_device attributes} from the volumes describe-volumes lists."""
    roots = _root_volumes(outs)
    return {roots[v["VolumeId"]]: {"volume_id": v["VolumeId"], "volume_size": v.get("Size"),
                                   "volume_type": v.get("VolumeType"), **_disk(v)}
            for v in items(outs, "Volumes") if v.get("VolumeId") in roots}


def _rule(r):
    return {"interval": r.get("Interval"), "interval_unit": r.get("IntervalUnit"), "count": r.get("Count")}


def _policy(doc):
    p = doc.get("Policy") or {}
    details = p.get("PolicyDetails") or {}
    return ("aws_dlm_lifecycle_policy", {
        "id": p.get("PolicyId"), "arn": p.get("PolicyArn"), "description": p.get("Description"),
        "state": p.get("State"), "execution_role_arn": p.get("ExecutionRoleArn"), "tags": p.get("Tags") or {},
        "policy_details": [{
            "resource_types": details.get("ResourceTypes") or [],
            "target_tags": tags_of(details.get("TargetTags")),
            "schedule": [{"name": s.get("Name"),
                          "create_rule": [{"interval": (s.get("CreateRule") or {}).get("Interval"),
                                           "interval_unit": (s.get("CreateRule") or {}).get("IntervalUnit"),
                                           "times": (s.get("CreateRule") or {}).get("Times") or []}],
                          "retain_rule": [_rule(s.get("RetainRule") or {})],
                          "cross_region_copy_rule": [{"target": c.get("Target") or c.get("TargetRegion"),
                                                      "encrypted": c.get("Encrypted"), "cmk_arn": c.get("CmkArn"),
                                                      "retain_rule": [_rule(c.get("RetainRule") or {})]}
                                                     for c in s.get("CrossRegionCopyRules") or ()]}
                         for s in details.get("Schedules") or ()]}]})


def volume_pairs(outs):
    """The (Terraform type, attributes) pairs of the EBS volumes (not the instances' root volumes) with their
    attachments, and of the Lifecycle Manager policies."""
    roots = _root_volumes(outs)
    volumes = [v for v in items(outs, "Volumes") if v.get("VolumeId") and v["VolumeId"] not in roots]
    return [*(("aws_ebs_volume", {"id": v["VolumeId"], "availability_zone": v.get("AvailabilityZone"),
                                  "size": v.get("Size"), "type": v.get("VolumeType"), **_disk(v)}) for v in volumes),
            *(("aws_volume_attachment", {"volume_id": v["VolumeId"], "instance_id": a.get("InstanceId"),
                                         "device_name": a.get("Device")})
              for v in volumes for a in v.get("Attachments") or () if a.get("State", "attached") == "attached"),
            *(_policy(doc) for _, doc in documents(outs, DLM))]
