"""AWS: an environment's compute groups (core compute.hosts, ciamComputeGroup) rendered as Terraform. Pure.

  each group: a launch template (its image, instance type, the role's instance profile and security group, session
  tokens required for instance metadata when it records so, its role's disks (volumes.template_disks) with the
  instances tagged Name, Role, BindingRole and the disks they get) and an autoscaling group in its subnets (the
  bindings of its ciamSubnetRole) scaling between its minimum and maximum size, at its desired size when it records
  one, registered in the target groups of the service names reaching its role and tagged Role and BindingRole (what
  the importer reads its roles from); an adopted group (its provider reference) imported by its name, its launch
  template replaced by this one (its instances take it when they are next replaced); a group an overlay inherits is
  its base's to render (a comment).
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import inherited_from, recorded
from opsdir.domains.access.workloads import identity_of
from opsdir.domains.compute.hosts import compute_groups, group_subnets
from opsdir.core.notes import note, note_comment
from opsdir.domains.network.plumbing import adopted
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block, tf_import, tf_name
from .volumes import template_disks

TOKENS = {"TRUE": "required", "FALSE": "optional"}      # ciamMetadataTokens -> metadata_options.http_tokens


def group_name(m, g):
    """The autoscaling group's name: the one its provider reference (an ARN) names, else ciam-<env>-<group>."""
    arn = one(g, "ciamProviderRef") or ""
    return arn.rsplit("autoScalingGroupName/", 1)[1] if "autoScalingGroupName/" in arn \
        else f"ciam-{rdn_value(m.env)}-{rdn_value(g)}"


def _count(g, attr, what):
    v = one(g, attr)
    return int(v) if v and v.isdigit() else recorded(g, attr, what)


def _launch_template(m, g, n, kms, identities):
    role = one(g, "ciamTargetRole")
    w = identity_of(identities, role)
    disks, disk_tags, volume_tags = template_disks(m, g, ref(f"data.aws_ami.{n}.root_device_name"), kms)
    tokens = TOKENS.get(one(g, "ciamMetadataTokens"))
    return (tf_block("data", ["aws_ami", n], [
                ("filter", Block((("name", "image-id"), ("values", [recorded(g, "ciamImageRef", "image")]))))]),
            tf_block("resource", ["aws_launch_template", n], [
                ("name", group_name(m, g)), ("image_id", recorded(g, "ciamImageRef", "image")),
                ("instance_type", recorded(g, "ciamInstanceSize", "size")),
                *((("iam_instance_profile",
                    Block((("name", ref(f"aws_iam_instance_profile.{tf_name(w.identity_role)}.name")),))),)
                  if w else ()),
                ("vpc_security_group_ids", [ref(f"aws_security_group.{tf_name(role)}.id")]),
                *((("metadata_options", Block((("http_endpoint", "enabled"), ("http_tokens", tokens)))),)
                  if tokens else ()),
                *disks,
                ("tag_specifications", Block((("resource_type", "instance"), ("tags", {
                    "Name": group_name(m, g), "Role": role, "BindingRole": one(g, "ciamBindingRole"), **disk_tags,
                    "ManagedBy": "opsdir"})))),
                ("tag_specifications", Block((("resource_type", "volume"), ("tags", volume_tags)))),
                ("tags", {"ManagedBy": "opsdir"})]))


def _autoscaling_group(m, g, n, target_groups):
    subnets = group_subnets(m, g)
    arns = target_groups.get(one(g, "ciamTargetRole"), ())
    tags = (("Role", one(g, "ciamTargetRole")), ("BindingRole", one(g, "ciamBindingRole")), ("ManagedBy", "opsdir"))
    return (*((comment(note_comment(replaced_note(m, g))),) if adopted(g) else ()),
            tf_block("resource", ["aws_autoscaling_group", n], [
                ("name", group_name(m, g)),
                ("min_size", _count(g, "ciamMinSize", "min-size")), ("max_size", _count(g, "ciamMaxSize", "max-size")),
                *((("desired_capacity", _count(g, "ciamDesiredSize", "desired-size")),)
                  if one(g, "ciamDesiredSize") else ()),
                ("vpc_zone_identifier", [ref(f"data.aws_subnet.{tf_name(rdn_value(s))}.id") for s in subnets]
                 if subnets else f"UNBOUND:{rdn_value(g)}-subnets"),
                ("launch_template", Block((("id", ref(f"aws_launch_template.{n}.id")),
                                           ("version", ref(f"aws_launch_template.{n}.latest_version"))))),
                *((("target_group_arns", list(arns)), ("health_check_type", "ELB")) if arns else ()),
                *(("tag", Block((("key", k), ("value", v), ("propagate_at_launch", False)))) for k, v in tags)]),
            *((tf_import(f"aws_autoscaling_group.{n}", group_name(m, g)),) if adopted(g) else ()))


def _group(m, g, kms, identities, target_groups):
    base = inherited_from(m, g)
    if base:
        return (comment(f"Compute group {rdn_value(g)} is {base}'s (this environment inherits it): rendered there"),)
    n = tf_name(rdn_value(g))
    return (*_launch_template(m, g, n, kms, identities), *_autoscaling_group(m, g, n, target_groups))


def replaced_note(m, g):
    """The render note of an existing (adopted) compute group (an action): applying gives it a new launch template,
    which its instances run only once they are replaced."""
    return note("Compute", "action", rdn_value(g), f"exists: applying gives it launch template {group_name(m, g)}, "
                "which its instances run when they are next replaced",
                (f"After applying, start an instance refresh on autoscaling group {group_name(m, g)} so its instances "
                 "run the new template",), g.dn)


def group_notes(m):
    """The render notes of environment m's compute groups (render_groups writes their comments)."""
    return tuple(replaced_note(m, g) for g in compute_groups(m) if adopted(g) and not inherited_from(m, g))


def render_groups(m, kms, identities, target_groups):
    """Terraform items for environment m's compute groups: per group the AMI it boots (for its root device's name),
    its launch template and its autoscaling group; one it inherits from a base a comment (the base renders it). kms:
    the disk-encryption key's reference URI (or None); identities: the environment's workload identities;
    target_groups: {server role: target group ARN references}."""
    return tuple(item for g in compute_groups(m) for item in _group(m, g, kms, identities, target_groups))
