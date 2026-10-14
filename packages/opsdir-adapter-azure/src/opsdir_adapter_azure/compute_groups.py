"""Azure: an environment's compute groups (core compute.hosts, ciamComputeGroup) rendered as Terraform. Pure.

  each group: a Linux virtual machine scale set (its size, image, the instances it runs (its desired size, else its
  minimum), the zones it spans, the role's disks (volumes.scale_set_disks: the boot volume as its os_disk, data
  volumes as data disks at LUN 0, 1, ...), one network interface in its first subnet (a scale set's instances share
  one subnet) with the role's network security group and the backend pools of the service names reaching its role
  (a load balancer's pool, an Application Gateway's servers pool), its role's user-assigned identity, tagged Role,
  BindingRole and the disks it gives each instance), and an autoscale setting holding it between its minimum and
  maximum size when it records them. An adopted group (its provider reference, the scale set's resource ID) is
  imported by it; an autoscale setting it already has must be imported by hand (its ID isn't recorded). A group an
  overlay inherits is its base's to render (a comment).
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import inherited_from, recorded
from opsdir.domains.access.workloads import identity_of
from opsdir.domains.compute.hosts import compute_groups, group_subnets
from opsdir.core.notes import note, note_comment
from opsdir.domains.network.plumbing import adopted
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block, tf_import, tf_name
from .account import tagged
from .identities import LOC, RG, vm_identity
from .volumes import scale_set_disks


def scale_set_name(m, g):
    """A scale set's name: the last segment of its provider reference (its resource ID), else
    vmss-ciam-<env>-<group>."""
    ref_ = one(g, "ciamProviderRef")
    return ref_.rsplit("/", 1)[-1] if ref_ else f"vmss-ciam-{rdn_value(m.env)}-{rdn_value(g)}"


def _count(g, attr, what):
    v = one(g, attr)
    return int(v) if v and v.isdigit() else recorded(g, attr, what)


def _network(m, g, n, pools):
    role, subnets = one(g, "ciamTargetRole"), group_subnets(m, g)
    subnet = ref(f"data.azurerm_subnet.{tf_name(rdn_value(subnets[0]))}.id") if subnets \
        else f"UNBOUND:{rdn_value(g)}-subnets"
    lb, gateway = pools.get(role, ((), ()))
    return (*((("#", f"a scale set's instances share one subnet: {rdn_value(subnets[0])}, not "
                     f"{', '.join(rdn_value(s) for s in subnets[1:])}"),) if len(subnets) > 1 else ()),
            ("network_interface", Block((
                ("name", "primary"), ("primary", True),
                ("network_security_group_id", ref(f"azurerm_network_security_group.{tf_name(role)}.id")),
                ("ip_configuration", Block((
                    ("name", "primary"), ("primary", True), ("subnet_id", subnet),
                    *((("load_balancer_backend_address_pool_ids", list(lb)),) if lb else ()),
                    *((("application_gateway_backend_address_pool_ids", list(gateway)),) if gateway else ()))))))))


def _scale_set(m, g, n, des, identities, pools):
    role = one(g, "ciamTargetRole")
    notes, osd, data, disk_tags = scale_set_disks(m, g, des)
    instances = _count(g, "ciamDesiredSize", "desired-size") if one(g, "ciamDesiredSize") \
        else _count(g, "ciamMinSize", "min-size")
    return (*notes, tf_block("resource", ["azurerm_linux_virtual_machine_scale_set", n], [
        ("name", scale_set_name(m, g)), ("resource_group_name", RG), ("location", LOC),
        ("sku", recorded(g, "ciamInstanceSize", "size")), ("instances", instances),
        *((("zones", list(values(g, "ciamSpansZone"))),) if values(g, "ciamSpansZone") else ()),
        ("admin_username", "ciamadmin"), ("source_image_id", recorded(g, "ciamImageRef", "image")),
        ("admin_ssh_key", Block((("username", "ciamadmin"), ("public_key", ref("var.admin_ssh_public_key"))))),
        ("os_disk", osd), *data, *_network(m, g, n, pools),
        *vm_identity(identity_of(identities, role)),
        ("tags", tagged(m, {"Role": role, "BindingRole": one(g, "ciamBindingRole"), **disk_tags,
                            "ManagedBy": "opsdir"}))]),
        *((tf_import(f"azurerm_linux_virtual_machine_scale_set.{n}", one(g, "ciamProviderRef")),)
          if adopted(g) else ()))


def autoscale_note(g):
    """The render note of an existing (adopted) compute group's autoscale setting (an action: import the one it has
    by hand, its ID isn't recorded, or applying adds a second one)."""
    return note("Compute", "action", rdn_value(g), "exists: an autoscale setting it already has must be imported by "
                "hand (its ID isn't recorded), or applying adds a second one",
                ("Before applying, import the scale set's autoscale setting into the rendered "
                 "azurerm_monitor_autoscale_setting (terraform import, its resource ID)",), g.dn)


def group_notes(m):
    """The render notes of environment m's compute groups (render_groups writes their comments)."""
    return tuple(autoscale_note(g) for g in compute_groups(m) if adopted(g) and not inherited_from(m, g)
                 and one(g, "ciamMinSize") and one(g, "ciamMaxSize"))


def _autoscale(m, g, n):
    if not (one(g, "ciamMinSize") and one(g, "ciamMaxSize")):
        return ()
    return (*((comment(note_comment(autoscale_note(g))),) if adopted(g) else ()),
            tf_block("resource", ["azurerm_monitor_autoscale_setting", n], [
                ("name", f"autoscale-{scale_set_name(m, g)}"), ("resource_group_name", RG), ("location", LOC),
                ("target_resource_id", ref(f"azurerm_linux_virtual_machine_scale_set.{n}.id")),
                ("profile", Block((("name", "default"), ("capacity", Block((
                    ("default", _count(g, "ciamDesiredSize", "desired-size") if one(g, "ciamDesiredSize")
                     else _count(g, "ciamMinSize", "min-size")),
                    ("minimum", _count(g, "ciamMinSize", "min-size")),
                    ("maximum", _count(g, "ciamMaxSize", "max-size")))))))),
                ("tags", tagged(m, {"ManagedBy": "opsdir"}))]))


def _group(m, g, des, identities, pools):
    base = inherited_from(m, g)
    if base:
        return (comment(f"Compute group {rdn_value(g)} is {base}'s (this environment inherits it): rendered there"),)
    n = tf_name(rdn_value(g))
    return (*_scale_set(m, g, n, des, identities, pools), *_autoscale(m, g, n))


def render_groups(m, des, identities, pools):
    """Terraform items for environment m's compute groups: per own group its scale set and autoscale setting; one it
    inherits a comment (its base renders it). des: the disk-encryption binding (or None); identities: the
    environment's workload identities; pools: {server role: (load balancer backend pool ID references, Application
    Gateway backend pool ID references)}."""
    return tuple(item for g in compute_groups(m) for item in _group(m, g, des, identities, pools))
