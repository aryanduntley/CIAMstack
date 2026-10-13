"""Google Cloud: an environment's compute groups (core compute.hosts, ciamComputeGroup) rendered as Terraform. Pure.

  each group: an instance template (its machine type, its role's disks (volumes.template_disks), a network interface
  in its first subnet, the role's network tag (VPC rules) or secure tag (a firewall policy's rules, bound through the
  template), shielded VM, its role's service account, OS Login, labels role and bindingrole, what the importer reads
  its roles from), a regional managed instance group running it in the zones it spans (its desired size as its first
  size, an autoscaler then moving it; the named port the service names reaching its role need), and a regional
  autoscaler between its minimum and maximum size when it records them. An adopted group (its provider reference, the
  instance group manager's) is imported by it: the template is new, its instances take it when they are next
  replaced; an autoscaler it already has must be imported by hand (said). A group an overlay inherits is its base's
  to render (a comment).
"""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import inherited_from, recorded
from opsdir.domains.access.workloads import identity_of
from opsdir.domains.compute.hosts import compute_groups, group_subnets
from opsdir.domains.network.plumbing import adopted
from opsdir_format_terraform.hcl import Block, comment, ref, tf_block, tf_import, tf_name
from .firewall_policy import template_tags
from .names import REGION, label, network_tag
from .volumes import template_disks


def group_name(m, g):
    """A managed instance group's name: its provider reference's last segment, else ciam-<env>-<group>."""
    ref_ = one(g, "ciamProviderRef")
    return ref_.rsplit("/", 1)[-1] if ref_ else f"ciam-{rdn_value(m.env)}-{rdn_value(g)}"


def _count(g, attr, what):
    v = one(g, attr)
    return int(v) if v and v.isdigit() else recorded(g, attr, what)


def _template(m, g, n, kms, identities):
    role, subnets = one(g, "ciamTargetRole"), group_subnets(m, g)
    w = identity_of(identities, role)
    notes, disks = template_disks(m, g, kms)
    subnet = ref(f"data.google_compute_subnetwork.{tf_name(rdn_value(subnets[0]))}.self_link") if subnets \
        else f"UNBOUND:{rdn_value(g)}-subnets"
    return (*notes, tf_block("resource", ["google_compute_instance_template", n], [
        ("name_prefix", f"{group_name(m, g)}-"), ("machine_type", recorded(g, "ciamInstanceSize", "size")),
        ("tags", [network_tag(m, role)]), *template_tags(m, role), *disks,
        *((("#", f"a template's instances sit in one subnet: {rdn_value(subnets[0])}, not "
                 f"{', '.join(rdn_value(s) for s in subnets[1:])}"),) if len(subnets) > 1 else ()),
        ("network_interface", Block((("subnetwork", subnet),))),
        ("shielded_instance_config", Block((("enable_secure_boot", True), ("enable_vtpm", True),
                                            ("enable_integrity_monitoring", True)))),
        *((("service_account", Block((("email", ref(f"google_service_account.{tf_name(w.identity_role)}.email")),
                                      ("scopes", ["cloud-platform"])))),) if w else ()),
        ("metadata", {"enable-oslogin": "TRUE", "ciam-role": role}),
        ("labels", {"role": label(role), "bindingrole": label(one(g, "ciamBindingRole")), "managed_by": "opsdir"}),
        ("lifecycle", Block((("create_before_destroy", True),)))]))


def _manager(m, g, n, ports):
    zones = values(g, "ciamSpansZone")
    named = tuple(dict.fromkeys(ports.get(one(g, "ciamTargetRole"), ())))
    first = _count(g, "ciamDesiredSize", "desired-size") if one(g, "ciamDesiredSize") \
        else _count(g, "ciamMinSize", "min-size")
    scaled = bool(one(g, "ciamMinSize") and one(g, "ciamMaxSize"))
    return (*((comment(f"{rdn_value(g)} exists: applying gives it a new instance template, which its instances run "
                       "when they are next replaced"),) if adopted(g) else ()),
            tf_block("resource", ["google_compute_region_instance_group_manager", n], [
                ("name", group_name(m, g)), ("region", REGION), ("base_instance_name", group_name(m, g)),
                ("version", Block((("instance_template", ref(f"google_compute_instance_template.{n}.id")),))),
                *((("distribution_policy_zones", list(zones)),) if zones else ()),
                ("target_size", first),
                *((("#", f"the service names reaching {one(g, 'ciamTargetRole')} use ports "
                         f"{', '.join(map(str, named))}; a backend service's named port 'ciam' is one: {named[0]}"),)
                  if len(named) > 1 else ()),
                *((("named_port", Block((("name", "ciam"), ("port", named[0])))),) if named else ()),
                *((("lifecycle", Block((("ignore_changes", [ref("target_size")]),))),) if scaled else ())]),
            *((tf_import(f"google_compute_region_instance_group_manager.{n}", one(g, "ciamProviderRef")),)
              if adopted(g) else ()))


def _autoscaler(m, g, n):
    if not (one(g, "ciamMinSize") and one(g, "ciamMaxSize")):
        return ()
    return (*((comment(f"{rdn_value(g)} exists: an autoscaler it already has must be imported by hand (its ID isn't "
                       "recorded), or applying adds a second one"),) if adopted(g) else ()),
            tf_block("resource", ["google_compute_region_autoscaler", n], [
        ("name", f"{group_name(m, g)}-autoscaler"), ("region", REGION),
        ("target", ref(f"google_compute_region_instance_group_manager.{n}.id")),
        ("autoscaling_policy", Block((("min_replicas", _count(g, "ciamMinSize", "min-size")),
                                      ("max_replicas", _count(g, "ciamMaxSize", "max-size")))))]),)


def _group(m, g, kms, identities, ports):
    base = inherited_from(m, g)
    if base:
        return (comment(f"Compute group {rdn_value(g)} is {base}'s (this environment inherits it): rendered there"),)
    n = tf_name(rdn_value(g))
    return (*_template(m, g, n, kms, identities), *_manager(m, g, n, ports), *_autoscaler(m, g, n))


def render_groups(m, kms, identities, ports):
    """Terraform items for environment m's compute groups: per own group its instance template, regional managed
    instance group and autoscaler; one it inherits a comment (its base renders it). kms: the disk-encryption key's
    reference URI (or None); identities: the environment's workload identities; ports: {server role: the ports its
    service names' backend services reach it on by the named port 'ciam'}."""
    return tuple(item for g in compute_groups(m) for item in _group(m, g, kms, identities, ports))
