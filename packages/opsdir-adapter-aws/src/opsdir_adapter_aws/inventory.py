"""What AWS says an environment runs, as the record's neutral resources (opsdir.core.inventory). Pure.

From Terraform state (terraform.tfstate, format version 4), managed resources and data sources alike:

  aws_vpc                                     -> network (role network)
  aws_subnet                                  -> subnet
  aws_instance                                -> server (name, role, hostname and product from its tags Name, Role,
                                                 Hostname, Product; the subnet it is in)
  aws_lb + aws_lb_listener + target groups    -> service: the DNS name of the Route 53 record aliasing the load
    + aws_route53_record (+ aws_eip)             balancer, its zone, listener ports, the role of the instances it
                                                 targets, its private address (internal) or Elastic IP allocation
  aws_vpc_security_group_ingress_rule,        -> firewall rules, grouped by the rule name their descriptions end with
    inline aws_security_group ingress            ("... (fw-name)") or by tag Name; the target role is the security
                                                 group's tag Role or the last part of its name (ciam-<env>-<role>)
  aws_secretsmanager_secret (+ its rotation)  -> secret reference aws-sm://<arn>; its value is never read
                                                 (aws_secretsmanager_secret_version is skipped)
  aws_kms_key (+ aws_kms_replica_key)         -> key reference aws-kms://<arn>, rotation, replica regions
  aws_s3_bucket                               -> storage s3://<bucket>
  aws_nat_gateway                             -> egress: its public address
Roles of resources the record doesn't have come from their tags Role (or BindingRole).
"""
import re
from collections import Counter

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get, make_entry, one
from opsdir.core.environment import env_dn
from opsdir.core.inventory import environment_groups, resource
from opsdir_format_terraform.state import read_state

PROVIDER = "aws"

SKIPPED = ("aws_secretsmanager_secret_version", "aws_ssm_parameter", "random_password", "tls_private_key",
           "aws_iam_access_key", "aws_db_instance")          # hold secret values, or aren't modeled yet
_RULE_NAME = re.compile(r"\(([A-Za-z0-9._-]+)\)\s*$")


def _tags(a):
    return a.get("tags") or a.get("tags_all") or {}


def _role(a):
    t = _tags(a)
    return t.get("Role") or t.get("BindingRole")


def _of(found, *types):
    return [a for t, a in found if t in types]


def _networks(found):
    return tuple(resource("network", a.get("id"), {"ciamCidr": a.get("cidr_block")}, name=_tags(a).get("Name"),
                          role=_role(a) or "network") for a in _of(found, "aws_vpc"))


def _subnets(found):
    return tuple(resource("subnet", a.get("id"), {"ciamCidr": a.get("cidr_block"), "ciamZone": a.get("availability_zone")},
                          name=_tags(a).get("Name"), role=_role(a)) for a in _of(found, "aws_subnet"))


def _servers(found):
    return tuple(resource("server", a.get("id"),
                          {"ciamPrivateIp": a.get("private_ip"), "ciamZone": a.get("availability_zone"),
                           "ciamInstanceSize": a.get("instance_type"), "ciamImageRef": a.get("ami"),
                           "ciamHostname": _tags(a).get("Hostname") or a.get("private_dns"),
                           "ciamProductVersion": _tags(a).get("Product")},
                          links={"ciamSubnet": a.get("subnet_id")}, name=_tags(a).get("Name") or a.get("id"),
                          role=_tags(a).get("Role"))
                 for a in _of(found, "aws_instance"))


def _services(found):
    """A service per load balancer: its DNS name (the Route 53 alias, or its tag Service), ports, targets' role."""
    instances = {a.get("id"): _tags(a).get("Role") for a in _of(found, "aws_instance")}
    eips = {a.get("allocation_id") or a.get("id"): a.get("public_ip") for a in _of(found, "aws_eip")}
    groups = {a.get("arn"): a for a in _of(found, "aws_lb_target_group")}
    records = _of(found, "aws_route53_record")

    def one_lb(lb):
        alias = next((r for r in records for al in r.get("alias") or () if al.get("name") == lb.get("dns_name")), None)
        listeners = [ls for ls in _of(found, "aws_lb_listener") if ls.get("load_balancer_arn") == lb.get("arn")]
        forwarded = {act.get("target_group_arn") for ls in listeners for act in ls.get("default_action") or ()}
        roles = Counter(instances.get(att.get("target_id")) for att in _of(found, "aws_lb_target_group_attachment")
                        if att.get("target_group_arn") in forwarded and instances.get(att.get("target_id")))
        mappings = lb.get("subnet_mapping") or ()
        private = next((m.get("private_ipv4_address") for m in mappings if m.get("private_ipv4_address")), None)
        allocation = next((m.get("allocation_id") for m in mappings if m.get("allocation_id")), None)
        return resource("service", lb.get("arn"), {
            "ciamFqdn": (alias or {}).get("name") or _tags(lb).get("Service"),
            "ciamDnsZoneRef": (alias or {}).get("zone_id"),
            "ciamPort": sorted({str(ls.get("port")) for ls in listeners if ls.get("port")} |
                               {str(groups[g].get("port")) for g in forwarded if g in groups and not listeners}),
            "ciamTargetRole": roles.most_common(1)[0][0] if roles else None,
            "ciamFrontendIp": private if lb.get("internal") else eips.get(allocation),
            "ciamProviderRef": None if lb.get("internal") else allocation},
            name=lb.get("name"), role=_role(lb))
    return tuple(one_lb(lb) for lb in _of(found, "aws_lb", "aws_alb"))


def _target_role(sg):
    return _role(sg) or (sg.get("name") or "").rsplit("-", 1)[-1] or None


def _firewall(found):
    """Firewall rules: ingress rules of the security groups, grouped into the record's rules by name."""
    groups = {a.get("id"): a for a in _of(found, "aws_security_group")}
    separate = [(groups.get(r.get("security_group_id")) or {}, r.get("cidr_ipv4"), r.get("from_port"),
                 r.get("ip_protocol"), r.get("description") or "", _tags(r).get("Name"), _role(r),
                 r.get("security_group_rule_id") or r.get("id"))
                for r in _of(found, "aws_vpc_security_group_ingress_rule")]
    inline = [(sg, cidr, rule.get("from_port"), rule.get("protocol"), rule.get("description") or "", None, None,
               f"{sg.get('id')}#{i}")
              for sg in groups.values() for i, rule in enumerate(sg.get("ingress") or ())
              for cidr in rule.get("cidr_blocks") or ()]
    named = [(_name_of(desc, tag, ref), sg, cidr, port, proto, role)
             for sg, cidr, port, proto, desc, tag, role, ref in (*separate, *inline)]
    names = list(dict.fromkeys(n for n, *_ in named))
    return tuple(resource("firewall", name, {
                     "ciamSourceCidr": sorted({cidr for n, _, cidr, *_ in named if n == name and cidr}),
                     "ciamPort": sorted({str(port) for n, _, _, port, *_ in named if n == name and port}),
                     "ciamProtocol": next((p for n, *_, p, _ in named if n == name and p in ("tcp", "udp")), None),
                     "ciamTargetRole": next((_target_role(sg) for n, sg, *_ in named if n == name and sg), None)},
                          name=name, role=next((r for n, *_, r in named if n == name and r), None))
                 for name in names)


def _name_of(description, tag, ref):
    m = _RULE_NAME.search(description)
    return tag or (m.group(1) if m else ref)


def _secrets(found):
    rotation = {a.get("secret_id"): a for a in _of(found, "aws_secretsmanager_secret_rotation")}
    return tuple(resource("secret", a.get("arn"), {
                     "ciamRefUri": f"aws-sm://{a.get('arn')}",
                     "ciamAutoRotate": "TRUE" if a.get("arn") in rotation or a.get("id") in rotation else None,
                     "ciamRotationFunction": (rotation.get(a.get("arn")) or rotation.get(a.get("id")) or {})
                     .get("rotation_lambda_arn")},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a))
                 for a in _of(found, "aws_secretsmanager_secret") if a.get("arn"))


def _keys(found):
    replicas = [a for a in _of(found, "aws_kms_replica_key")]
    return tuple(resource("key", a.get("arn"), {
                     "ciamRefUri": f"aws-kms://{a.get('arn')}",
                     "ciamAutoRotate": {True: "TRUE", False: "FALSE"}.get(a.get("enable_key_rotation")),
                     "ciamReplicaRegion": sorted({r.get("arn", "").split(":")[3] for r in replicas
                                                  if r.get("primary_key_arn") == a.get("arn") and r.get("arn")})},
                          name=_tags(a).get("Name") or a.get("key_id"), role=_role(a))
                 for a in _of(found, "aws_kms_key") if a.get("arn"))


def _storage(found):
    return tuple(resource("storage", a.get("arn") or a.get("bucket"), {"ciamStorageRef": f"s3://{a.get('bucket')}"},
                          name=a.get("bucket"), role=_role(a))
                 for a in _of(found, "aws_s3_bucket") if a.get("bucket"))


def _egress(found):
    return tuple(resource("egress", a.get("id"), {"ciamCidr": f"{a.get('public_ip')}/32" if a.get("public_ip") else None},
                          name=_tags(a).get("Name") or a.get("id"), role=_role(a))
                 for a in _of(found, "aws_nat_gateway") if a.get("id"))


def state_resources(text):
    """(resources, notices) of an AWS Terraform state."""
    found, problem = read_state(text)
    if problem:
        return (), (problem,)
    pairs = [(r.type, r.attributes) for r in found]
    skipped = Counter(t for t, _ in pairs if t in SKIPPED)
    return ((*_networks(pairs), *_subnets(pairs), *_servers(pairs), *_services(pairs), *_firewall(pairs),
             *_secrets(pairs), *_keys(pairs), *_storage(pairs), *_egress(pairs)),
            tuple(f"{t} ({n}): not read (holds secret values, or isn't modeled yet)" for t, n in sorted(skipped.items())))


# ------------------------------------------------------------------ the importer
def _environments(files):
    """{'cloud/env': (paths of the Terraform states under <cloud>/<env>/)}, and paths outside that layout."""
    states = sorted(p for p in files if p.endswith(".tfstate"))
    placed = {p: "/".join(p.split("/")[:2]) for p in states if p.count("/") >= 2}
    return ({spec: tuple(p for p in states if placed.get(p) == spec) for spec in dict.fromkeys(placed.values())},
            tuple(p for p in states if p not in placed))


def _bindings_container(spec):
    dn = f"ou=bindings,{env_dn(spec)}"
    return make_entry(dn, ("top", "organizationalUnit"), {"ou": ("bindings",)})


def read_terraform_state(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the AWS Terraform states under <cloud>/<env>/."""
    envs, stray = _environments(files)
    parsed = {spec: [state_resources(files[p]) for p in paths] for spec, paths in envs.items()}
    wrong = [spec for spec in envs if get(d, env_dn(spec)) is not None
             and one(get(d, env_dn(spec).split(",", 1)[1]), "ciamCloudProvider") != PROVIDER]
    placed = {spec: environment_groups(d, spec, tuple(r for rs, _ in parsed[spec] for r in rs))
              for spec in envs if spec not in wrong}
    return Imported(
        containers=tuple(_bindings_container(spec) for spec in placed),
        groups=tuple(g for groups, _ in placed.values() for g in groups),
        notices=(*(n for spec in placed for _, ns in parsed[spec] for n in ns),
                 *(n for _, ns in placed.values() for n in ns),
                 *(f"{spec}: not an AWS environment in the record; not imported" for spec in wrong),
                 *(f"{p}: put each environment's state under <cloud>/<env>/ (e.g. source/prod/terraform.tfstate); "
                   f"not imported" for p in stray),
                 *(("no Terraform state found (*.tfstate under <cloud>/<env>/)",) if not envs and not stray else ())))


TERRAFORM_STATE = Importer("terraform-state", "AWS Terraform state (terraform.tfstate) under <cloud>/<env>/, as the "
                                              "environment's servers and bindings", read_terraform_state)
