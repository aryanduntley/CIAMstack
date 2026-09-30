"""What the AWS CLI reports about an environment, read into the record's neutral resources. Pure.

The outputs of `aws … --output json`, saved under <cloud>/<env>/ (any file names, except where a command's output
doesn't say what it describes), are recognized by their top-level key and normalized to the attribute names of the
matching Terraform resource, so the same mapping reads them as reads Terraform state
(opsdir_adapter_aws.inventory.pairs_resources):

  ec2 describe-vpcs                     Vpcs                      -> aws_vpc (the listed VPCs scope everything else)
  ec2 describe-subnets                  Subnets                   -> aws_subnet
  ec2 describe-instances                Reservations              -> aws_instance (terminated ones skipped)
  ec2 describe-security-groups          SecurityGroups            -> aws_security_group with inline ingress
  ec2 describe-security-group-rules     SecurityGroupRules        -> aws_vpc_security_group_ingress_rule (when given,
                                                                     the groups' inline permissions aren't read twice)
  ec2 describe-nat-gateways             NatGateways               -> aws_nat_gateway
  elbv2 describe-load-balancers         LoadBalancers             -> aws_lb (+ aws_eip for its Elastic IPs)
  elbv2 describe-tags                   TagDescriptions           -> the load balancers' tags
  elbv2 describe-listeners              Listeners                 -> aws_lb_listener
  elbv2 describe-target-groups          TargetGroups              -> aws_lb_target_group
  elbv2 describe-target-health          TargetHealthDescriptions  -> aws_lb_target_group_attachment; the output doesn't
                                                                     name its target group: save it as
                                                                     target-health/<target group name>.json
  route53 list-resource-record-sets     ResourceRecordSets        -> aws_route53_record (alias records); the output
                                                                     doesn't name its zone: save it as
                                                                     route53/<hosted zone ID>.json
  secretsmanager list-secrets           SecretList                -> aws_secretsmanager_secret (+ rotation, last
                                                                     rotated); values are never listed
  kms describe-key                      KeyMetadata               -> aws_kms_key (+ aws_kms_replica_key), customer
                                                                     managed keys only
  kms get-key-rotation-status           KeyRotationEnabled        -> the key's rotation (the key from its KeyId, else
                                                                     the file name rotation-<key id>.json)
  s3api list-buckets                    Buckets                   -> aws_s3_bucket
Network resources outside the listed VPCs are counted, not read; secrets, keys and buckets are account-wide, so the
importer counts rather than lists the ones the record doesn't have and nothing names a role for.
"""
import datetime as dt
import json
from collections import Counter

from opsdir.core.contract import Importer
from opsdir.core.inventory import layout_import
from .inventory import PROVIDER, pairs_resources

KEYS = ("Vpcs", "Subnets", "Reservations", "SecurityGroups", "SecurityGroupRules", "NatGateways", "LoadBalancers",
        "TagDescriptions", "Listeners", "TargetGroups", "TargetHealthDescriptions", "ResourceRecordSets", "SecretList",
        "KeyMetadata", "KeyRotationEnabled", "Buckets")
IN_VPC = ("aws_subnet", "aws_instance", "aws_security_group", "aws_lb", "aws_nat_gateway")
ACCOUNT_WIDE = ("secret", "key", "storage")


def _outputs(texts):
    """((path, key, document) of each recognized output), notices for the rest."""
    def recognize(path, text):
        try:
            doc = json.loads(text)
        except ValueError:
            return None
        return next(((path, k, doc) for k in KEYS if isinstance(doc, dict) and k in doc), None)
    found = {p: recognize(p, t) for p, t in sorted(texts.items())}
    return (tuple(o for o in found.values() if o),
            tuple(f"{p}: not an AWS CLI output this importer reads; not read" for p, o in found.items() if not o))


def _all(outs, key):
    """The items of every output with this top-level key, in file order."""
    return [item for _, k, doc in outs if k == key for item in doc.get(key) or ()]


def _tags(tags):
    return {t["Key"]: t.get("Value", "") for t in tags or () if isinstance(t, dict) and "Key" in t}


def _stem(path):
    return path.rsplit("/", 1)[-1].rsplit(".", 1)[0]


def generalized_time(value):
    """An AWS timestamp (ISO 8601, or seconds since the epoch) as LDAP generalized time (YYYYMMDDhhmmssZ); None when it
    is neither."""
    try:
        when = (dt.datetime.fromtimestamp(float(value), dt.timezone.utc) if isinstance(value, (int, float))
                else dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except (TypeError, ValueError):
        return None
    return (when if when.tzinfo else when.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc) \
        .strftime("%Y%m%d%H%M%SZ")


def _dns(name):
    """A DNS name as Terraform holds it: lower case, no trailing dot, no dualstack. prefix."""
    n = (name or "").lower().rstrip(".")
    return n[len("dualstack."):] if n.startswith("dualstack.") else n


def _network(outs):
    return [
        *(("aws_vpc", {"id": v.get("VpcId"), "cidr_block": v.get("CidrBlock"), "tags": _tags(v.get("Tags"))})
          for v in _all(outs, "Vpcs")),
        *(("aws_subnet", {"id": s.get("SubnetId"), "vpc_id": s.get("VpcId"), "cidr_block": s.get("CidrBlock"),
                          "availability_zone": s.get("AvailabilityZone"), "tags": _tags(s.get("Tags"))})
          for s in _all(outs, "Subnets")),
        *(("aws_nat_gateway", {"id": n.get("NatGatewayId"), "vpc_id": n.get("VpcId"),
                               "public_ip": next((a.get("PublicIp") for a in n.get("NatGatewayAddresses") or ()
                                                  if a.get("PublicIp")), None), "tags": _tags(n.get("Tags"))})
          for n in _all(outs, "NatGateways") if n.get("State") not in ("deleting", "deleted", "failed"))]


def _instances(outs):
    return [("aws_instance", {
                "id": i.get("InstanceId"), "ami": i.get("ImageId"), "instance_type": i.get("InstanceType"),
                "private_ip": i.get("PrivateIpAddress"), "private_dns": i.get("PrivateDnsName"),
                "availability_zone": (i.get("Placement") or {}).get("AvailabilityZone"), "subnet_id": i.get("SubnetId"),
                "vpc_id": i.get("VpcId"), "vpc_security_group_ids": [g.get("GroupId") for g in i.get("SecurityGroups") or ()],
                "tags": _tags(i.get("Tags"))})
            for r in _all(outs, "Reservations") for i in r.get("Instances") or ()
            if (i.get("State") or {}).get("Name") not in ("terminated", "shutting-down")]


def _security_groups(outs):
    """Groups (with their inline ingress unless the rules are listed separately) and separately listed ingress rules."""
    separate = any(k == "SecurityGroupRules" for _, k, _ in outs)

    def inline(g):
        return [] if separate else [
            {"from_port": p.get("FromPort"), "protocol": p.get("IpProtocol"), "cidr_blocks": [r.get("CidrIp")],
             "description": r.get("Description") or ""}
            for p in g.get("IpPermissions") or () for r in p.get("IpRanges") or () if r.get("CidrIp")]
    return [*(("aws_security_group", {"id": g.get("GroupId"), "name": g.get("GroupName"), "vpc_id": g.get("VpcId"),
                                      "tags": _tags(g.get("Tags")), "ingress": inline(g)})
              for g in _all(outs, "SecurityGroups")),
            *(("aws_vpc_security_group_ingress_rule", {
                "security_group_rule_id": r.get("SecurityGroupRuleId"), "security_group_id": r.get("GroupId"),
                "cidr_ipv4": r.get("CidrIpv4"), "from_port": r.get("FromPort"), "ip_protocol": r.get("IpProtocol"),
                "description": r.get("Description") or "", "tags": _tags(r.get("Tags"))})
              for r in _all(outs, "SecurityGroupRules") if not r.get("IsEgress") and r.get("CidrIpv4"))]


def _load_balancers(outs):
    tags = {t.get("ResourceArn"): _tags(t.get("Tags")) for t in _all(outs, "TagDescriptions")}
    lbs = _all(outs, "LoadBalancers")
    addresses = [(z.get("SubnetId"), a) for lb in lbs for z in lb.get("AvailabilityZones") or ()
                 for a in (z.get("LoadBalancerAddresses") or ())]
    return [*(("aws_lb", {"arn": lb.get("LoadBalancerArn"), "name": lb.get("LoadBalancerName"),
                          "internal": lb.get("Scheme") == "internal", "dns_name": _dns(lb.get("DNSName")),
                          "vpc_id": lb.get("VpcId"), "tags": tags.get(lb.get("LoadBalancerArn"), {}),
                          "subnet_mapping": [{"subnet_id": z.get("SubnetId"),
                                              "private_ipv4_address": a.get("PrivateIPv4Address"),
                                              "allocation_id": a.get("AllocationId")}
                                             for z in lb.get("AvailabilityZones") or ()
                                             for a in (z.get("LoadBalancerAddresses") or ({},))]})
              for lb in lbs),
            *(("aws_eip", {"allocation_id": a.get("AllocationId"), "public_ip": a.get("IpAddress")})
              for _, a in addresses if a.get("AllocationId") and a.get("IpAddress"))]


def _forwarding(outs):
    """Listeners, target groups and their targets; (pairs, notices for target health naming no known group)."""
    groups = _all(outs, "TargetGroups")
    by_name = {g.get("TargetGroupName"): g.get("TargetGroupArn") for g in groups}
    health = [(p, _stem(p), doc) for p, k, doc in outs if k == "TargetHealthDescriptions"]

    def forwards(action):
        return action.get("TargetGroupArn") or next(
            (t.get("TargetGroupArn") for t in (action.get("ForwardConfig") or {}).get("TargetGroups") or ()), None)
    return ([*(("aws_lb_listener", {"load_balancer_arn": ls.get("LoadBalancerArn"), "port": ls.get("Port"),
                                    "default_action": [{"type": a.get("Type"), "target_group_arn": forwards(a)}
                                                       for a in ls.get("DefaultActions") or ()]})
               for ls in _all(outs, "Listeners")),
             *(("aws_lb_target_group", {"arn": g.get("TargetGroupArn"), "name": g.get("TargetGroupName"),
                                        "port": g.get("Port")}) for g in groups),
             *(("aws_lb_target_group_attachment", {"target_group_arn": by_name[name],
                                                   "target_id": (t.get("Target") or {}).get("Id")})
               for _, name, doc in health if name in by_name for t in doc.get("TargetHealthDescriptions") or ())],
            tuple(f"{p}: no target group named {name} is listed (save describe-target-health as "
                  f"target-health/<target group name>.json, with describe-target-groups); not read"
                  for p, name, _ in health if name not in by_name))


def _records(outs):
    """Alias records of each zone's listing, the zone from the file name (route53/<hosted zone ID>.json)."""
    return [("aws_route53_record", {"name": _dns(r.get("Name")), "zone_id": _stem(p), "type": r.get("Type"),
                                    "alias": [{"name": _dns(r["AliasTarget"].get("DNSName")),
                                               "zone_id": r["AliasTarget"].get("HostedZoneId")}]})
            for p, k, doc in outs if k == "ResourceRecordSets"
            for r in doc.get("ResourceRecordSets") or () if r.get("AliasTarget")]


def _secrets(outs):
    listed = _all(outs, "SecretList")
    return [*(("aws_secretsmanager_secret", {"arn": s.get("ARN"), "name": s.get("Name"), "tags": _tags(s.get("Tags")),
                                             "rotation_enabled": bool(s.get("RotationEnabled")),
                                             "last_rotated": generalized_time(s.get("LastRotatedDate"))})
              for s in listed),
            *(("aws_secretsmanager_secret_rotation", {"secret_id": s.get("ARN"),
                                                      "rotation_lambda_arn": s.get("RotationLambdaARN")})
              for s in listed if s.get("RotationEnabled"))]


def _keys(outs):
    """Customer managed keys (describe-key, one per file) with their rotation and replicas; (pairs, notices)."""
    metas = [doc["KeyMetadata"] for _, k, doc in outs if k == "KeyMetadata" and isinstance(doc["KeyMetadata"], dict)]
    rotation = {**{_stem(p).removeprefix("rotation-"): doc["KeyRotationEnabled"]
                   for p, k, doc in outs if k == "KeyRotationEnabled"},
                **{doc["KeyId"]: doc["KeyRotationEnabled"] for _, k, doc in outs
                   if k == "KeyRotationEnabled" and doc.get("KeyId")}}
    live = [m for m in metas if m.get("KeyState") not in ("PendingDeletion", "PendingReplicaDeletion")]
    customer = [m for m in live if m.get("KeyManager") == "CUSTOMER"
                and (m.get("MultiRegionConfiguration") or {}).get("MultiRegionKeyType") != "REPLICA"]
    managed = [m for m in live if m.get("KeyManager") != "CUSTOMER"]
    return ([*(("aws_kms_key", {"arn": m.get("Arn"), "key_id": m.get("KeyId"),
                                "enable_key_rotation": rotation.get(m.get("Arn"), rotation.get(m.get("KeyId")))})
               for m in customer),
             *(("aws_kms_replica_key", {"arn": r.get("Arn"), "primary_key_arn": m.get("Arn")})
               for m in customer for r in (m.get("MultiRegionConfiguration") or {}).get("ReplicaKeys") or ())],
            (f"kms: {len(managed)} AWS managed key(s) not read (the record holds customer managed keys)",)
            if managed else ())


def _scoped(pairs):
    """(pairs, notices): network resources inside the listed VPCs only, and the rules of the groups kept."""
    vpcs = {a.get("id") for t, a in pairs if t == "aws_vpc"}
    if not vpcs:
        return pairs, ("no describe-vpcs output: network resources are not scoped to the environment's VPC",) \
            if any(t in IN_VPC for t, _ in pairs) else ()
    outside = Counter(t for t, a in pairs if t in IN_VPC and a.get("vpc_id") not in vpcs)
    kept = [(t, a) for t, a in pairs if t not in IN_VPC or a.get("vpc_id") in vpcs]
    groups = {a.get("id") for t, a in kept if t == "aws_security_group"}
    has_groups = any(t == "aws_security_group" for t, _ in pairs)
    rules = [(t, a) for t, a in kept if t == "aws_vpc_security_group_ingress_rule"
             and has_groups and a.get("security_group_id") not in groups]
    return ([p for p in kept if p not in rules],
            (*(f"{t} ({n}): outside the listed VPCs ({', '.join(sorted(vpcs))}); not read"
               for t, n in sorted(outside.items())),
             *((f"aws_vpc_security_group_ingress_rule ({len(rules)}): of security groups outside the listed VPCs; "
                f"not read",) if rules else ())))


def cli_resources(texts):
    """(resources, notices) of an environment's AWS CLI outputs ({path within the folder: text})."""
    outs, unknown = _outputs(texts)
    forwarding, target_notices = _forwarding(outs)
    keys, key_notices = _keys(outs)
    pairs, scope_notices = _scoped([*_network(outs), *_instances(outs), *_security_groups(outs),
                                    *_load_balancers(outs), *forwarding, *_records(outs), *_secrets(outs), *keys,
                                    *(("aws_s3_bucket", {"bucket": b.get("Name")}) for b in _all(outs, "Buckets"))])
    return pairs_resources(pairs), (*unknown, *target_notices, *key_notices, *scope_notices)


def read_cli_inventory(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the AWS CLI outputs under <cloud>/<env>/."""
    return layout_import(files, d, PROVIDER, "AWS", cli_resources, ".json", "AWS CLI output", "vpcs.json",
                         summarize=ACCOUNT_WIDE)


CLI_INVENTORY = Importer("cli-inventory", "AWS CLI outputs (aws … --output json) under <cloud>/<env>/, as the "
                                          "environment's servers and bindings", read_cli_inventory)
