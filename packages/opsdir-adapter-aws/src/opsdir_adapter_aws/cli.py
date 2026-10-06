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
  route53 list-resource-record-sets     ResourceRecordSets        -> aws_route53_record (alias and other records,
                                                                     TTLs, routing); the output doesn't name its zone:
                                                                     save it as route53/<hosted zone ID>.json
  secretsmanager list-secrets           SecretList                -> aws_secretsmanager_secret (+ rotation, last
                                                                     rotated); values are never listed
  kms describe-key                      KeyMetadata               -> aws_kms_key (+ aws_kms_replica_key), customer
                                                                     managed keys only
  kms get-key-rotation-status           KeyRotationEnabled        -> the key's rotation (the key from its KeyId, else
                                                                     the file name rotation-<key id>.json)
  s3api list-buckets                    Buckets                   -> aws_s3_bucket
  lambda list-functions                 Functions                 -> aws_lambda_function
  lambda list-tags                      Tags                      -> a function's tags; the output doesn't name the
                                                                     function: save it as lambda-tags/<function>.json
  events list-rules                     Rules                     -> aws_cloudwatch_event_rule (enabled rules)
  events list-targets-by-rule           Targets                   -> aws_cloudwatch_event_target; the output doesn't
                                                                     name its rule: save it as event-targets/<rule>.json
  scheduler get-schedule                ScheduleExpression        -> aws_scheduler_schedule (enabled; one per file)
  codepipeline get-pipeline             pipeline                  -> aws_codepipeline (its ARN from metadata)
  codebuild batch-get-projects          projects                  -> aws_codebuild_project
  The edge: load balancer and target group attributes, web ACLs, Shield, CloudFront, hosted zones, resolver rules:
                                                                  see cli_edge.py
  IAM: get-account-authorization-details, key and bucket policies, resource policies, control policies, Identity
  Center, the policy simulator's verdicts                         -> see cli_iam.py
  The network depth: route tables, network ACLs, VPC endpoints and endpoint services, peering, transit and VPN, flow
  logs, Network Firewall rule groups, policies and firewalls      -> see cli_network.py
  Managed databases: RDS instances, Aurora clusters, subnet groups, user-set parameters -> see cli_database.py
Network resources outside the listed VPCs are counted, not read; secrets, keys, buckets, functions, pipelines and build
projects are account-wide, so the importer counts rather than lists the ones the record doesn't have and nothing names
a role for.
"""
import datetime as dt
from collections import Counter

from opsdir.core.contract import Importer
from opsdir.core.directory import gtime
from opsdir.core.inventory import layout_import
from opsdir.core.sources import json_document
from .cli_database import KEYS as DATABASE_KEYS, database_pairs
from .cli_edge import KEYS as EDGE_KEYS, attributes, edge_pairs, record_attributes
from .cli_iam import KEYS as IAM_KEYS, iam_pairs
from .cli_network import KEYS as NETWORK_KEYS, network_pairs
from .cli_outputs import items, stem, tags_of
from .inventory import PROVIDER, pairs_resources

KEYS = ("Vpcs", "Subnets", "Reservations", "SecurityGroups", "SecurityGroupRules", "NatGateways", "LoadBalancers",
        "TagDescriptions", "Listeners", "TargetGroups", "TargetHealthDescriptions", "ResourceRecordSets", "SecretList",
        "KeyMetadata", "KeyRotationEnabled", "Buckets", "Functions", "Rules", "Targets", "ScheduleExpression",
        "pipeline", "projects", *IAM_KEYS, *EDGE_KEYS, *NETWORK_KEYS, *DATABASE_KEYS,
        "Tags")   # Tags last: others carry tags too
IN_VPC = ("aws_subnet", "aws_instance", "aws_security_group", "aws_lb", "aws_nat_gateway", "aws_route_table",
          "aws_network_acl", "aws_vpc_endpoint", "aws_ec2_transit_gateway_vpc_attachment", "aws_db_instance",
          "aws_rds_cluster", "aws_rds_cluster_instance", "aws_db_subnet_group")
ACCOUNT_WIDE = ("secret", "key", "storage", "job", "identity")


def _outputs(texts):
    """((path, key, document) of each recognized output), notices for the rest."""
    def recognize(path, text):
        doc = json_document(text, dict) or {}
        return next(((path, k, doc) for k in KEYS if k in doc), None)
    found = {p: recognize(p, t) for p, t in sorted(texts.items())}
    return (tuple(o for o in found.values() if o),
            tuple(f"{p}: not an AWS CLI output this importer reads; not read" for p, o in found.items() if not o))


def generalized_time(value):
    """An AWS timestamp (ISO 8601, or seconds since the epoch) as LDAP generalized time (YYYYMMDDhhmmssZ); None when it
    is neither."""
    try:
        when = (dt.datetime.fromtimestamp(float(value), dt.timezone.utc) if isinstance(value, (int, float))
                else dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except (TypeError, ValueError):
        return None
    return gtime(when)


def _dns(name):
    """A DNS name as Terraform holds it: lower case, no trailing dot, no dualstack. prefix."""
    n = (name or "").lower().rstrip(".")
    return n[len("dualstack."):] if n.startswith("dualstack.") else n


def _network(outs):
    return [
        *(("aws_vpc", {"id": v.get("VpcId"), "cidr_block": v.get("CidrBlock"), "tags": tags_of(v.get("Tags"))})
          for v in items(outs, "Vpcs")),
        *(("aws_subnet", {"id": s.get("SubnetId"), "vpc_id": s.get("VpcId"), "cidr_block": s.get("CidrBlock"),
                          "availability_zone": s.get("AvailabilityZone"), "tags": tags_of(s.get("Tags"))})
          for s in items(outs, "Subnets")),
        *(("aws_nat_gateway", {"id": n.get("NatGatewayId"), "vpc_id": n.get("VpcId"),
                               "public_ip": next((a.get("PublicIp") for a in n.get("NatGatewayAddresses") or ()
                                                  if a.get("PublicIp")), None), "tags": tags_of(n.get("Tags"))})
          for n in items(outs, "NatGateways") if n.get("State") not in ("deleting", "deleted", "failed"))]


def _instances(outs):
    return [("aws_instance", {
                "id": i.get("InstanceId"), "ami": i.get("ImageId"), "instance_type": i.get("InstanceType"),
                "private_ip": i.get("PrivateIpAddress"), "private_dns": i.get("PrivateDnsName"),
                "availability_zone": (i.get("Placement") or {}).get("AvailabilityZone"), "subnet_id": i.get("SubnetId"),
                "vpc_id": i.get("VpcId"), "vpc_security_group_ids": [g.get("GroupId") for g in i.get("SecurityGroups") or ()],
                "tags": tags_of(i.get("Tags"))})
            for r in items(outs, "Reservations") for i in r.get("Instances") or ()
            if (i.get("State") or {}).get("Name") not in ("terminated", "shutting-down")]


def _security_groups(outs):
    """Groups (with their inline ingress unless the rules are listed separately) and separately listed ingress rules."""
    separate = any(k == "SecurityGroupRules" for _, k, _ in outs)

    def inline(g):
        """One Terraform-shaped ingress block per permission and description, every kind of source kept."""
        def blocks(p):
            sources = [*(("cidr_blocks", r.get("CidrIp"), r.get("Description")) for r in p.get("IpRanges") or ()),
                       *(("ipv6_cidr_blocks", r.get("CidrIpv6"), r.get("Description")) for r in p.get("Ipv6Ranges") or ()),
                       *(("security_groups", r.get("GroupId"), r.get("Description"))
                         for r in p.get("UserIdGroupPairs") or ()),
                       *(("prefix_list_ids", r.get("PrefixListId"), r.get("Description"))
                         for r in p.get("PrefixListIds") or ())]
            return [{"from_port": p.get("FromPort"), "to_port": p.get("ToPort"), "protocol": p.get("IpProtocol"),
                     "description": desc or "",
                     **{k: [v for kk, v, dd in sources if kk == k and (dd or "") == desc and v]
                        for k in ("cidr_blocks", "ipv6_cidr_blocks", "security_groups", "prefix_list_ids")}}
                    for desc in dict.fromkeys(d or "" for _, _, d in sources)]
        return [] if separate else [b for p in g.get("IpPermissions") or () for b in blocks(p)]
    return [*(("aws_security_group", {"id": g.get("GroupId"), "name": g.get("GroupName"), "vpc_id": g.get("VpcId"),
                                      "tags": tags_of(g.get("Tags")), "ingress": inline(g)})
              for g in items(outs, "SecurityGroups")),
            *(("aws_vpc_security_group_ingress_rule", {
                "security_group_rule_id": r.get("SecurityGroupRuleId"), "security_group_id": r.get("GroupId"),
                "cidr_ipv4": r.get("CidrIpv4"), "cidr_ipv6": r.get("CidrIpv6"),
                "referenced_security_group_id": (r.get("ReferencedGroupInfo") or {}).get("GroupId"),
                "prefix_list_id": r.get("PrefixListId"), "from_port": r.get("FromPort"), "to_port": r.get("ToPort"),
                "ip_protocol": r.get("IpProtocol"), "description": r.get("Description") or "",
                "tags": tags_of(r.get("Tags"))})
              for r in items(outs, "SecurityGroupRules") if not r.get("IsEgress"))]


def _load_balancers(outs):
    tags = {t.get("ResourceArn"): tags_of(t.get("Tags")) for t in items(outs, "TagDescriptions")}
    lbs = items(outs, "LoadBalancers")
    addresses = [(z.get("SubnetId"), a) for lb in lbs for z in lb.get("AvailabilityZones") or ()
                 for a in (z.get("LoadBalancerAddresses") or ())]
    settings = attributes(outs, "lb-attributes")
    return [*(("aws_lb", {"arn": lb.get("LoadBalancerArn"), "name": lb.get("LoadBalancerName"),
                          "internal": lb.get("Scheme") == "internal", "dns_name": _dns(lb.get("DNSName")),
                          "load_balancer_type": lb.get("Type"), "security_groups": lb.get("SecurityGroups") or [],
                          "idle_timeout": settings.get(lb.get("LoadBalancerName"), {}).get("idle_timeout.timeout_seconds"),
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
    groups = items(outs, "TargetGroups")
    by_name = {g.get("TargetGroupName"): g.get("TargetGroupArn") for g in groups}
    health = [(p, stem(p), doc) for p, k, doc in outs if k == "TargetHealthDescriptions"]

    def forwards(action):
        return action.get("TargetGroupArn") or next(
            (t.get("TargetGroupArn") for t in (action.get("ForwardConfig") or {}).get("TargetGroups") or ()), None)
    settings = attributes(outs, "tg-attributes")

    def stickiness(name):
        a = settings.get(name, {})
        return [{"enabled": a.get("stickiness.enabled") == "true", "type": a.get("stickiness.type"),
                 "cookie_duration": a.get("stickiness.lb_cookie.duration_seconds")}] if a else []
    return ([*(("aws_lb_listener", {"load_balancer_arn": ls.get("LoadBalancerArn"), "port": ls.get("Port"),
                                    "protocol": ls.get("Protocol"), "ssl_policy": ls.get("SslPolicy"),
                                    "default_action": [{"type": a.get("Type"), "target_group_arn": forwards(a)}
                                                       for a in ls.get("DefaultActions") or ()]})
               for ls in items(outs, "Listeners")),
             *(("aws_lb_target_group", {
                 "arn": g.get("TargetGroupArn"), "name": g.get("TargetGroupName"), "port": g.get("Port"),
                 "protocol": g.get("Protocol"),
                 "health_check": [{"protocol": g.get("HealthCheckProtocol"), "path": g.get("HealthCheckPath")}],
                 "stickiness": stickiness(g.get("TargetGroupName")),
                 "deregistration_delay": settings.get(g.get("TargetGroupName"), {}).get(
                     "deregistration_delay.timeout_seconds")}) for g in groups),
             *(("aws_lb_target_group_attachment", {"target_group_arn": by_name[name],
                                                   "target_id": (t.get("Target") or {}).get("Id")})
               for _, name, doc in health if name in by_name for t in doc.get("TargetHealthDescriptions") or ())],
            tuple(f"{p}: no target group named {name} is listed (save describe-target-health as "
                  f"target-health/<target group name>.json, with describe-target-groups); not read"
                  for p, name, _ in health if name not in by_name))


def _records(outs):
    """Each zone's record sets (aliases, and the others with their TTLs, values and routing), the zone from the file
    name (route53/<hosted zone ID>.json); a zone's own NS and SOA records are the zone's, not read."""
    return [("aws_route53_record", {"name": _dns(r.get("Name")), "zone_id": stem(p), "type": r.get("Type"),
                                    **record_attributes(r),
                                    "alias": [{"name": _dns(r["AliasTarget"].get("DNSName")),
                                               "zone_id": r["AliasTarget"].get("HostedZoneId")}]
                                    if r.get("AliasTarget") else []})
            for p, k, doc in outs if k == "ResourceRecordSets"
            for r in doc.get("ResourceRecordSets") or () if r.get("Type") not in ("NS", "SOA")]


def _secrets(outs):
    listed = items(outs, "SecretList")
    return [*(("aws_secretsmanager_secret", {"arn": s.get("ARN"), "name": s.get("Name"), "tags": tags_of(s.get("Tags")),
                                             "rotation_enabled": bool(s.get("RotationEnabled")),
                                             "kms_key_id": s.get("KmsKeyId"),
                                             "last_rotated": generalized_time(s.get("LastRotatedDate"))})
              for s in listed),
            *(("aws_secretsmanager_secret_rotation", {"secret_id": s.get("ARN"),
                                                      "rotation_lambda_arn": s.get("RotationLambdaARN")})
              for s in listed if s.get("RotationEnabled"))]


def _keys(outs):
    """Customer managed keys (describe-key, one per file) with their rotation and replicas; (pairs, notices)."""
    metas = [doc["KeyMetadata"] for _, k, doc in outs if k == "KeyMetadata" and isinstance(doc["KeyMetadata"], dict)]
    rotation = {**{stem(p).removeprefix("rotation-"): doc["KeyRotationEnabled"]
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


def _enabled(item):
    return item.get("State", "ENABLED") == "ENABLED"


def _jobs(outs):
    """(pairs, notices): functions, build projects and pipelines, and the enabled rules and schedules that start them."""
    function_tags = {stem(p): doc["Tags"] for p, k, doc in outs if k == "Tags" and isinstance(doc.get("Tags"), dict)}
    rules = items(outs, "Rules")
    schedules = [doc for _, k, doc in outs if k == "ScheduleExpression"]
    off = [r for r in rules if not _enabled(r)] + [s for s in schedules if not _enabled(s)]
    return ([*(("aws_lambda_function", {"arn": f.get("FunctionArn"), "function_name": f.get("FunctionName"),
                                        "runtime": f.get("Runtime"), "tags": function_tags.get(f.get("FunctionName"), {})})
               for f in items(outs, "Functions")),
             *(("aws_cloudwatch_event_rule", {"name": r.get("Name"), "arn": r.get("Arn"),
                                              "schedule_expression": r.get("ScheduleExpression")})
               for r in rules if _enabled(r)),
             *(("aws_cloudwatch_event_target", {"rule": stem(p), "arn": t.get("Arn")})
               for p, k, doc in outs if k == "Targets" for t in doc.get("Targets") or ()),
             *(("aws_scheduler_schedule", {"name": s.get("Name"), "arn": s.get("Arn"),
                                           "schedule_expression": s.get("ScheduleExpression"),
                                           "target": {"arn": (s.get("Target") or {}).get("Arn")}})
               for s in schedules if _enabled(s)),
             *(("aws_codepipeline", {"arn": (doc.get("metadata") or {}).get("pipelineArn"),
                                     "name": (doc.get("pipeline") or {}).get("name")})
               for _, k, doc in outs if k == "pipeline"),
             *(("aws_codebuild_project", {"arn": pr.get("arn"), "name": pr.get("name"),
                                          "environment": {"image": (pr.get("environment") or {}).get("image")},
                                          "tags": {t.get("key"): t.get("value") for t in pr.get("tags") or ()
                                                   if isinstance(t, dict)}})
               for pr in items(outs, "projects"))],
            (f"events/scheduler: {len(off)} disabled rule(s) or schedule(s) not read",) if off else ())


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


def cli_resources(texts, at=None):
    """(resources, notices) of an environment's AWS CLI outputs ({path within the folder: text}); at dates the cloud
    evaluator's verdicts among them (the import's time)."""
    outs, unknown = _outputs(texts)
    iam, iam_notices = iam_pairs(outs, at)
    forwarding, target_notices = _forwarding(outs)
    keys, key_notices = _keys(outs)
    jobs, job_notices = _jobs(outs)
    databases, database_notices = database_pairs(outs)
    pairs, scope_notices = _scoped([*_network(outs), *_instances(outs), *_security_groups(outs),
                                    *_load_balancers(outs), *forwarding, *_records(outs), *_secrets(outs), *keys,
                                    *(("aws_s3_bucket", {"bucket": b.get("Name")}) for b in items(outs, "Buckets")),
                                    *jobs, *iam, *edge_pairs(outs, _dns), *network_pairs(outs), *databases])
    resources, rule_notices = pairs_resources(pairs)
    return resources, (*unknown, *target_notices, *key_notices, *job_notices, *iam_notices, *database_notices,
                       *scope_notices, *rule_notices)


def read_cli_inventory(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the AWS CLI outputs under <cloud>/<env>/."""
    return layout_import(files, d, PROVIDER, "AWS", lambda texts: cli_resources(texts, at), ".json", "AWS CLI output",
                         "vpcs.json", summarize=ACCOUNT_WIDE)


CLI_INVENTORY = Importer("cli-inventory", "AWS CLI outputs (aws … --output json) under <cloud>/<env>/, as the "
                                          "environment's servers and bindings", read_cli_inventory)
