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
    inline aws_security_group ingress            ("... (fw-name)") or by tag Name; the target role is that of the
                                                 instances in the security group, else its tag Role, else the last
                                                 part of its name (ciam-<env>-<role>)
  aws_secretsmanager_secret (+ its rotation)  -> secret reference aws-sm://<arn>, rotation (and, from the CLI, whether
                                                 rotation is off and when it last ran), the role of the customer
                                                 managed key that encrypts it (kms_key_id: ciamEncryptedByRole); its
                                                 value is never read (aws_secretsmanager_secret_version is skipped)
  aws_kms_key (+ aws_kms_replica_key)         -> key reference aws-kms://<arn>, rotation, replica regions
  aws_s3_bucket                               -> storage s3://<bucket>, with its versioning, Object Lock,
                                                 encryption, public access block, lifecycle and replication (storage.py)
  aws_nat_gateway                             -> egress: its public address
  aws_lambda_function, aws_codepipeline,      -> job bindings (what realizes a job: kind job, ciamJobBinding): the
    aws_codebuild_project                        ARN, runtime (a build project's image), and the schedules
  + aws_cloudwatch_event_rule/_target,           EventBridge rules and Scheduler schedules start it on (a Lambda
    aws_scheduler_schedule                       alias or version ARN counts as its function)
  aws_autoscaling_group (+ its               -> compute group (kind compute, ciamComputeGroup): the server role it runs
    aws_launch_template)                         (tag Role), min/desired/max, zones (its subnets' or its own), the
                                                 template's image, instance type and whether the metadata service
                                                 requires tokens (http_tokens required: IMDSv2)
  aws_eks_cluster (+ aws_eks_node_group,     -> cluster (kind cluster, ciamCluster): version, add-ons, node pools
    aws_eks_addon)                               (name: instance types, min-max), zones of its subnets
  aws_sesv2_email_identity,                   -> sending identity (kind sending, ciamSendingIdentity) for a domain: DKIM
    aws_ses_domain_identity (+ the domain's     verified (DKIM signing status SUCCESS), SPF authorizing SES (include:
    Route 53 TXT records)                        amazonses.com) and the DMARC policy, from the domain's TXT records
  aws_sqs_queue, aws_sns_topic,               -> stream carriers (kind stream, ciamStreamBinding): queue, topic, bus,
    aws_cloudwatch_event_bus,                    log stream; an SNS topic an alarm notifies is an alert channel instead
    aws_kinesis_stream
  aws_sns_topic an alarm's actions name       -> alert channel (kind channel, ciamAlertChannel): topic
  aws_cloudwatch_log_group                    -> log destination (kind logs, ciamLogDestination): log group, its
                                                 retention in days (0: never expires)
  aws_cloudwatch_metric_alarm                 -> alarm (kind alarm, ciamAlarmBinding): what it evaluates (namespace and
                                                 metric, or a metric query), the topics it notifies, the alert rule it
                                                 realizes (tag Realizes)
  aws_synthetics_canary                       -> synthetic check (kind canary, ciamCanaryBinding): its rate as an
                                                 interval, the canary it realizes (tag Realizes)
  aws_cloudtrail                              -> audit trail (kind audit, ciamAuditTrail): scope, the activity its
                                                 event selectors record, all regions, integrity validation, where its
                                                 records go (its bucket's or log group's role): see audit.py
  aws_db_instance, aws_rds_cluster (+ its      -> database (kind database, ciamDatabase): engine, edition, version,
    instances, subnet and parameter groups)      endpoint, size, availability, TLS, backups, parameters, its subnets,
                                                 key and master secret as roles; never its password: see databases.py
  IAM: roles, resource policies, permission sets, control policies, access paths: see iam.py
Roles of resources the record doesn't have come from their tags Role (or BindingRole). A compute group's binding role
is its tag BindingRole, else compute-<its tag Role>; a cluster's is its tag BindingRole or Role, else cluster; an
alarm's or synthetic check's, else alarm-<Realizes> or canary-<Realizes>.
"""
import re
from collections import Counter
from functools import reduce

from opsdir.core.contract import Importer
from opsdir.core.inventory import (cluster_role, compute_roles, duration_text, layout_import, of_types, per_file,
                                   realization_roles, resource, tagged_role)
from opsdir.domains.messaging.dns import dmarc_policy, spf_authorizes
from opsdir_format_terraform.state import blocks, read_state
from .network_inventory import endpoint_security_groups, network_resources
from .edge_inventory import (aliased_names, dns_resources, edge_services, lb_facts, lb_security_groups,
                             service_dns)
from .iam import iam_resources
from .databases import database_resources, database_security_groups
from .audit import trail_resources
from .backups import backup_resources
from .volumes import volume_resources
from .storage import object_store_resources
from .tags import state_tags as _tags

PROVIDER = "aws"

SKIPPED = ("aws_secretsmanager_secret_version", "aws_ssm_parameter", "random_password", "tls_private_key",
           "aws_iam_access_key")          # hold secret values, or aren't modeled yet
_RULE_NAME = re.compile(r"\(([A-Za-z0-9._-]+)\)\s*$")


def _role(a):
    return tagged_role(_tags(a))


def _networks(found):
    return tuple(resource("network", a.get("id"), {"ciamCidr": a.get("cidr_block")}, name=_tags(a).get("Name"),
                          role=_role(a) or "network", tags=_tags(a)) for a in of_types(found, "aws_vpc"))


def _subnets(found):
    return tuple(resource("subnet", a.get("id"), {"ciamCidr": a.get("cidr_block"), "ciamZone": a.get("availability_zone")},
                          name=_tags(a).get("Name"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, "aws_subnet"))


def _servers(found):
    return tuple(resource("server", a.get("id"),
                          {"ciamPrivateIp": a.get("private_ip"), "ciamZone": a.get("availability_zone"),
                           "ciamInstanceSize": a.get("instance_type"), "ciamImageRef": a.get("ami"),
                           "ciamHostname": _tags(a).get("Hostname") or a.get("private_dns"),
                           "ciamProductVersion": _tags(a).get("Product")},
                          links={"ciamSubnet": a.get("subnet_id")}, name=_tags(a).get("Name") or a.get("id"),
                          role=_tags(a).get("Role"), tags=_tags(a))
                 for a in of_types(found, "aws_instance"))


def _services(found):
    """A service per load balancer: its DNS name (the Route 53 alias, or its tag Service), ports, targets' role."""
    instances = {a.get("id"): _tags(a).get("Role") for a in of_types(found, "aws_instance")}
    eips = {a.get("allocation_id") or a.get("id"): a.get("public_ip") for a in of_types(found, "aws_eip")}
    groups = {a.get("arn"): a for a in of_types(found, "aws_lb_target_group")}
    records = of_types(found, "aws_route53_record")

    def one_lb(lb):
        names = aliased_names(found, lb)
        alias = next((r for r in records for al in r.get("alias") or () if al.get("name") in names), None)
        listeners = [ls for ls in of_types(found, "aws_lb_listener") if ls.get("load_balancer_arn") == lb.get("arn")]
        forwarded = {act.get("target_group_arn") for ls in listeners for act in ls.get("default_action") or ()}
        facts, settings = lb_facts(lb, listeners, [groups[g] for g in sorted(forwarded) if g in groups])
        roles = Counter(instances.get(att.get("target_id")) for att in of_types(found, "aws_lb_target_group_attachment")
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
            "ciamFrontendIp": private if lb.get("internal") else eips.get(allocation) or next(
                (m.get("public_ip") for m in mappings if m.get("public_ip")), None),
            "ciamProviderRef": None if lb.get("internal") else allocation,
            "ciamEdgeFact": facts, "ciamEdgeSetting": settings, **(service_dns(alias) if alias else {})},
            name=lb.get("name"), role=_role(lb), tags=_tags(lb))
    return tuple(one_lb(lb) for lb in of_types(found, "aws_lb", "aws_alb"))


def _served(found):
    """The Route 53 records that are the environment's service names (aliases of its load balancers or of their
    CloudFront distributions), by identity."""
    names = {n for lb in of_types(found, "aws_lb", "aws_alb") for n in aliased_names(found, lb)}
    return {id(r) for r in of_types(found, "aws_route53_record") for al in r.get("alias") or ()
            if al.get("name") in names}


def _target_role(sg, members):
    """The role a security group guards: its instances' (tag Role), its own tag Role, or its name's last part."""
    roles = Counter(members.get(sg.get("id")) or ())
    return (roles.most_common(1)[0][0] if roles else None) or _role(sg) or \
        (sg.get("name") or "").rsplit("-", 1)[-1] or None


def _port(rule):
    """(the rule's single port or None, why not when it isn't one): a range and all ports aren't single ports."""
    low, high, proto = rule.get("from_port"), rule.get("to_port"), str(rule.get("protocol") or "")
    if proto == "-1" or low in (None, -1, "-1") or str(low) == "0" and str(high) in ("0", "65535", "None"):
        return None, "all ports"
    if high not in (None, "") and str(high) != str(low):
        return None, f"port range {low}-{high}"
    return str(low), None


def _other_sources(rule, claimed=frozenset()):
    """The rule's sources that aren't IPv4 ranges: IPv6 ranges, security groups (a load balancer's is the load
    balancer's own path to its servers, not named), prefix lists."""
    return (*(f"IPv6 range {c}" for c in (rule.get("ipv6_cidr_blocks") or ()) or
              ((rule.get("cidr_ipv6"),) if rule.get("cidr_ipv6") else ())),
            *(f"security group {g}" for g in (rule.get("security_groups") or ()) or
              ((rule.get("referenced_security_group_id"),) if rule.get("referenced_security_group_id") else ())
              if g not in claimed),
            *(f"prefix list {p}" for p in (rule.get("prefix_list_ids") or ()) or
              ((rule.get("prefix_list_id"),) if rule.get("prefix_list_id") else ())),
            *(("its own security group",) if rule.get("self") is True else ()))


# what claims a security group, so its rules are its claimant's (a load balancer's, a VPC endpoint's, a database's),
# not the record's firewall rules: each a function of the pairs -> the ids of the groups it claims
CLAIMS = (lb_security_groups, endpoint_security_groups, database_security_groups)


def _claimed(found):
    return frozenset().union(*(claim(found) for claim in CLAIMS))


def _firewall(found, claimed=frozenset()):
    """(firewall rules, notices): ingress rules of the security groups other readers don't claim, grouped into the
    record's rules by name. The record holds IPv4 sources and single ports: ranges, all-ports rules and other sources
    are named, not recorded."""
    groups = {a.get("id"): a for a in of_types(found, "aws_security_group") if a.get("id") not in claimed}
    members = reduce(lambda acc, i: {**acc, **{g: (*acc.get(g, ()), _tags(i)["Role"])
                                                for g in i.get("vpc_security_group_ids") or ()}},
                     (i for i in of_types(found, "aws_instance") if _tags(i).get("Role")), {})
    separate = [(groups.get(r.get("security_group_id")) or {}, (r.get("cidr_ipv4"),),
                 {**r, "protocol": r.get("ip_protocol")}, _tags(r).get("Name"), _role(r),
                 r.get("security_group_rule_id") or r.get("id"))
                for r in of_types(found, "aws_vpc_security_group_ingress_rule")
                if r.get("security_group_id") not in claimed]
    inline = [(sg, tuple(rule.get("cidr_blocks") or ()), rule, None, None, f"{sg.get('id')}#{i}")
              for sg in groups.values() for i, rule in enumerate(sg.get("ingress") or ())]
    rules = [(_name_of(rule.get("description") or "", tag, ref), sg, tuple(c for c in cidrs if c), rule, role)
             for sg, cidrs, rule, tag, role, ref in (*separate, *inline)]
    named = [(n, sg, cidr, _port(rule)[0], str(rule.get("protocol") or ""), role)
             for n, sg, cidrs, rule, role in rules for cidr in cidrs]
    names = list(dict.fromkeys(n for n, *_ in named))
    # a separate rule is a resource with its own tags; an inline rule is part of its group (judged as no resource)
    tagged = {_name_of(rule.get("description") or "", tag, ref): _tags(rule)
              for _, _, rule, tag, _, ref in separate}
    notices = (*(f"security group rule {n}: {why}, not a single port; not recorded" for n, why in
                 dict.fromkeys((n, _port(rule)[1]) for n, _, cidrs, rule, _ in rules if cidrs and _port(rule)[1])),
               *(f"security group rule {n}: source {s} is not an IPv4 address range; not recorded"
                 for n, _, _, rule, _ in rules for s in _other_sources(rule, claimed)))
    return tuple(resource("firewall", name, {
                     "ciamSourceCidr": sorted({cidr for n, _, cidr, *_ in named if n == name and cidr}),
                     "ciamPort": sorted({port for n, _, _, port, *_ in named if n == name and port}, key=int),
                     "ciamProtocol": next((p for n, *_, p, _ in named if n == name and p in ("tcp", "udp")), None),
                     "ciamTargetRole": next((_target_role(sg, members) for n, sg, *_ in named if n == name and sg),
                                            None)},
                          name=name, role=next((r for n, *_, r in named if n == name and r), None),
                          tags=tagged.get(name))
                 for name in names), notices


def _name_of(description, tag, ref):
    m = _RULE_NAME.search(description)
    return tag or (m.group(1) if m else ref)


def _secrets(found):
    rotation = {a.get("secret_id"): a for a in of_types(found, "aws_secretsmanager_secret_rotation")}
    keys = {k: a.get("arn") for a in of_types(found, "aws_kms_key") for k in (a.get("key_id"), a.get("arn")) if k}
    return tuple(resource("secret", a.get("arn"), {
                     "ciamRefUri": f"aws-sm://{a.get('arn')}",
                     "ciamAutoRotate": "TRUE" if a.get("arn") in rotation or a.get("id") in rotation else
                     "FALSE" if a.get("rotation_enabled") is False else None,
                     "ciamLastRotated": a.get("last_rotated"),
                     "ciamRotationFunction": (rotation.get(a.get("arn")) or rotation.get(a.get("id")) or {})
                     .get("rotation_lambda_arn")},
                          links={"ciamEncryptedByRole": keys.get(a.get("kms_key_id"))},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, "aws_secretsmanager_secret") if a.get("arn"))


def _keys(found):
    replicas = [a for a in of_types(found, "aws_kms_replica_key")]
    return tuple(resource("key", a.get("arn"), {
                     "ciamRefUri": f"aws-kms://{a.get('arn')}",
                     "ciamAutoRotate": {True: "TRUE", False: "FALSE"}.get(a.get("enable_key_rotation")),
                     "ciamReplicaRegion": sorted({r.get("arn", "").split(":")[3] for r in replicas
                                                  if r.get("primary_key_arn") == a.get("arn") and r.get("arn")})},
                          name=_tags(a).get("Name") or a.get("key_id"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, "aws_kms_key") if a.get("arn"))


def _egress(found):
    """NAT gateways: a public one's Elastic IP is a fixed address (static allocation); a private one has none."""
    return tuple(resource("egress", a.get("id"), {
                              "ciamCidr": f"{a.get('public_ip')}/32" if a.get("public_ip") else None,
                              "ciamNatAllocation": "static" if a.get("public_ip") else None},
                          name=_tags(a).get("Name") or a.get("id"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, "aws_nat_gateway") if a.get("id"))


def base_arn(arn):
    """A Lambda function's ARN without its version or alias qualifier; any other ARN as it is."""
    parts = (arn or "").split(":")
    return ":".join(parts[:7]) if len(parts) > 7 and parts[2] == "lambda" and parts[5] == "function" else arn


def _jobs(found):
    """Functions, pipelines and build projects, each with the schedules EventBridge rules and Scheduler run it on."""
    rules = {a.get("name"): a.get("schedule_expression") for a in of_types(found, "aws_cloudwatch_event_rule")}
    started = [*((base_arn(t.get("arn")), rules.get(t.get("rule"))) for t in of_types(found, "aws_cloudwatch_event_target")),
               *((base_arn(b.get("arn")), a.get("schedule_expression")) for a in of_types(found, "aws_scheduler_schedule")
                 for b in blocks(a.get("target")))]

    def schedules(arn):
        return sorted({when for target, when in started if target == arn and when})

    def image(a):
        return next((b.get("image") for b in blocks(a.get("environment")) if b.get("image")), None)
    return (*(resource("job", a.get("arn"), {"ciamRuntime": a.get("runtime"), "ciamSchedule": schedules(a.get("arn"))},
                       name=a.get("function_name"), role=_role(a),
                       tags=_tags(a)) for a in of_types(found, "aws_lambda_function")
              if a.get("arn")),
            *(resource("job", a.get("arn"), {"ciamSchedule": schedules(a.get("arn"))}, name=a.get("name"),
                       role=_role(a), tags=_tags(a)) for a in of_types(found, "aws_codepipeline") if a.get("arn")),
            *(resource("job", a.get("arn"), {"ciamRuntime": image(a), "ciamSchedule": schedules(a.get("arn"))},
                       name=a.get("name"), role=_role(a),
                       tags=_tags(a)) for a in of_types(found, "aws_codebuild_project") if a.get("arn")))


def _asg_tags(a):
    """An autoscaling group's tags: its tag blocks (key, value) and any tags map."""
    return {**{t.get("key"): t.get("value") for t in blocks(a.get("tag")) if t.get("key")}, **_tags(a)}


def _template_of(a, templates):
    ref = next((t for t in (*blocks(a.get("launch_template")),
                            *(lt for p in blocks(a.get("mixed_instances_policy"))
                              for spec in blocks(p.get("launch_template"))
                              for lt in blocks(spec.get("launch_template_specification")))) if t), {})
    return templates.get(ref.get("id")) or templates.get(ref.get("name")) or \
        templates.get(ref.get("launch_template_id")) or templates.get(ref.get("launch_template_name")) or {}


def _tokens(template):
    tokens = next((m.get("http_tokens") for m in blocks(template.get("metadata_options")) if m.get("http_tokens")),
                  None)
    return {"required": "TRUE", "optional": "FALSE"}.get(tokens)


def _zones_of(subnet_ids, zones_by_subnet):
    return sorted({zones_by_subnet[s] for s in subnet_ids or () if zones_by_subnet.get(s)})


def _compute(found):
    """Autoscaling groups as compute groups, with what their launch template says."""
    templates = {k: t for t in of_types(found, "aws_launch_template") for k in (t.get("id"), t.get("name")) if k}
    zones = {s.get("id"): s.get("availability_zone") for s in of_types(found, "aws_subnet")}

    def group(a):
        template = _template_of(a, templates)
        binding, target = compute_roles(_asg_tags(a))
        return resource("compute", a.get("arn") or a.get("name"), {
            "ciamTargetRole": target, "ciamImageRef": template.get("image_id"),
            "ciamInstanceSize": template.get("instance_type"), "ciamMinSize": a.get("min_size"),
            "ciamMaxSize": a.get("max_size"), "ciamDesiredSize": a.get("desired_capacity"),
            "ciamSpansZone": _zones_of(a.get("vpc_zone_identifier"), zones)
            or sorted(a.get("availability_zones") or ()),
            "ciamMetadataTokens": _tokens(template)}, name=a.get("name"), role=binding, tags=_asg_tags(a))
    return tuple(group(a) for a in of_types(found, "aws_autoscaling_group") if a.get("arn") or a.get("name"))


def _clusters(found):
    """EKS clusters, their node groups and add-ons."""
    zones = {s.get("id"): s.get("availability_zone") for s in of_types(found, "aws_subnet")}

    def pool(n):
        scale = next(iter(blocks(n.get("scaling_config"))), {})
        return (f"{n.get('node_group_name')}: {', '.join(n.get('instance_types') or ()) or '?'}, "
                f"{scale.get('min_size', '?')}-{scale.get('max_size', '?')}")

    def cluster(c):
        name = c.get("name")
        subnets = [s for v in blocks(c.get("vpc_config")) for s in v.get("subnet_ids") or ()]
        return resource("cluster", c.get("arn") or name, {
            "ciamClusterVersion": c.get("version"),
            "ciamClusterAddon": sorted(f"{a.get('addon_name')} {a.get('addon_version') or ''}".strip()
                                       for a in of_types(found, "aws_eks_addon") if a.get("cluster_name") == name),
            "ciamNodePool": sorted(pool(n) for n in of_types(found, "aws_eks_node_group")
                                   if n.get("cluster_name") == name),
            "ciamSpansZone": _zones_of(subnets, zones)}, name=name, role=cluster_role(_tags(c)), tags=_tags(c))
    return tuple(cluster(c) for c in of_types(found, "aws_eks_cluster") if c.get("arn") or c.get("name"))


SES_SPF = "amazonses.com"          # the SPF include that authorizes Amazon SES
STREAM_TYPES = (("aws_sqs_queue", "queue"), ("aws_sns_topic", "topic"), ("aws_cloudwatch_event_bus", "bus"),
                ("aws_kinesis_stream", "log-stream"))


def _txt(found, name):
    """The TXT values Route 53 holds for a name (with or without its trailing dot)."""
    wanted = name.lower().rstrip(".")
    return tuple(v for r in of_types(found, "aws_route53_record") if str(r.get("type")).upper() == "TXT"
                 and (r.get("name") or "").lower().rstrip(".") == wanted for v in r.get("records") or ())


def _dkim(identity, found, domain):
    status = next((b.get("status") for b in blocks(identity.get("dkim_signing_attributes")) if b.get("status")), None)
    if status:
        return "TRUE" if str(status).upper() == "SUCCESS" else "FALSE"
    return "TRUE" if any((a.get("domain") or "").lower() == domain for a in of_types(found, "aws_ses_domain_dkim")) \
        else None


def _sending(found):
    """SES domain identities as sending identities, with what the domain's DNS says of SPF and DMARC."""
    def identity(a):
        domain = (a.get("email_identity") or a.get("domain") or "").lower()
        return resource("sending", a.get("arn") or domain, {
            "ciamSenderDomain": domain, "ciamDkimVerified": _dkim(a, found, domain),
            "ciamSpfAuthorized": spf_authorizes(_txt(found, domain), SES_SPF),
            "ciamDmarcPolicy": dmarc_policy(_txt(found, f"_dmarc.{domain}"))}, name=f"ses-{domain}", role=_role(a),
                        tags=_tags(a) if a.get("email_identity") else None)   # SES v1 identities take no tags
    return tuple(identity(a) for a in of_types(found, "aws_sesv2_email_identity", "aws_ses_domain_identity")
                 if "@" not in (a.get("email_identity") or a.get("domain") or "@"))


ALARM_ACTIONS = ("alarm_actions", "ok_actions", "insufficient_data_actions")
_RATE = re.compile(r"^rate\((\d+) (minute|minutes|hour|hours|day|days)\)$")
_UNIT_SECONDS = {"minute": 60, "hour": 3600, "day": 86400}


def _notified(found):
    """The ARNs every alarm's actions name (alert channels: topics alarms notify)."""
    return frozenset(arn for a in of_types(found, "aws_cloudwatch_metric_alarm") for k in ALARM_ACTIONS
                     for arn in a.get(k) or ())


def _channels(found):
    """SNS topics an alarm notifies, as alert channels."""
    notified = _notified(found)
    return tuple(resource("channel", a.get("arn"), {"ciamChannelKind": "topic"}, name=a.get("name"), role=_role(a),
                          tags=_tags(a))
                 for a in of_types(found, "aws_sns_topic") if a.get("arn") in notified)


def _log_destinations(found):
    """CloudWatch log groups, with their retention (0: never expires)."""
    return tuple(resource("logs", a.get("arn"), {"ciamDestinationKind": "log-group",
                                                 "ciamRetentionDays": a.get("retention_in_days")},
                          name=a.get("name"), role=_role(a), tags=_tags(a))
                 for a in of_types(found, "aws_cloudwatch_log_group") if a.get("arn"))


def _metric(a):
    named = " ".join(p for p in (a.get("namespace"), a.get("metric_name")) if p)
    return named or ("metric query" if a.get("metric_query") else None)


def _alarms(found):
    """CloudWatch metric alarms: what each evaluates, what it notifies, the alert rule it realizes."""
    def alarm(a):
        role, realizes = realization_roles(_tags(a), "alarm")
        notifies = sorted({x for k in ALARM_ACTIONS for x in a.get(k) or ()})
        return resource("alarm", a.get("arn"), {"ciamMetric": _metric(a), "ciamRealizes": realizes,
                                                "ciamNotifies": notifies}, name=a.get("alarm_name"), role=role,
                        tags=_tags(a))
    return tuple(alarm(a) for a in of_types(found, "aws_cloudwatch_metric_alarm") if a.get("arn"))


def _interval(schedule):
    m = _RATE.match(((schedule or [{}])[0] or {}).get("expression") or "")
    return duration_text(int(m.group(1)) * _UNIT_SECONDS[m.group(2).rstrip("s")]) if m else None


def _canaries(found):
    """CloudWatch Synthetics canaries: how often each runs, the canary it realizes."""
    def canary(a):
        role, realizes = realization_roles(_tags(a), "canary")
        return resource("canary", a.get("arn"), {"ciamInterval": _interval(a.get("schedule")),
                                                 "ciamRealizes": realizes}, name=a.get("name"), role=role,
                        tags=_tags(a))
    return tuple(canary(a) for a in of_types(found, "aws_synthetics_canary") if a.get("arn"))


def _streams(found):
    """Queues, topics, event buses and data streams as stream carriers (the default event bus, and topics an alarm
    notifies, left out)."""
    notified = _notified(found)
    return tuple(resource("stream", a.get("arn"), {"ciamStreamKind": kind}, name=a.get("name"), role=_role(a),
                          tags=_tags(a))
                 for t, kind in STREAM_TYPES for a in of_types(found, t)
                 if a.get("arn") and not (t == "aws_cloudwatch_event_bus" and a.get("name") == "default")
                 and not (t == "aws_sns_topic" and a.get("arn") in notified))


def pairs_resources(pairs):
    """(resources, notices) of (Terraform resource type, attributes) pairs: what every AWS source is read into
    (Terraform state as it is; CLI output and CloudFormation normalized to the same attribute names)."""
    rules, rule_notices = _firewall(pairs, _claimed(pairs))
    iam, iam_notices = iam_resources(pairs)
    zones, records, forwarders, dns_notices = dns_resources(pairs, _served(pairs))
    network, network_notices = network_resources(pairs)
    volumes, volume_notices = volume_resources(pairs)
    backups, backup_notices = backup_resources(pairs)
    return ((*_networks(pairs), *_subnets(pairs), *_servers(pairs), *_services(pairs), *rules, *_secrets(pairs),
             *_keys(pairs), *object_store_resources(pairs), *_egress(pairs), *_jobs(pairs), *_compute(pairs), *_clusters(pairs),
             *_sending(pairs), *_streams(pairs), *_channels(pairs), *_log_destinations(pairs), *_alarms(pairs),
             *_canaries(pairs), *iam, *edge_services(pairs), *zones, *records, *forwarders, *network,
             *database_resources(pairs), *volumes, *backups, *trail_resources(pairs)),
            (*rule_notices, *iam_notices, *dns_notices, *network_notices, *volume_notices, *backup_notices))


def state_resources(text):
    """(resources, notices) of an AWS Terraform state."""
    found, problem = read_state(text)
    if problem:
        return (), (problem,)
    pairs = [(r.type, r.attributes) for r in found]
    skipped = Counter(t for t, _ in pairs if t in SKIPPED)
    resources, notices = pairs_resources(pairs)
    return (resources, (*notices, *(f"{t} ({n}): not read (holds secret values, or isn't modeled yet)"
                                    for t, n in sorted(skipped.items()))))


# ------------------------------------------------------------------ the importer
def read_terraform_state(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the AWS Terraform states under <cloud>/<env>/."""
    return layout_import(files, d, PROVIDER, "AWS", per_file(state_resources), ".tfstate", "Terraform state",
                         "terraform.tfstate", summarize=("identity",))   # groups, users, service agents: counted


TERRAFORM_STATE = Importer("terraform-state", "AWS Terraform state (terraform.tfstate) under <cloud>/<env>/, as the "
                                              "environment's servers and bindings", read_terraform_state)
