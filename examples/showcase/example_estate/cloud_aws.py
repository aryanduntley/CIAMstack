"""What AWS reports the source environment runs (pure: builds text), from the same fixture data as the record, with
the drift planted here (`opsdir import --dry-run` shows it). The public names are on the corporate DNS team's Infoblox,
so Route 53 holds the private ones only (the load balancers' Service tags name them); the gateway load balancer sticks
by source address; the AD domain is forwarded by a Resolver rule.

  source/prod, AWS Terraform state (terraform.tfstate):
    - pf-engine-2 resized in the console (m6i.large -> m6i.xlarge)
    - an untagged bastion instance nobody recorded
    - a hand-opened security group rule, "temporary vendor access", 10.99.0.0/16 to LDAPS
    - the disk key's automatic rotation switched off
    - a CloudWatch alarm someone added in the console (ds-cpu-high), untagged: named, not recorded
    - PingFederate's role given secretsmanager:ListSecrets on everything in the console
  Its CloudTrail trail and the Object Lock bucket keeping its log files, as the record has them (read back unchanged).
  Its network depth as the stack's own Terraform made it: the Secrets Manager endpoint, the LDAPS endpoint service and
  the egress firewall's domain list.
  source/prod, the landing zone's Terraform state (landing-zone.tfstate): the pipeline's OIDC role, the admins'
    permission set, the break-glass role, whose AWS managed policy (AdministratorAccess) a state doesn't hold: named
"""
import json

from opsdir.core.jsondata import indented
from opsdir.domains.data.storage import parse_lifecycle
from opsdir.domains.network.stack import sites_by_port

from .access import ACCT, AWS_IDENTITIES
from .cloud_common import by_role, hex_id, listed, rows_of, servers_of, service_named
from .infrastructure import SECRET_ROLES, SOURCE
from .observability import MONITORING
from .estate import CONFIG_BUCKET, SECURITY

ACCOUNT, REGION = "111122223333", "us-east-1"


# ------------------------------------------------------------------ source/prod: AWS Terraform state
def _res(mode, type_, name, attrs):
    return {"mode": mode, "type": type_, "name": name.replace("-", "_"),
            "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [{"schema_version": 1, "attributes": attrs, "sensitive_attributes": []}]}


def _source_ids(p):
    subnets = {cn: ref for cn, _, ref, _, _ in p["subnets"]}
    instances = {cn: f"i-0{hex_id('instance', cn, n=16)}" for cn, *_ in p["servers"]}
    roles = (*(s[1] for s in p["servers"]), *(role for _, _, role, _ in p["databases"]))
    groups = {role: f"sg-0{hex_id('group', role, n=16)}" for role in dict.fromkeys(roles)}
    return subnets, instances, groups


def _aws_network(p, subnets):
    return [_res("data", "aws_vpc", "main", {"id": p["net"][1], "cidr_block": p["net"][2]}),
            *(_res("data", "aws_subnet", cn, {"id": ref, "cidr_block": cidr, "availability_zone": zone,
                                              "vpc_id": p["net"][1]})
              for cn, _, ref, cidr, zone in p["subnets"]),
            _res("data", "aws_nat_gateway", "pf_egress", {"id": p["egress"][0], "public_ip": p["egress"][1][:-3]})]


def _aws_servers(p, subnets, instances, groups, resized):
    return [_res("managed", "aws_instance", cn, {
                "id": instances[cn], "ami": image, "instance_type": resized.get(cn, size), "private_ip": ip,
                "availability_zone": zone, "subnet_id": subnets[subnet], "vpc_security_group_ids": [groups[role]],
                "tags": {"Name": cn, "Role": role, "Hostname": host, "Product": version, "ManagedBy": "opsdir"}})
            for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]]


def _aws_firewall(p, groups):
    """The security groups (a database's carries its role and name: no instance says what it guards) and the rules."""
    databases = {role: cn for _, cn, role, _ in p["databases"]}
    return [*(_res("managed", "aws_security_group", role, {
                "id": gid, "name": f"ciam-prod-{role}", "vpc_id": p["net"][1], "ingress": [],
                **({"tags": {"Name": databases[role], "Role": role, "ManagedBy": "opsdir"}}
                   if role in databases else {})})
              for role, gid in groups.items()),
            *(_res("managed", "aws_vpc_security_group_ingress_rule", f"{cn}_{i}_{port}", {
                "security_group_rule_id": f"sgr-0{hex_id(cn, cidr, port, n=16)}",
                "security_group_id": groups[trole], "cidr_ipv4": cidr, "from_port": port, "to_port": port,
                "ip_protocol": "tcp", "description": f"{consumer or role} ({cn})"})
              for cn, role, cidrs, ports, trole, consumer, _ in p["fw"] for i, cidr in enumerate(cidrs) for port in ports)]


def _lb_arn(cn):
    return f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/net/ciam-prod-{cn}/{hex_id(cn, n=16)}"


def _aws_service(p, instances, cn, fqdn, zref, trole, ports, ip, pref):
    """A network load balancer, its Elastic IP (public) or private address, alias record, listeners and targets."""
    arn = _lb_arn(cn)
    dns = f"ciam-prod-{cn}-{hex_id(cn, n=8)}.elb.{REGION}.amazonaws.com"
    internal = pref is None
    targets = [s[0] for s in p["servers"] if s[1] == trole]

    def group(port):
        return f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/ciam-prod-{cn}-{port}/{hex_id(cn, port, n=16)}"
    sticky = "stickiness source-ip" in (p.get("service_attrs") or {}).get(cn, {}).get("ciamEdgeFact", ())
    return [_res("managed", "aws_lb", cn, {"arn": arn, "name": f"ciam-prod-{cn}", "internal": internal,
                                           "load_balancer_type": "network", "dns_name": dns,
                                           "tags": {"Service": fqdn, "ManagedBy": "opsdir"}, "subnet_mapping": [
                                               {"private_ipv4_address": ip} if internal else {"allocation_id": pref}]}),
            *(() if internal else (_res("data", "aws_eip", cn, {"allocation_id": pref, "public_ip": ip}),)),
            # the public names are on the corporate DNS team's Infoblox: Route 53 holds the private one only
            *((_res("managed", "aws_route53_record", cn, {"name": fqdn, "zone_id": zref, "type": "A",
                                                          "alias": [{"name": dns, "zone_id": "Z26RNL4JYFTOTI"}]}),)
              if internal else ()),
            *(r for port in ports for r in (
                _res("managed", "aws_lb_target_group", f"{cn}_{port}", {
                    "arn": group(port), "port": port,
                    **({"stickiness": [{"type": "source_ip", "enabled": True}]} if sticky else {})}),
                _res("managed", "aws_lb_listener", f"{cn}_{port}", {
                    "load_balancer_arn": arn, "port": port,
                    "default_action": [{"type": "forward", "target_group_arn": group(port)}]}),
                *(_res("managed", "aws_lb_target_group_attachment", f"{cn}_{port}_{t}",
                       {"target_group_arn": group(port), "target_id": instances[t]}) for t in targets)))]


def _aws_services(p, instances):
    return [r for cn, _, fqdn, _, zref, trole, ports, ip, pref, _ in p["services"]
            for r in _aws_service(p, instances, cn, fqdn, zref, trole, ports, ip, pref)]


def _aws_keys(p, rotation):
    secret = p["secret"]
    rotated = {role: facts for role, facts in p["key_facts"].items() if facts.get("ciamRotationFunction")}
    key_arn = p["key"][0].split("://", 1)[1]
    return [*(_res("data", "aws_secretsmanager_secret", role, {"arn": secret(role).split("://", 1)[1],
                                                               "name": f"ciam/prod/{role}"})
              for role in SECRET_ROLES),
            *(_res("managed", "aws_secretsmanager_secret_rotation", role, {
                "secret_id": secret(role).split("://", 1)[1], "rotation_lambda_arn": facts["ciamRotationFunction"]})
              for role, facts in rotated.items()),
            _res("managed", "aws_kms_key", "disk", {"arn": key_arn, "key_id": key_arn.rsplit("/", 1)[1],
                                                    "enable_key_rotation": rotation}),
            *(_res("managed", "aws_kms_replica_key", f"disk_{r}", {"arn": key_arn.replace(REGION, r),
                                                                   "primary_key_arn": key_arn})
              for r in (p["key_facts"]["disk-encryption"].get("ciamReplicaRegion"),) if r),
            *_aws_backup(p),
            *(_res("data", "aws_s3_bucket", "pf_cluster", {"bucket": bucket, "arn": f"arn:aws:s3:::{bucket}"})
              for bucket in (p["discovery"][len("s3://"):].split("/", 1)[0],) if p.get("discovery"))]


_TIERS = {"cool": "STANDARD_IA", "cold": "GLACIER_IR", "archive": "DEEP_ARCHIVE"}


def _aws_backup(p):
    """The backup bucket as the stack's Terraform made it: the bucket and each of its settings."""
    bucket, a = p["backup"][len("s3://"):], p["backup_depth"]
    tags = {"Name": "backup", "Role": "backup-target", "ManagedBy": "opsdir"}
    rules = [parse_lifecycle(v) for v in a["ciamStorageLifecycle"]]
    rule = {"id": "ciam", "status": "Enabled",
            **{f"{'noncurrent_version_' if nc else ''}transition": [
                {"noncurrent_days" if nc else "days": d, "storage_class": _TIERS[act]}
                for n, d, act in rules if n == nc and act in _TIERS] for nc in (False, True)},
            **{f"{'noncurrent_version_' if nc else ''}expiration": [
                {"noncurrent_days" if nc else "days": d} for n, d, act in rules if n == nc and act == "delete"]
               for nc in (False, True)}}
    return [_res("managed", "aws_s3_bucket", "backup", {"bucket": bucket, "arn": a["ciamProviderRef"],
                                                        "object_lock_enabled": True, "tags": tags}),
            _res("managed", "aws_s3_bucket_versioning", "backup", {
                "bucket": bucket, "versioning_configuration": [{"status": "Enabled"}]}),
            _res("managed", "aws_s3_bucket_object_lock_configuration", "backup", {"bucket": bucket, "rule": [
                {"default_retention": [{"mode": a["ciamStorageImmutability"].upper(),
                                        "days": int(a["ciamStorageLockDays"]), "years": None}]}]}),
            _res("managed", "aws_s3_bucket_server_side_encryption_configuration", "backup", {"bucket": bucket, "rule": [
                {"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms",
                                                              "kms_master_key_id": p["key"][0].split("://", 1)[1]}],
                 "bucket_key_enabled": True}]}),
            _res("managed", "aws_s3_bucket_public_access_block", "backup", {
                "bucket": bucket, "block_public_acls": True, "block_public_policy": True, "ignore_public_acls": True,
                "restrict_public_buckets": True}),
            _res("managed", "aws_s3_bucket_lifecycle_configuration", "backup", {"bucket": bucket, "rule": [rule]}),
            _res("managed", "aws_s3_bucket_replication_configuration", "backup", {
                "bucket": bucket, "role": f"arn:aws:iam::{ACCOUNT}:role/ciam-prod-backup-replication",
                "rule": [{"id": "ciam", "status": "Enabled", "destination": [
                    {"bucket": f"arn:aws:s3:::{a['ciamStorageReplicaRef'][len('s3://'):]}"}]}]})]


def _aws_monitoring():
    """CloudWatch as the source runs it: the alert topic, the log groups, the alarms and the canary the record holds
    (each tagged with its role or the rule it realizes), and one alarm nobody tagged (named in the dry run)."""
    by_class = {oc: [(cn, role, attrs) for c, cn, role, attrs in MONITORING["source"] if c == oc]
                for oc in ("ciamAlertChannel", "ciamLogDestination", "ciamAlarmBinding", "ciamCanaryBinding")}
    return [*(_res("managed", "aws_sns_topic", cn, {"arn": a["ciamProviderRef"], "name": f"ciam-prod-{cn}",
                                                    "tags": {"Role": role}})
              for cn, role, a in by_class["ciamAlertChannel"]),
            *(_res("managed", "aws_cloudwatch_log_group", cn, {
                "arn": a["ciamProviderRef"], "name": a["ciamProviderRef"].split("log-group:", 1)[1],
                "retention_in_days": a["ciamRetentionDays"], "tags": {"Role": role}})
              for cn, role, a in by_class["ciamLogDestination"]),
            *(_res("managed", "aws_cloudwatch_metric_alarm", cn, {
                "arn": a["ciamProviderRef"], "alarm_name": cn, "namespace": a["ciamMetric"].split(" ")[0],
                "metric_name": a["ciamMetric"].split(" ")[1], "alarm_actions": [a["ciamNotifies"]],
                "tags": {"Realizes": a["ciamRealizes"]}})
              for cn, _, a in by_class["ciamAlarmBinding"]),
            *(_res("managed", "aws_synthetics_canary", cn, {
                "arn": a["ciamProviderRef"], "name": f"ciam-{cn}", "schedule": [{"expression": "rate(5 minutes)"}],
                "tags": {"Realizes": a["ciamRealizes"]}})
              for cn, _, a in by_class["ciamCanaryBinding"]),
            _res("managed", "aws_cloudwatch_metric_alarm", "ds-cpu-high", {      # someone added it in the console
                "arn": "arn:aws:cloudwatch:us-east-1:111122223333:alarm:ds-cpu-high", "alarm_name": "ds-cpu-high",
                "namespace": "AWS/EC2", "metric_name": "CPUUtilization"})]


def _aws_audit():
    """The source's CloudTrail trail (management events, and S3 data writes to the backup bucket) and the bucket under
    Object Lock that keeps its log files."""
    (_, cn, role, store), = [x for x in MONITORING["source"] if x[0] == "ciamObjectStore"]
    (_, _, trail_role, trail), = [x for x in MONITORING["source"] if x[0] == "ciamAuditTrail"]
    bucket = store["ciamStorageRef"][len("s3://"):]
    return [_res("managed", "aws_s3_bucket", cn, {"bucket": bucket, "arn": store["ciamProviderRef"],
                                                  "object_lock_enabled": True,
                                                  "tags": {"Name": cn, "Role": role, "ManagedBy": "opsdir"}}),
            _res("managed", "aws_s3_bucket_versioning", cn, {
                "bucket": bucket, "versioning_configuration": [{"status": "Enabled"}]}),
            _res("managed", "aws_s3_bucket_object_lock_configuration", cn, {"bucket": bucket, "rule": [
                {"default_retention": [{"mode": store["ciamStorageImmutability"].upper(),
                                        "days": int(store["ciamStorageLockDays"]), "years": None}]}]}),
            _res("managed", "aws_cloudtrail", "ciam_prod", {
                "arn": trail["ciamProviderRef"], "name": trail["ciamProviderRef"].rsplit("/", 1)[1],
                "s3_bucket_name": bucket, "is_multi_region_trail": True, "include_global_service_events": True,
                "enable_log_file_validation": True, "is_organization_trail": False,
                "event_selector": [{"read_write_type": "WriteOnly", "include_management_events": True,
                                    "data_resource": [{"type": "AWS::S3::Object", "values": [
                                        f"arn:aws:s3:::{SOURCE['backup'][len('s3://'):]}/"]}]}],
                "tags": {"Role": trail_role, "ManagedBy": "opsdir"}})]


def _aws_security():
    """The source's security services as Terraform holds them: GuardDuty with its protection plans, Inspector, AWS
    Config recording into its bucket (kept 2557 days), Security Hub with its standards, and the EventBridge rules that
    send GuardDuty's, Inspector's and Security Hub's findings to the security topic."""
    by_cn = {cn: (role, a) for _, cn, role, a in SECURITY["source"]}
    topic = by_cn["security-alerts"][1]["ciamProviderRef"]
    detector = by_cn["guardduty"][1]["ciamProviderRef"]
    detector_id = detector.rsplit("/", 1)[1]
    hub = "arn:aws:securityhub:us-east-1::standards/"
    rules = (("guardduty", "aws.guardduty", "GuardDuty Finding"), ("inspector", "aws.inspector2", "Inspector2 Finding"),
             ("security-hub", "aws.securityhub", "Security Hub Findings - Imported"))
    return [_res("managed", "aws_sns_topic", "security-alerts", {
                "arn": topic, "name": topic.rsplit(":", 1)[1],
                "tags": {"Role": "security-findings", "ManagedBy": "opsdir"}}),
            _res("managed", "aws_guardduty_detector", "guardduty", {
                "id": detector_id, "arn": detector, "enable": True, "finding_publishing_frequency": "FIFTEEN_MINUTES",
                "tags": {"Role": "threat-detection", "ManagedBy": "opsdir"}}),
            *(_res("managed", "aws_guardduty_detector_feature", f"guardduty-{name.lower()}", {
                "detector_id": detector_id, "name": name, "status": "ENABLED",
                "additional_configuration": [{"name": x, "status": "ENABLED"} for x in extra]})
              for name, extra in (("S3_DATA_EVENTS", ()), ("EKS_AUDIT_LOGS", ()),
                                  ("RUNTIME_MONITORING", ("EKS_ADDON_MANAGEMENT", "EC2_AGENT_MANAGEMENT")),
                                  ("EBS_MALWARE_PROTECTION", ()), ("RDS_LOGIN_EVENTS", ()))),
            _res("managed", "aws_inspector2_enabler", "inspector", {
                "id": "111122223333-EC2:ECR", "account_ids": ["111122223333"], "resource_types": ["EC2", "ECR"]}),
            _res("managed", "aws_s3_bucket", "config-history", {
                "bucket": CONFIG_BUCKET, "arn": f"arn:aws:s3:::{CONFIG_BUCKET}",
                "tags": {"Name": "config-history", "Role": "config-history", "ManagedBy": "opsdir"}}),
            _res("managed", "aws_s3_bucket_versioning", "config-history", {
                "bucket": CONFIG_BUCKET, "versioning_configuration": [{"status": "Enabled"}]}),
            _res("managed", "aws_config_configuration_recorder", "config", {
                "id": "config", "name": "config",
                "role_arn": "arn:aws:iam::111122223333:role/aws-service-role/config.amazonaws.com/"
                            "AWSServiceRoleForConfig",
                "recording_group": [{"all_supported": True, "include_global_resource_types": True}]}),
            _res("managed", "aws_config_delivery_channel", "config", {
                "id": "config", "name": "config", "s3_bucket_name": CONFIG_BUCKET}),
            _res("managed", "aws_config_retention_configuration", "config", {
                "id": "default", "name": "default", "retention_period_in_days": 2557}),
            _res("managed", "aws_securityhub_account", "security-hub", {
                "id": "111122223333", "arn": by_cn["security-hub"][1]["ciamProviderRef"],
                "control_finding_generator": "SECURITY_CONTROL", "enable_default_standards": False}),
            *(_res("managed", "aws_securityhub_standards_subscription", f"security-hub-{n}", {
                "id": f"arn:aws:securityhub:us-east-1:111122223333:subscription/{path}",
                "standards_arn": hub + path})
              for n, path in (("nist-800-53", "nist-800-53/v/5.0.0"), ("nist-800-171", "nist-800-171/v/2.0.0"),
                              ("fsbp", "aws-foundational-security-best-practices/v/1.0.0"))),
            *(x for cn, source, detail in rules for x in (
                _res("managed", "aws_cloudwatch_event_rule", f"{cn}-findings", {
                    "name": f"{cn}-findings", "arn": f"arn:aws:events:us-east-1:111122223333:rule/{cn}-findings",
                    "event_pattern": json.dumps({"source": [source], "detail-type": [detail]}),
                    "tags": {"ManagedBy": "opsdir"}}),
                _res("managed", "aws_cloudwatch_event_target", f"{cn}-findings", {
                    "rule": f"{cn}-findings", "arn": topic, "target_id": "security-topic"})))]


def _drifted_source(p, subnets, groups):
    """What someone did outside the record: an untagged bastion and a hand-opened rule."""
    return [_res("managed", "aws_instance", "bastion", {
                "id": "i-0b4571011cafe0001", "ami": "ami-0bastion0000000001", "instance_type": "t3.micro",
                "private_ip": "10.20.4.99", "availability_zone": "us-east-1a", "subnet_id": subnets["subnet-pf-a"],
                "vpc_security_group_ids": [groups["pf-engine"]], "private_dns": "ip-10-20-4-99.ec2.internal"}),
            _res("managed", "aws_vpc_security_group_ingress_rule", "vendor", {
                "security_group_rule_id": "sgr-0feedc0ffee000001", "security_group_id": groups["ds"],
                "cidr_ipv4": "10.99.0.0/16", "from_port": 1636, "to_port": 1636, "ip_protocol": "tcp",
                "description": "temporary vendor access"})]


# ------------------------------------------------------------------ source/prod: IAM, the platform's and the landing zone's
LANDING = ("identity-ci", "identity-admins", "identity-break-glass")      # kept by the landing zone, not the platform


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _allows(grants):
    """A policy's statements from the record's grants ('<action> on <resource>')."""
    return [{"Effect": "Allow", "Action": a, "Resource": r} for a, _, r in (g.partition(" on ") for g in grants)]


def _trust(trusted):
    def one(who):
        if who.startswith("https://"):
            issuer, subject = who.split(" ", 1)
            host = issuer.split("://", 1)[1]
            return {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                    "Principal": {"Federated": f"{ACCT}:oidc-provider/{host}"},
                    "Condition": {"StringEquals": {f"{host}:aud": "sts.amazonaws.com"},
                                  "StringLike": {f"{host}:sub": subject}}}
        if who.endswith(".amazonaws.com"):
            return {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": who}}
        return {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": who},
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    return _policy(*(one(w) for w in trusted))


def _role(cn, ref, trusted, grants, extra=(), managed=()):
    name = ref.rsplit("/", 1)[1]
    return _res("managed", "aws_iam_role", name, {
        "arn": ref, "name": name, "assume_role_policy": _trust(trusted), "tags": {"Role": cn},
        "inline_policy": [{"name": "ciam", "policy": _policy(*_allows(grants), *extra)}] if grants or extra else [],
        "managed_policy_arns": list(managed)})


def _source_iam():
    """The platform's workload roles, PingFederate's with the grant someone added in the console."""
    console = ({"Effect": "Allow", "Action": "secretsmanager:ListSecrets", "Resource": "*"},)
    return [_role(cn, ref, trusted, grants, console if cn == "identity-pf" else ())
            for cn, kind, ref, trusted, grants in AWS_IDENTITIES if cn not in LANDING]


def landing_zone_state():
    """The landing zone's Terraform state: the pipeline's OIDC provider and role, the admins' permission set, the
    break-glass role (its AWS managed policy isn't in a state), and the network plumbing it keeps (route table,
    network ACL, flow log)."""
    rows = {cn: (kind, ref, trusted, grants) for cn, kind, ref, trusted, grants in AWS_IDENTITIES}
    ps = "arn:aws:sso:::permissionSet/ssoins-72231a2b3c4d5e6f/ps-ciamadmins01"
    _, ci_ref, ci_trust, ci_grants = rows["identity-ci"]
    _, group, _, admin_grants = rows["identity-admins"]
    _, bg_ref, bg_trust, _ = rows["identity-break-glass"]
    resources = [
        _res("managed", "aws_iam_openid_connect_provider", "github", {
            "arn": f"{ACCT}:oidc-provider/token.actions.githubusercontent.com",
            "url": "https://token.actions.githubusercontent.com", "client_id_list": ["sts.amazonaws.com"]}),
        _role("identity-ci", ci_ref, ci_trust, ci_grants),
        _res("managed", "aws_ssoadmin_permission_set", "ciam_admins", {
            "arn": ps, "name": "ciam-admins", "session_duration": "PT4H", "tags": {"Role": "identity-admins"}}),
        _res("managed", "aws_ssoadmin_permission_set_inline_policy", "ciam_admins", {
            "permission_set_arn": ps, "inline_policy": _policy(*_allows(admin_grants))}),
        _res("managed", "aws_ssoadmin_account_assignment", "ciam_admins", {
            "permission_set_arn": ps, "principal_id": group, "principal_type": "GROUP", "target_id": ACCOUNT,
            "target_type": "AWS_ACCOUNT"}),
        _role("identity-break-glass", bg_ref, bg_trust, (), managed=("arn:aws:iam::aws:policy/AdministratorAccess",)),
        *(r for oc, cn, role, a in SOURCE["network"]
          for r in _aws_plumbing(SOURCE, oc, cn, a, {"Name": cn, "Role": role, "ManagedBy": "opsdir"}))]
    return indented({"version": 4, "terraform_version": "1.9.5", "serial": 31, "lineage": "7a1d-ciam-landing-zone",
                   "outputs": {}, "resources": resources})


def _aws_dns(p):
    """The Resolver rules forwarding the environment's queries (the AD domain to the domain controllers)."""
    return [_res("managed", "aws_route53_resolver_rule", attrs["ciamProviderRef"], {
                "id": attrs["ciamProviderRef"], "name": cn, "rule_type": "FORWARD",
                "domain_name": f"{attrs['ciamForwardDomain']}.",
                "target_ip": [{"ip": ip, "port": 53} for ip in attrs["ciamForwardTarget"]]})
            for oc, cn, _, attrs in p["edge"] if oc == "ciamDnsForwarder"]


def _domain_list(sites):
    """An allowlist as a Network Firewall domain list's targets: hosts without ports, *.example as .example."""
    return list(dict.fromkeys(h[1:] if h.startswith("*.") else h for _, hosts in sites_by_port(sites) for h in hosts))


def _acl_entry(rule):
    """An aws_network_acl ingress/egress block of a ciamAclRule ('<number> <action> <in|out> <protocol> <ports>
    <cidr>')."""
    number, action, _, protocol, ports, cidr = rule.split(" ")
    low, _, high = ("0-0" if ports == "all" else ports).partition("-")
    return {"rule_no": int(number), "action": action, "protocol": "-1" if protocol == "all" else protocol,
            "from_port": int(low), "to_port": int(high or low), "cidr_block": cidr}


def _aws_plumbing(p, oc, cn, a, tags):
    """The landing zone's plumbing as Terraform state: a route table and its subnet associations, a network ACL, a
    flow log to the ops log group."""
    if oc == "ciamRouteTable":
        (dest, _, _), = (r.split(" ") for r in a["ciamRoute"])       # out through the NAT gateway (pf-egress)
        nat = p["egress"][0]
        return [_res("managed", "aws_route_table", cn, {
                    "id": a["ciamProviderRef"], "vpc_id": p["net"][1], "tags": tags,
                    "route": [{"cidr_block": dest, "nat_gateway_id": nat}]}),
                *(_res("managed", "aws_route_table_association", f"{cn}_{i}", {
                    "id": f"rtbassoc-0{hex_id('assoc', cn, subnet, n=16)}", "route_table_id": a["ciamProviderRef"],
                    "subnet_id": subnet}) for i, subnet in enumerate(by_role(p["subnets"], a["ciamSubnetRole"])))]
    if oc == "ciamNetworkAcl":
        rules = [r.split(" ") for r in a["ciamAclRule"]]
        return [_res("managed", "aws_network_acl", cn, {
            "id": a["ciamProviderRef"], "vpc_id": p["net"][1], "tags": tags,
            "subnet_ids": by_role(p["subnets"], a["ciamSubnetRole"]),
            "ingress": [_acl_entry(" ".join(r)) for r in rules if r[2] == "in"],
            "egress": [_acl_entry(" ".join(r)) for r in rules if r[2] == "out"]})]
    if oc == "ciamFlowLog":
        return [_res("managed", "aws_flow_log", cn, {
            "id": a["ciamProviderRef"], "vpc_id": p["net"][1], "traffic_type": "ALL", "tags": tags,
            "log_destination_type": "cloud-watch-logs",
            "log_destination": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/ciam/prod/access"})]
    return []


def _aws_network_depth(p):
    """What the stack's own Terraform made of its network depth: the Secrets Manager endpoint and its security group,
    the LDAPS endpoint service, the egress firewall's domain list."""
    out = []
    for oc, cn, role, a in p["network"]:
        tags = {"Name": cn, "Role": role, "ManagedBy": "opsdir"}
        if oc == "ciamPrivateEndpoint":
            group = f"sg-0{hex_id('endpoint', cn, n=16)}"
            out += [_res("managed", "aws_security_group", f"{cn}_endpoint", {
                        "id": group, "name": f"ciam-prod-{cn}", "vpc_id": p["net"][1], "tags": {"ManagedBy": "opsdir"},
                        "ingress": [{"cidr_blocks": [p["net"][2]], "from_port": 443, "to_port": 443,
                                     "protocol": "tcp", "description": f"the network to {cn}"}]}),
                    _res("managed", "aws_vpc_endpoint", cn, {
                        "id": a["ciamProviderRef"], "vpc_id": p["net"][1], "vpc_endpoint_type": "Interface",
                        "service_name": f"com.amazonaws.{REGION}.secretsmanager",
                        "subnet_ids": by_role(p["subnets"], a["ciamSubnetRole"]),
                        "private_dns_enabled": a["ciamPrivateDns"] == "TRUE", "security_group_ids": [group],
                        "tags": tags})]
        elif oc == "ciamEndpointService":
            out.append(_res("managed", "aws_vpc_endpoint_service", cn, {
                "id": a["ciamProviderRef"], "service_name": a["ciamServiceAlias"],
                "acceptance_required": a["ciamAcceptanceRequired"] == "TRUE",
                "allowed_principals": [a["ciamAllowedPrincipal"]],
                "network_load_balancer_arns": [_lb_arn(service_named(p, a["ciamServiceRole"]))], "tags": tags}))
        elif oc == "ciamProxy":
            out.append(_res("managed", "aws_networkfirewall_rule_group", f"{cn}_domains", {
                "arn": f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:stateful-rulegroup/ciam-prod-{cn}-domains",
                "tags": {**tags, "FirewallPolicy": a["ciamProviderRef"]},
                "rule_group": [{"rules_source": [{"rules_source_list": [{
                    "generated_rules_type": "ALLOWLIST", "target_types": ["TLS_SNI", "HTTP_HOST"],
                    "targets": _domain_list(a["ciamAllowedDestination"])}]}]}]}))
    return out


def _aws_databases(p, groups):
    """The managed databases as the stack's Terraform made them: each RDS instance with its subnet and parameter
    groups and its security group, whose rules admit its clients' ranges (RDS keeps the master password in Secrets
    Manager: the state holds the secret's ARN, never the password)."""
    out = []
    for _, cn, role, a in p["databases"]:
        params = [{"name": k, "value": v} for k, v in (x.split("=", 1) for x in a["ciamDbParameter"])]
        tags = {"Name": cn, "Role": role, "ManagedBy": "opsdir"}
        out += [_res("managed", "aws_db_subnet_group", cn, {
                    "name": cn, "subnet_ids": by_role(p["subnets"], a["ciamSubnetRole"]), "tags": tags}),
                _res("managed", "aws_db_parameter_group", cn, {
                    "name": cn, "family": f"postgres{a['ciamDbEngineVersion'].split('.')[0]}", "parameter": params,
                    "tags": tags}),
                _res("managed", "aws_db_instance", cn, {
                    "arn": a["ciamProviderRef"], "identifier": cn, "engine": "postgres",
                    "engine_version": a["ciamDbEngineVersion"], "engine_version_actual": a["ciamDbEngineVersion"],
                    "address": a["ciamFqdn"], "port": int(a["ciamPort"]), "instance_class": a["ciamInstanceSize"],
                    "allocated_storage": int(a["ciamDbStorageGb"]),
                    "multi_az": a["ciamDbHighAvailability"] == "zone-redundant",
                    "backup_retention_period": int(a["ciamRetentionDays"]),
                    "deletion_protection": a["ciamDbDeletionProtection"] == "TRUE", "storage_encrypted": True,
                    "kms_key_id": p["key"][0].split("://", 1)[1], "db_subnet_group_name": cn,
                    "parameter_group_name": cn, "vpc_security_group_ids": [groups[role]], "publicly_accessible": False,
                    "master_user_secret": [{"secret_arn": p["secret"](a["ciamDbCredentialRole"]).split("://", 1)[1],
                                            "secret_status": "active"}],
                    "tags": tags}),
                *(_res("managed", "aws_db_instance_automated_backups_replication", f"{cn}_{region}", {
                    "id": f"arn:aws:rds:{region}:{ACCOUNT}:auto-backup:ab-{hex_id(cn, region, n=26)}",
                    "source_db_instance_arn": a["ciamProviderRef"], "retention_period": int(a["ciamRetentionDays"]),
                    "kms_key_id": p["key"][0].split("://", 1)[1].replace(REGION, region)})
                  for region in ([a["ciamCopyRegion"]] if a.get("ciamCopyRegion") else [])),
                *(_res("managed", "aws_vpc_security_group_ingress_rule", f"{role}_{i}", {
                    "security_group_rule_id": f"sgr-0{hex_id(role, cidr, n=16)}", "security_group_id": groups[role],
                    "cidr_ipv4": cidr, "from_port": int(a["ciamPort"]), "to_port": int(a["ciamPort"]),
                    "ip_protocol": "tcp", "description": f"clients of database {cn} ({role})"})
                  for i, cidr in enumerate(a["ciamSourceCidr"]))]
    return out


_EBS = {"standard": "st1", "ssd": "gp3", "provisioned": "io2"}


def _aws_volumes(p, instances):
    """The disks as the stack's Terraform made them: each data volume of a role an EBS volume on each of its servers,
    in the server's zone, attached at /dev/sdf, /dev/sdg ...; each snapshot policy a Lifecycle Manager policy
    snapshotting the volumes tagged with its role, copying each snapshot with the disk key's replica in the copy
    region."""
    key = p["key"][0].split("://", 1)[1]
    volumes = rows_of(p.get("volumes") or (), "ciamVolume")
    out = []
    for k, (cn, role, a) in enumerate(volumes):
        device = "fghijklmnop"[[v[2]["ciamTargetRole"] for v in volumes[:k]].count(a["ciamTargetRole"])]
        for s in servers_of(p, a["ciamTargetRole"]):
            vid = f"vol-0{hex_id('volume', s[0], cn, n=16)}"
            out += [_res("managed", "aws_ebs_volume", f"{s[0]}_{cn}", {
                        "id": vid, "arn": f"arn:aws:ec2:{REGION}:{ACCOUNT}:volume/{vid}", "availability_zone": s[4],
                        "size": int(a["ciamVolumeSizeGb"]), "type": _EBS[a["ciamVolumeClass"]],
                        "iops": int(a["ciamIops"]) if a.get("ciamIops") else None,
                        "throughput": int(a["ciamThroughputMb"]) if a.get("ciamThroughputMb") else None,
                        "encrypted": a["ciamVolumeEncrypted"] == "TRUE", "kms_key_id": key,
                        "tags": {"Name": f"{s[0]}-{cn}", "Volume": cn, "Role": role, "Server": s[0],
                                 **({"SnapshotPolicy": a["ciamSnapshotPolicyRole"]}
                                    if a.get("ciamSnapshotPolicyRole") else {}), "ManagedBy": "opsdir"}}),
                    _res("managed", "aws_volume_attachment", f"{s[0]}_{cn}", {
                        "device_name": f"/dev/sd{device}", "volume_id": vid, "instance_id": instances[s[0]]})]
    for cn, role, a in rows_of(p.get("volumes") or (), "ciamSnapshotPolicy"):
        days = [{"interval": int(a["ciamRetentionDays"]), "interval_unit": "DAYS"}]
        out.append(_res("managed", "aws_dlm_lifecycle_policy", cn, {
            "id": a["ciamProviderRef"], "arn": f"arn:aws:dlm:{REGION}:{ACCOUNT}:policy/{a['ciamProviderRef']}",
            "execution_role_arn": f"arn:aws:iam::{ACCOUNT}:role/AWSDataLifecycleManagerDefaultRole",
            "state": "ENABLED", "tags": {"Name": cn, "Role": role, "ManagedBy": "opsdir"},
            "policy_details": [{"resource_types": ["VOLUME"], "target_tags": {"SnapshotPolicy": role}, "schedule": [{
                "name": role, "copy_tags": True, "retain_rule": days,
                "create_rule": [{"interval": int(a["ciamSnapshotEveryHours"]), "interval_unit": "HOURS",
                                 "times": [a["ciamSnapshotAt"]]}],
                "cross_region_copy_rule": [{"target": region, "encrypted": True, "copy_tags": True,
                                            "cmk_arn": key.replace(REGION, region), "retain_rule": days}
                                           for region in listed(a.get("ciamCopyRegion"))]
            }]}]}))
    return out


def _aws_backups(p):
    """AWS Backup as the stack's Terraform made it: each vault (the platform's key) with its lock, each plan's rule into
    its vault (daily from its hour, its window, retention, a copy to the vault of each copy region) and its selection
    by tag Role of what it protects."""
    rows = p.get("volumes") or ()
    names = {role: f"ciam-prod-{cn}" for cn, role, _ in rows_of(rows, "ciamBackupVault")}
    out = []
    for cn, role, a in rows_of(rows, "ciamBackupVault"):
        locked = (a.get("ciamStorageImmutability") or "none") != "none"
        out += [_res("managed", "aws_backup_vault", cn, {
                    "name": names[role], "arn": a["ciamProviderRef"],
                    "kms_key_arn": p["key"][0].split("://", 1)[1] if a.get("ciamEncryptedByRole") else None,
                    "tags": {"Name": cn, "Role": role, "ManagedBy": "opsdir"}}),
                *((_res("managed", "aws_backup_vault_lock_configuration", cn, {
                    "backup_vault_name": names[role], "min_retention_days": int(a["ciamStorageLockDays"]),
                    "changeable_for_days": 3 if a["ciamStorageImmutability"] == "compliance" else None}),)
                  if locked else ())]
    for cn, role, a in rows_of(rows, "ciamBackupPlan"):
        pid, keep = a["ciamProviderRef"].rsplit(":", 1)[1], [{"delete_after": int(a["ciamRetentionDays"])}]
        hour, minute = (int(x) for x in a["ciamBackupAt"].split(":"))
        vault = names[a["ciamBackupVaultRole"]]
        out += [_res("managed", "aws_backup_plan", cn, {
                    "id": pid, "arn": a["ciamProviderRef"], "name": f"ciam-prod-{cn}",
                    "tags": {"Name": cn, "Role": role, "ManagedBy": "opsdir"},
                    "rule": [{"rule_name": cn.replace("-", "_"), "target_vault_name": vault,
                              "schedule": f"cron({minute} {hour} ? * * *)",
                              "start_window": int(a["ciamBackupWindowHours"]) * 60 if a.get("ciamBackupWindowHours")
                              else None, "lifecycle": keep,
                              "copy_action": [{"destination_vault_arn": f"arn:aws:backup:{region}:{ACCOUNT}:backup-vault:"
                                                                        f"{vault}", "lifecycle": keep}
                                              for region in listed(a.get("ciamCopyRegion"))]}]}),
                _res("managed", "aws_backup_selection", cn, {
                    "id": f"{hex_id('selection', cn, n=8)}-0000-4000-8000-{hex_id('selection', cn, n=12)}",
                    "plan_id": pid, "name": f"ciam-prod-{cn}",
                    "iam_role_arn": f"arn:aws:iam::{ACCOUNT}:role/service-role/AWSBackupDefaultServiceRole",
                    "selection_tag": [{"type": "STRINGEQUALS", "key": "Role", "value": r}
                                      for r in listed(a["ciamProtectsRole"])]})]
    return out


def source_state():
    """The source environment's Terraform state (format version 4), with the planted drift."""
    p = SOURCE
    subnets, instances, groups = _source_ids(p)
    resources = [*_aws_network(p, subnets), *_aws_servers(p, subnets, instances, groups, {"pf-engine-2": "m6i.xlarge"}),
                 *_aws_firewall(p, groups), *_aws_services(p, instances), *_aws_keys(p, rotation=False),
                 *_aws_monitoring(), *_aws_audit(), *_aws_security(), *_drifted_source(p, subnets, groups), *_source_iam(), *_aws_dns(p),
                 *_aws_network_depth(p), *_aws_databases(p, groups), *_aws_volumes(p, instances),
                 *_aws_backups(p)]
    return indented({"version": 4, "terraform_version": "1.9.5", "serial": 214, "lineage": "5e0c-ciam-prod",
                   "outputs": {}, "resources": resources})
