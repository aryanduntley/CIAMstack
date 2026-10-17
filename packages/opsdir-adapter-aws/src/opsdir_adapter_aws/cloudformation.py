"""What CloudFormation stacks declare an environment runs, read into the record's neutral resources. Pure.

One folder per stack under <cloud>/<env>/ (any name; files directly in the environment folder are one stack), holding
any of, recognized by shape:

  aws cloudformation describe-stacks --stack-name S        Stacks: parameters, region and account (from the stack ID)
  aws cloudformation list-stack-resources --stack-name S   StackResourceSummaries (or describe-stack-resources,
                                                           StackResources): each resource's physical ID
  aws cloudformation get-template --stack-name S           TemplateBody (JSON, or YAML as text)
  the template itself                                      Resources (JSON, or YAML with the short tags !Ref, !Sub, …)

and, anywhere in the environment's folder, the Terraform state of a root kept beside the stacks (*.tfstate: what an
opsdir CloudFormation render keeps in Terraform, applied), read with them by the state reader's mapping, so one import
sees the whole environment.

The template says what each resource is declared with; the stack's resources give the IDs the record matches on. Values
are resolved from the stack's parameters (else the template's defaults), pseudo parameters and physical IDs: Ref,
Fn::Sub, Fn::Join, Fn::Select, and Fn::GetAtt where it links resources (a DNS alias to its load balancer, an Elastic
IP's address). What else a value is computed with (Fn::If, Fn::ImportValue, Fn::FindInMap, …) is counted, and the
record keeps its value for that attribute. Resolved properties are normalized to the attribute names of the matching
Terraform resource and read by the same mapping (opsdir_adapter_aws.inventory.pairs_resources):

  AWS::EC2::VPC, AWS::EC2::Subnet, AWS::EC2::Instance, AWS::EC2::SecurityGroup (+ SecurityGroupIngress),
  AWS::EC2::NatGateway, AWS::EC2::EIP, AWS::ElasticLoadBalancingV2::LoadBalancer (+ Listener, TargetGroup with its
  Targets), AWS::Route53::RecordSet (+ RecordSetGroup), AWS::SecretsManager::Secret (+ RotationSchedule; SecretString
  is never read), AWS::KMS::Key (+ ReplicaKey), AWS::S3::Bucket, AWS::CloudTrail::Trail (its ARN from the stack's
  region and account; cli_audit.py); the network depth (route tables, network ACLs, VPC endpoints and endpoint
  services, peering, transit and VPN, flow logs, Network Firewall): cloudformation_network.py; IAM and guardrails, the
  edge, data stores, security services (GuardDuty, AWS Config, Security Hub) and suppressions, observability (log
  groups, alarms, canaries), volumes and backups, budgets, Cognito user pools; EventBridge rules with their event
  patterns (findings routes); compute groups (autoscaling groups and their launch templates) and EKS clusters;
  resource policies and Instance Connect Endpoints; hosted zones; queues, topics, event buses, data streams and SES
  identities: cloudformation_iam.py, _edge.py, _data.py, _security.py, _observability.py, _backups.py, _budgets.py,
  _compute.py, _messaging.py; a listener's mutual TLS (MutualAuthentication) and ALB trust stores
  (AWS::ElasticLoadBalancingV2::TrustStore), which the record's edge trust policies are checked against:
  mtls_inventory.py
Resources that weren't created (no physical ID, deleted, failed) are skipped; other resource types are counted.
"""
import json
import re
from collections import Counter
from types import MappingProxyType

import yaml

from opsdir.core.contract import Importer
from opsdir.core.inventory import layout_import
from opsdir.core.sources import json_document, parsed
from .cli_audit import trail_attributes
from .cli_edge import record_attributes
from .cloudformation_backups import BACKUP_TYPES, backup_stack_pairs
from .cloudformation_budgets import BUDGET_TYPES, budget_stack_pairs
from .cloudformation_compute import COMPUTE_TYPES, compute_stack_pairs
from .cloudformation_data import DATA_TYPES, data_stack_pairs
from .cloudformation_edge import EDGE_TYPES, edge_stack_pairs
from .cloudformation_iam import IAM_TYPES, iam_stack_pairs
from .cloudformation_messaging import MESSAGING_TYPES, messaging_stack_pairs
from .cloudformation_network import NETWORK_TYPES, network_stack_pairs
from .cloudformation_observability import OBSERVABILITY_TYPES, observability_stack_pairs
from .cloudformation_security import SECURITY_TYPES, security_stack_pairs
from .cloudformation_values import dns_target, getatt, number, stack_arn, tag_map, truth
from .inventory import PROVIDER, pairs_resources, state_pairs
from .mtls_inventory import TRUST_TYPES, mutual_authentication, stack_trust_pairs, with_mtls_notices

READ = ("AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::Instance", "AWS::EC2::SecurityGroup",
        "AWS::EC2::SecurityGroupIngress", "AWS::EC2::NatGateway", "AWS::EC2::EIP",
        "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancingV2::Listener",
        "AWS::ElasticLoadBalancingV2::TargetGroup", "AWS::Route53::RecordSet", "AWS::Route53::RecordSetGroup",
        "AWS::SecretsManager::Secret", "AWS::SecretsManager::RotationSchedule", "AWS::KMS::Key",
        "AWS::KMS::ReplicaKey", "AWS::S3::Bucket", "AWS::Lambda::Function", "AWS::Events::Rule",
        "AWS::Scheduler::Schedule", "AWS::CodePipeline::Pipeline", "AWS::CodeBuild::Project", "AWS::CloudTrail::Trail",
        *NETWORK_TYPES, *IAM_TYPES, *EDGE_TYPES, *DATA_TYPES, *SECURITY_TYPES, *OBSERVABILITY_TYPES,
        *BACKUP_TYPES, *BUDGET_TYPES, *COMPUTE_TYPES, *MESSAGING_TYPES, *TRUST_TYPES)
EVALUATED = ("Ref", "Fn::Sub", "Fn::Join", "Fn::Select", "Fn::GetAtt")
NOT_CREATED = ("CREATE_FAILED", "DELETE_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED")
ACCOUNT_WIDE = ("secret", "key", "storage")
_SUB = re.compile(r"\$\{([^}!][^}]*)\}")


# ------------------------------------------------------------------ reading templates
class _TemplateLoader(yaml.SafeLoader):     # a namespace for the short-tag constructors below; no methods
    pass


def _short_tag(loader, suffix, node):
    """!Ref x -> {"Ref": x}; !GetAtt a.b -> {"Fn::GetAtt": [a, b]}; !Name v -> {"Fn::Name": v}."""
    value = (loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else
             loader.construct_sequence(node, deep=True) if isinstance(node, yaml.SequenceNode) else
             loader.construct_mapping(node, deep=True))
    if suffix == "Ref":
        return {"Ref": value}
    if suffix == "GetAtt" and isinstance(value, str):
        return {"Fn::GetAtt": value.split(".", 1)}
    return {suffix if suffix == "Condition" else f"Fn::{suffix}": value}


yaml.add_multi_constructor("!", _short_tag, Loader=_TemplateLoader)


def read_document(text):
    """A JSON or CloudFormation YAML document (short tags included); None when it is neither."""
    doc = json_document(text)
    return doc if doc is not None else parsed(lambda t: yaml.load(t, Loader=_TemplateLoader), text, (yaml.YAMLError,))


# ------------------------------------------------------------------ a stack
def _stacks(texts):
    """({folder: {"stack": …, "resources": [...], "template": {...}}}, notices): each folder's outputs by shape."""
    def kind(doc):
        if not isinstance(doc, dict):
            return None
        return next((k for k, key in (("stack", "Stacks"), ("resources", "StackResourceSummaries"),
                                      ("resources", "StackResources"), ("template", "TemplateBody"),
                                      ("template", "Resources")) if key in doc), None)
    docs = [(p.rsplit("/", 1)[0] if "/" in p else "", p, read_document(t)) for p, t in sorted(texts.items())]
    found = [(folder, p, kind(doc), doc) for folder, p, doc in docs]

    def content(k, doc):
        if k == "stack":
            return (doc.get("Stacks") or [{}])[0]
        if k == "resources":
            return doc.get("StackResourceSummaries") or doc.get("StackResources") or []
        body = doc.get("TemplateBody", doc)
        return read_document(body) if isinstance(body, str) else body
    folders = dict.fromkeys(f for f, _, k, _ in found if k)
    return ({f: {k: content(k, doc) for f2, _, k, doc in found if f2 == f and k} for f in folders},
            tuple(f"{p}: not a CloudFormation stack output or template; not read" for _, p, k, _ in found if not k))


def _pseudo(stack, resources):
    """AWS::Region, AWS::AccountId, AWS::Partition, AWS::StackName from the stack ID (else from any ARN it created)."""
    arn = stack.get("StackId") or next((r.get("PhysicalResourceId") for r in resources
                                        if str(r.get("PhysicalResourceId", "")).startswith("arn:")), "")
    parts = (arn.split(":") + [""] * 6)[:6]
    return {"AWS::Partition": parts[1] or "aws", "AWS::Region": parts[3] or None, "AWS::AccountId": parts[4] or None,
            "AWS::StackName": stack.get("StackName"), "AWS::StackId": stack.get("StackId"),
            "AWS::URLSuffix": "amazonaws.com", "AWS::NoValue": None}


def _arn(service, path, region=True):
    """An ARN maker for a type's GetAtt: arn:<partition>:<service>:<region>:<account>:<path with {id}>."""
    return lambda pid, ps: stack_arn(ps, service, path.format(id=pid), region)


def _waf_arn(pid, ps, kind):
    """A WAF web ACL's or IP set's ARN: its physical id when that is one, else from 'name|id|scope' (Ref's form)."""
    if str(pid).startswith("arn:"):
        return pid
    parts = str(pid).split("|")
    if len(parts) != 3:
        return None
    where = "global" if parts[2] == "CLOUDFRONT" else "regional"
    region = "us-east-1" if where == "global" else ps["AWS::Region"] or ""
    account = ps["AWS::AccountId"] or ""
    return f"arn:{ps['AWS::Partition']}:wafv2:{region}:{account}:{where}/{kind}/{parts[0]}/{parts[1]}"


# The Fn::GetAtt attributes that follow from a resource's physical id (its Ref) and the stack's pseudo parameters,
# by type: (physical id, pseudo parameters) -> the attribute
GETATT = MappingProxyType({
    "AWS::EC2::SecurityGroup": {"GroupId": lambda pid, ps: pid},
    "AWS::EC2::LaunchTemplate": {"LaunchTemplateId": lambda pid, ps: pid},
    "AWS::EKS::Cluster": {"Arn": _arn("eks", "cluster/{id}")},
    "AWS::IAM::Role": {"Arn": _arn("iam", "role/{id}", False)},
    "AWS::IAM::InstanceProfile": {"Arn": _arn("iam", "instance-profile/{id}", False)},
    "AWS::IAM::OIDCProvider": {"Arn": lambda pid, ps: pid},
    "AWS::IAM::ManagedPolicy": {"PolicyArn": lambda pid, ps: pid},
    "AWS::SSO::PermissionSet": {"PermissionSetArn": lambda pid, ps: pid},
    "AWS::Organizations::Policy": {"Arn": lambda pid, ps: pid if str(pid).startswith("arn:") else None,
                                   "Id": lambda pid, ps: str(pid).rsplit("/", 1)[-1]},
    "AWS::KMS::Key": {"Arn": _arn("kms", "key/{id}"), "KeyId": lambda pid, ps: pid},
    "AWS::S3::Bucket": {"Arn": lambda pid, ps: f"arn:{ps['AWS::Partition']}:s3:::{pid}"},
    "AWS::Logs::LogGroup": {"Arn": _arn("logs", "log-group:{id}:*")},
    "AWS::CloudWatch::Alarm": {"Arn": _arn("cloudwatch", "alarm:{id}")},
    "AWS::DLM::LifecyclePolicy": {"Arn": _arn("dlm", "policy/{id}")},
    "AWS::Backup::BackupVault": {"BackupVaultArn": _arn("backup", "backup-vault:{id}")},
    "AWS::Backup::BackupPlan": {"BackupPlanArn": _arn("backup", "backup-plan:{id}")},
    "AWS::SNS::Topic": {"TopicArn": lambda pid, ps: pid},
    "AWS::Route53::HostedZone": {"Id": lambda pid, ps: pid},
    "AWS::SQS::Queue": {"Arn": lambda pid, ps: stack_arn(ps, "sqs", str(pid).rsplit("/", 1)[-1]),
                        "QueueName": lambda pid, ps: str(pid).rsplit("/", 1)[-1], "QueueUrl": lambda pid, ps: pid},
    "AWS::Events::EventBus": {"Arn": lambda pid, ps: stack_arn(ps, "events", f"event-bus/{pid}"),
                              "Name": lambda pid, ps: pid},      # its Ref is its name (a partner bus's holds '/')
    "AWS::Kinesis::Stream": {"Arn": _arn("kinesis", "stream/{id}")},
    "AWS::KinesisFirehose::DeliveryStream": {"Arn": _arn("firehose", "deliverystream/{id}")},    # Ref: its name
    "AWS::SecretsManager::Secret": {"Id": lambda pid, ps: pid},
    "AWS::WAFv2::WebACL": {"Arn": lambda pid, ps: _waf_arn(pid, ps, "webacl")},
    "AWS::WAFv2::IPSet": {"Arn": lambda pid, ps: _waf_arn(pid, ps, "ipset")},
    "AWS::Shield::Protection": {"ProtectionArn": lambda pid, ps: pid if str(pid).startswith("arn:") else None},
    "AWS::RDS::DBInstance": {"DBInstanceArn": _arn("rds", "db:{id}")},
    "AWS::RDS::DBCluster": {"DBClusterArn": _arn("rds", "cluster:{id}")},
    "AWS::Cognito::UserPool": {"Arn": _arn("cognito-idp", "userpool/{id}")},
    "AWS::SecurityHub::AutomationRule": {"RuleArn": lambda pid, ps: pid if str(pid).startswith("arn:") else None},
    "AWS::CloudFront::Distribution": {"Id": lambda pid, ps: pid,
                                      "Arn": _arn("cloudfront", "distribution/{id}", False)}})


def _context(stack, resources, template):
    """What names resolve to: parameters (the stack's, else the template's defaults), pseudo parameters, physical
    IDs, and '<logical ID>.<attribute>' for the Fn::GetAtt attributes that follow from a physical id (GETATT)."""
    defaults = {k: (v or {}).get("Default") for k, v in (template.get("Parameters") or {}).items()}
    given = {p.get("ParameterKey"): p.get("ResolvedValue", p.get("ParameterValue"))
             for p in stack.get("Parameters") or ()}
    physical = {r.get("LogicalResourceId"): r.get("PhysicalResourceId") for r in resources
                if r.get("PhysicalResourceId") and r.get("ResourceStatus") not in NOT_CREATED}
    pseudo = _pseudo(stack, resources)
    types = {lid: r.get("Type") for lid, r in (template.get("Resources") or {}).items() if isinstance(r, dict)}
    attributes = {f"{lid}.{attr}": make(pid, pseudo) for lid, pid in physical.items()
                  for attr, make in GETATT.get(types.get(lid), {}).items() if make is not None}
    return {**physical, **{k: v for k, v in attributes.items() if v is not None}, **pseudo, **defaults, **given}


def resolve(v, names):
    """A template value with Ref, Fn::GetAtt (what names holds as '<logical ID>.<attribute>'), Fn::Sub, Fn::Join and
    Fn::Select evaluated against names; None where it depends on anything else (then the record keeps its value)."""
    if isinstance(v, list):
        return [resolve(x, names) for x in v]
    if not isinstance(v, dict):
        return v
    if len(v) != 1 or not (next(iter(v)) == "Ref" or next(iter(v)).startswith("Fn::")):
        return {k: resolve(x, names) for k, x in v.items()}
    fn, arg = next(iter(v.items()))
    if fn == "Ref":
        return names.get(arg)
    if fn == "Fn::GetAtt":
        at = getatt(v)
        return names.get(f"{at[0]}.{at[1]}") if at else None
    if fn == "Fn::Sub":
        text, extra = (arg, {}) if isinstance(arg, str) else (arg[0], {k: resolve(x, names) for k, x in arg[1].items()})
        found = {m: {**names, **extra}.get(m) for m in _SUB.findall(text)}
        return None if any(x is None for x in found.values()) else \
            _SUB.sub(lambda m: str(found[m.group(1)]), text).replace("${!", "${")
    if fn == "Fn::Join":
        parts = resolve(arg[1], names)
        return arg[0].join(str(p) for p in parts) if isinstance(parts, list) and None not in parts else None
    if fn == "Fn::Select":
        index, items = resolve(arg[0], names), resolve(arg[1], names)
        return items[int(index)] if isinstance(items, list) and str(index).isdigit() and int(index) < len(items) \
            else None
    return None


def stack_outputs(stack, resources, template):
    """{output key: value} of a stack's Outputs, resolved as its resources are; a load balancer's or distribution's DNS
    name (Fn::GetAtt DNSName / DomainName) as cfn:<logical ID>, as an alias of it reads; None where unresolved."""
    names = _context(stack, resources, template)

    def value(v):
        at = getatt(v)
        return f"cfn:{at[0]}" if at and at[1] in ("DNSName", "DomainName") else resolve(v, names)
    return {k: value(o.get("Value")) for k, o in (template.get("Outputs") or {}).items() if isinstance(o, dict)}


def _unevaluated(template):
    """Counter of the intrinsic functions in the resources' properties that aren't evaluated."""
    def walk(v):
        if isinstance(v, list):
            return sum((walk(x) for x in v), Counter())
        if not isinstance(v, dict):
            return Counter()
        here = Counter(k for k in v if (k.startswith("Fn::") or k == "Condition") and k not in EVALUATED)
        return sum((walk(x) for x in v.values()), here)
    return sum((walk((r or {}).get("Properties")) for r in (template.get("Resources") or {}).values()), Counter())


# ------------------------------------------------------------------ normalized to Terraform attribute names
SECRET_PROPERTIES = ("SecretString", "GenerateSecretString", "SecretBinary")    # never read


def _declared(template, names):
    """(logical ID, type, resolved properties, raw properties, physical ID) of each created resource; a secret's value
    properties are dropped before anything is resolved."""
    def props(r):
        return {k: v for k, v in (r.get("Properties") or {}).items() if k not in SECRET_PROPERTIES}
    return [(logical, r.get("Type"), resolve(props(r), names), props(r), names.get(logical))
            for logical, r in (template.get("Resources") or {}).items()
            if isinstance(r, dict) and names.get(logical) and r.get("Type") in READ]


def _public_ip(raw_allocation, names):
    """The address of an Elastic IP an AllocationId points at with Fn::GetAtt (an EIP's physical ID is its address)."""
    ref = getatt(raw_allocation)
    return names.get(ref[0]) if ref and ref[1] == "AllocationId" else None


def _network(declared):
    of = {t: [(lg, p, raw, pid) for lg, t2, p, raw, pid in declared if t2 == t] for t in READ}
    return [
        *(("aws_vpc", {"id": pid, "cidr_block": p.get("CidrBlock"), "tags": tag_map(p.get("Tags"))})
          for _, p, _, pid in of["AWS::EC2::VPC"]),
        *(("aws_subnet", {"id": pid, "vpc_id": p.get("VpcId"), "cidr_block": p.get("CidrBlock"),
                          "availability_zone": p.get("AvailabilityZone"), "tags": tag_map(p.get("Tags"))})
          for _, p, _, pid in of["AWS::EC2::Subnet"])]


def _instances(declared, names):
    def nic(p):
        return next((n for n in p.get("NetworkInterfaces") or () if str(n.get("DeviceIndex", "0")) == "0"), {})
    return [("aws_instance", {"id": pid, "ami": p.get("ImageId"), "instance_type": p.get("InstanceType"),
                              "private_ip": p.get("PrivateIpAddress") or nic(p).get("PrivateIpAddress"),
                              "availability_zone": p.get("AvailabilityZone"),
                              "subnet_id": p.get("SubnetId") or nic(p).get("SubnetId"),
                              "vpc_security_group_ids": p.get("SecurityGroupIds") or nic(p).get("GroupSet") or [],
                              "tags": tag_map(p.get("Tags"))})
            for _, t, p, _, pid in declared if t == "AWS::EC2::Instance"]


def _ingress(i):
    """A security group's inline ingress rule as the Terraform block (every kind of source kept)."""
    def given(key):
        return [i.get(key)] if i.get(key) else []
    return {"from_port": i.get("FromPort"), "to_port": i.get("ToPort"), "protocol": i.get("IpProtocol"),
            "description": i.get("Description") or "", "cidr_blocks": given("CidrIp"),
            "ipv6_cidr_blocks": given("CidrIpv6"), "security_groups": given("SourceSecurityGroupId"),
            "prefix_list_ids": given("SourcePrefixListId")}


def _security_groups(declared):
    return [*(("aws_security_group", {"id": pid, "name": p.get("GroupName"), "vpc_id": p.get("VpcId"),
                                      "tags": tag_map(p.get("Tags")),
                                      "ingress": [_ingress(i) for i in p.get("SecurityGroupIngress") or ()]})
              for _, t, p, _, pid in declared if t == "AWS::EC2::SecurityGroup"),
            *(("aws_vpc_security_group_ingress_rule", {
                "security_group_rule_id": pid, "security_group_id": p.get("GroupId"), "cidr_ipv4": p.get("CidrIp"),
                "cidr_ipv6": p.get("CidrIpv6"), "referenced_security_group_id": p.get("SourceSecurityGroupId"),
                "prefix_list_id": p.get("SourcePrefixListId"), "from_port": p.get("FromPort"),
                "to_port": p.get("ToPort"), "ip_protocol": p.get("IpProtocol"),
                "description": p.get("Description") or ""})
              for _, t, p, _, pid in declared if t == "AWS::EC2::SecurityGroupIngress")]


def _egress(declared, names):
    return [("aws_nat_gateway", {"id": pid, "public_ip": _public_ip(raw.get("AllocationId"), names),
                                 "tags": tag_map(p.get("Tags"))})
            for _, t, p, raw, pid in declared if t == "AWS::EC2::NatGateway"]


def _load_balancers(declared, names):
    def mappings(p, raw):
        given = list(zip(p.get("SubnetMappings") or (), raw.get("SubnetMappings") or ()))
        return ([{"subnet_id": m.get("SubnetId"), "private_ipv4_address": m.get("PrivateIPv4Address"),
                  "allocation_id": m.get("AllocationId"), "public_ip": _public_ip(r.get("AllocationId"), names)}
                 for m, r in given] or [{"subnet_id": s} for s in p.get("Subnets") or ()])
    def name(p, arn):           # arn:…:loadbalancer/<net|app>/<name>/<id> when the template leaves the name to AWS
        return p.get("Name") or (arn.split("/")[-2] if arn.count("/") >= 3 else None)
    def setting(p, key):
        return next((a.get("Value") for a in p.get("LoadBalancerAttributes") or () if a.get("Key") == key), None)
    return [("aws_lb", {"arn": pid, "name": name(p, pid), "load_balancer_type": p.get("Type") or "application",
                        "internal": p.get("Scheme") == "internal", "dns_name": f"cfn:{logical}",
                        "security_groups": list(p.get("SecurityGroups") or ()),
                        "idle_timeout": setting(p, "idle_timeout.timeout_seconds"),
                        "subnet_mapping": mappings(p, raw), "tags": tag_map(p.get("Tags"))})
            for logical, t, p, raw, pid in declared if t == "AWS::ElasticLoadBalancingV2::LoadBalancer"]


def _forwarding(declared):
    def target_group(action):
        return action.get("TargetGroupArn") or next(
            (g.get("TargetGroupArn") for g in (action.get("ForwardConfig") or {}).get("TargetGroups") or ()), None)
    groups = [(p, pid) for _, t, p, _, pid in declared if t == "AWS::ElasticLoadBalancingV2::TargetGroup"]

    def settings(p):
        return {a.get("Key"): a.get("Value") for a in p.get("TargetGroupAttributes") or () if isinstance(a, dict)}

    def stickiness(p):
        a = settings(p)
        return [{"enabled": str(a.get("stickiness.enabled")).lower() == "true", "type": a.get("stickiness.type"),
                 "cookie_duration": a.get("stickiness.lb_cookie.duration_seconds")}] \
            if "stickiness.enabled" in a else []
    return [*(("aws_lb_listener", {"load_balancer_arn": p.get("LoadBalancerArn"), "port": p.get("Port"),
                                   "protocol": p.get("Protocol"), "ssl_policy": p.get("SslPolicy"),
                                   "default_action": [{"type": a.get("Type"), "target_group_arn": target_group(a)}
                                                      for a in p.get("DefaultActions") or ()],
                                   "mutual_authentication": mutual_authentication(p.get("MutualAuthentication"))})
              for _, t, p, _, _ in declared if t == "AWS::ElasticLoadBalancingV2::Listener"),
            *(("aws_lb_target_group", {
                "arn": pid, "name": p.get("Name"), "port": p.get("Port"), "protocol": p.get("Protocol"),
                "health_check": [{"protocol": p.get("HealthCheckProtocol"), "path": p.get("HealthCheckPath")}],
                "stickiness": stickiness(p),
                "deregistration_delay": settings(p).get("deregistration_delay.timeout_seconds")})
              for p, pid in groups),
            *(("aws_lb_target_group_attachment", {"target_group_arn": pid, "target_id": g.get("Id")})
              for p, pid in groups for g in p.get("Targets") or ())]


def _records(declared):
    """Record sets (in a RecordSetGroup too): an alias by its target (cfn:<logical ID> for a load balancer or
    distribution of the stack), the others with their TTL, values and routing, as the CLI reader takes them."""
    def record(p, raw, zone):
        alias = p.get("AliasTarget")
        return ("aws_route53_record", {
            "name": (p.get("Name") or "").lower().rstrip("."), "zone_id": zone, "type": p.get("Type"),
            **record_attributes({"Type": p.get("Type"), "TTL": number(p.get("TTL")),
                                 "ResourceRecords": [{"Value": v} for v in p.get("ResourceRecords") or ()],
                                 "SetIdentifier": p.get("SetIdentifier"), "Failover": p.get("Failover"),
                                 "Weight": number(p.get("Weight"))}),
            "alias": [{"name": dns_target((raw.get("AliasTarget") or {}).get("DNSName"), alias.get("DNSName")),
                       "zone_id": alias.get("HostedZoneId")}] if isinstance(alias, dict) else []})
    return [*(record(p, raw, p.get("HostedZoneId")) for _, t, p, raw, _ in declared
              if t == "AWS::Route53::RecordSet"),
            *(record(rs, rraw, p.get("HostedZoneId")) for _, t, p, raw, _ in declared
              if t == "AWS::Route53::RecordSetGroup"
              for rs, rraw in zip(p.get("RecordSets") or (), raw.get("RecordSets") or ()))]


def _secrets(declared):
    """Secrets from their ARN (the physical ID), name and tags; SecretString and GenerateSecretString aren't read."""
    return [*(("aws_secretsmanager_secret", {"arn": pid, "name": p.get("Name"), "tags": tag_map(p.get("Tags"))})
              for _, t, p, _, pid in declared if t == "AWS::SecretsManager::Secret"),
            *(("aws_secretsmanager_secret_rotation", {"secret_id": p.get("SecretId"),
                                                      "rotation_lambda_arn": p.get("RotationLambdaARN")})
              for _, t, p, _, _ in declared if t == "AWS::SecretsManager::RotationSchedule" and p.get("SecretId"))]


def _keys(declared, names):
    """KMS keys: the physical ID is the key ID, the ARN is built from the stack's partition, region and account."""
    def arn(key_id):
        where = (names.get("AWS::Partition"), names.get("AWS::Region"), names.get("AWS::AccountId"))
        return f"arn:{where[0]}:kms:{where[1]}:{where[2]}:key/{key_id}" if all(where) else None
    return [*(("aws_kms_key", {"arn": arn(pid), "key_id": pid,
                               "enable_key_rotation": truth(p.get("EnableKeyRotation", False))})
              for _, t, p, _, pid in declared if t == "AWS::KMS::Key" and arn(pid)),     # rotation is off unless set
            *(("aws_kms_replica_key", {"arn": arn(pid), "primary_key_arn": p.get("PrimaryKeyArn")})
              for _, t, p, _, pid in declared if t == "AWS::KMS::ReplicaKey" and arn(pid))]


# job resources: (Terraform type, ARN service, ARN resource part from the physical ID)
JOB_TYPES = MappingProxyType({"AWS::Lambda::Function": ("aws_lambda_function", "lambda", "function:{}"),
                              "AWS::CodePipeline::Pipeline": ("aws_codepipeline", "codepipeline", "{}"),
                              "AWS::CodeBuild::Project": ("aws_codebuild_project", "codebuild", "project/{}")})


def _pattern(pattern):
    """A rule's EventPattern (an object, or its JSON text) as the JSON text Terraform holds it as."""
    return json.dumps(pattern) if isinstance(pattern, dict) else pattern


def _jobs(declared, names):
    """Functions, pipelines and build projects (their ARNs built from the stack's partition, region and account), and
    the enabled EventBridge rules and Scheduler schedules that start them (a Fn::GetAtt X.Arn target is X's ARN)."""
    where = (names.get("AWS::Partition"), names.get("AWS::Region"), names.get("AWS::AccountId"))
    arns = {lg: f"arn:{where[0]}:{JOB_TYPES[t][1]}:{where[1]}:{where[2]}:{JOB_TYPES[t][2].format(pid)}"
            for lg, t, _, _, pid in declared if t in JOB_TYPES and all(where)}

    def target(raw, resolved):
        found = getatt(raw)
        return arns.get(found[0]) if found and found[1] == "Arn" else resolved

    def attrs(lg, t, p, pid):
        given = {"function_name": pid} if t == "AWS::Lambda::Function" else {"name": pid}
        env = p.get("Environment") or {}           # a function's variables; a build project's image
        return {**given, "arn": arns.get(lg), "runtime": p.get("Runtime"), "tags": tag_map(p.get("Tags")),
                "environment": [{"variables": env.get("Variables") or {}}] if t == "AWS::Lambda::Function"
                else {"image": env.get("Image")}}
    enabled = [(lg, t, p, raw, pid) for lg, t, p, raw, pid in declared if p.get("State", "ENABLED") == "ENABLED"]
    return [*((JOB_TYPES[t][0], attrs(lg, t, p, pid)) for lg, t, p, _, pid in declared if t in JOB_TYPES),
            *(("aws_cloudwatch_event_rule", {"name": pid, "schedule_expression": p.get("ScheduleExpression"),
                                              "event_pattern": _pattern(p.get("EventPattern"))})
              for _, t, p, _, pid in enabled if t == "AWS::Events::Rule"),
            *(("aws_cloudwatch_event_target", {"rule": pid, "arn": target(r.get("Arn"), t_.get("Arn"))})
              for _, t, p, raw, pid in enabled if t == "AWS::Events::Rule"
              for r, t_ in zip(raw.get("Targets") or (), p.get("Targets") or ())),
            *(("aws_scheduler_schedule", {"name": pid, "schedule_expression": p.get("ScheduleExpression"),
                                          "target": {"arn": target((raw.get("Target") or {}).get("Arn"),
                                                                   (p.get("Target") or {}).get("Arn"))}})
              for _, t, p, raw, pid in enabled if t == "AWS::Scheduler::Schedule")]


def _trails(declared, names):
    """CloudTrail trails: the trail's ARN from its name (the physical ID) and the stack's partition, region and
    account; properties in CloudTrail's own names (cli_audit.trail_attributes)."""
    def arn(name):
        where = (names.get("AWS::Partition"), names.get("AWS::Region"), names.get("AWS::AccountId"))
        return name if name.startswith("arn:") or not all(where) else \
            f"arn:{where[0]}:cloudtrail:{where[1]}:{where[2]}:trail/{name}"
    return [("aws_cloudtrail", trail_attributes(arn(pid), {"TrailName": pid, **p}, tags=tag_map(p.get("Tags"))))
            for _, t, p, _, pid in declared if t == "AWS::CloudTrail::Trail"]


def stack_pairs(stack, resources, template):
    """((Terraform resource type, attributes) pairs, notices) of one stack."""
    names = _context(stack, resources, template)
    declared = _declared(template, names)
    types = Counter(r.get("Type") for r in (template.get("Resources") or {}).values()
                    if isinstance(r, dict) and r.get("Type") not in READ)
    not_created = [lg for lg, r in (template.get("Resources") or {}).items()
                   if isinstance(r, dict) and not names.get(lg) and r.get("Type") in READ]
    label = stack.get("StackName") or "stack"
    return ([*_network(declared), *_instances(declared, names), *_security_groups(declared), *_egress(declared, names),
             *_load_balancers(declared, names), *_forwarding(declared), *_records(declared), *_secrets(declared),
             *_keys(declared, names), *_jobs(declared, names),
             *(("aws_s3_bucket", {"bucket": pid}) for _, t, _, _, pid in declared if t == "AWS::S3::Bucket"),
             *_trails(declared, names), *network_stack_pairs(declared), *iam_stack_pairs(declared, names),
             *edge_stack_pairs(declared, names, lambda name: (name or "").lower().rstrip(".") or None),
             *data_stack_pairs(declared, names), *security_stack_pairs(declared, names),
             *budget_stack_pairs(declared, names),
             *observability_stack_pairs(declared, names), *backup_stack_pairs(declared, names),
             *compute_stack_pairs(declared, names), *messaging_stack_pairs(declared, names),
             *stack_trust_pairs(declared, tag_map)],
            (*((f"{label}: {', '.join(f'{fn} ({n})' for fn, n in sorted(_unevaluated(template).items()))} not "
                f"evaluated; the attributes computed with them keep the record's values",)
               if _unevaluated(template) else ()),
             *((f"{label}: {len(not_created)} resource(s) without a physical ID (not created, or no stack resources "
                f"listed): {', '.join(not_created[:5])}",) if not_created else ()),
             *((f"{label}: resource types not read: {', '.join(f'{t} ({n})' for t, n in sorted(types.items()))}",)
               if types else ())))


def cloudformation_pairs(texts):
    """((Terraform resource type, attributes) pairs, notices) of an environment's CloudFormation stacks ({path within
    the folder: text}), with the Terraform state of a root kept beside them (*.tfstate: what a CloudFormation render
    keeps in Terraform), read together as one environment."""
    stacks, unknown = _stacks({p: t for p, t in texts.items() if not p.endswith(".tfstate")})
    states = tuple(state_pairs(t) for p, t in sorted(texts.items()) if p.endswith(".tfstate"))
    missing = [f or "." for f, s in stacks.items() if not s.get("template")]
    read = [stack_pairs(s.get("stack") or {}, s.get("resources") or [], s["template"])
            for s in stacks.values() if isinstance(s.get("template"), dict)]
    return ([p for pairs, _ in (*read, *states) for p in pairs],
            (*unknown, *(f"{f}: no template (get-template output or the template file); stack not read"
                         for f in missing), *(n for _, ns in (*read, *states) for n in ns)))


def cloudformation_resources(texts):
    """(resources, notices) of an environment's CloudFormation stacks and the Terraform state kept beside them
    (cloudformation_pairs), read by the state reader's mapping."""
    pairs, notices = cloudformation_pairs(texts)
    resources, rule_notices = pairs_resources(pairs)
    return resources, (*notices, *rule_notices)


SUFFIXES = (".json", ".yaml", ".yml", ".template", ".tfstate")


def read_cloudformation(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from its CloudFormation stacks under <cloud>/<env>/<stack>/,
    with what its edge runs of the record's edge trust policies checked against them (mtls_inventory)."""
    return with_mtls_notices(layout_import(files, d, PROVIDER, "AWS", cloudformation_resources, SUFFIXES,
                                           "CloudFormation stack", "network/template.yaml", summarize=ACCOUNT_WIDE),
                             files, d, SUFFIXES, lambda texts: cloudformation_pairs(texts)[0])


CLOUDFORMATION = Importer("cloudformation", "CloudFormation stacks (template + describe-stacks + list-stack-resources, "
                                            "one folder per stack) under <cloud>/<env>/, as the environment's servers "
                                            "and bindings", read_cloudformation)
