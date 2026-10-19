"""AWS: what applying an environment's rendered Terraform would record, so aws/terraform-state reads the render back
(the round trip, milestone 5.5c). Pure.

Each rendered root (terraform/, terraform/landing-zone/, ...) becomes a Terraform state (opsdir_format_terraform.
state_builder): what its blocks configure, and what AWS would assign, which this module gives from the record the
render was made from:
  - a resource realizing a binding the record holds (REALIZES: its type and the binding's object class; the block
    named after the binding, tf_name of its name, a forwarder's rules numbered _0, _1, ...) gets that binding's
    provider reference as the importer reads it: an ARN as arn (its last part as id), a composite reference
    (inspector2:<id>) as id, any other as id;
  - any other resource an AWS-shaped synthetic id and ARN, in the root's partition, region and account (its provider
    block: region, allowed_account_ids), and what AWS assigns its type (ASSIGNS: a load balancer's DNS name and zone,
    a Firehose stream's ARN);
  - tags_all: the provider's default_tags under the resource's tags, as the provider records them;
  - the data sources AWS answers from the account itself (aws_partition, aws_caller_identity, aws_region).

A CloudFormation render (5.6c, decision 2629) reads back through aws/cloudformation: each template becomes a stack
folder as the CLI saves one (rendered_stacks): the template, describe-stacks (its parameters' defaults, the stack in
the cloud's region and account, or the region its provider alias names) and list-stack-resources, each resource's
physical id what the Terraform read-back assigns the address it came from (placements.json): the provider reference
of a binding it realizes, else the address; each Terraform root kept beside the templates (applied after them, or
before them: what they read) becomes its state.
"""
import json
import posixpath
import re
from types import MappingProxyType

from opsdir.core.directory import one
from opsdir.core.environment import env_dn, env_model
from opsdir_format_terraform.hcl import Block
from opsdir_format_cloudformation.template import logical_id
from opsdir_format_terraform.native import placements_of, side_inputs
from opsdir_format_terraform.realized import realized
from opsdir_format_terraform.state_builder import root_states, synthetic
from .cfn_render import BEFORE_ROOT
from .cloudformation import read_document, stack_outputs

# Resource types realizing a binding the record matches by its provider reference -> the binding's object class
REALIZES = MappingProxyType({
    "aws_network_acl": "ciamNetworkAcl", "aws_flow_log": "ciamFlowLog", "aws_route_table": "ciamRouteTable",
    "aws_vpc_endpoint": "ciamPrivateEndpoint", "aws_vpc_endpoint_service": "ciamEndpointService",
    "aws_guardduty_detector": "ciamSecurityService", "aws_inspector2_enabler": "ciamSecurityService",
    "aws_securityhub_account": "ciamSecurityService", "aws_macie2_classification_job": "ciamDataDiscovery",
    "aws_lambda_function": "ciamDataDiscovery",          # a data discovery's scheduler (discovery.py)
    "aws_db_instance": "ciamDatabase", "aws_rds_cluster": "ciamDatabase", "aws_budgets_budget": "ciamBudget",
    "aws_route53_resolver_rule": "ciamDnsForwarder", "aws_organizations_policy": "ciamGuardrail",
    "aws_cloudtrail": "ciamAuditTrail", "aws_cloudwatch_log_group": "ciamLogDestination",
    "aws_cloudwatch_metric_alarm": "ciamAlarmBinding", "aws_synthetics_canary": "ciamCanaryBinding",
    "aws_iam_role": "ciamIdentityBinding", "aws_securityhub_automation_rule": "ciamSuppression",
    "aws_autoscaling_group": "ciamComputeGroup", "aws_cognito_user_pool": "ciamManagedIdentity"})
# What AWS assigns a resource of a type beyond its id and ARN, as the importers read it: (block name, configured
# attributes, partition, region, account) -> attributes
ASSIGNS = MappingProxyType({
    "aws_lb": lambda name, configured, partition, region, account: {
        "dns_name": f"{name.replace('_', '-')}-0.{region}.elb.amazonaws.com",
        "zone_id": f"ZELB{region.upper().replace('-', '')}"},
    # an RDS cluster's id is its identifier (what its members' cluster_identifier names)
    "aws_rds_cluster": lambda name, configured, partition, region, account: {
        "id": configured.get("cluster_identifier", name)},
    "aws_iam_openid_connect_provider": lambda name, configured, partition, region, account: {
        "arn": f"arn:{partition}:iam::{account}:oidc-provider/"
               + str(configured.get("url", name)).removeprefix("https://")},
    # a Firehose stream's ARN names it (what a role's grant on it reads, as the CloudFormation read-back makes it)
    "aws_kinesis_firehose_delivery_stream": lambda name, configured, partition, region, account: {
        "arn": f"arn:{partition}:firehose:{region}:{account}:deliverystream/{configured.get('name', name)}"},
    # an SQS queue's ARN names it (what the pull's reader role is granted on, as the CloudFormation read-back makes it)
    "aws_sqs_queue": lambda name, configured, partition, region, account: {
        "arn": f"arn:{partition}:sqs:{region}:{account}:{configured.get('name', name)}"}})


def _unquote(k):
    return k[1:-1] if len(k) > 1 and k[0] == k[-1] == '"' else k


def provider_facts(blocks):
    """(partition, region, account, default tags) of a root's default aws provider block."""
    body = next((b.body for b in blocks if b.kind == "provider" and b.labels == ("aws",)
                 and not any(k == "alias" for k, _ in b.body)), ())
    region = next((v for k, v in body if k == "region"), "") or ""
    account = next((v[0] for k, v in body if k == "allowed_account_ids" and v), "000000000000")
    defaults = next((v for k, v in body if k == "default_tags" and isinstance(v, Block)), Block(()))
    tags = next((v for k, v in defaults.body if k == "tags" and isinstance(v, dict)), {})
    partition = "aws-us-gov" if region.startswith("us-gov-") else "aws"
    return partition, region, account, {_unquote(k): v for k, v in tags.items()}


def reference_attributes(ref):
    """The attributes a provider reference is read back from: an ARN as arn (its last part as id), a composite
    reference ('inspector2:<id>') as id, any other as id."""
    if ref.startswith("arn:"):
        return {"arn": ref, "id": re.split(r"[/:]", ref)[-1]}
    return {"id": ref.split(":", 1)[1] if ":" in ref else ref}


def aws_assigned(m, blocks):
    """assigned() for one rendered root of environment m (see opsdir_format_terraform.state_builder.tf_state)."""
    partition, region, account, default_tags = provider_facts(blocks)
    answers = {"aws_partition": {"partition": partition, "dns_suffix": "amazonaws.com", "id": partition},
               "aws_caller_identity": {"account_id": account, "id": account,
                                       "arn": f"arn:{partition}:iam::{account}:role/opsdir-round-trip"},
               "aws_region": {"name": region, "region": region, "id": region}}

    def assigned(mode, type_, name, index, configured):
        if mode == "data":
            return {**synthetic(mode, type_, name, index, configured), **answers.get(type_, {})}
        binding = realized(m, REALIZES, type_, name)
        ref = one(binding, "ciamProviderRef") if binding is not None else None
        made = {**synthetic(mode, type_, name, index, configured),
                "arn": f"arn:{partition}:{type_[4:]}:{region}:{account}:{name}" + (f"/{index}" if index else ""),
                **(ASSIGNS[type_](name, configured, partition, region, account) if type_ in ASSIGNS else {})}
        tagged = {"tags_all": {**default_tags, **configured.get("tags", {})}} if default_tags else {}
        return {**made, **tagged, **(reference_attributes(ref) if ref else {})}
    return assigned


# What CloudFormation's physical id (Ref) of a type is, where it isn't the resource's id: a name property of the
# template (S3's bucket name), or its ARN
PHYSICAL_NAMES = MappingProxyType({
    "AWS::S3::Bucket": "BucketName", "AWS::IAM::Role": "RoleName", "AWS::RDS::DBInstance": "DBInstanceIdentifier",
    "AWS::RDS::DBCluster": "DBClusterIdentifier", "AWS::RDS::DBSubnetGroup": "DBSubnetGroupName",
    "AWS::RDS::DBParameterGroup": "DBParameterGroupName",
    "AWS::RDS::DBClusterParameterGroup": "DBClusterParameterGroupName", "AWS::Logs::LogGroup": "LogGroupName",
    "AWS::Backup::BackupVault": "BackupVaultName", "AWS::CloudWatch::Alarm": "AlarmName",
    "AWS::Synthetics::Canary": "Name", "AWS::Config::ConfigurationRecorder": "Name",
    "AWS::Config::DeliveryChannel": "Name", "AWS::KinesisFirehose::DeliveryStream": "DeliveryStreamName",
    "AWS::SQS::Queue": "QueueName"})     # a real queue's physical id is its URL; the reader takes its last segment
# Physical ids made from the template's properties (an OIDC provider's ARN names its issuer), as aws_assigned makes
# the ARN of the Terraform type it came from: (properties, partition, account) -> the physical id
PHYSICAL_MADE = MappingProxyType({
    "AWS::Budgets::Budget": lambda props, partition, account: (props.get("Budget") or {}).get("BudgetName"),
    "AWS::IAM::OIDCProvider": lambda props, partition, account:
        f"arn:{partition}:iam::{account}:oidc-provider/" + str(props.get("Url", "")).removeprefix("https://")})
PHYSICAL_ARNS = frozenset({"AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancingV2::TargetGroup",
                           "AWS::ElasticLoadBalancingV2::Listener", "AWS::SecretsManager::Secret",
                           "AWS::IAM::ManagedPolicy", "AWS::SSO::PermissionSet", "AWS::Organizations::Policy",
                           "AWS::WAFv2::WebACL", "AWS::WAFv2::IPSet", "AWS::Shield::Protection",
                           "AWS::SecurityHub::AutomationRule", "AWS::SecurityHub::Hub",
                           "AWS::ElasticLoadBalancingV2::TrustStore"})


def _physical_id(m, address, resource, arn_of, made):
    """The physical id applying gives the native resource (a template's Resources entry) a Terraform address became,
    as the Terraform read-back assigns it: the name property the type's physical id is (PHYSICAL_NAMES), or what
    made(properties) makes of the template's properties (PHYSICAL_MADE: a budget's nested name, an OIDC provider's
    ARN), when the template gives it; else a binding it realizes gives its provider reference (its ARN where the type's
    physical id is one, else its id); else the ARN arn_of(Terraform type, name) gives (PHYSICAL_ARNS), or the address
    (the read-back's synthetic id)."""
    type_, name = address.split("[", 1)[0].split(".", 1)
    kind, props = resource.get("Type"), resource.get("Properties") or {}
    binding = realized(m, REALIZES, type_, name)
    ref = one(binding, "ciamProviderRef") if binding is not None else None
    held = reference_attributes(ref) if ref else {}
    named = props.get(PHYSICAL_NAMES[kind]) if kind in PHYSICAL_NAMES else \
        made(kind, props) if kind in PHYSICAL_MADE else None
    if isinstance(named, str):
        return named
    return (held.get("arn", held.get("id")) if kind in PHYSICAL_ARNS else held.get("id")) if held else \
        arn_of(type_, name) if kind in PHYSICAL_ARNS else address


_REGION = re.compile(r"^[a-z]{2}(?:_gov)?_[a-z]+_\d$")


def _stack_documents(m, path, text, origins):
    """(folder, describe-stacks entry, list-stack-resources entries, template) of one rendered template as applying it
    would record; origins: {logical id: the Terraform address it came from}."""
    doc = read_document(text) or {}
    stem = posixpath.basename(path)[:-len(".yaml")]
    alias = stem.split(".", 1)[1] if "." in stem else None
    region = alias.replace("_", "-") if alias and _REGION.match(alias) else one(m.cloud, "ciamRegion") or ""
    gov = (one(m.cloud, "ciamRegion") or "").startswith("us-gov-")
    account = (one(m.cloud, "ciamBillingAccountRef") if gov and not region.startswith("us-gov-") else None) or \
        one(m.cloud, "ciamAccountRef") or "000000000000"
    folder = f"{posixpath.dirname(path)}/{stem.replace('.', '-')}"
    name = folder.split("/", 2)[-1].replace("/", "-")
    partition = "aws-us-gov" if region.startswith("us-gov-") else "aws"
    stack = {"StackName": name, "StackId": f"arn:{partition}:cloudformation:{region}:{account}:stack/{name}/read-back",
             "Parameters": [{"ParameterKey": k, "ParameterValue": str(p["Default"])}
                            for k, p in (doc.get("Parameters") or {}).items()
                            if isinstance(p, dict) and "Default" in p]}

    def arn_of(type_, resource_name):
        return f"arn:{partition}:{type_[4:]}:{region}:{account}:{resource_name}"     # as aws_assigned writes one
    resources = [{"LogicalResourceId": lid, "ResourceType": r.get("Type"), "ResourceStatus": "CREATE_COMPLETE",
                  "PhysicalResourceId": _physical_id(m, origins[lid], r, arn_of, lambda kind, props:
                                                     PHYSICAL_MADE[kind](props, partition, account))
                  if lid in origins else lid}
                 for lid, r in (doc.get("Resources") or {}).items() if isinstance(r, dict)]
    return folder, stack, resources, doc


def _given(stack, doc, outputs):
    """A stack's parameters with what the deployer passes another stack's outputs as (a parameter without a default
    that names one of them, as the render names a value across templates)."""
    held = {p["ParameterKey"] for p in stack["Parameters"]}
    return {**stack, "Parameters": [*stack["Parameters"], *(
        {"ParameterKey": k, "ParameterValue": str(outputs[k])} for k in (doc.get("Parameters") or {})
        if k not in held and outputs.get(k) is not None)]}


def rendered_stacks(files, d, environment):
    """The CloudFormation ReadBack's prepare: an environment's rendered CloudFormation ({<cloud>/<env>/...: text}) as
    applying it would record: each template a stack folder (template, describe-stacks, list-stack-resources: the
    physical ids from its root's placements.json and the record d; the values a stack takes from another's outputs
    passed as its parameters), each Terraform root kept beside them (terraform/ and BEFORE_ROOT/) its state (its
    variables the templates' outputs they name)."""
    m = env_model(d, env_dn(environment))
    places = {p.rsplit("/", 1)[0]: placements_of(json.loads(t), lambda where, root=p.rsplit("/", 1)[0]:
                                                 posixpath.join(root, where))
              for p, t in files.items() if p.endswith("/placements.json")}
    templates = tuple(p for p in sorted(files) if p.endswith(".yaml") and posixpath.dirname(p) in places)
    built = tuple((p, *_stack_documents(m, p, files[p], {
        pl.detail: a for a, pl in places[posixpath.dirname(p)].items() if pl.kind == "template" and pl.where == p}))
        for p in templates)
    outputs = {k: v for _, _, stack, resources, doc in built for k, v in stack_outputs(stack, resources, doc).items()}
    stacks = {k: v for p, folder, stack, resources, doc in built for k, v in (
        (f"{folder}/template.yaml", files[p]),
        (f"{folder}/stack.json", json.dumps({"Stacks": [_given(stack, doc, outputs)]})),
        (f"{folder}/resources.json", json.dumps({"StackResourceSummaries": resources})))}
    side = {p: t for p, t in files.items() if p.endswith(".tf") and posixpath.basename(posixpath.dirname(p))
            in ("terraform", BEFORE_ROOT) and posixpath.dirname(posixpath.dirname(p)) in places}
    return {**stacks, **root_states(side, environment, lambda blocks: aws_assigned(m, blocks),
                                    side_inputs(side, outputs, logical_id))}


def rendered_states(files, d, environment):
    """The ReadBack's prepare: the rendered Terraform roots of an environment ({<cloud>/<env>/...tf: text}) as the
    states applying them would record ({<cloud>/<env>/<root>.tfstate: text}), what AWS assigns from record d."""
    m = env_model(d, env_dn(environment))
    return root_states(files, environment, lambda blocks: aws_assigned(m, blocks))
