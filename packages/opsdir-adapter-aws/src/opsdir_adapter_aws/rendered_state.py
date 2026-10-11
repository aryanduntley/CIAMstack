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
    block: region, allowed_account_ids), and what AWS assigns its type (ASSIGNS: a load balancer's DNS name and zone);
  - tags_all: the provider's default_tags under the resource's tags, as the provider records them;
  - the data sources AWS answers from the account itself (aws_partition, aws_caller_identity, aws_region).
"""
import re
from types import MappingProxyType

from opsdir.core.directory import one
from opsdir.core.environment import env_dn, env_model
from opsdir_format_terraform.hcl import Block
from opsdir_format_terraform.realized import realized
from opsdir_format_terraform.state_builder import root_states, synthetic

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
    "aws_iam_role": "ciamIdentityBinding", "aws_securityhub_automation_rule": "ciamSuppression"})
# What AWS assigns a resource of a type beyond its id and ARN, as the importers read it: (block name, configured
# attributes, partition, region, account) -> attributes
ASSIGNS = MappingProxyType({
    "aws_lb": lambda name, configured, partition, region, account: {
        "dns_name": f"{name.replace('_', '-')}-0.{region}.elb.amazonaws.com",
        "zone_id": f"ZELB{region.upper().replace('-', '')}"},
    "aws_iam_openid_connect_provider": lambda name, configured, partition, region, account: {
        "arn": f"arn:{partition}:iam::{account}:oidc-provider/"
               + str(configured.get("url", name)).removeprefix("https://")}})


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


def rendered_states(files, d, environment):
    """The ReadBack's prepare: the rendered Terraform roots of an environment ({<cloud>/<env>/...tf: text}) as the
    states applying them would record ({<cloud>/<env>/<root>.tfstate: text}), what AWS assigns from record d."""
    m = env_model(d, env_dn(environment))
    return root_states(files, environment, lambda blocks: aws_assigned(m, blocks))
