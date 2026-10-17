"""Every type the AWS renderers write, translated to CloudFormation (5.6): the showcase and the CloudFormation sample
(cloudformation_sample: plumbing with peering and VPNs, a CDN front with address rules and Shield Advanced, DNS
failover, Aurora, suppressions, quotas, Macie, Fluent Bit's IRSA role, Cognito's clients, a log group forwarded to a
SIEM through Firehose) rendered in us-east-1 and GovCloud cover the whole mapping, and each translates: every resource
goes exactly one place, the computed forms (an IRSA trust policy, an Aurora member's engine, TXT values, Shield's
automatic response, a Firehose stream's secret-held token) come out as AWS takes them."""
import json

import pytest

from opsdir.connectors.registry import ADAPTERS, environment_specs, services
from opsdir.connectors.render import render_parts
from opsdir_adapter_aws.cfn_render import document_of, object_key
from opsdir_adapter_aws.cfn_types import (DATA, NO_NATIVE, NOT_IN_GOVCLOUD, TYPES, cloudformation_files,
                                          cloudformation_translation)
from opsdir_adapter_aws.cloudformation import cloudformation_resources
from opsdir_adapter_aws.inventory import pairs_resources, state_pairs
from opsdir_adapter_aws.rendered_state import rendered_stacks, rendered_states
from opsdir_adapter_aws.terraform import WHAT, render_files
from opsdir_format_cloudformation.template import sub, template_data
from opsdir_format_terraform.hcl import TfBlock
from opsdir_format_terraform.translate import address, root_items, roots
import cloudformation_sample
from native_parity import Native, differences

REGIONS = ("us-east-1", "us-gov-west-1")


@pytest.fixture(scope="module")
def sample():
    """{region: ((name, model, Terraform files, translation), ...)}."""
    return {r: tuple((n, m, files, cloudformation_translation(m, files, WHAT))
                     for n, m, files in cloudformation_sample.renders(r)) for r in REGIONS}


def _types(files, kind):
    return {b.labels[0] for root in roots(files).values() for b in root_items(root)
            if isinstance(b, TfBlock) and b.kind == kind}


def _resources(t):
    """{logical id: resource document} over a translation's templates."""
    return {lid: r for tpl in t.templates.values() for lid, r in template_data(tpl)["Resources"].items()}


def _by_name(sample, region, name):
    return next(x for x in sample[region] if x[0] == name)


def test_the_showcase_and_the_sample_render_every_type_the_table_knows(sample, estate):
    found = services(ADAPTERS)
    showcase = tuple(render_files(render_parts(d, spec)[0], found) for d in estate.values()
                     for spec in environment_specs(d)
                     if any(a.name == "aws" for a in render_parts(d, spec)[1]))
    rendered = (*showcase, *(files for xs in sample.values() for _, _, files, _ in xs))
    resources = set().union(*(_types(f, "resource") for f in rendered))
    data = set().union(*(_types(f, "data") for f in rendered))
    assert resources - set(TYPES) - NO_NATIVE == set()
    assert data - set(DATA) == set()
    assert set(TYPES) | NO_NATIVE <= resources
    assert set(DATA) <= data


def test_every_terraform_resource_goes_exactly_one_place(sample):
    for region, xs in sample.items():
        for name, _, files, t in xs:
            for directory, root in roots(files).items():
                resources = {address(b) for b in root_items(root) if isinstance(b, TfBlock) and b.kind == "resource"}
                assert set(t.placements[directory]) == resources, (region, name, directory)


def test_what_has_no_native_form_stays_terraform_saying_why(sample):
    places = {a: p for _, _, _, t in sample["us-east-1"] for ps in t.placements.values() for a, p in ps.items()}
    assert places["aws_servicequotas_service_quota.cpus_vcpus"].detail == "no CloudFormation type"
    assert places["aws_default_route_table.rt_main"].kind == "terraform"
    assert places["aws_route_table.rt_ds"].detail == ("adopted (an import block): CloudFormation imports a route by "
                                                     "its table and IPv4 CIDR, which route ::/0 hasn't")
    assert places["aws_macie2_classification_job.macie_weekly"].kind == "terraform"
    assert places["aws_vpc_peering_connection.peer"].kind == "template"
    assert places["aws_vpn_connection_route.vpn_b_0"].kind == "template"


def test_an_irsa_trust_policy_is_its_json_in_one_sub_naming_the_clusters_issuer(sample):
    _, _, _, t = _by_name(sample, "us-east-1", "logs")
    role = next(r for r in _resources(t).values() if r["Type"] == "AWS::IAM::Role"
                and "fluent-bit" in r["Properties"]["RoleName"])
    text = role["Properties"]["AssumeRolePolicyDocument"]["Fn::Sub"]
    issuer = "${EksClusterCiamEksOidcIssuer}"
    document = json.loads(text.replace(issuer, "ISSUER").replace("${AWS::Partition}", "aws")
                          .replace("${AWS::AccountId}", "1"))
    statement = document["Statement"][0]
    assert statement["Principal"] == {"Federated": ["arn:aws:iam::1:oidc-provider/ISSUER"]}
    assert statement["Condition"]["StringEquals"] == {"ISSUER:sub": ["system:serviceaccount:ciam-logging:fluent-bit"],
                                                      "ISSUER:aud": ["sts.amazonaws.com"]}
    parameter = next(p for tpl in t.templates.values() for p in tpl.parameters
                     if p.logical_id == "EksClusterCiamEksOidcIssuer")
    assert "without https://" in parameter.description
    parsed = document_of(role["Properties"]["AssumeRolePolicyDocument"])         # the string form reads back
    assert parsed["Statement"][0]["Condition"]["StringEquals"] == {
        object_key(sub("${EksClusterCiamEksOidcIssuer}:sub")): ["system:serviceaccount:ciam-logging:fluent-bit"],
        object_key(sub("${EksClusterCiamEksOidcIssuer}:aud")): ["sts.amazonaws.com"]}


def test_aurora_members_take_the_clusters_engine_and_txt_values_are_quoted(sample):
    _, _, _, services_t = _by_name(sample, "us-east-1", "services")
    found = _resources(services_t)
    member = next(r for r in found.values() if r["Type"] == "AWS::RDS::DBInstance")["Properties"]
    assert member["Engine"] == "aurora-postgresql" and "EngineVersion" not in member
    assert next(r for r in found.values() if r["Type"] == "AWS::RDS::DBCluster")["Properties"]["EngineVersion"] \
        == "16.4"
    _, _, _, dns = _by_name(sample, "us-east-1", "dns")
    txt = next(r for r in _resources(dns).values() if r["Type"] == "AWS::Route53::RecordSet"
               and r["Properties"]["Type"] == "TXT")
    assert txt["Properties"]["ResourceRecords"] == ['"token=abc"']


def test_shields_automatic_response_is_part_of_the_protection(sample):
    for region in REGIONS:
        _, _, _, t = _by_name(sample, region, "gateway")
        protection = next(r for r in _resources(t).values() if r["Type"] == "AWS::Shield::Protection")
        assert protection["Properties"]["ApplicationLayerAutomaticResponseConfiguration"] == {
            "Action": {"Block": {}}, "Status": "ENABLED"}
        assert "DependsOn" not in protection                    # its ResourceArn already orders it


def test_a_forwarded_log_group_feeds_a_firehose_stream_reading_its_token_from_the_secret(sample):
    """The siem sample's subscription delivers to the stream by its ARN; the stream's Splunk destination holds no
    HECToken (Firehose reads it from Secrets Manager) and keeps what it can't deliver in the partition's bucket."""
    for region in REGIONS:
        _, _, _, t = _by_name(sample, region, "siem")
        found = _resources(t)
        stream_id, stream = next((k, r) for k, r in found.items()
                                 if r["Type"] == "AWS::KinesisFirehose::DeliveryStream")
        splunk = stream["Properties"]["SplunkDestinationConfiguration"]
        assert "HECToken" not in splunk and splunk["SecretsManagerConfiguration"]["Enabled"] is True
        partition = "aws-us-gov" if region.startswith("us-gov-") else "aws"
        assert splunk["S3Configuration"]["BucketARN"] == f"arn:{partition}:s3:::ciam-siem-failed"
        subscription = next(r for r in found.values() if r["Type"] == "AWS::Logs::SubscriptionFilter")["Properties"]
        assert subscription["DestinationArn"] == {"Fn::GetAtt": [stream_id, "Arn"]}
        assert subscription["FilterPattern"] == ""


def test_a_public_cognito_client_is_a_user_pool_client_without_a_secret(sample):
    for region in REGIONS:
        _, _, _, t = _by_name(sample, region, "services")
        clients = [r["Properties"] for r in _resources(t).values() if r["Type"] == "AWS::Cognito::UserPoolClient"]
        assert [(c["ClientName"], c["GenerateSecret"], c["AllowedOAuthFlows"]) for c in clients] == \
            [("mobile", False, ["code"])]                   # the confidential portal client is its own stack


def test_in_govcloud_cloudfront_runs_from_the_standard_accounts_us_east_1_template(sample):
    _, _, _, t = _by_name(sample, "us-gov-west-1", "gateway")
    where = {r["Type"]: path for path, tpl in t.templates.items() for r in template_data(tpl)["Resources"].values()}
    assert where["AWS::CloudFront::Distribution"].endswith("template.us_east_1.yaml")
    assert "aws_cloudfront_distribution" in NOT_IN_GOVCLOUD


# The CloudFormation read-back against the Terraform one (native_parity): both read the same kinds; a physical id
# carries what AWS assigns
CLOUDFORMATION = Native("cloudformation/", lambda m, files: cloudformation_files(m, files, WHAT), rendered_stacks,
                        cloudformation_resources, rendered_states, state_pairs, pairs_resources,
                        frozenset(), frozenset())


def test_the_native_read_back_reads_what_the_terraform_one_does(sample):
    """Every environment of the sample (but Fluent Bit's, whose render takes its own log sources) reads back the same
    resources both ways (native_parity.differences), but what only Terraform reads."""
    for name, m, files, _ in sample["us-east-1"]:
        if name != "logs":
            assert differences(CLOUDFORMATION, m, files, "alpha/prod") == (set(), set(), {}), name


def test_the_showcases_native_read_back_reads_what_the_terraform_one_does(estate):
    """So does every AWS environment of the showcase, before and after the approved changes: volumes and their
    snapshot policy, backups, alarms and canaries included."""
    found, checked = services(ADAPTERS), []
    for state, d in estate.items():
        for spec in environment_specs(d):
            m, adapters = render_parts(d, spec)[:2]
            if any(a.name == "aws" for a in adapters):
                assert differences(CLOUDFORMATION, m, render_files(m, found), spec) == (set(), set(), {}), \
                    (state, spec)
                checked.append(spec)
    assert checked
