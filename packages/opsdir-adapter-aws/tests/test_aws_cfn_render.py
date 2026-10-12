"""AWS CloudFormation translated from the AWS render's Terraform data (5.6): values (references, interpolations,
jsonencode documents, indexed lookups), a root's resources as templates (merges, expansions, the provider's default
tags, comments), lookups as parameters, adopted resources imported (or kept in Terraform when CloudFormation can't
import them as Terraform does), what has no native form in a Terraform root beside the template reading its outputs,
an aliased provider's resources in a template of their own, and refusals of what the table doesn't know."""
import json
from types import SimpleNamespace

import pytest

from opsdir_format_cloudformation.template import get_att, ref, sub
from opsdir_format_terraform.hcl import Block, TfFile, comment, ref as tf_ref, tf_block, tf_import
from opsdir_format_terraform.translate import TfRef
from opsdir_adapter_aws.cfn_render import concat, document_of, json_document, object_key, referenced_ids, translate, \
    trim_prefix
from opsdir_adapter_aws.cfn_types import NO_EGRESS, cloudformation_files, cloudformation_translation

M = SimpleNamespace(dn="env=prod,cloud=alpha,ou=environments,dc=ciam-ops", label="alpha/prod")
WHAT = "AWS infrastructure"


def resolve(r):
    return {"aws_vpc": ref("Vpc"), "aws_s3_bucket": get_att("Bucket", "Arn")}.get(r.type, ref(r.name))


@pytest.mark.parametrize("value, expected", [
    ("plain", "plain"),
    (tf_ref("aws_vpc.main.id"), ref("Vpc")),
    ("${aws_s3_bucket.b.arn}/*", sub("${Bucket.Arn}/*")),
    ("arn:${var.partition}:s3:::x-$y", sub("arn:${partition}:s3:::x-$y")),
    (tf_ref('"${var.a},${var.b}"'), sub("${a},${b}")),
    (tf_ref('jsonencode({"Resource" : "${aws_s3_bucket.b.arn}/*", "N" : 1})'),
     {"Resource": sub("${Bucket.Arn}/*"), "N": 1}),
    (tf_ref("tolist(data.aws_ssoadmin_instances.sso.arns)[0]"), ref("sso")),
    (["${var.x}", 2, {"k": "${var.y}"}], [ref("x"), 2, {"k": ref("y")}])])
def test_terraform_values_as_cloudformation_values(value, expected):
    def resolve_indexed(r):
        assert r.attr != "arns" and (r.attr == "arns[0]" or r.kind != "data")
        return resolve(r)
    assert translate(value, resolve_indexed) == expected


def test_an_expression_with_no_native_form_is_refused_by_name():
    with pytest.raises(SystemExit, match="no CloudFormation form for the Terraform expression 'cidrsubnet"):
        translate(tf_ref('cidrsubnet(var.cidr, 8, 1)'), resolve)


PROVIDERS = TfFile("", (
    tf_block("terraform", [], [("required_version", ">= 1.6")]),
    tf_block("provider", ["aws"], [("region", "us-east-1"), ("default_tags", Block((("tags", {"Owner": "ciam"}),)))]),
    tf_block("provider", ["aws"], [("alias", "us_west_2"), ("region", "us-west-2")]),
    tf_block("variable", ["backup_role_arn"], [("type", tf_ref("string")), ("description", "The replication role")])))
MAIN = TfFile("", (
    tf_block("data", ["aws_vpc", "main"], [("id", "vpc-1")]),
    tf_block("data", ["aws_subnet", "a"], [("id", "subnet-1")]),
    comment("the servers' group"),
    tf_block("resource", ["aws_security_group", "ds"], [("name", "ds"), ("description", "DS"),
                                                        ("vpc_id", tf_ref("data.aws_vpc.main.id"))]),
    tf_block("resource", ["aws_security_group", "alb"], [("name", "alb"), ("description", "ALB"),
                                                         ("vpc_id", tf_ref("data.aws_vpc.main.id"))]),
    tf_block("resource", ["aws_vpc_security_group_egress_rule", "alb_to_ds"], [
        ("security_group_id", tf_ref("aws_security_group.alb.id")),
        ("referenced_security_group_id", tf_ref("aws_security_group.ds.id")), ("from_port", 443), ("to_port", 443),
        ("ip_protocol", "tcp")]),
    tf_block("resource", ["aws_vpc_security_group_ingress_rule", "ds_from_alb"], [
        ("security_group_id", tf_ref("aws_security_group.ds.id")),
        ("referenced_security_group_id", tf_ref("aws_security_group.alb.id")), ("from_port", 443), ("to_port", 443),
        ("ip_protocol", "tcp")]),
    tf_block("resource", ["aws_s3_bucket", "backup"], [("bucket", "backups"), ("tags", {"Role": "backup"})]),
    tf_block("resource", ["aws_s3_bucket_versioning", "backup"], [
        ("bucket", tf_ref("aws_s3_bucket.backup.id")), ("versioning_configuration", Block((("status", "Enabled"),)))]),
    tf_import("aws_s3_bucket.backup", "backups"),
    tf_block("resource", ["aws_instance", "ds_1"], [
        ("ami", "ami-1"), ("instance_type", "m6i.large"), ("subnet_id", tf_ref("data.aws_subnet.a.id")),
        ("vpc_security_group_ids", [tf_ref("aws_security_group.ds.id")]),
        ("root_block_device", Block((("encrypted", True),)))]),
    tf_block("resource", ["aws_route_table", "private"], [
        ("vpc_id", tf_ref("data.aws_vpc.main.id")),
        ("route", Block((("cidr_block", "0.0.0.0/0"), ("nat_gateway_id", "nat-1"))))]),
    tf_import("aws_route_table.private", "rtb-1"),
    tf_block("resource", ["aws_route_table_association", "private_a"], [
        ("subnet_id", tf_ref("data.aws_subnet.a.id")), ("route_table_id", tf_ref("aws_route_table.private.id"))]),
    tf_import("aws_route_table_association.private_a", "subnet-1/rtb-1"),
    tf_block("resource", ["aws_config_retention_configuration", "config"], [("retention_period_in_days", 2557)]),
    tf_block("resource", ["aws_macie2_classification_export_configuration", "macie"], [
        ("s3_destination", Block((("bucket_name", tf_ref("aws_s3_bucket.backup.id")),)))]),
    tf_block("resource", ["aws_cloudwatch_log_group", "copies"], [("provider", tf_ref("aws.us_west_2")),
                                                                  ("name", "/copies"), ("retention_in_days", 7)]),
    tf_block("resource", ["aws_cloudwatch_metric_alarm", "copies"], [
        ("alarm_name", "copies"), ("namespace", "X"), ("metric_name", "Y"), ("statistic", "Sum"), ("period", 60),
        ("evaluation_periods", 1), ("comparison_operator", "GreaterThanThreshold"), ("threshold", 1),
        ("alarm_description", "${aws_cloudwatch_log_group.copies.name} grows")])))
FILES = {"terraform/providers.tf": PROVIDERS, "terraform/main.tf": MAIN, "terraform/scripts/x.py": "print(1)\n"}


@pytest.fixture(scope="module")
def done():
    return cloudformation_translation(M, FILES, WHAT)


def _resources(t):
    return {r.logical_id: r for r in t.resources}


def test_a_root_is_a_template_per_provider_with_the_files_it_packages(done):
    assert set(done.templates) == {"cloudformation/template.yaml", "cloudformation/template.us_west_2.yaml"}
    assert done.packaged == {"cloudformation/scripts/x.py": "print(1)\n"}
    main = done.templates["cloudformation/template.yaml"]
    assert main.metadata["cfn-lint"]["config"]["regions"] == ["us-east-1"]
    assert done.templates["cloudformation/template.us_west_2.yaml"].metadata["cfn-lint"]["config"]["regions"] == \
        ["us-west-2"]


def test_lookups_are_parameters_with_the_records_ids_and_variables_their_own(done):
    params = {p.logical_id: p for p in done.templates["cloudformation/template.yaml"].parameters}
    assert (params["VpcMain"].type, params["VpcMain"].default) == ("AWS::EC2::VPC::Id", "vpc-1")
    assert (params["SubnetA"].type, params["SubnetA"].default) == ("AWS::EC2::Subnet::Id", "subnet-1")
    assert params["RootDeviceAmi1"].default is None and "root device name of AMI ami-1" in params[
        "RootDeviceAmi1"].description


def test_security_groups_keep_terraform_s_egress_and_rules_reference_without_cycles(done):
    r = _resources(done.templates["cloudformation/template.yaml"])
    assert r["SecurityGroupDs"].properties["SecurityGroupEgress"] == [NO_EGRESS]
    assert r["SecurityGroupAlb"].properties["SecurityGroupEgress"] == [{
        "DestinationSecurityGroupId": get_att("SecurityGroupDs", "GroupId"), "FromPort": 443, "ToPort": 443,
        "IpProtocol": "tcp"}]
    assert r["VpcSecurityGroupIngressRuleDsFromAlb"].properties["SourceSecurityGroupId"] == \
        get_att("SecurityGroupAlb", "GroupId")
    assert "VpcSecurityGroupEgressRuleAlbToDs" not in r
    assert r["SecurityGroupDs"].metadata == {"Comments": ["the servers' group"]}


def test_merged_settings_default_tags_and_an_adopted_resource_imported(done):
    bucket = _resources(done.templates["cloudformation/template.yaml"])["S3BucketBackup"]
    assert bucket.properties["VersioningConfiguration"] == {"Status": "Enabled"}
    assert bucket.properties["Tags"] == [{"Key": "Owner", "Value": "ciam"}, {"Key": "Role", "Value": "backup"}]
    assert (bucket.deletion_policy, bucket.update_replace_policy) == ("Retain", "Retain")
    imports = done.imports["cloudformation/template.resources-to-import.json"]
    assert {"ResourceType": "AWS::S3::Bucket", "LogicalResourceId": "S3BucketBackup",
            "ResourceIdentifier": {"BucketName": "backups"}} in imports
    assert {"ResourceType": "AWS::EC2::Route", "LogicalResourceId": "RouteTablePrivateRoute0",
            "ResourceIdentifier": {"RouteTableId": "rtb-1", "CidrBlock": "0.0.0.0/0"}} in imports
    instance = _resources(done.templates["cloudformation/template.yaml"])["InstanceDs1"]
    assert instance.properties["BlockDeviceMappings"] == [{"DeviceName": ref("RootDeviceAmi1"),
                                                           "Ebs": {"Encrypted": True}}]


def test_what_stays_terraform_is_beside_the_template_with_why_reading_its_outputs(done):
    places = done.placements["terraform"]
    assert places["aws_s3_bucket_versioning.backup"].kind == "merged"
    assert places["aws_route_table_association.private_a"].detail.startswith("adopted (an import block)")
    assert places["aws_config_retention_configuration.config"].detail == "no CloudFormation type"
    side = done.side["cloudformation/terraform/main.tf"]
    assert "#   aws_macie2_classification_export_configuration.macie: no CloudFormation type" in side.head
    kept = {b.labels[1] for b in side.items if hasattr(b, "kind") and b.kind == "resource"}
    assert kept == {"private_a", "config", "macie"}
    outputs = {o.logical_id: o for o in done.templates["cloudformation/template.yaml"].outputs}
    assert outputs["AwsS3BucketBackupId"].value == ref("S3BucketBackup")
    assert outputs["AwsRouteTablePrivateId"].value == ref("RouteTablePrivate")


def test_another_provider_s_resources_are_another_template_read_through_parameters(done):
    main, west = (done.templates[f"cloudformation/{n}"] for n in ("template.yaml", "template.us_west_2.yaml"))
    assert [r.logical_id for r in west.resources] == ["CloudwatchLogGroupCopies"]
    assert [o.logical_id for o in west.outputs] == ["AwsCloudwatchLogGroupCopiesName"]
    alarm = _resources(main)["CloudwatchMetricAlarmCopies"]
    assert alarm.properties["AlarmDescription"] == sub("${AwsCloudwatchLogGroupCopiesName} grows")
    assert "AwsCloudwatchLogGroupCopiesName" in {p.logical_id for p in main.parameters}


def test_the_files_are_written_with_headers():
    files = cloudformation_files(M, FILES, WHAT)
    assert files["cloudformation/template.yaml"].startswith("# Generated by opsdir from env=prod,cloud=alpha")
    assert '"LogicalResourceId": "S3BucketBackup"' in files["cloudformation/template.resources-to-import.json"]
    assert isinstance(files["cloudformation/terraform/main.tf"], TfFile)


def _one(*blocks):
    return {"terraform/main.tf": TfFile("", (tf_block("provider", ["aws"], [("region", "us-east-1")]), *blocks))}


@pytest.mark.parametrize("block, refusal", [
    (tf_block("resource", ["aws_nosuch_thing", "x"], []), "no CloudFormation mapping for aws_nosuch_thing"),
    (tf_block("resource", ["aws_cloudwatch_log_group", "x"], [("name", "x"), ("skip_destroy", True)]),
     "aws_cloudwatch_log_group.x: no CloudFormation form for skip_destroy"),
    (tf_block("resource", ["aws_volume_attachment", "x"], [("device_name", "/dev/sdf"), ("tags", {"a": "b"})]),
     "tagged in Terraform, but its CloudFormation type takes no tags"),
    (tf_block("resource", ["aws_iam_role", "r"], [("name", "r"), ("assume_role_policy", "{}"),
                                                  ("description", "${aws_iam_role.r.create_date}")]),
     "no CloudFormation form for attribute 'create_date'")])
def test_what_the_table_doesn_t_know_is_refused_by_name(block, refusal):
    with pytest.raises(SystemExit, match=refusal):
        cloudformation_translation(M, _one(block), WHAT)


def test_govcloud_keeps_types_its_cloudformation_lacks_in_terraform():
    gov = {"terraform/main.tf": TfFile("", (
        tf_block("provider", ["aws"], [("region", "us-gov-west-1")]),
        tf_block("resource", ["aws_macie2_account", "macie"], [("status", "ENABLED")])))}
    done = cloudformation_translation(M, gov, WHAT)
    assert done.placements["terraform"]["aws_macie2_account.macie"].detail == \
        "no CloudFormation type in us-gov-west-1"
    assert TfRef  # the translate types are format-terraform's


# ------------------------------------------------------------------ 5.6 (d2): values computed natively

def test_values_concatenate_into_one_sub_inlining_others():
    assert concat("a", "b") == "ab" and concat(ref("X")) == ref("X")
    assert concat("arn:", ref("AWS::Partition"), ":x/", get_att("B", "Arn")) == \
        sub("arn:${AWS::Partition}:x/${B.Arn}")
    assert concat("https://", sub("${A}-${V0}", {"V0": {"Fn::Select": [0, ref("L")]}}), "/$x${y}") == \
        sub("https://${A}-${V1V0}/$x${!y}", {"V1V0": {"Fn::Select": [0, ref("L")]}})


@pytest.mark.parametrize("value, prefix, expected", [
    ("https://x", "https://", "x"), ("x", "https://", "x"),
    (sub("https://${I}"), "https://", ref("I")), (sub("https://${B.Arn}/p"), "https://", sub("${B.Arn}/p")),
    (sub("ftp://${I}"), "https://", sub("ftp://${I}"))])
def test_trimprefix_strips_a_known_leading_text(value, prefix, expected):
    assert trim_prefix(value, prefix) == expected


def test_trimprefix_of_a_value_known_only_at_deploy_time_is_refused():
    with pytest.raises(SystemExit, match="known only at deploy time"):
        trim_prefix(ref("I"), "https://")
    with pytest.raises(SystemExit, match="known only at deploy time"):
        trim_prefix(sub("http${I}"), "https://")


def test_join_and_trimprefix_expressions_are_evaluated():
    def resolve(r):
        return sub("https://${Issuer}") if r.attr == "identity[0].oidc[0].issuer" else ref(r.name)
    expr = tf_ref('join(":", [trimprefix(data.aws_eks_cluster.k.identity[0].oidc[0].issuer, "https://"), "sub"])')
    assert translate(expr, resolve) == sub("${Issuer}:sub")
    assert translate(tf_ref('join(",", ["a", var.b])'), resolve) == sub("a,${b}")
    assert translate(tf_ref('join(",", var.list)'), resolve) == {"Fn::Join": [",", ref("list")]}


def test_a_document_with_a_computed_key_is_its_json_text_in_one_sub():
    plain = {"Statement": [{"Resource": ref("B")}]}
    assert json_document(plain) == plain
    document = {"Condition": {"StringEquals": {object_key(sub("${I}:sub")): ["a"]}}, "Note": "${aws:username}"}
    assert json_document(document) == sub('{"Condition": {"StringEquals": {"${I}:sub": ["a"]}}, '
                                          '"Note": "${!aws:username}"}')


def test_dependencies_a_reference_already_orders_are_found():
    assert referenced_ids({"A": [ref("X"), get_att("Y", "Arn")], "B": sub("${Z.Arn}/${AWS::Region}/${V}",
                                                                          {"V": ref("W")})}) == \
        {"X", "Y", "Z", "AWS::Region", "W"}


ISSUER_KEY = ('join(":", [trimprefix(data.aws_eks_cluster.k.identity[0].oidc[0].issuer, "https://"), '
              '"sub"])')
STATEMENT = Block((
    ("actions", ["sts:AssumeRoleWithWebIdentity"]),
    ("principals", Block((("type", "Federated"),
                          ("identifiers", [tf_ref("data.aws_iam_openid_connect_provider.k.arn")])))),
    ("condition", Block((("test", "StringEquals"), ("variable", tf_ref(ISSUER_KEY)),
                         ("values", ["system:serviceaccount:ns:sa"]))))))
EKS = TfFile("", (
    tf_block("provider", ["aws"], [("region", "us-east-1")]),
    tf_block("data", ["aws_eks_cluster", "k"], [("name", "ciam-eks")]),
    tf_block("data", ["aws_iam_openid_connect_provider", "k"], [
        ("url", tf_ref("data.aws_eks_cluster.k.identity[0].oidc[0].issuer"))]),
    tf_block("data", ["aws_iam_policy_document", "trust"], [("statement", STATEMENT)]),
    tf_block("resource", ["aws_iam_role", "irsa"], [
        ("name", "irsa"), ("assume_role_policy", tf_ref("data.aws_iam_policy_document.trust.json"))])))


def test_an_irsa_role_s_trust_policy_reads_the_clusters_issuer_through_one_parameter():
    t = cloudformation_translation(M, {"terraform/main.tf": EKS}, WHAT).templates["cloudformation/template.yaml"]
    assert [p.logical_id for p in t.parameters] == ["EksClusterKOidcIssuer"]
    text = _resources(t)["IamRoleIrsa"].properties["AssumeRolePolicyDocument"]["Fn::Sub"]
    assert ('"Principal": {"Federated": ["arn:${AWS::Partition}:iam::${AWS::AccountId}:oidc-provider/'
            '${EksClusterKOidcIssuer}"]}') in text
    assert '"Condition": {"StringEquals": {"${EksClusterKOidcIssuer}:sub": ["system:serviceaccount:ns:sa"]}}' in text


def test_a_merge_finds_its_target_by_type_and_an_attribute_reads_the_block():
    files = _one(
        tf_block("resource", ["aws_lb", "a"], [("name", "a"), ("load_balancer_type", "application")]),
        tf_block("resource", ["aws_shield_protection", "a"], [("name", "a"), ("resource_arn", tf_ref("aws_lb.a.arn"))]),
        tf_block("resource", ["aws_shield_application_layer_automatic_response", "a"], [
            ("resource_arn", tf_ref("aws_lb.a.arn")), ("action", "COUNT"),
            ("depends_on", [tf_ref("aws_lb.a"), tf_ref("aws_shield_protection.a")])]),
        tf_block("resource", ["aws_rds_cluster", "c"], [("cluster_identifier", "c"), ("engine", "aurora-mysql")]),
        tf_block("resource", ["aws_rds_cluster_instance", "c1"], [
            ("identifier", "c1"), ("cluster_identifier", tf_ref("aws_rds_cluster.c.id")),
            ("engine", tf_ref("aws_rds_cluster.c.engine")), ("instance_class", "db.r6g.large")]))
    t = cloudformation_translation(M, files, WHAT)
    assert t.placements["terraform"]["aws_shield_application_layer_automatic_response.a"].detail == \
        "aws_shield_protection.a"
    r = _resources(t.templates["cloudformation/template.yaml"])
    assert r["ShieldProtectionA"].properties["ApplicationLayerAutomaticResponseConfiguration"] == {
        "Action": {"Count": {}}, "Status": "ENABLED"}
    assert r["RdsClusterInstanceC1"].properties["Engine"] == "aurora-mysql"


def test_an_adopted_route_table_with_a_route_cloudformation_cant_identify_stays_terraform():
    files = _one(tf_block("resource", ["aws_route_table", "t"], [
        ("vpc_id", "vpc-1"), ("route", Block((("cidr_block", "0.0.0.0/0"), ("nat_gateway_id", "nat-1")))),
        ("route", Block((("ipv6_cidr_block", "::/0"), ("egress_only_gateway_id", "eigw-1"))))]),
        tf_import("aws_route_table.t", "rtb-1"))
    t = cloudformation_translation(M, files, WHAT)
    assert t.placements["terraform"]["aws_route_table.t"].detail == (
        "adopted (an import block): CloudFormation imports a route by its table and IPv4 CIDR, which route ::/0 "
        "hasn't")


def test_what_references_a_vpn_gateway_waits_for_its_attachment():
    files = _one(
        tf_block("resource", ["aws_vpn_gateway", "main"], [("vpc_id", "vpc-1"), ("amazon_side_asn", 64512)]),
        tf_block("resource", ["aws_customer_gateway", "b"], [("bgp_asn", 65000), ("ip_address", "198.51.100.2"),
                                                              ("type", "ipsec.1")]),
        tf_block("resource", ["aws_vpn_connection", "b"], [
            ("customer_gateway_id", tf_ref("aws_customer_gateway.b.id")),
            ("vpn_gateway_id", tf_ref("aws_vpn_gateway.main.id")), ("type", "ipsec.1"),
            ("static_routes_only", True)]),
        tf_block("resource", ["aws_route_table", "t"], [("vpc_id", "vpc-1"), ("route", Block((
            ("cidr_block", "10.6.0.0/16"), ("gateway_id", tf_ref("aws_vpn_gateway.main.id")))))]))
    r = _resources(cloudformation_translation(M, files, WHAT).templates["cloudformation/template.yaml"])
    assert r["VpnGatewayMain"].properties == {"Type": "ipsec.1", "AmazonSideAsn": 64512}
    assert r["VpnGatewayMainAttachment"].properties == {"VpcId": "vpc-1", "VpnGatewayId": ref("VpnGatewayMain")}
    assert r["VpnGatewayMainAttachment"].depends_on == ()
    assert r["RouteTableTRoute0"].depends_on == ("VpnGatewayMainAttachment",)
    assert r["VpnConnectionB"].depends_on == ("VpnGatewayMainAttachment",)


# ------------------------------------------------------------------ 5.6 (d3): the JSON-string form parses back

@pytest.mark.parametrize("document", [
    {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["sts:AssumeRoleWithWebIdentity"],
        "Principal": {"Federated": [sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:oidc-provider/${I}")]},
        "Condition": {"StringEquals": {object_key(sub("${I}:sub")): ["system:serviceaccount:ns:sa"],
                                       object_key(ref("Aud")): ["sts.amazonaws.com"]}}}]},
    {object_key(get_att("B", "Arn")): {"Note": "${aws:username}", "N": 1, "Ok": True, "Nothing": None},
     "Select": {"Fn::Select": [0, ref("L")]}}])
def test_a_document_written_as_its_json_string_parses_back(document):
    written = json_document(document)
    assert "Fn::Sub" in written
    assert document_of(written) == document


def test_only_a_documents_json_string_parses_and_other_values_stay():
    assert document_of({"Statement": []}) == {"Statement": []}
    assert document_of(sub("arn:${AWS::Partition}:s3:::b")) == sub("arn:${AWS::Partition}:s3:::b")
    assert document_of(sub('"${X}"')) == sub('"${X}"')
    inlined = json_document({object_key(sub("${A}-${V0}", {"V0": ref("L")})): "x"})
    (key, value), = document_of(inlined).items()                     # the inner variable renamed, still bound
    text, variables = json.loads(key.text)["Fn::Sub"]
    (name, bound), = variables.items()
    assert (text, bound, value) == ("${A}-${" + name + "}", ref("L"), "x")
