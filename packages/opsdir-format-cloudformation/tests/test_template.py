import json

import pytest

from opsdir.connectors.registry import format_named
from opsdir_format_cloudformation.format import JSON_FORMAT, YAML_FORMAT, as_json, as_yaml
from opsdir_format_cloudformation.template import (ACCOUNT_ID, NO_VALUE, Output, Parameter, Resource, Template,
                                                    equals, get_att, if_, import_value, join, logical_id, ref,
                                                    resolve, resource_types, select, split, sub, template_data)

ROLE = Resource("IdentityPf", "AWS::IAM::Role", {"RoleName": "ciam-prod-pf", "AssumeRolePolicyDocument": {
    "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                            "Action": "sts:AssumeRole"}]}})
PROFILE = Resource("IdentityPfProfile", "AWS::IAM::InstanceProfile", {"Roles": [ref("IdentityPf")]},
                   depends_on=("IdentityPf",))
SUBNET = Parameter("SubnetPfA", "AWS::EC2::Subnet::Id", "subnet-0a1", "subnet-pf-a, as the record holds it")
TEMPLATE = Template("ciam source/prod: platform", (ROLE, PROFILE), (SUBNET,),
                    outputs=(Output("IdentityPfArn", get_att("IdentityPf", "Arn"), export="ciam-prod-identity-pf"),))


@pytest.mark.parametrize("parts, expected", [(("identity_pf",), "IdentityPf"), (("pf-engine", "a"), "PfEngineA"),
                                             (("1st",), "R1st"), (("sg", "pf_admin"), "SgPfAdmin")])
def test_logical_ids_are_letters_and_digits(parts, expected):
    assert logical_id(*parts) == expected


def test_a_logical_id_needs_some_letters_or_digits():
    with pytest.raises(ValueError):
        logical_id("--")


def test_intrinsic_functions_are_long_form_data():
    assert ref(ACCOUNT_ID) == {"Ref": "AWS::AccountId"}
    assert get_att("Lb", "DNSName") == {"Fn::GetAtt": ["Lb", "DNSName"]}
    assert sub("arn:${AWS::Partition}:s3:::b") == {"Fn::Sub": "arn:${AWS::Partition}:s3:::b"}
    assert sub("${Name}-x", {"Name": ref("P")}) == {"Fn::Sub": ["${Name}-x", {"Name": {"Ref": "P"}}]}
    assert join(",", ("a", "b")) == {"Fn::Join": [",", ["a", "b"]]}
    assert select(0, split(",", ref("Cidrs"))) == {"Fn::Select": [0, {"Fn::Split": [",", {"Ref": "Cidrs"}]}]}
    assert import_value("x") == {"Fn::ImportValue": "x"}
    assert if_("Gov", "a", ref(NO_VALUE)) == {"Fn::If": ["Gov", "a", {"Ref": "AWS::NoValue"}]}
    assert equals(ref("AWS::Partition"), "aws-us-gov") == {"Fn::Equals": [{"Ref": "AWS::Partition"}, "aws-us-gov"]}
    assert resolve("secretsmanager", "ciam/prod/pf:SecretString:password::") == \
        "{{resolve:secretsmanager:ciam/prod/pf:SecretString:password::}}"


def test_the_template_document_keeps_cloudformations_section_order_and_leaves_empty_ones_out():
    doc = template_data(TEMPLATE)
    assert list(doc) == ["AWSTemplateFormatVersion", "Description", "Parameters", "Resources", "Outputs"]
    assert doc["Parameters"] == {"SubnetPfA": {"Type": "AWS::EC2::Subnet::Id", "Default": "subnet-0a1",
                                               "Description": "subnet-pf-a, as the record holds it"}}
    assert list(doc["Resources"]) == ["IdentityPf", "IdentityPfProfile"]
    assert doc["Resources"]["IdentityPfProfile"] == {"Type": "AWS::IAM::InstanceProfile", "DependsOn": ["IdentityPf"],
                                                     "Properties": {"Roles": [{"Ref": "IdentityPf"}]}}
    assert doc["Outputs"]["IdentityPfArn"] == {"Value": {"Fn::GetAtt": ["IdentityPf", "Arn"]},
                                               "Export": {"Name": "ciam-prod-identity-pf"}}
    assert list(template_data(Template(None, (ROLE,)))) == ["AWSTemplateFormatVersion", "Resources"]


def test_a_logical_id_used_twice_is_refused():
    with pytest.raises(ValueError, match="resource logical ids used more than once: IdentityPf"):
        template_data(Template("x", (ROLE, ROLE)))


def test_json_and_yaml_are_the_same_template():
    assert json.loads(as_json(TEMPLATE)) == template_data(TEMPLATE)
    text = as_yaml(TEMPLATE)
    assert text.startswith("AWSTemplateFormatVersion: \"2010-09-09\"\n")         # a date-like string stays a string
    assert "  IdentityPfProfile:\n    Type: AWS::IAM::InstanceProfile\n    DependsOn:\n    - IdentityPf\n" in text
    assert "      Roles:\n      - Ref: IdentityPf\n" in text
    assert "    Value:\n      Fn::GetAtt:\n      - IdentityPf\n      - Arn\n" in text


def test_resource_types_once_each_in_order():
    assert resource_types(Template("x", (ROLE, PROFILE, ROLE._replace(logical_id="Other")))) == (
        "AWS::IAM::Role", "AWS::IAM::InstanceProfile")


def test_the_formats_are_registered():
    assert format_named("cloudformation-yaml") is YAML_FORMAT and format_named("cloudformation-json") is JSON_FORMAT
    assert YAML_FORMAT.comment == ("#",) and JSON_FORMAT.comment == ()
