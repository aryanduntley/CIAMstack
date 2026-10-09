"""What the record can't hold of a security group rule is named, never truncated: a port range, all ports, and
sources that aren't IPv4 ranges (IPv6, a referenced security group, a prefix list), from Terraform state, CLI output
and CloudFormation alike; single IPv4 ports are recorded as before."""
import json

from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.cloudformation import cloudformation_resources
from opsdir_adapter_aws.inventory import state_resources


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("aws_security_group", "app", {"id": "sg-app", "name": "ciam-prod-app", "ingress": [
        {"from_port": 8000, "to_port": 8100, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/16"],
         "description": "app range (fw-app-range)"},
        {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/16"],
         "ipv6_cidr_blocks": ["2001:db8::/32"], "description": "https (fw-https)"},
        {"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["10.9.0.0/16"],
         "description": "anything (fw-any)"}]}),
    ("aws_vpc_security_group_ingress_rule", "ldaps", {
        "security_group_rule_id": "sgr-1", "security_group_id": "sg-app", "referenced_security_group_id": "sg-pf",
        "from_port": 1636, "to_port": 1636, "ip_protocol": "tcp", "description": "ldaps (fw-ldaps-sg)"}),
    ("aws_vpc_security_group_ingress_rule", "admin", {
        "security_group_rule_id": "sgr-2", "security_group_id": "sg-app", "cidr_ipv4": "10.20.9.0/28",
        "from_port": 4444, "to_port": 4444, "ip_protocol": "tcp", "description": "admin (fw-admin)"}))
EXPECTED = (
    "security group rule fw-app-range: port range 8000-8100, not a single port; not recorded",
    "security group rule fw-any: all ports, not a single port; not recorded",
    "security group rule fw-https: source IPv6 range 2001:db8::/32 is not an IPv4 address range; not recorded",
    "security group rule fw-ldaps-sg: source security group sg-pf is not an IPv4 address range; not recorded")


def _rules(resources):
    return {r.name: r.attrs for r in resources if r.kind == "firewall"}


def test_terraform_state_names_what_it_cant_record():
    resources, notices = state_resources(STATE)
    rules = _rules(resources)
    assert set(EXPECTED) <= set(notices)
    assert "ciamPort" not in rules["fw-app-range"] and "ciamPort" not in rules["fw-any"]
    assert rules["fw-https"]["ciamPort"] == ("443",) and rules["fw-admin"]["ciamPort"] == ("4444",)
    assert "fw-ldaps-sg" not in rules                       # no IPv4 source: nothing to record


def test_cli_output_names_the_same():
    groups = {"SecurityGroups": [{"GroupId": "sg-app", "GroupName": "ciam-prod-app", "IpPermissions": [
        {"FromPort": 8000, "ToPort": 8100, "IpProtocol": "tcp",
         "IpRanges": [{"CidrIp": "10.0.0.0/16", "Description": "app range (fw-app-range)"}]},
        {"FromPort": 443, "ToPort": 443, "IpProtocol": "tcp",
         "IpRanges": [{"CidrIp": "10.0.0.0/16", "Description": "https (fw-https)"}],
         "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32", "Description": "https (fw-https)"}]},
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.9.0.0/16", "Description": "anything (fw-any)"}]},
        {"FromPort": 1636, "ToPort": 1636, "IpProtocol": "tcp",
         "UserIdGroupPairs": [{"GroupId": "sg-pf", "Description": "ldaps (fw-ldaps-sg)"}]}]}]}
    resources, notices = cli_resources({"security-groups.json": json.dumps(groups)})
    assert set(EXPECTED) <= set(notices)
    assert _rules(resources)["fw-https"]["ciamPort"] == ("443",)


def test_cloudformation_names_the_same():
    template = {"Resources": {
        "AppSg": {"Type": "AWS::EC2::SecurityGroup",
                  "Properties": {"GroupName": "ciam-prod-app", "SecurityGroupIngress": [
            {"FromPort": 8000, "ToPort": 8100, "IpProtocol": "tcp", "CidrIp": "10.0.0.0/16",
             "Description": "app range (fw-app-range)"},
            {"FromPort": 0, "ToPort": 0, "IpProtocol": "-1", "CidrIp": "10.9.0.0/16",
             "Description": "anything (fw-any)"},
            {"FromPort": 443, "ToPort": 443, "IpProtocol": "tcp", "CidrIpv6": "2001:db8::/32",
             "Description": "https (fw-https)"}]}},
        "Ldaps": {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": {
            "GroupId": {"Ref": "AppSg"}, "SourceSecurityGroupId": "sg-pf", "FromPort": 1636, "ToPort": 1636,
            "IpProtocol": "tcp", "Description": "ldaps (fw-ldaps-sg)"}}}}
    stack = {"Stacks": [{"StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/app/0a1b", "StackName": "app",
                         "StackStatus": "CREATE_COMPLETE", "Parameters": []}]}
    physical = {"StackResourceSummaries": [{"LogicalResourceId": k, "PhysicalResourceId": v, "ResourceType": "",
                                            "ResourceStatus": "CREATE_COMPLETE"}
                                           for k, v in (("AppSg", "sg-app"), ("Ldaps", "sgr-1"))]}
    _, notices = cloudformation_resources({"app/stack.json": json.dumps(stack),
                                           "app/resources.json": json.dumps(physical),
                                           "app/template.json": json.dumps(template)})
    assert set(EXPECTED) <= set(notices)
