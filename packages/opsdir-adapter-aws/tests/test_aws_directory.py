"""AWS Managed Microsoft AD as a managed directory (flow 76): the descriptor the planner reads (AWS's documented
capabilities, GovCloud's differences), a target rendered as a CloudFormation stack whose Admin password is a Secrets
Manager dynamic reference (never in Terraform state), its further regions and conditional forwarders; trusts and the
rest as actions; a neighbour isn't rendered. Read back from Terraform state, from the stack and from the CLI's
describe-directories, projected: no password, no RADIUS secret."""
import json

from opsdir.connectors.managed_directory import managed_directory_check
from opsdir.core.contract import PlanContext
from opsdir.core.interchange.ldif import parse
from opsdir_format_terraform.hcl import as_text, written
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.boundary import aws_services
from opsdir_adapter_aws.cfn_types import cloudformation_files
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.cli_directory import DIRECTORY_QUERY
from opsdir_adapter_aws.cloudformation import cloudformation_resources
from opsdir_adapter_aws.directory import (AWS_MANAGED_AD, SERVICE, directory_notes, directory_resources,
                                          directory_template, render_directories)
from opsdir_adapter_aws.inventory import state_resources
from opsdir_adapter_aws.terraform import WHAT, render_files
from network_fixtures import ALPHA, BETA, entry, model

ARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/ad-admin-AbCdEf"
SECRET = f"aws-sm://{ARN}"
DIRECTORY = f"cn=user-dir,ou=bindings,{ALPHA}"
AD = dict(ciamBindingRole="user-dir", ciamManagedService=SERVICE, ciamRealizes="ds", ciamFqdn="corp.example.test",
          ciamNetbiosName="CORP", ciamDirectoryEdition="enterprise", ciamSubnetRole=("subnet-ds", "subnet-web"),
          ciamCredentialRole="ad-admin", ciamReplicaRegion="us-west-2", ciamReplicaCount="3",
          ciamLdapsMode="private")
RECORDS = (entry(ALPHA, "ad-admin", "ciamSecretRef", ciamBindingRole="ad-admin", ciamRefUri=SECRET),
           entry(ALPHA, "user-dir", "ciamManagedDirectory", **AD),
           entry(DIRECTORY, "hq", "ciamDirectoryTrust", ciamFqdn="hq.example.test", ciamTrustType="forest",
                 ciamTrustDirection="two-way", ciamForwardTarget=("10.9.0.10", "10.9.0.11")))
SUBNETS = tuple(f"dn: cn={n},ou=bindings,{ALPHA}\nchangetype: modify\nadd: ciamProviderRef\nciamProviderRef: {r}\n"
                for n, r in (("subnet-ds", "subnet-0aaa"), ("subnet-web", "subnet-0bbb")))


def _model(*records, changes=()):
    return model(alpha=records, changes=(*parse("\n".join(SUBNETS)), *changes))[1]


def _render(*records, changes=()):
    return "\n\n".join(as_text(render_directories(_model(*records, changes=changes))))


# ------------------------------------------------------------------ the descriptor
def test_the_adapter_declares_aws_managed_ad_with_aws_s_documented_capabilities():
    assert ADAPTER.managed_directory == (AWS_MANAGED_AD,)
    assert SERVICE in ADAPTER.vocabulary["ciamManagedService"]
    assert ADAPTER.vocabulary["ciamDirectoryEdition"] == ("standard", "enterprise")
    assert set(AWS_MANAGED_AD.available) == {"aws", "aws-us-gov"} and not AWS_MANAGED_AD.absent
    assert {"schema-extension", "password-policies", "ldaps", "multi-region", "trust:external:one-way-incoming",
            "trust:forest:two-way"} <= set(AWS_MANAGED_AD.supported)
    # internet LDAPS: AWS documents it neither way
    assert "ldaps-internet" not in {*AWS_MANAGED_AD.supported, *AWS_MANAGED_AD.unsupported}
    assert AWS_MANAGED_AD.limits["password-policies"][0] == 5 and AWS_MANAGED_AD.limits["regions"][0] == 5
    assert AWS_MANAGED_AD.editions["multi-region"][0] == ("enterprise",)
    # GovCloud: the guide doesn't say multi-Region replication is missing, and nothing says it's there
    assert set(AWS_MANAGED_AD.partition_unestablished["aws-us-gov"]) == {"multi-region"}
    assert [t for t, _, _ in AWS_MANAGED_AD.notes["aws-us-gov"]] == ["GovCloud", "export control"]


def test_the_customer_ou_is_named_after_the_netbios_name():
    m = _model(*RECORDS)
    b = next(x for x in m.bindings if x.dn == DIRECTORY)
    assert AWS_MANAGED_AD.default_base(b) == "OU=CORP,DC=corp,DC=example,DC=test"


def test_a_directory_is_aws_directory_service_in_the_fedramp_boundary():
    assert ("AWS Directory Service", "user-dir") in aws_services(_model(*RECORDS))


# ------------------------------------------------------------------ render
def test_a_target_is_a_cloudformation_stack_with_the_password_as_a_dynamic_reference():
    out = _render(*RECORDS)
    for line in ('resource "aws_cloudformation_stack" "user_dir"', 'name = "ciam-prod-user-dir-directory"',
                 '"Type" : "AWS::DirectoryService::MicrosoftAD"', '"DeletionPolicy" : "Retain"',
                 '"Name" : "corp.example.test"', '"ShortName" : "CORP"', '"Edition" : "Enterprise"',
                 '"Password" : "{{resolve:secretsmanager:' + ARN + '}}"',
                 '"VpcId" : "${data.aws_vpc.main.id}"',
                 '"${data.aws_subnet.subnet_ds.id}"', 'Realizes  = "ds"', 'create = "90m"',
                 'resource "aws_directory_service_region" "user_dir_us_west_2"',
                 'directory_id                         = aws_cloudformation_stack.user_dir.outputs["DirectoryId"]',
                 "desired_number_of_domain_controllers = 3", "vpc_id     = var.user_dir_us_west_2_vpc_id",
                 'resource "aws_directory_service_conditional_forwarder" "user_dir_hq"',
                 'dns_ips            = ["10.9.0.10", "10.9.0.11"]'):
        assert line in out, line
    # no secret value anywhere: the reference is the only mention of the secret, and there is no trust password
    assert out.count("resolve:secretsmanager") == 1 and "password =" not in out and "trust_password" not in out
    template = directory_template(_model(*RECORDS), next(x for x in _model(*RECORDS).bindings if x.dn == DIRECTORY))
    assert set(template["Outputs"]) == {"DirectoryId", "DnsIpAddresses"} and "Parameters" not in template


def test_what_isnt_rendered_is_an_action():
    notes = {n.subject: n for n in directory_notes(_model(*RECORDS))}
    assert notes["directory user-dir trust hq"].severity == "action"
    assert "the trust with hq.example.test (forest, two-way): its password is shared" in \
        notes["directory user-dir trust hq"].text
    assert "aws ds enable-ldaps --type Server" in notes["directory user-dir LDAPS"].how[0]
    assert notes["directory user-dir domain controllers"].how == (
        "Run aws ds update-number-of-domain-controllers --desired-number 3",)
    assert "var.user_dir_us_west_2_vpc_id, var.user_dir_us_west_2_subnet_ids" in \
        notes["directory user-dir regions"].how[0]
    assert "changing the reference replaces the directory" in notes["directory user-dir Admin password"].text


def test_a_directory_missing_what_it_needs_isnt_rendered_and_a_neighbour_is_a_note():
    bare = parse(f"dn: {DIRECTORY}\nchangetype: modify\ndelete: ciamCredentialRole\n")
    out = _render(*RECORDS, changes=bare)
    assert "aws_cloudformation_stack" not in out
    assert "UNBOUND: directory user-dir records no its Admin password's Secrets Manager secret" in out
    neighbour = _model(entry(ALPHA, "corp-ad", "ciamManagedDirectory", ciamBindingRole="corp-ad",
                             ciamManagedService=SERVICE))
    assert [x for x in render_directories(neighbour) if x[0] != "#"] == []
    (n,) = directory_notes(neighbour)
    assert (n.severity, n.subject) == ("note", "directory corp-ad") and "not rendered" in n.text


def test_a_cloudformation_render_keeps_the_directory_stack_in_the_terraform_root_beside_it():
    m = _model(*RECORDS)
    files = written(cloudformation_files(m, render_files(m, None), WHAT))
    assert "AWS::DirectoryService::MicrosoftAD" not in files["cloudformation/template.yaml"]
    beside = "\n".join(t for p, t in files.items() if p.startswith("cloudformation/") and p.endswith(".tf"))
    assert 'resource "aws_cloudformation_stack" "user_dir"' in beside
    assert 'resource "aws_directory_service_conditional_forwarder" "user_dir_hq"' in beside


# ------------------------------------------------------------------ the planner, on what AWS documents
def test_the_planner_asks_govcloud_to_confirm_multi_region_replication():
    check = managed_directory_check((ADAPTER,))
    gov = parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamRegion\n"
                "ciamRegion: us-gov-west-1\n")
    target = entry(BETA, "user-dir", "ciamManagedDirectory", **AD)
    d, alpha, beta = model(beta=(target,), changes=gov)
    found = check(PlanContext(d, alpha, beta, None, None, {}, {}, ()))
    assert any("replicate to further regions, and no vendor documentation establishes that it can" in b[1]
               for b in found.blockers)
    assert any("Directory sharing with other accounts, Hybrid Edition and the Directory Service Data API" in a[1]
               for a in found.actions)
    assert any("which AWS Managed Microsoft AD does on a condition: a certificate for its domain controllers" in a[1]
               for a in found.actions)
    d, alpha, beta = model(beta=(target,))
    commercial = check(PlanContext(d, alpha, beta, None, None, {}, {}, ()))
    assert not any("replicate to further regions" in b[1] for b in commercial.blockers)


# ------------------------------------------------------------------ read back
def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.16.5", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


def test_a_rendered_directory_is_read_back_from_state_without_its_password():
    template = directory_template(_model(*RECORDS), next(x for x in _model(*RECORDS).bindings if x.dn == DIRECTORY))
    resources, _ = state_resources(_state(
        ("aws_cloudformation_stack", "user_dir", {"name": "ciam-prod-user-dir-directory",
                                                  "template_body": json.dumps(template),
                                                  "outputs": {"DirectoryId": "d-1234567890"},
                                                  "tags": {"Name": "user-dir", "Role": "user-dir", "Realizes": "ds"}}),
        ("aws_directory_service_region", "r", {"directory_id": "d-1234567890", "region_name": "us-west-2"})))
    (ad,) = (r for r in resources if r.kind == "managed-directory")
    assert (ad.ref, ad.name, ad.role) == ("d-1234567890", "user-dir", "user-dir")
    assert ad.attrs == {"ciamManagedService": (SERVICE,), "ciamRealizes": ("ds",), "ciamFqdn": ("corp.example.test",),
                        "ciamNetbiosName": ("CORP",), "ciamDirectoryEdition": ("enterprise",),
                        "ciamReplicaRegion": ("us-west-2",)}
    assert "resolve:secretsmanager" not in repr(ad)


def test_a_directory_is_read_back_from_its_stack():
    template = {"Resources": {"Directory": {"Type": "AWS::DirectoryService::MicrosoftAD", "Properties": {
        "Name": "corp.example.test", "ShortName": "CORP", "Edition": "Standard", "Password": "{{resolve:x}}",
        "VpcSettings": {"VpcId": "vpc-0abc", "SubnetIds": ["subnet-0aaa", "subnet-0bbb"]}}}}}
    stack = {"Stacks": [{"StackId": "arn:aws:cloudformation:us-east-1:111122223333:stack/ad/0a1b",
                         "StackName": "ad", "StackStatus": "CREATE_COMPLETE", "Parameters": []}]}
    found = {"resources.json": {"StackResourceSummaries": [{"LogicalResourceId": "Directory",
                                                            "PhysicalResourceId": "d-0987654321",
                                                            "ResourceStatus": "CREATE_COMPLETE"}]},
             "stack.json": stack, "template.json": {"TemplateBody": template}}
    resources, _ = cloudformation_resources({f"ad/{p}": json.dumps(t) for p, t in found.items()})
    (ad,) = (r for r in resources if r.kind == "managed-directory")
    assert ad.ref == "d-0987654321" and ad.attrs["ciamDirectoryEdition"] == ("standard",)


def test_the_cli_reads_the_projected_directory_and_its_tags():
    texts = {"vpcs.json": json.dumps({"Vpcs": [{"VpcId": "vpc-0abc", "CidrBlock": "10.1.0.0/16"}]}),
             "directories.json": json.dumps({"DirectoryDescriptions": [
                 {"DirectoryId": "d-1234567890", "Type": "MicrosoftAD", "Name": "corp.example.test",
                  "ShortName": "CORP", "Edition": "Enterprise", "VpcSettings": {"VpcId": "vpc-0abc"},
                  "RegionsInfo": {"AdditionalRegions": ["us-west-2"]}},
                 {"DirectoryId": "d-0000000001", "Type": "ADConnector", "Name": "hq.example.test",
                  "VpcSettings": {"VpcId": "vpc-0abc"}},
                 {"DirectoryId": "d-0000000002", "Type": "MicrosoftAD", "Name": "other.example.test",
                  "VpcSettings": {"VpcId": "vpc-0other"}}]}),
             "directory-tags/d-1234567890.json": json.dumps({"Tags": [{"Key": "Role", "Value": "user-dir"},
                                                                      {"Key": "Realizes", "Value": "ds"}]})}
    resources, notices = cli_resources(texts)
    (ad,) = (r for r in resources if r.kind == "managed-directory")
    assert (ad.ref, ad.role, ad.attrs["ciamRealizes"], ad.attrs["ciamReplicaRegion"]) == (
        "d-1234567890", "user-dir", ("ds",), ("us-west-2",))
    assert any("aws_directory_service_directory (1): outside the listed VPCs" in n for n in notices)
    assert "RadiusSettings" not in DIRECTORY_QUERY and "DirectoryId: DirectoryId" in DIRECTORY_QUERY


def test_what_it_renders_reads_back_as_recorded():
    m = _model(*RECORDS)
    template = directory_template(m, next(x for x in m.bindings if x.dn == DIRECTORY))
    (ad,) = directory_resources((("aws_cloudformation_stack", {"template_body": json.dumps(template),
                                                               "outputs": {"DirectoryId": "d-1"},
                                                               "tags": {"Name": "user-dir", "Realizes": "ds"}}),))
    assert {k: ad.attrs[k] for k in ("ciamFqdn", "ciamNetbiosName", "ciamDirectoryEdition", "ciamRealizes")} == {
        k: (AD[k],) for k in ("ciamFqdn", "ciamNetbiosName", "ciamDirectoryEdition", "ciamRealizes")}
