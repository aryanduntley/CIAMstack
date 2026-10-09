"""AWS collectors: the identity check against the account the cloud records; the cli-inventory calls in rounds (the
listings in the environment's VPC and region, then each item's details), exactly the operations pinned below and none
that returns secret material (projections leave out environment variables, inputs and custom headers); per-bucket and
per-secret calls only for what the record holds; the collected export reads as the same export saved by hand; FIPS
endpoints; Terraform state read from the collection source's object or with terraform state pull; CloudFormation stacks
named by collection sources (and their nested stacks) read as the README's script saves them."""
import importlib.util
import json
import pathlib
import shlex

from opsdir.connectors.collecting import collect, provenance
from opsdir.core.directory import make_entry
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.cli import read_cli_inventory
from opsdir_adapter_aws.cloudformation import read_cloudformation
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.collect import (COLLECTORS, PROJECTIONS, identity_check, inventory_problems, inventory_steps,
                                        stack_of, stack_problems, stack_steps, state_steps)

# the CLI reader's own fixtures (its record and the outputs saved by hand), loaded by path: one source of truth
_SPEC = importlib.util.spec_from_file_location("aws_cli_fixtures", pathlib.Path(__file__).with_name("test_aws_cli.py"))
_CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CLI)
LB, SECRET, VPC, _outputs, _record = _CLI.LB, _CLI.SECRET, _CLI.VPC, _CLI._outputs, _CLI._record
_SPEC_CFN = importlib.util.spec_from_file_location("aws_cfn_fixtures",
                                                   pathlib.Path(__file__).with_name("test_aws_cloudformation.py"))
_CFN = importlib.util.module_from_spec(_SPEC_CFN)
_SPEC_CFN.loader.exec_module(_CFN)

ACCOUNT = "111122223333"
# every (service, operation) the cli-inventory collector may run: reviewed, read-only, no secret values
OPERATIONS = {
    ("ec2", "describe-vpcs"), ("ec2", "describe-subnets"), ("ec2", "describe-instances"),
    ("ec2", "describe-security-groups"), ("ec2", "describe-security-group-rules"), ("ec2", "describe-nat-gateways"),
    ("elbv2", "describe-load-balancers"), ("elbv2", "describe-target-groups"), ("elbv2", "describe-listeners"),
    ("elbv2", "describe-tags"), ("elbv2", "describe-load-balancer-attributes"), ("elbv2", "describe-target-health"),
    ("elbv2", "describe-target-group-attributes"), ("secretsmanager", "list-secrets"),
    ("secretsmanager", "get-resource-policy"), ("kms", "list-keys"), ("kms", "describe-key"),
    ("kms", "get-key-rotation-status"), ("kms", "get-key-policy"), ("s3api", "list-buckets"),
    ("s3api", "get-bucket-versioning"), ("s3api", "get-object-lock-configuration"), ("s3api", "get-bucket-encryption"),
    ("s3api", "get-public-access-block"), ("s3api", "get-bucket-lifecycle-configuration"),
    ("s3api", "get-bucket-replication"), ("s3api", "get-bucket-policy"), ("lambda", "list-functions"),
    ("lambda", "list-tags"), ("events", "list-rules"), ("events", "list-targets-by-rule"),
    ("scheduler", "list-schedules"), ("scheduler", "get-schedule"), ("codepipeline", "list-pipelines"),
    ("codepipeline", "get-pipeline"), ("codebuild", "list-projects"), ("codebuild", "batch-get-projects"),
    ("wafv2", "list-web-acls"), ("wafv2", "get-web-acl"), ("wafv2", "list-resources-for-web-acl"),
    ("wafv2", "list-ip-sets"), ("wafv2", "get-ip-set"), ("shield", "list-protections"),
    ("cloudfront", "list-distributions"), ("route53", "list-hosted-zones"), ("route53", "list-resource-record-sets"),
    ("route53resolver", "list-resolver-rules"), ("ec2", "describe-route-tables"), ("ec2", "describe-network-acls"),
    ("ec2", "describe-vpc-endpoints"), ("ec2", "describe-vpc-endpoint-service-configurations"),
    ("ec2", "describe-vpc-endpoint-service-permissions"), ("ec2", "describe-vpc-peering-connections"),
    ("ec2", "describe-transit-gateway-vpc-attachments"), ("ec2", "describe-vpn-connections"),
    ("ec2", "describe-customer-gateways"), ("ec2", "describe-vpn-gateways"), ("ec2", "describe-flow-logs"),
    ("network-firewall", "list-rule-groups"), ("network-firewall", "describe-rule-group"),
    ("network-firewall", "list-firewall-policies"), ("network-firewall", "describe-firewall-policy"),
    ("network-firewall", "list-firewalls"), ("network-firewall", "describe-firewall"), ("rds", "describe-db-instances"),
    ("rds", "describe-db-clusters"), ("rds", "describe-db-subnet-groups"), ("rds", "describe-db-parameter-groups"),
    ("rds", "describe-db-parameters"), ("rds", "describe-db-cluster-parameter-groups"),
    ("rds", "describe-db-cluster-parameters"), ("ec2", "describe-volumes"), ("dlm", "get-lifecycle-policies"),
    ("dlm", "get-lifecycle-policy"), ("backup", "list-backup-vaults"), ("backup", "list-tags"),
    ("backup", "list-backup-plans"), ("backup", "get-backup-plan"), ("backup", "list-backup-selections"),
    ("backup", "get-backup-selection"), ("cloudtrail", "describe-trails"), ("cloudtrail", "get-event-selectors"),
    ("cloudtrail", "list-tags"), ("iam", "get-account-authorization-details"), ("sso-admin", "list-instances"),
    ("sso-admin", "list-permission-sets"), ("sso-admin", "describe-permission-set"),
    ("sso-admin", "get-inline-policy-for-permission-set"), ("sso-admin", "list-managed-policies-in-permission-set"),
    ("sso-admin", "list-account-assignments")}
NEVER = ("get-secret-value", "get-parameter", "get-parameters", "--with-decryption", "describe-instance-attribute",
         "get-function", "get-function-configuration", "get-object", "--debug")
SSO = "arn:aws:sso:::instance/ssoins-1"
PS = "arn:aws:sso:::permissionSet/ssoins-1/ps-1"


def _model(**cloud):
    d = _record()
    if cloud:
        dn = "cloud=main,ou=environments,dc=ciam-ops"
        d = d._replace(entries={**d.entries, dn.lower(): make_entry(dn, (*d.entries[dn.lower()].classes,
                                                                          "ciamCloudAccount", "ciamCloudEndpoints"),
                                                                    {**d.entries[dn.lower()].attrs,
                                                                     **{k: (v,) for k, v in cloud.items()}})})
    return env_model(d, "main/prod")


def _fixture():
    return {p.split("/", 2)[2]: json.loads(t) for p, t in _outputs().items()}


def _answer(argv):
    """What the AWS CLI prints for one call of the collector, from the CLI reader's own fixtures."""
    f, op = _fixture(), tuple(argv[1:3])
    arg = dict(zip(argv[3::1], argv[4::1]))
    special = {("kms", "list-keys"): {"Keys": [{"KeyId": "mrk-1234"}, {"KeyId": "0ebs"}]},
               ("route53", "list-hosted-zones"): {"HostedZones": [{"Id": "/hostedzone/Z0PRIVATE"}]},
               ("sso-admin", "list-instances"): {"Instances": [{"InstanceArn": SSO}]},
               ("sso-admin", "list-permission-sets"): {"PermissionSets": [PS]},
               ("sso-admin", "describe-permission-set"): {"PermissionSet": {"Name": "CiamOperators",
                                                                             "PermissionSetArn": PS}},
               ("sts", "get-caller-identity"): {"Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/r/me"}}
    by_file = {("ec2", "describe-vpcs"): "vpcs.json", ("ec2", "describe-subnets"): "subnets.json",
               ("ec2", "describe-instances"): "instances.json", ("ec2", "describe-security-groups"):
               "security-groups.json", ("ec2", "describe-nat-gateways"): "nat-gateways.json",
               ("elbv2", "describe-load-balancers"): "load-balancers.json", ("elbv2", "describe-listeners"):
               "listeners-svc-ldaps.json", ("elbv2", "describe-target-groups"): "target-groups.json",
               ("elbv2", "describe-target-health"): "target-health/ciam-prod-svc-ldaps-1636.json",
               ("route53", "list-resource-record-sets"): "route53/Z0PRIVATE.json",
               ("secretsmanager", "list-secrets"): "secrets.json", ("s3api", "list-buckets"): "buckets.json"}
    if op in special:
        return json.dumps(special[op]), None
    if op == ("kms", "describe-key"):
        return json.dumps(f["kms/key-mrk-1234.json" if arg.get("--key-id") == "mrk-1234"
                            else "kms/key-aws-ebs.json"]), None
    if op == ("kms", "get-key-rotation-status"):
        return json.dumps(f["kms/rotation-mrk-1234.json"] if arg.get("--key-id") == "mrk-1234" else {}), None
    if op[0] == "s3api" and op[1] != "list-buckets":
        return None, None                   # a bucket without these settings: nothing there, the file is left out
    return json.dumps(f[by_file[op]] if op in by_file else {}), None


def _run(call):
    return _answer(call.argv)


def test_the_collectors_are_declared_on_the_adapter():
    assert [(c.importer, c.scope) for c in ADAPTER.collectors] == [("cli-inventory", "environment"),
                                                                    ("terraform-state", "environment"),
                                                                    ("cloudformation", "environment")]


def test_the_login_must_be_the_account_the_cloud_records():
    call, check = identity_check(None, _model(ciamAccountRef=ACCOUNT))
    assert call.argv == ("aws", "sts", "get-caller-identity", "--output", "json", "--region", "us-east-1")
    assert check(json.dumps({"Account": ACCOUNT})) is None
    assert check(json.dumps({"Account": "999999999999"})) == \
        f"signed in to account 999999999999, the record names {ACCOUNT}"
    assert identity_check(None, _model())[1]("{}") == \
        "the cloud records no account (ciamAccountRef) to check the login against"


def test_the_collected_export_reads_as_the_export_saved_by_hand():
    m = _model(ciamAccountRef=ACCOUNT)
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, _run)
    assert c.problems == () and all(p.startswith("main/prod/") for p in c.files)
    assert not any(p.startswith("main/prod/_work") or "_work/" in p for p in c.files)
    by_hand = read_cli_inventory(_outputs(), m.d, ())
    collected = read_cli_inventory(c.files, m.d, ())
    assert collected.groups == by_hand.groups
    assert {x.path.split("/")[2] for x in c.calls if x.sha256 is None} == {
        "bucket-versioning", "bucket-object-lock", "bucket-encryption", "bucket-public-access", "bucket-lifecycle",
        "bucket-replication", "bucket-policy"}


def test_exactly_the_reviewed_operations_and_never_a_secret():
    m = _model(ciamAccountRef=ACCOUNT)
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, _run)
    ran = [shlex.split(x.provenance) for x in c.calls]
    assert {tuple(a[1:3]) for a in ran} <= OPERATIONS
    assert not [a for a in ran for word in NEVER if word in a]
    assert all(a[0] == "aws" and a[-4:] == ["--output", "json", "--region", "us-east-1"] for a in ran)
    assert ["aws", "ec2", "describe-instances", "--filters", f"Name=vpc-id,Values={VPC}"] == ran[2][:5]
    functions = next(a for a in ran if a[1:3] == ["lambda", "list-functions"])
    assert functions[functions.index("--query") + 1] == PROJECTIONS["functions"]       # no environment variables
    assert ["aws", "elbv2", "describe-listeners", "--load-balancer-arn", LB] == next(
        a for a in ran if a[2] == "describe-listeners")[:5]
    buckets = {a[a.index("--bucket") + 1] for a in ran if "--bucket" in a}
    assert buckets == {"ciam-backups"}                           # only the buckets the record holds
    assert [a for a in ran if a[2] == "get-resource-policy"][0][4] == SECRET
    assert ["aws", "sso-admin", "list-account-assignments"] == \
        next(a for a in ran if a[2] == "list-account-assignments")[:3]
    assert "sso-CiamOperators.json" in {x.path.rsplit("/", 1)[-1] for x in c.calls}


def test_fips_endpoints_and_no_vpc():
    m = _model(ciamAccountRef=ACCOUNT, ciamFipsEndpoints="TRUE")
    (path, call), *_ = inventory_steps(m.d, m, {}, {})
    assert call.env == (("AWS_USE_FIPS_ENDPOINT", "true"),)
    assert identity_check(None, m)[0].env == (("AWS_USE_FIPS_ENDPOINT", "true"),)
    no_vpc = m._replace(bindings=tuple(b for b in m.bindings if "ciamNetwork" not in b.classes))
    assert inventory_steps(m.d, no_vpc, {}, {}) == ()


def test_terraform_state_from_the_source_object_or_terraform_state_pull():
    m = _model(ciamAccountRef=ACCOUNT)
    assert state_steps(m.d, m, {}, {}) == ()                     # no collection source: nothing to collect
    source = make_entry("cn=tf-state,ou=bindings,env=prod,cloud=main,ou=environments,dc=ciam-ops",
                        ("top", "ciamCollectionSource"),
                        {"cn": ("tf-state",), "ciamBindingRole": ("collect-state",),
                         "ciamImporter": ("aws/terraform-state",),
                         "ciamSourceRef": ("s3://ciam-tf-state/env:/prod/ciam/terraform.tfstate",)})
    with_source = m._replace(bindings=(*m.bindings, source))
    ((path, call),) = state_steps(m.d, with_source, {}, {})
    assert path == "main/prod/terraform.tfstate"
    assert provenance(call) == ("aws s3 cp s3://ciam-tf-state/env:/prod/ciam/terraform.tfstate - --output json "
                                "--region us-east-1")
    ((path, call),) = state_steps(m.d, with_source, {}, {"terraform_dir": "/work/ciam-prod"})
    assert (path, call.argv) == ("main/prod/terraform.tfstate",
                                 ("terraform", "-chdir=/work/ciam-prod", "state", "pull"))


STACKS = {"cloudformation describe-stacks", "cloudformation list-stack-resources", "cloudformation get-template"}
NET_ARN = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/ciam-prod-network/0a1b-2c3d"


def _with_sources(m, *refs):
    sources = tuple(make_entry(f"cn=stack-{n},ou=bindings,env=prod,cloud=main,ou=environments,dc=ciam-ops",
                               ("top", "ciamCollectionSource"),
                               {"cn": (f"stack-{n}",), "ciamBindingRole": (f"collect-stack-{n}",),
                                "ciamImporter": ("aws/cloudformation",), "ciamSourceRef": (ref,)})
                    for n, ref in enumerate(refs))
    return m._replace(bindings=(*m.bindings, *sources))


def _stack_answer(argv):
    """What the AWS CLI prints for a stack call, from the CloudFormation reader's own fixtures; the app stack nests the
    network stack."""
    saved = {p.split("/")[2] + "/" + p.split("/")[3]: t for p, t in _CFN._files().items()}
    folder = "network" if "ciam-prod-network" in argv[argv.index("--stack-name") + 1] else "app"
    op = argv[2]
    if op == "describe-stacks":
        return saved[f"{folder}/stack.json"], None
    if op == "get-template":
        return (saved["app/template.json"] if folder == "app" else
                json.dumps({"TemplateBody": saved["network/template.yaml"]})), None
    listed = json.loads(saved[f"{folder}/resources.json"])
    nested = [{"LogicalResourceId": "Network", "PhysicalResourceId": NET_ARN,
               "ResourceType": "AWS::CloudFormation::Stack",
               "ResourceStatus": "CREATE_COMPLETE"}] if folder == "app" else []
    return json.dumps({"StackResourceSummaries": [*listed["StackResourceSummaries"], *nested]}), None


def test_stacks_named_by_collection_sources_and_their_nested_stacks_are_read_as_saved_by_hand():
    m = _model(ciamAccountRef=ACCOUNT)
    assert stack_steps(m.d, m, {}, {}) == () and stack_problems(m.d, m, {}) == ()      # no source: nothing to read
    m = _with_sources(m, "cfn://ciam-prod-app")
    c = collect("aws/cloudformation", COLLECTORS[2], m.d, m, lambda call: _stack_answer(call.argv))
    assert c.problems == ()
    assert sorted(c.files) == [f"main/prod/{s}/{f}" for s in ("ciam-prod-app", "ciam-prod-network")
                               for f in ("resources.json", "stack.json", "template.json")]
    ran = [shlex.split(x.provenance) for x in c.calls]
    assert {" ".join(a[1:3]) for a in ran} == STACKS and all(a[-4:] == ["--output", "json", "--region", "us-east-1"]
                                                             for a in ran)
    described = next(a for a in ran if a[2] == "describe-stacks")
    assert described[described.index("--query") + 1] == PROJECTIONS["stack"] and "Outputs" not in PROJECTIONS["stack"]
    assert next(a for a in ran if a[2] == "get-template")[5:7] == ["--template-stage", "Processed"]
    assert ["--stack-name", NET_ARN] == next(a for a in ran if NET_ARN in a and a[2] == "describe-stacks")[3:5]
    by_hand = read_cloudformation(_CFN._files(), _CFN._record(), ())
    collected = read_cloudformation(c.files, _CFN._record(), ())
    assert collected.groups == by_hand.groups


def test_a_source_must_name_a_stack_in_the_clouds_account():
    assert stack_of("cfn://ciam-prod-app") == ("ciam-prod-app", "ciam-prod-app", None, None)
    assert stack_of(NET_ARN) == ("ciam-prod-network", NET_ARN, "us-east-1", ACCOUNT)
    assert [stack_of(r) for r in ("cfn://-oops", "cfn://a;b", "s3://bucket/key", None)] == [None] * 4
    other = NET_ARN.replace(ACCOUNT, "999999999999").replace("us-east-1", "us-west-2")
    m = _with_sources(_model(ciamAccountRef=ACCOUNT), "cfn://--debug", other, NET_ARN.replace("us-east-1", "us-west-2"))
    assert stack_problems(m.d, m, {}) == (
        "collection source `stack-0`: cfn://--debug isn't a stack (cfn://<stack name>, or the stack's ARN)",
        f"collection source `stack-1`: {other} is a stack in account 999999999999, the cloud records {ACCOUNT}")
    (_, call), *_ = stack_steps(m.d, m, {}, {})                 # only the stack in the cloud's account, in its region
    assert call.argv[-2:] == ("--region", "us-west-2") and "999999999999" not in " ".join(call.argv)


ORG, OU, ROOT = "o-abcdefghij", "ou-ab12-cdefgh34", "r-ab12"
ORG_OPERATIONS = {("sts", "get-caller-identity"), ("organizations", "describe-organization"),
                  ("organizations", "list-parents"), ("organizations", "list-policies-for-target"),
                  ("organizations", "describe-policy")}
ATTACHED = {(ACCOUNT, "SERVICE_CONTROL_POLICY"): ["p-fence0001"], (OU, "SERVICE_CONTROL_POLICY"): ["p-FullAWSAccess"],
            (ROOT, "SERVICE_CONTROL_POLICY"): ["p-FullAWSAccess"], (OU, "RESOURCE_CONTROL_POLICY"): ["p-rcpdata01"]}


def _policy(pid):
    kind = "RESOURCE_CONTROL_POLICY" if pid == "p-rcpdata01" else "SERVICE_CONTROL_POLICY"
    deny = {"Sid": "DenyKeyDeletion", "Effect": "Deny", "Action": "kms:ScheduleKeyDeletion", "Resource": "*"}
    return {"Policy": {"PolicySummary": {"Arn": f"arn:aws:organizations::999988887777:policy/{ORG}/"
                                                f"{kind.lower()}/{pid}", "Id": pid, "Name": pid, "Type": kind},
                       "Content": json.dumps({"Version": "2012-10-17", "Statement": [deny]})}}


def _org_answer(argv, org=ORG):
    """The organization's answers to the profile's calls (the account in an OU under the root; RCPs enabled only on the
    OU's listing), else the environment's (_answer)."""
    if "--profile" not in argv:
        return _answer(argv)
    arg, op = dict(zip(argv[3::1], argv[4::1])), tuple(argv[1:3])
    if op == ("sts", "get-caller-identity"):
        return json.dumps({"Account": "999988887777", "Arn": "arn:aws:sts::999988887777:assumed-role/OrgRead/me"}), None
    if op == ("organizations", "describe-organization"):
        return json.dumps({"Organization": {"Id": org, "MasterAccountId": "999988887777"}}), None
    if op == ("organizations", "list-parents"):
        parent = {ACCOUNT: (OU, "ORGANIZATIONAL_UNIT"), OU: (ROOT, "ROOT")}[arg["--child-id"]]
        return json.dumps({"Parents": [{"Id": parent[0], "Type": parent[1]}]}), None
    if op == ("organizations", "list-policies-for-target"):
        return json.dumps({"Policies": [{"Id": p}
                                        for p in ATTACHED.get((arg["--target-id"], arg["--filter"]), [])]}), None
    return json.dumps(_policy(arg["--policy-id"])), None


def _with_profile(m, *profiles):
    return m._replace(bindings=(*m.bindings, *(
        make_entry(f"cn=org-{n},ou=bindings,env=prod,cloud=main,ou=environments,dc=ciam-ops",
                   ("top", "ciamCollectionSource"),
                   {"cn": (f"org-{n}",), "ciamBindingRole": (f"collect-org-{n}",),
                    "ciamImporter": ("aws/cli-inventory",),
                    "ciamSourceRef": (f"aws-profile://{p}",)}) for n, p in enumerate(profiles))))


def test_the_organizations_policies_on_the_account_and_above_it_through_the_named_profile():
    m = _with_profile(_model(ciamAccountRef=ACCOUNT, ciamOrganizationRef=ORG), "org-mgmt")
    assert inventory_problems(m.d, m, {}) == ()
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, lambda call: _org_answer(call.argv))
    assert c.problems == ()
    ran = [shlex.split(x.provenance) for x in c.calls]
    profiled = [a for a in ran if "--profile" in a]
    assert {tuple(a[1:3]) for a in ran} <= OPERATIONS | ORG_OPERATIONS
    assert {tuple(a[1:3]) for a in profiled} == ORG_OPERATIONS and all(
        a[a.index("--profile") + 1] == "org-mgmt" for a in profiled)
    assert not [a for a in ran if "--profile" not in a and a[1] == "organizations"]   # never under the env's login
    assert sorted(" ".join(a[3:5]) for a in profiled if a[2] == "list-parents") == [f"--child-id {ACCOUNT}",
                                                                                   f"--child-id {OU}"]
    assert sum(a[2] == "list-policies-for-target" for a in profiled) == 6                # 3 targets x 2 types
    assert sorted(p for p in c.files if "/org/" in p) == [
        "main/prod/org/p-FullAWSAccess.json", "main/prod/org/p-fence0001.json", "main/prod/org/p-rcpdata01.json"]
    assert sum(a[2] == "describe-policy" for a in profiled) == 3                         # inherited once each
    resources, _ = cli_resources({p.split("/", 2)[2]: t for p, t in c.files.items() if "/org/" in p}, None)
    assert {r.ref.rsplit("/", 1)[-1] for r in resources if r.kind == "guardrail"} >= {"p-fence0001"}


def test_a_profile_signed_in_to_another_organization_reads_no_policy_and_imports_nothing():
    m = _with_profile(_model(ciamAccountRef=ACCOUNT, ciamOrganizationRef=f"arn:aws:organizations::999988887777:"
                                                                         f"organization/{ORG}"), "org-mgmt")
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, lambda call: _org_answer(call.argv, org="o-zzzzzzzzzz"))
    assert c.files is None and c.problems == (
        f"profile org-mgmt is signed in to organization o-zzzzzzzzzz, the cloud records {ORG}: "
        "its policies are not read",)
    assert not [x for x in c.calls if "list-policies-for-target" in x.provenance]


def test_an_organization_profile_source_that_cant_be_used_safely():
    m = _model(ciamAccountRef=ACCOUNT)
    assert inventory_problems(m.d, _with_profile(m, "org-mgmt"), {}) == (
        "the cloud records no AWS organization (ciamOrganizationRef o-…) to check the profile against",)
    m = _model(ciamAccountRef=ACCOUNT, ciamOrganizationRef=ORG)
    assert inventory_problems(m.d, _with_profile(m, "a", "--debug"), {}) == (
        "more than one aws-profile:// collection source: name one profile for the organization's policies",
        "aws-profile://--debug: not a profile name opsdir passes to the AWS CLI")
