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


def _fixtures(name):
    """Another test module's fixtures, loaded by path."""
    spec = importlib.util.spec_from_file_location(f"aws_{name}_fixtures", pathlib.Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMPUTE, _MONITOR = _fixtures("test_aws_compute.py"), _fixtures("test_aws_observability.py")
_SECURITY, _BUDGETS = _fixtures("test_aws_security.py"), _fixtures("test_aws_quotas_budgets.py")
_MESSAGING = _fixtures("test_aws_messaging.py")

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
    ("cognito-idp", "list-user-pools"), ("cognito-idp", "describe-user-pool"),
    ("rds", "describe-db-clusters"), ("rds", "describe-db-subnet-groups"), ("rds", "describe-db-parameter-groups"),
    ("rds", "describe-db-parameters"), ("rds", "describe-db-cluster-parameter-groups"),
    ("rds", "describe-db-cluster-parameters"), ("ec2", "describe-volumes"), ("dlm", "get-lifecycle-policies"),
    ("dlm", "get-lifecycle-policy"), ("backup", "list-backup-vaults"), ("backup", "list-tags"),
    ("backup", "list-backup-plans"), ("backup", "get-backup-plan"), ("backup", "list-backup-selections"),
    ("backup", "get-backup-selection"), ("cloudtrail", "describe-trails"), ("cloudtrail", "get-event-selectors"),
    ("cloudtrail", "list-tags"), ("iam", "get-account-authorization-details"), ("sso-admin", "list-instances"),
    ("sso-admin", "list-permission-sets"), ("sso-admin", "describe-permission-set"),
    ("sso-admin", "get-inline-policy-for-permission-set"), ("sso-admin", "list-managed-policies-in-permission-set"),
    ("sso-admin", "list-account-assignments"), ("autoscaling", "describe-auto-scaling-groups"),
    ("ec2", "describe-launch-template-versions"), ("eks", "list-clusters"), ("eks", "describe-cluster"),
    ("eks", "list-nodegroups"), ("eks", "describe-nodegroup"), ("eks", "list-addons"), ("eks", "describe-addon"),
    ("cloudwatch", "describe-alarms"), ("cloudwatch", "list-tags-for-resource"), ("logs", "describe-log-groups"),
    ("logs", "list-tags-for-resource"), ("synthetics", "describe-canaries"), ("sns", "list-topics"),
    ("sns", "list-tags-for-resource"), ("guardduty", "list-detectors"), ("guardduty", "get-detector"),
    ("guardduty", "describe-organization-configuration"), ("inspector2", "batch-get-account-status"),
    ("inspector2", "describe-organization-configuration"), ("configservice", "describe-configuration-recorders"),
    ("configservice", "describe-delivery-channels"), ("configservice", "describe-retention-configurations"),
    ("securityhub", "describe-hub"), ("securityhub", "get-enabled-standards"),
    ("securityhub", "describe-organization-configuration"), ("budgets", "describe-budgets"),
    ("budgets", "describe-notifications-for-budget"), ("budgets", "describe-subscribers-for-notification"),
    ("budgets", "list-tags-for-resource"), ("sqs", "list-queues"), ("sqs", "get-queue-attributes"),
    ("sqs", "list-queue-tags"), ("events", "list-event-buses"), ("events", "list-tags-for-resource"),
    ("kinesis", "list-streams"), ("kinesis", "list-tags-for-resource"), ("sesv2", "list-email-identities"),
    ("sesv2", "get-email-identity"), ("ec2", "describe-instance-connect-endpoints")}
NEVER = ("get-secret-value", "get-parameter", "get-parameters", "--with-decryption", "describe-instance-attribute",
         "get-function", "get-function-configuration", "get-object", "--debug",
         "describe-user-pool-client", "describe-identity-provider")       # client and upstream secrets
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
    from opsdir_adapter_aws.collect import POLICY_TYPES
    assert sum(a[2] == "list-policies-for-target" for a in profiled) == 3 * len(POLICY_TYPES)   # 3 targets
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


def _compute_monitor_answer(argv):
    """What the AWS CLI prints for the compute and monitoring calls, from those readers' own fixtures."""
    c, mo, op = _COMPUTE.CLI, _MONITOR.CLI, tuple(argv[1:3])
    arg = dict(zip(argv[3::1], argv[4::1]))
    eks = [p for p in c if p.startswith("eks/")]
    if op == ("ec2", "describe-launch-template-versions"):
        assert (arg["--launch-template-id"], arg["--versions"]) == ("lt-0123", "$Latest")
        return json.dumps(c["launch-templates/lt-0123-$Latest.json"]), None
    if op == ("eks", "describe-cluster"):
        return json.dumps(c[f"eks/{arg['--name']}.json"]), None
    if op in (("eks", "describe-nodegroup"), ("eks", "describe-addon")):
        kind = op[1].split("-")[1]
        return json.dumps(c[f"eks/{arg['--cluster-name']}-{kind}-{arg['--' + kind + '-name']}.json"]), None
    if op[1] == "list-tags-for-resource":
        folder = {"cloudwatch": "alarm-tags", "logs": "log-group-tags", "sns": "topic-tags"}[op[0]]
        name = {"arn:cw:alarm:ds-lag": "ds-replication-lag", "arn:logs:audit": "%2Fciam%2Faudit",
                _MONITOR.PAGE: "ciam-page", _MONITOR.EVENTS: "ciam-events"}.get(arg["--resource-arn"])
        return json.dumps(mo.get(f"{folder}/{name}.json", {"Tags": []} if op[0] != "logs" else {"tags": {}})), None
    listed = {("autoscaling", "describe-auto-scaling-groups"): c["autoscaling-groups.json"],
              ("eks", "list-clusters"): {"clusters": ["ciam-prod"]},
              ("eks", "list-nodegroups"): {"nodegroups": [p.split("-nodegroup-")[1][:-5] for p in eks
                                                          if "-nodegroup-" in p]},
              ("eks", "list-addons"): {"addons": [p.split("-addon-")[1][:-5] for p in eks if "-addon-" in p]},
              ("cloudwatch", "describe-alarms"): mo["alarms.json"], ("logs", "describe-log-groups"):
              mo["log-groups.json"], ("synthetics", "describe-canaries"): mo["canaries.json"],
              ("sns", "list-topics"): mo["topics.json"]}
    return (json.dumps(listed[op]), None) if op in listed else _answer(argv)


def test_compute_groups_clusters_and_monitoring_collected_read_as_saved_by_hand():
    m = _model(ciamAccountRef=ACCOUNT)
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, lambda call: _compute_monitor_answer(call.argv))
    assert c.problems == ()
    ran = [shlex.split(x.provenance) for x in c.calls]
    assert {tuple(a[1:3]) for a in ran} <= OPERATIONS
    versions = next(a for a in ran if a[2] == "describe-launch-template-versions")
    assert versions[versions.index("--query") + 1] == PROJECTIONS["launch-template-versions"]    # never user data
    canaries = next(a for a in ran if a[2] == "describe-canaries")
    assert canaries[canaries.index("--query") + 1] == PROJECTIONS["canaries"]
    files = {p.split("/", 2)[2]: t for p, t in c.files.items()}
    assert {"launch-templates/lt-0123-%24Latest.json", "eks/ciam-prod-nodegroup-system.json",
            "eks/ciam-prod-addon-vpc-cni.json", "log-group-tags/%2Fciam%2Faudit.json",
            "topic-tags/ciam-events.json"} <= set(files)
    network = {p: json.dumps(_COMPUTE.CLI[p]) for p in ("vpcs.json", "subnets.json")}
    kinds = ("compute", "cluster", *_MONITOR.KINDS)
    collected = cli_resources({**files, **network})[0]                  # the compute fixtures' VPC
    by_hand = cli_resources({p: json.dumps(d) for p, d in {**_COMPUTE.CLI, **_MONITOR.CLI}.items()})[0]
    assert {r.ref: r for r in collected if r.kind in kinds} == {r.ref: r for r in by_hand if r.kind in kinds} != {}


def _messaging_answer(argv):
    """What the AWS CLI prints for the messaging calls (after their --query), from that reader's own fixtures."""
    f, op = _MESSAGING.CLI, tuple(argv[1:3])
    arg = dict(zip(argv[3::1], argv[4::1]))
    queue = (arg.get("--queue-url") or "").rsplit("/", 1)[-1]
    tagged = {"events": "event-bus-tags", "kinesis": "stream-tags"}
    answers = {
        ("sqs", "list-queues"): {"QueueUrls": [f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/{q}"
                                               for q in ("ciam-crm", "ciam-crm-dlq")]},
        ("sqs", "get-queue-attributes"): {"QueueArn": f"arn:aws:sqs:us-east-1:{ACCOUNT}:{queue}"},
        ("sqs", "list-queue-tags"): f.get(f"queue-tags/{queue}.json"),
        ("events", "list-event-buses"): f["event-buses.json"], ("kinesis", "list-streams"): f["streams.json"],
        ("sesv2", "list-email-identities"): {"EmailIdentities": [
            {"IdentityName": "example.test", "IdentityType": "DOMAIN"},
            {"IdentityName": "ops@example.test", "IdentityType": "EMAIL_ADDRESS"}]},
        ("sesv2", "get-email-identity"): f.get(f"email-identities/{arg.get('--email-identity')}.json")}
    if op[1] == "list-tags-for-resource" and op[0] in tagged:
        name = (arg["--resource-arn"].split(":event-bus/", 1) + [""])[1] or arg["--resource-arn"].rsplit("/", 1)[-1]
        return json.dumps(f[f"{tagged[op[0]]}/{name.replace('/', '%2F')}.json"]), None
    return (json.dumps(answers[op]), None) if op in answers else _answer(argv)


def test_messaging_collected_reads_as_saved_by_hand():
    """Queues (ARN and tags, projected), event buses' and streams' tags (none asked for the default bus) and SES
    domain identities (projected: no policies; addresses aren't asked for) read to the same record as the outputs
    saved by hand."""
    m = _model(ciamAccountRef=ACCOUNT)
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, lambda call: _messaging_answer(call.argv))
    assert c.problems == ()
    ran = [shlex.split(x.provenance) for x in c.calls]
    assert {tuple(a[1:3]) for a in ran} <= OPERATIONS
    for op, projection in (("get-queue-attributes", "queue-arn"), ("list-queue-tags", "queue-tags"),
                           ("get-email-identity", "email-identity")):
        assert all(a[a.index("--query") + 1] == PROJECTIONS[projection] for a in ran if a[2] == op)
    assert [a[a.index("--email-identity") + 1] for a in ran if a[2] == "get-email-identity"] == ["example.test"]
    buses = [a[a.index("--resource-arn") + 1] for a in ran if a[1:3] == ["events", "list-tags-for-resource"]]
    assert len(buses) == 2 and not [b for b in buses if b.endswith("/default")]
    files = {p.split("/", 2)[2]: t for p, t in c.files.items()}
    assert {"queues/ciam-crm.json", "queue-tags/ciam-crm-dlq.json", "event-bus-tags/ciam-audit.json",
            "event-bus-tags/aws.partner%2Fexample.com%2F123%2Faudit.json", "stream-tags/ciam-logs.json",
            "email-identities/example.test.json"} <= set(files)
    network = {p: json.dumps(_MESSAGING.CLI[p]) for p in ("vpcs.json", "subnets.json")}
    collected = cli_resources({**files, **network})[0]
    by_hand = cli_resources({p: json.dumps(d) for p, d in _MESSAGING.CLI.items()})[0]
    kinds = _MESSAGING.KINDS
    assert {r.ref: r for r in collected if r.kind in kinds} == {r.ref: r for r in by_hand if r.kind in kinds} != {}


def _security_answer(argv):
    """What the AWS CLI prints for the security calls, from the security reader's fixtures: GuardDuty's organization
    configuration answers (a delegated administrator for it), Inspector's and Security Hub's refuse."""
    f, op = _SECURITY.CLI, tuple(argv[1:3])
    by_op = {("guardduty", "list-detectors"): {"DetectorIds": ["12abc"]},
             ("guardduty", "get-detector"): f["guardduty/12abc.json"],
             ("guardduty", "describe-organization-configuration"): f["organization-configuration/guardduty-12abc.json"],
             ("inspector2", "batch-get-account-status"): f["inspector2.json"],
             ("configservice", "describe-configuration-recorders"): f["config-recorders.json"],
             ("configservice", "describe-delivery-channels"): f["config-channels.json"],
             ("configservice", "describe-retention-configurations"): f["config-retention.json"],
             ("securityhub", "describe-hub"): f["securityhub-hub.json"],
             ("securityhub", "get-enabled-standards"): f["securityhub-standards.json"]}
    if op in (("inspector2", "describe-organization-configuration"),
              ("securityhub", "describe-organization-configuration")):
        return None, None                   # not the delegated administrator: the documented error, the file left out
    return (json.dumps(by_op[op]), None) if op in by_op else _answer(argv)


def test_security_services_collected_read_as_saved_by_hand():
    m = _model(ciamAccountRef=ACCOUNT)
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, lambda call: _security_answer(call.argv))
    assert c.problems == ()
    ran = [shlex.split(x.provenance) for x in c.calls]
    assert {tuple(a[1:3]) for a in ran} <= OPERATIONS
    assert ["aws", "guardduty", "get-detector", "--detector-id", "12abc"] == next(
        a for a in ran if a[2] == "get-detector")[:5]
    files = {p.split("/", 2)[2]: t for p, t in c.files.items()}
    assert {"guardduty/12abc.json", "organization-configuration/guardduty-12abc.json", "inspector2.json",
            "securityhub-standards.json"} <= set(files)
    refused = {"organization-configuration/inspector2.json", "organization-configuration/securityhub.json"}
    assert not refused & set(files)
    security = ("guardduty/", "organization-configuration/", "inspector2", "config-", "securityhub-")
    assert all(json.loads(files[p]) == d for p, d in _SECURITY.CLI.items() if p.startswith(security))   # as by hand
    scopes = {r.attrs["ciamSecurityKind"][0]: r.attrs["ciamAuditScope"] for r in cli_resources(files)[0]
              if r.kind == "security"}
    assert scopes == {"threat-detection": ("organization",), "vulnerability-scanning": ("account",),
                      "config-recording": ("account",), "posture": ("account",)}


BILLING = "111122223333"             # the budgets fixtures' account: here a GovCloud cloud's standard account


def _budget_answer(argv, account=ACCOUNT):
    """What AWS Budgets prints, from the budget reader's fixtures (saved for BILLING), for the account asked about;
    the profiles' identities: billing-std in BILLING, org-mgmt elsewhere."""
    f, op = _BUDGETS.BUDGET_CLI, tuple(argv[1:3])
    arg = dict(zip(argv[3::1], argv[4::1]))
    folder = "budgets/111122223333/alpha-prod-monthly"
    if op == ("sts", "get-caller-identity") and "--profile" in argv:
        who = BILLING if arg["--profile"] == "billing-std" else "999988887777"
        return json.dumps({"Account": who}), None
    if op[0] == "budgets":
        assert arg.get("--account-id", account) == account
        if op[1] == "describe-subscribers-for-notification":
            notes = f[f"{folder}/notifications.json"]["Notifications"]
            i = next(i for i, n in enumerate(notes) if json.loads(arg["--notification"]) == n)
            return json.dumps(f[f"{folder}/subscribers-{i}.json"]), None
        doc = {"describe-budgets": f["budgets/111122223333.json"],
               "describe-notifications-for-budget": f[f"{folder}/notifications.json"],
               "list-tags-for-resource": f[f"{folder}/tags.json"]}[op[1]]
        return json.dumps(doc), None
    return _org_answer(argv) if "--profile" in argv else _answer(argv)


def test_the_accounts_budgets_collected_read_as_saved_by_hand():
    m = _model(ciamAccountRef=BILLING)
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, lambda call: _budget_answer(call.argv, BILLING))
    assert c.problems == ()
    files = {p.split("/", 2)[2]: t for p, t in c.files.items()}
    assert all(json.loads(files[p]) == d for p, d in _BUDGETS.BUDGET_CLI.items() if p.startswith("budgets/"))
    ran = [shlex.split(x.provenance) for x in c.calls]
    subscribers = next(a for a in ran if a[2] == "describe-subscribers-for-notification")
    assert subscribers[subscribers.index("--query") + 1] == PROJECTIONS["subscribers"]       # no e-mail addresses
    assert {tuple(a[1:3]) for a in ran} <= OPERATIONS


def test_govcloud_budgets_come_from_the_standard_account_through_its_profile():
    m = _with_profile(_model(ciamAccountRef=ACCOUNT, ciamOrganizationRef=ORG, ciamRegion="us-gov-west-1",
                             ciamBillingAccountRef=BILLING), "org-mgmt", "billing-std")
    assert inventory_problems(m.d, m, {}) == ()
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, lambda call: _budget_answer(call.argv, BILLING))
    assert c.problems == ()
    ran = [shlex.split(x.provenance) for x in c.calls]
    budgets = [a for a in ran if a[1] == "budgets"]
    assert budgets and all(a[a.index("--profile") + 1] == "billing-std" and a[-1] == "us-east-1" for a in budgets)
    assert all(a[a.index("--profile") + 1] == "org-mgmt" for a in ran if a[1] == "organizations")
    files = {p.split("/", 2)[2] for p in c.files}
    assert "budgets/111122223333.json" in files and "budgets/222233334444.json" not in files
    resources, _ = cli_resources({p.split("/", 2)[2]: t for p, t in c.files.items()})
    assert [r.ref for r in resources if r.kind == "budget"] == [
        "arn:aws:budgets::111122223333:budget/alpha-prod-monthly"]


def test_profile_sources_beyond_the_organizations_and_the_standard_accounts_are_problems():
    gov = _model(ciamAccountRef=ACCOUNT, ciamRegion="us-gov-west-1", ciamBillingAccountRef=BILLING)
    assert inventory_problems(gov.d, _with_profile(gov, "a", "b", "c"), {}) == (
        "more than two aws-profile:// collection sources: name one profile for the organization's policies and one "
        "for the standard account's budgets",)
    assert inventory_problems(gov.d, _with_profile(gov, "billing-std"), {}) == ()     # no organization recorded


def test_budget_calls_name_us_east_1_and_never_ask_for_fips_endpoints():
    m = _model(ciamAccountRef=BILLING, ciamFipsEndpoints="TRUE")
    c = collect("aws/cli-inventory", COLLECTORS[0], m.d, m, lambda call: _budget_answer(call.argv, BILLING))
    steps = inventory_steps(m.d, m, c.files, {})
    budgets = [call for _, call in steps if not isinstance(call, str) and call.argv[1] == "budgets"]
    others = [call for _, call in steps if not isinstance(call, str) and call.argv[1] != "budgets"]
    assert budgets and all(call.env == () and call.argv[-1] == "us-east-1" for call in budgets)   # no FIPS endpoint
    assert all(call.env == (("AWS_USE_FIPS_ENDPOINT", "true"),) for call in others)
