"""AWS IAM read from the AWS CLI's outputs, as from Terraform state: roles and policies from
get-account-authorization-details (AWS managed policies included), key and bucket policies named by their files,
control policies from the management account, Identity Center; the policy simulator's verdicts, asked by the
renderer's access/evaluate.sh and read back dated, preferred by the planner."""
import datetime as dt
import json
from types import SimpleNamespace
from urllib.parse import quote

from opsdir.connectors.render import render_env
from opsdir.core.directory import make_entry
from opsdir.core.interchange.ldif import parse
from opsdir.domains.access.grants import DENIED, effective
from opsdir_adapter_aws.access import ACCESS
from opsdir_adapter_aws.cli import cli_resources
from support import REGISTRY, build_directory

ACCT = "arn:aws:iam::111122223333"
ROLE = f"{ACCT}:role/ciam-prod-pf"
SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/pf-admin-password"
KEY = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234"
AT = dt.datetime(2026, 10, 2, 12, tzinfo=dt.timezone.utc)


def _doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


AUTHORIZATION = {
    "UserDetailList": [{"UserName": "legacy"}], "GroupDetailList": [],
    "RoleDetailList": [{
        "RoleName": "ciam-prod-pf", "Arn": ROLE, "Tags": [{"Key": "Role", "Value": "identity-pf"}],
        "AssumeRolePolicyDocument": quote(json.dumps(_doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                                                           "Principal": {"Service": "ec2.amazonaws.com"}}))),
        "RolePolicyList": [{"PolicyName": "app", "PolicyDocument": _doc(
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": f"{SECRET}-??????"})}],
        "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]}],
    "Policies": [{"Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess",
                  "PolicyVersionList": [{"IsDefaultVersion": False, "Document": _doc()},
                                        {"IsDefaultVersion": True, "Document": _doc(
                                            {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"],
                                             "Resource": "*"})}]}]}


def _outputs(**extra):
    return {"iam.json": json.dumps(AUTHORIZATION),
            "key-policy/mrk-1234.json": json.dumps({"PolicyName": "default", "Policy": json.dumps(_doc(
                {"Effect": "Allow", "Principal": {"AWS": ROLE}, "Action": "kms:Decrypt", "Resource": "*"}))}),
            "bucket-policy/ciam-backups.json": json.dumps({"Policy": json.dumps(_doc(
                {"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteObject",
                 "Resource": "arn:aws:s3:::ciam-backups/*"}))}),
            "keys/mrk-1234.json": json.dumps({"KeyMetadata": {
                "Arn": KEY, "KeyId": "mrk-1234", "KeyManager": "CUSTOMER", "KeyState": "Enabled"}}),
            "secrets.json": json.dumps({"SecretList": [{
                "ARN": f"{SECRET}-AbC123", "Name": "ciam/prod/pf-admin-password", "KmsKeyId": KEY}]}),
            "org/fence.json": json.dumps({"Policy": {"PolicySummary": {
                "Arn": "arn:aws:organizations::1:policy/o-1/service_control_policy/p-1", "Id": "p-1",
                "Name": "ciam-prod-fence", "Type": "SERVICE_CONTROL_POLICY"},
                "Content": json.dumps(_doc({"Sid": "DenyKeyDeletion", "Effect": "Deny",
                                            "Action": "kms:ScheduleKeyDeletion", "Resource": "*"}))}}),
            "sso/admins.json": json.dumps({"PermissionSet": {
                "Name": "ciam-admins", "PermissionSetArn": "arn:aws:sso:::permissionSet/i/ps-1"}}),
            "sso-inline/ciam-admins.json": json.dumps({"InlinePolicy": json.dumps(_doc(
                {"Effect": "Allow", "Action": "secretsmanager:PutSecretValue", "Resource": f"{SECRET}-??????"}))}),
            "sso/assignments.json": json.dumps({"AccountAssignments": [{
                "AccountId": "111122223333", "PermissionSetArn": "arn:aws:sso:::permissionSet/i/ps-1",
                "PrincipalType": "GROUP", "PrincipalId": "9a4f-group"}]}),
            **extra}


def _one(resources, kind, ref):
    return next(r for r in resources if r.kind == kind and r.ref == ref)


def test_iam_from_the_cli_reads_as_from_state():
    resources, notices = cli_resources(_outputs(), AT)
    role = _one(resources, "identity", ROLE)
    assert role.role == "identity-pf" and role.attrs["ciamTrustedBy"] == ("ec2.amazonaws.com",)   # URL-encoded
    assert set(role.attrs["ciamGrant"]) == {
        f"secretsmanager:GetSecretValue on {SECRET}-??????", "s3:Get* on *", "s3:List* on *",       # AWS managed
        f"kms:Decrypt on {KEY} (resource policy)"}
    assert role.attrs["ciamDenial"] == ("s3:DeleteObject on arn:aws:s3:::ciam-backups/* (resource policy)",)
    secret = _one(resources, "secret", f"{SECRET}-AbC123")
    assert secret.links == {"ciamEncryptedByRole": KEY}
    fence = _one(resources, "guardrail", "arn:aws:organizations::1:policy/o-1/service_control_policy/p-1")
    assert fence.attrs["ciamDenies"] == ("key-deletion",)
    admins = _one(resources, "identity", "9a4f-group")
    assert admins.attrs["ciamGrant"] == (f"secretsmanager:PutSecretValue on {SECRET}-??????",)
    assert ("iam: 1 user(s) and 0 group(s) not read (the record's identities are roles, permission sets and "
            "federated principals)") in notices


def test_a_policy_that_doesnt_say_whose_is_named():
    _, notices = cli_resources({"policy.json": json.dumps({"Policy": "{}"})}, AT)
    assert notices == ("policy.json: a key or bucket policy that doesn't say whose (save get-key-policy as "
                       "key-policy/<key id>.json, get-bucket-policy as bucket-policy/<bucket>.json); not read",)


def test_simulator_verdicts_are_read_back_dated_and_preferred():
    simulated = {
        "evaluations/ciam-prod-pf/read-secret__pf-admin-password.1.json": json.dumps({"EvaluationResults": [
            {"EvalActionName": "secretsmanager:GetSecretValue", "EvalDecision": "allowed"}]}),
        "evaluations/ciam-prod-pf/read-secret__pf-admin-password.2.json": json.dumps({"EvaluationResults": [
            {"EvalActionName": "kms:Decrypt", "EvalDecision": "explicitDeny"}]}),
        "evaluations/ciam-prod-pf/write-logs__audit-logs.json": json.dumps({"EvaluationResults": [
            {"EvalActionName": "logs:PutLogEvents", "EvalDecision": "allowed"},           # on one of the resources
            {"EvalActionName": "logs:PutLogEvents", "EvalDecision": "implicitDeny"},
            {"EvalActionName": "logs:CreateLogStream", "EvalDecision": "implicitDeny",
             "MissingContextValues": ["aws:SourceVpc"]}]}),
        "evaluations/ciam-other/read-secret__pf-admin-password.json": json.dumps({"EvaluationResults": [
            {"EvalActionName": "secretsmanager:GetSecretValue", "EvalDecision": "implicitDeny"}]})}
    resources, _ = cli_resources(_outputs(**simulated), AT)
    assert _one(resources, "identity", ROLE).attrs["ciamEvaluated"] == (
        "read-secret pf-admin-password: denied (aws-simulator 2026-10-02)",          # the worst of its parts
        "write-logs audit-logs: unknown (aws-simulator 2026-10-02)")
    other = _one(resources, "identity", "ciam-other")                              # simulated only: by name
    assert "ciamIdentityKind" not in other.attrs
    assert other.attrs["ciamEvaluated"] == ("read-secret pf-admin-password: denied (aws-simulator 2026-10-02)",)
    identity = make_entry("cn=pf,ou=bindings,env=prod", ("top", "ciamIdentityBinding"),
                          {"ciamGrant": [f"secretsmanager:GetSecretValue on {SECRET}-??????"],
                           "ciamEvaluated": list(_one(resources, "identity", ROLE).attrs["ciamEvaluated"])})
    env = SimpleNamespace(bindings=(make_entry("cn=s,ou=bindings,env=prod", ("top", "ciamSecretRef"), {
        "ciamBindingRole": ["pf-admin-password"], "ciamRefUri": [f"aws-sm://{SECRET}"]}),))
    verdict = effective(ACCESS, env, "read-secret pf-admin-password", identity)
    assert verdict.state == DENIED and verdict.why == "by aws-simulator 2026-10-02"


ENV = "env=prod,cloud=aws,ou=environments,dc=ciam-ops"


def _entry(dn, oc, **attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: {oc}\n" + "".join(f"{k}: {v}\n" for k, v in attrs.items())


def test_the_renderer_writes_the_script_that_asks_the_simulator():
    records = "\n".join((
        "dn: dc=ciam-ops\nobjectClass: top\nobjectClass: domain\ndc: ciam-ops\n",
        "dn: ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: environments\n",
        _entry("cloud=aws,ou=environments,dc=ciam-ops", "ciamCloud", cloud="aws", ciamCloudProvider="aws",
               ciamRegion="us-east-1"),
        _entry(ENV, "ciamEnvironment", env="prod"),
        _entry(f"ou=bindings,{ENV}", "organizationalUnit", ou="bindings"),
        _entry(f"cn=vpc,ou=bindings,{ENV}", "ciamNetwork", cn="vpc", ciamBindingRole="network",
               ciamCidr="10.20.0.0/16", ciamProviderRef="vpc-0a1b2c3d4e5f67890"),
        _entry(f"cn=secret,ou=bindings,{ENV}", "ciamSecretRef", cn="secret", ciamBindingRole="pf-admin-password",
               ciamRefUri=f"aws-sm://{SECRET}-AbC123", ciamEncryptedByRole="secrets-key"),        # as imported
        _entry(f"cn=key,ou=bindings,{ENV}", "ciamKeyRef", cn="key", ciamBindingRole="secrets-key",
               ciamRefUri=f"aws-kms://{KEY}"),
        _entry(f"cn=identity-pf,ou=bindings,{ENV}", "ciamIdentityBinding", cn="identity-pf",
               ciamBindingRole="identity-pf", ciamProviderRef=ROLE, ciamIdentityKind="role"),
        "dn: ou=permission-sets,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: permission-sets\n",
        _entry("cn=pf,ou=permission-sets,dc=ciam-ops", "ciamPermissionSet", cn="pf",
               ciamPermits="read-secret pf-admin-password"),
        "dn: ou=principals,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: principals\n",
        _entry("cn=pingfederate,ou=principals,dc=ciam-ops", "ciamPrincipal", cn="pingfederate",
               ciamPrincipalKind="service", ciamIdentityRole="identity-pf",
               ciamHoldsSet="cn=pf,ou=permission-sets,dc=ciam-ops")))
    _, files = render_env(build_directory(REGISTRY, tuple(parse(records))), "aws/prod")
    script = files["access/evaluate.sh"]
    assert 'mkdir -p "$OUT/evaluations/ciam-prod-pf"' in script
    assert (f"aws iam simulate-principal-policy --policy-source-arn {ROLE} --action-names "
            f"secretsmanager:GetSecretValue --resource-arns {SECRET}-AbC123 --output json "
            '> "$OUT/evaluations/ciam-prod-pf/read-secret__pf-admin-password.1.json"') in script
    assert (f"--action-names kms:Decrypt --resource-arns {KEY} --output json "
            '> "$OUT/evaluations/ciam-prod-pf/read-secret__pf-admin-password.2.json"') in script
