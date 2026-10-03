"""AWS IAM read from Terraform state into the record's identities, guardrails and access paths: a role's trust, grants,
denials and boundary; resource policies on the roles they name; permission sets by group; control policies with what
they prevent; the key that encrypts a secret; and what the record then says of a permission."""
import json
from types import SimpleNamespace

from opsdir.core.directory import make_directory, one, values
from opsdir.domains.access.grants import ALLOWED, DENIED, UNKNOWN, effective
from opsdir_adapter_aws.access import ACCESS
from opsdir_adapter_aws.guardrails import _statements
from opsdir_adapter_aws.iam import iam_resources
from opsdir_adapter_aws.inventory import read_terraform_state

ACCT = "arn:aws:iam::111122223333"
ROLE = f"{ACCT}:role/ciam-prod-pf"
SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/pf-admin-password-AbC123"
KEY = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234"
OIDC = f"{ACCT}:oidc-provider/token.actions.githubusercontent.com"
ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
B = f"ou=bindings,{ENV}"


def _doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _pairs(*extra):
    return [
        ("aws_iam_role", {"arn": ROLE, "name": "ciam-prod-pf", "tags": {"Role": "identity-pf"},
                          "permissions_boundary": f"{ACCT}:policy/ciam-boundary",
                          "assume_role_policy": _doc(
                              {"Effect": "Allow", "Action": "sts:AssumeRole",
                               "Principal": {"Service": "ec2.amazonaws.com"}},
                              {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                               "Principal": {"Federated": OIDC}, "Condition": {"StringLike": {
                                   "token.actions.githubusercontent.com:sub": "repo:example/ciam:environment:prod"}}}),
                          "inline_policy": [{"name": "app", "policy": _doc(
                              {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": SECRET},
                              {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::ciam-backups/*",
                               "Condition": {"Bool": {"aws:SecureTransport": "true"}}},
                              {"Effect": "Deny", "NotAction": ["kms:*", "secretsmanager:*"], "Resource": "*"})}],
                          "managed_policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]}),
        ("aws_iam_role_policy_attachment", {"role": "ciam-prod-pf", "policy_arn": f"{ACCT}:policy/ciam-logs"}),
        ("aws_iam_policy", {"arn": f"{ACCT}:policy/ciam-logs", "policy": _doc(
            {"Effect": "Allow", "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
             "Resource": "arn:aws:logs:us-east-1:111122223333:log-group:ciam:*"})}),
        ("aws_iam_policy", {"arn": f"{ACCT}:policy/ciam-boundary", "policy": _doc(
            {"Effect": "Allow", "Action": ["secretsmanager:*", "kms:*", "logs:*"], "Resource": "*"})}),
        ("aws_kms_key", {"arn": KEY, "key_id": "mrk-1234", "policy": _doc(
            {"Effect": "Allow", "Principal": {"AWS": f"{ACCT}:root"}, "Action": "kms:*", "Resource": "*"},
            {"Effect": "Allow", "Principal": {"AWS": [ROLE, f"{ACCT}:role/elsewhere"]}, "Action": "kms:Decrypt",
             "Resource": "*"})}),
        ("aws_s3_bucket_policy", {"bucket": "ciam-backups", "policy": _doc(
            {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::ciam-backups/*",
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}})}),
        *extra]


def _one(resources, kind, ref):
    return next(r for r in resources if r.kind == kind and r.ref == ref)


def test_a_roles_trust_grants_denials_and_boundary():
    resources, notices = iam_resources(_pairs())
    role = _one(resources, "identity", ROLE)
    assert role.role == "identity-pf" and role.attrs["ciamIdentityKind"] == ("federated",)
    assert role.attrs["ciamTrustedBy"] == (
        "ec2.amazonaws.com", "https://token.actions.githubusercontent.com repo:example/ciam:environment:prod")
    assert set(role.attrs["ciamGrant"]) == {
        f"secretsmanager:GetSecretValue on {SECRET}",
        "s3:PutObject on arn:aws:s3:::ciam-backups/* (if Bool aws:SecureTransport true)",
        "logs:PutLogEvents on arn:aws:logs:us-east-1:111122223333:log-group:ciam:*",
        "logs:CreateLogStream on arn:aws:logs:us-east-1:111122223333:log-group:ciam:*",
        f"kms:Decrypt on {KEY} (resource policy)"}                       # the key policy's '*' is the key
    assert set(role.attrs["ciamDenial"]) == {
        "!kms:*|secretsmanager:* on *",
        "s3:* on arn:aws:s3:::ciam-backups/* (resource policy) (if Bool aws:SecureTransport false)"}
    assert set(role.attrs["ciamBoundary"]) == {"secretsmanager:* on *", "kms:* on *", "logs:* on *"}
    assert ("role ciam-prod-pf: policy arn:aws:iam::aws:policy/ReadOnlyAccess isn't in the state (an AWS managed "
            "policy, or kept elsewhere); its grants not read") in notices
    assert f"resource policies grant {ACCT}:role/elsewhere, which isn't a role in this state; not recorded" in notices
    assert not any(":root" in n for n in notices)                         # the account itself isn't a stranger


def test_permission_sets_by_group_and_control_policies():
    group = "9a4f7c2e-0000-4000-8000-000000000001"
    sets = "arn:aws:sso:::permissionSet/ssoins-1/ps-1"
    scp = _doc(*_statements("key-deletion", "us-east-1"), *_statements("service-account-keys", "us-east-1"),
               {"Effect": "Allow", "Action": "*", "Resource": "*"})
    resources, _ = iam_resources(_pairs(
        ("aws_ssoadmin_permission_set", {"arn": sets, "name": "ciam-admins", "tags": {"Role": "admin-group"}}),
        ("aws_ssoadmin_permission_set_inline_policy", {"permission_set_arn": sets, "inline_policy": _doc(
            {"Effect": "Allow", "Action": "secretsmanager:PutSecretValue", "Resource": SECRET})}),
        ("aws_ssoadmin_account_assignment", {"permission_set_arn": sets, "principal_id": group,
                                             "principal_type": "GROUP", "target_id": "111122223333"}),
        ("aws_organizations_policy", {"arn": "arn:aws:organizations::1:policy/o-1/service_control_policy/p-1",
                                      "name": "ciam-prod-fence", "type": "SERVICE_CONTROL_POLICY", "content": scp,
                                      "tags": {"Role": "org-guardrails"}}),
        ("aws_organizations_policy", {"arn": "arn:aws:organizations::1:policy/o-1/resource_control_policy/p-2",
                                      "name": "ciam-rcp", "type": "RESOURCE_CONTROL_POLICY", "content": _doc(
                                          {"Effect": "Allow", "Action": "s3:*", "Resource": "*"})}),
        ("aws_ssoadmin_instances", {"arns": ["arn:aws:sso:::instance/ssoins-1"], "identity_store_ids": ["d-1"]})))
    admins = _one(resources, "identity", group)
    assert admins.role == "admin-group" and admins.attrs["ciamIdentityKind"] == ("permission-set",)
    assert admins.attrs["ciamGrant"] == (f"secretsmanager:PutSecretValue on {SECRET}",)
    fence = _one(resources, "guardrail", "arn:aws:organizations::1:policy/o-1/service_control_policy/p-1")
    assert fence.attrs["ciamGuardrailKind"] == ("service-control",)
    assert fence.attrs["ciamDenies"] == ("key-deletion", "service-account-keys")    # by the renderer's statement ids
    assert "kms:ScheduleKeyDeletion on *" in fence.attrs["ciamDenial"]
    assert "ciamBoundary" not in fence.attrs                              # allowing everything is no ceiling
    rcp = _one(resources, "guardrail", "arn:aws:organizations::1:policy/o-1/resource_control_policy/p-2")
    assert rcp.attrs["ciamGuardrailKind"] == ("resource-control",) and rcp.attrs["ciamBoundary"] == ("s3:* on *",)
    sso = _one(resources, "access", "arn:aws:sso:::instance/ssoins-1")
    assert sso.role == "access-workforce-sso" and sso.attrs["ciamTrustedBy"] == ("d-1",)


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return make_directory((), {}, (
        _row("cloud=main,ou=environments,dc=ciam-ops", ("ciamCloud",), cloud="main", ciamCloudProvider="aws",
             ciamRegion="us-east-1"),
        _row(ENV, ("ciamEnvironment",), env="prod"),
        _row(B, ("organizationalUnit",), ou="bindings"),
        _row(f"cn=pf-admin,{B}", ("ciamSecretRef",), cn="pf-admin", ciamBindingRole="pf-admin-password",
             ciamRefUri=f"aws-sm://{SECRET}"),
        _row(f"cn=secrets-key,{B}", ("ciamKeyRef",), cn="secrets-key", ciamBindingRole="secrets-key",
             ciamRefUri=f"aws-kms://{KEY}"),
        _row(f"cn=pf-identity,{B}", ("ciamIdentityBinding",), cn="pf-identity", ciamBindingRole="identity-pf",
             ciamProviderRef="ciam-prod-pf")))                            # named by the role's name only


def _state(*extra):
    def res(type_, attrs):
        return {"mode": "managed", "type": type_, "name": "x", "instances": [{"attributes": attrs}]}
    return json.dumps({"version": 4, "resources": [res(t, a) for t, a in (
        *_pairs(*extra), ("aws_secretsmanager_secret", {"arn": SECRET, "name": "ciam/prod/pf-admin-password",
                                                        "kms_key_id": "mrk-1234"}))]})


def _imported(state):
    d = _record()
    imported = read_terraform_state({"main/prod/terraform.tfstate": state}, d, ())
    entries = {e.norm: e for _, es in imported.groups for e in es}
    return SimpleNamespace(bindings=tuple(entries.values())), entries, imported.notices


def test_the_record_learns_the_identity_and_what_it_may_do():
    env, _, _ = _imported(_state())
    identity = next(e for e in env.bindings if one(e, "ciamBindingRole") == "identity-pf")
    assert identity.dn.lower() == f"cn=pf-identity,{B}".lower()           # matched by its short name
    assert one(identity, "ciamProviderRef") == ROLE
    secret = next(e for e in env.bindings if one(e, "ciamBindingRole") == "pf-admin-password")
    assert values(secret, "ciamEncryptedByRole") == ("secrets-key",)     # the key's role, not its DN
    verdict = effective(ACCESS, env, "read-secret pf-admin-password", identity)
    assert verdict.state == ALLOWED                                       # GetSecretValue + kms:Decrypt by key policy
    assert effective(ACCESS, env, "write-secret pf-admin-password", identity).state == "not granted"


def test_a_deny_or_a_ceiling_in_the_state_decides_it():
    deny = ("aws_iam_role_policy", {"role": "ciam-prod-pf", "policy": _doc(
        {"Effect": "Deny", "Action": "secretsmanager:GetSecretValue", "Resource": "*"})})
    env, _, _ = _imported(_state(deny))
    identity = next(e for e in env.bindings if one(e, "ciamBindingRole") == "identity-pf")
    verdict = effective(ACCESS, env, "read-secret pf-admin-password", identity)
    assert verdict.state == DENIED and "secretsmanager:GetSecretValue on *" in verdict.why
    conditional = ("aws_iam_role_policy", {"role": "ciam-prod-pf", "policy": _doc(
        {"Effect": "Deny", "Action": "secretsmanager:*", "Resource": "*",
         "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-1"}}})})
    env, _, _ = _imported(_state(conditional))
    identity = next(e for e in env.bindings if one(e, "ciamBindingRole") == "identity-pf")
    assert effective(ACCESS, env, "read-secret pf-admin-password", identity).state == UNKNOWN
