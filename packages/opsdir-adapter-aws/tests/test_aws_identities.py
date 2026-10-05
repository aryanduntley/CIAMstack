"""A workload's identity as AWS Terraform: an IAM role EC2 may assume, a least-privilege policy from the AWS
permission table (the first action of each requirement, on the binding's resources), the instance profile, and notes
for what can't be granted."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.access.workloads import WorkloadIdentity
from opsdir_adapter_aws.access import PERMISSIONS
from opsdir_adapter_aws.terraform import _identity

SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/pf-admin-password"
BINDING = make_entry("cn=secret,ou=bindings,env=prod", ("top", "ciamSecretRef"),
                     {"ciamBindingRole": ["pf-admin-password"], "ciamRefUri": [f"aws-sm://{SECRET}"]})
ROW = next(r for r in PERMISSIONS if r.verb == "read-secret")


def _rendered(grants, notes=()):
    return "\n".join(_identity(None, WorkloadIdentity("pf-engine", "identity-pf-engine", "pf-engine",
                                                      "ciam-prod-pf-engine", grants, notes)))


def test_a_role_with_its_least_privilege_policy_and_instance_profile():
    out = _rendered((("read-secret pf-admin-password", BINDING, ROW),))
    assert 'resource "aws_iam_role" "identity_pf_engine"' in out and '"Service" : "ec2.amazonaws.com"' in out
    assert '"Sid" : "ReadSecretPfAdminPassword"' in out and '"secretsmanager:GetSecretValue"' in out
    assert f'"{SECRET}-??????"' in out and f'"{SECRET}"' not in out
    assert 'role = aws_iam_role.identity_pf_engine.id' in out
    assert 'resource "aws_iam_instance_profile" "identity_pf_engine"' in out


def test_a_secret_under_a_customer_key_also_gets_that_key_through_secrets_manager():
    key_arn = "arn:aws:kms:us-east-1:111122223333:key/abcd"
    locked = make_entry("cn=locked,ou=bindings,env=prod", ("top", "ciamSecretRef"),
                        {"ciamBindingRole": ["ds-root-password"], "ciamRefUri": [f"aws-sm://{SECRET}"],
                         "ciamEncryptedByRole": ["secrets-key"]})
    key = make_entry("cn=key,ou=bindings,env=prod", ("top", "ciamKeyRef"),
                     {"ciamBindingRole": ["secrets-key"], "ciamRefUri": [f"aws-kms://{key_arn}"]})
    m = SimpleNamespace(bindings=(locked, key), cloud=make_entry("cloud=c", ("top", "ciamCloud"),
                                                                 {"ciamRegion": ["us-east-1"]}))
    out = "\n".join(_identity(m, WorkloadIdentity("pf-engine", "identity-pf-engine", "pf-engine", "ciam-prod-pf-engine",
                                                  (("read-secret ds-root-password", locked, ROW),), ())))
    assert '"Sid" : "ReadSecretDsRootPasswordKey"' in out and '"kms:Decrypt"' in out and f'"{key_arn}"' in out
    assert '"kms:ViaService" : "secretsmanager.us-east-1.amazonaws.com"' in out


def test_what_cant_be_granted_is_a_note_and_no_empty_policy_is_written():
    out = _rendered((), ("use-key disk-encryption: role `disk-encryption` has no binding in this environment",))
    assert "# NOTE: principal pf-engine: use-key disk-encryption: role `disk-encryption` has no binding" in out
    assert "aws_iam_role_policy" not in out and "aws_iam_instance_profile" in out
