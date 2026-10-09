"""A workload's identity as AWS Terraform: an IAM role EC2 may assume, a least-privilege policy from the AWS
permission table (the first action of each requirement, on the binding's resources), the instance profile, notes
for what can't be granted, and the trust of the Kubernetes service accounts that assume it (IRSA)."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.access.workloads import Pod, WorkloadIdentity
from opsdir_adapter_aws.access import PERMISSIONS
from opsdir_adapter_aws.identities import eks_data
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


def test_kubernetes_service_accounts_assume_the_role_through_their_clusters_oidc_provider():
    cluster = make_entry("cn=eks,ou=bindings,env=prod", ("top", "ciamCluster"), {
        "ciamBindingRole": ["k8s"], "ciamProviderRef": ["arn:aws:eks:us-east-1:111122223333:cluster/ciam-prod"]})
    w = WorkloadIdentity("am", "identity-am", "am", "ciam-prod-am", (), (), servers=False,
                         pods=(Pod("identity", "am", cluster), Pod("identity", "amster", cluster),
                               Pod("tools", "x", None)))
    data = "\n".join(eks_data((w,)))
    assert 'data "aws_eks_cluster" "ciam_prod"' in data and 'name = "ciam-prod"' in data
    assert "url = data.aws_eks_cluster.ciam_prod.identity[0].oidc[0].issuer" in data
    out = "\n".join(_identity(None, w))
    assert 'data "aws_iam_policy_document" "identity_am_trust"' in out
    assert "identifiers = [data.aws_iam_openid_connect_provider.ciam_prod.arn]" in out
    assert 'values   = ["system:serviceaccount:identity:am", "system:serviceaccount:identity:amster"]' in out
    assert 'values   = ["sts.amazonaws.com"]' in out
    assert "assume_role_policy = data.aws_iam_policy_document.identity_am_trust.json" in out
    assert "ec2.amazonaws.com" not in out and "aws_iam_instance_profile" not in out     # no servers of am here
    assert "# NOTE: principal am: service account tools/x runs in a cluster this environment doesn't bind" in out
    both = "\n".join(_identity(None, w._replace(servers=True)))
    assert '"ec2.amazonaws.com"' in both and 'resource "aws_iam_instance_profile"' in both
