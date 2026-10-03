"""AWS IAM read as the record's permissions: a secret by its suffixed ARN or a pattern, objects in a bucket, a topic
by kind, and the actions that raise an identity's access."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.access.grants import effective, escalating, grant_of, granted
from opsdir_adapter_aws.access import ACCESS

SECRET = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/pf-admin-password"
TOPIC = "arn:aws:sns:us-east-1:111122223333:ciam-audit"
ENV = SimpleNamespace(bindings=(
    make_entry("cn=secret,ou=bindings,env=prod", ("top", "ciamSecretRef"),
               {"ciamBindingRole": ["pf-admin-password"], "ciamRefUri": [f"aws-sm://{SECRET}"]}),
    make_entry("cn=backup,ou=bindings,env=prod", ("top", "ciamBackupTarget"),
               {"ciamBindingRole": ["backup-target"], "ciamStorageRef": ["s3://ciam-backups/ds"]}),
    make_entry("cn=audit,ou=bindings,env=prod", ("top", "ciamStreamBinding"),
               {"ciamBindingRole": ["audit-events"], "ciamProviderRef": [TOPIC], "ciamStreamKind": ["topic"]})))


def _granted(permit, *grants):
    return granted(ACCESS, ENV, permit, tuple(grant_of(g) for g in grants))[0]


def test_permissions_through_the_aws_table():
    assert _granted("read-secret pf-admin-password", f"secretsmanager:GetSecretValue on {SECRET}-AbCdEf")
    assert _granted("read-secret pf-admin-password", "secretsmanager:GetSecretValue on "
                    "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/*")
    assert not _granted("read-secret pf-admin-password", f"secretsmanager:GetSecretValue on {SECRET}-other-*")
    assert not _granted("read-secret pf-admin-password", f"secretsmanager:GetSecretValue on {SECRET}")  # no suffix
    assert _granted("write-storage backup-target", "s3:PutObject on arn:aws:s3:::ciam-backups/ds*")
    assert not _granted("read-storage backup-target", "s3:GetObject on arn:aws:s3:::ciam-backups/*")   # ListBucket
    assert _granted("publish-stream audit-events", f"sns:Publish on {TOPIC}")
    assert not _granted("publish-stream audit-events", f"sqs:SendMessage on {TOPIC}")


def test_escalating_actions():
    gs = tuple(grant_of(g) for g in ("iam:PassRole on arn:aws:iam::1:role/x", "iam:* on *", "s3:GetObject on b"))
    assert [g.action for g in escalating(ACCESS, gs)] == ["iam:PassRole", "iam:*"]


def test_managing_a_service_name_and_a_secret_under_a_customer_key():
    svc = make_entry("cn=svc-sso,ou=bindings,env=prod", ("top", "ciamServiceName"),
                     {"ciamBindingRole": ["pf-sso-service"], "ciamDnsZoneRef": ["Z0EXAMPLE"]})
    lb = "arn:aws:elasticloadbalancing:us-east-1:111122223333"
    env = SimpleNamespace(bindings=(svc,))
    grants = tuple(grant_of(g) for g in (
        f"elasticloadbalancing:ModifyListener on {lb}:listener/net/ciam-prod-svc-sso/1/2",
        f"elasticloadbalancing:RegisterTargets on {lb}:targetgroup/ciam-prod-svc-sso-443/3",
        f"elasticloadbalancing:DeregisterTargets on {lb}:targetgroup/ciam-prod-svc-sso-443/3",
        "route53:ChangeResourceRecordSets on arn:aws:route53:::hostedzone/Z0EXAMPLE"))
    assert granted(ACCESS, env, "manage pf-sso-service", grants)[0]
    assert not granted(ACCESS, env, "manage pf-sso-service", grants[:3])[0]             # the DNS records too
    locked = make_entry("cn=locked,ou=bindings,env=prod", ("top", "ciamSecretRef"),
                        {"ciamBindingRole": ["ds-root-password"], "ciamRefUri": [f"aws-sm://{SECRET}"],
                         "ciamEncryptedByRole": ["secrets-key"]})
    key = make_entry("cn=key,ou=bindings,env=prod", ("top", "ciamKeyRef"),
                     {"ciamBindingRole": ["secrets-key"], "ciamRefUri": ["aws-kms://arn:aws:kms:us-east-1:1:key/k"]})
    identity = make_entry("cn=id,ou=bindings,env=prod", ("top", "ciamIdentityBinding"),
                          {"ciamGrant": [f"secretsmanager:GetSecretValue on {SECRET}-AbCdEf"]})
    v = effective(ACCESS, SimpleNamespace(bindings=(locked, key)), "read-secret ds-root-password", identity)
    assert v.state == "not granted"                                       # kms:Decrypt on the key is missing
