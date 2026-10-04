"""AWS IAM as the record's neutral permissions: what each verb on a binding needs (IAM actions; the first of each
requirement is what the renderer grants), the actions that let an identity raise its own access, and how AWS names a
binding's resource (ARNs). Pure.

Sources: the AWS Secrets Manager, KMS, S3, SNS/SQS/EventBridge/Kinesis and CloudWatch Logs service authorization
references (checked 2026-10-02, note 450). A secret's ARN carries a random six-character suffix, so a secret is named
by its ARN followed by -?????? (exactly six characters, as AWS advises: -* would also match pf-admin-password-other);
a full ARN (imported: the suffix included) is named as it is.
A secret encrypted with a customer managed key (ciamEncryptedByRole) also needs kms:Decrypt on that key to be read,
and kms:GenerateDataKey and kms:Decrypt to be written (granted with kms:ViaService = secretsmanager.<region>).
`manage` means a secret's lifecycle, a service name's load balancer and DNS records, a compute group's size.
Evaluator: the IAM policy simulator (simulate-principal-policy) for each permission's actions on the binding's
resources, and on the key that encrypts a secret; not for a resource the record names by a pattern.
"""
import re

from opsdir.core.contract import AccessModel, Permission
from opsdir.core.directory import is_a, one, rdn_of, rdn_value
from opsdir.core.environment import environment_of, one_role
from opsdir.domains.access.evaluations import quoted
from opsdir.domains.access.grants import ALLOWED, DENIED, UNKNOWN, covered

SECRET, KEY, STORAGE, STREAM, LOGS = ("ciamSecretRef", "ciamKeyRef", "ciamObjectStore", "ciamStreamBinding",
                                      "ciamLogDestination")
SERVICE, COMPUTE = "ciamServiceName", "ciamComputeGroup"
ENCRYPTED_BY = "ciamEncryptedByRole"      # a secret under a customer managed key: that key is needed too
PERMISSIONS = (
    Permission("read-secret", SECRET, None, (("secretsmanager:GetSecretValue",),), False,
               ((ENCRYPTED_BY, (("kms:Decrypt",),)),)),
    Permission("write-secret", SECRET, None, (("secretsmanager:PutSecretValue",),), False,
               ((ENCRYPTED_BY, (("kms:GenerateDataKey",), ("kms:Decrypt",))),)),
    Permission("manage", SECRET, None, (("secretsmanager:PutSecretValue",), ("secretsmanager:UpdateSecret",),
                                        ("secretsmanager:RotateSecret",), ("secretsmanager:DeleteSecret",)), False,
               ((ENCRYPTED_BY, (("kms:GenerateDataKey",), ("kms:Decrypt",))),)),
    Permission("manage", SERVICE, None, (("elasticloadbalancing:ModifyListener",),
                                         ("elasticloadbalancing:RegisterTargets",),
                                         ("elasticloadbalancing:DeregisterTargets",),
                                         ("route53:ChangeResourceRecordSets",)), False),
    Permission("manage", COMPUTE, None, (("autoscaling:UpdateAutoScalingGroup",),
                                         ("autoscaling:SetDesiredCapacity",)), False),
    Permission("use-key", KEY, None, (("kms:Decrypt",), ("kms:Encrypt",), ("kms:GenerateDataKey",)), False),
    Permission("manage-key", KEY, None, (("kms:DescribeKey",), ("kms:EnableKeyRotation",), ("kms:PutKeyPolicy",)),
               False),
    Permission("read-storage", STORAGE, None, (("s3:GetObject",), ("s3:ListBucket",)), False),
    Permission("write-storage", STORAGE, None, (("s3:PutObject",),), False),
    Permission("publish-stream", STREAM, "topic", (("sns:Publish",),), False),
    Permission("publish-stream", STREAM, "queue", (("sqs:SendMessage",),), False),
    Permission("publish-stream", STREAM, "bus", (("events:PutEvents",),), False),
    Permission("publish-stream", STREAM, "log-stream", (("kinesis:PutRecords", "kinesis:PutRecord"),), False),
    Permission("consume-stream", STREAM, "queue", (("sqs:ReceiveMessage",), ("sqs:DeleteMessage",)), False),
    Permission("consume-stream", STREAM, "log-stream", (("kinesis:GetRecords",), ("kinesis:GetShardIterator",)),
               False),
    Permission("write-logs", LOGS, None, (("logs:PutLogEvents",), ("logs:CreateLogStream",)), False),
    Permission("read-logs", LOGS, None, (("logs:GetLogEvents",), ("logs:FilterLogEvents",)), False),
)
# Actions that let an identity raise its own (or another's) access
ESCALATIONS = ("iam:PassRole", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:AttachRolePolicy",
               "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:CreateAccessKey", "iam:CreateLoginProfile",
               "iam:UpdateLoginProfile", "iam:DeleteRolePermissionsBoundary", "kms:PutKeyPolicy", "kms:CreateGrant",
               "kms:ScheduleKeyDeletion", "sts:AssumeRole")


# A secret's full ARN (as a state or the CLI gives it) ends in Secrets Manager's random suffix: six letters and digits,
# taken to be one when they include a capital or a digit (a record's own names are lowercase words)
_SUFFIXED = re.compile(r"-(?=[a-z]*[A-Z0-9])[A-Za-z0-9]{6}$")


def _arn(uri):
    return (uri or "").split("://", 1)[-1] or None


def resources(binding):
    """A binding's resource as IAM policies name it, most specific first."""
    if one(binding, "ciamRefUri", "").startswith("aws-sm://"):
        arn = _arn(one(binding, "ciamRefUri"))
        return (arn,) if _SUFFIXED.search(arn) else (f"{arn}-??????",)   # the bare name never matches the secret
    if one(binding, "ciamRefUri", "").startswith("aws-kms://"):
        return (_arn(one(binding, "ciamRefUri")),)
    if one(binding, "ciamStorageRef", "").startswith("s3://"):
        bucket, _, prefix = one(binding, "ciamStorageRef")[5:].partition("/")
        return (f"arn:aws:s3:::{bucket}/{prefix}*", f"arn:aws:s3:::{bucket}")
    if is_a(binding, "ciamServiceName"):          # as the renderer names its load balancer and target groups
        name = f"ciam-{rdn_of(environment_of(binding))}-{rdn_value(binding)}"
        return (f"arn:aws:elasticloadbalancing:*:*:loadbalancer/net/{name}/*",
                f"arn:aws:elasticloadbalancing:*:*:listener/net/{name}/*",
                f"arn:aws:elasticloadbalancing:*:*:targetgroup/{name}-*",
                *((f"arn:aws:route53:::hostedzone/{one(binding, 'ciamDnsZoneRef')}",)
                  if one(binding, "ciamDnsZoneRef") else ()))
    ref = one(binding, "ciamProviderRef", "")
    return (f"{ref}:*", ref) if ref.startswith("arn:aws:logs:") else ((ref,) if ref.startswith("arn:") else ())


def _askable(names):
    """Whether the simulator can be asked about a binding's resources: each a concrete ARN, or one ending in a single
    wildcard (a log group's streams, a bucket's objects); not the record's patterns (a secret without its suffix, the
    renderer's load balancer names)."""
    return bool(names) and all("?" not in n and "*" not in n.rstrip("*") for n in names)


def _simulation(ref, actions, names):
    return quoted("aws", "iam", "simulate-principal-policy", "--policy-source-arn", ref, "--action-names", *actions,
                  "--resource-arns", *names, "--output", "json")


def evaluator(m, identity, binding, row):
    """The policy simulator's commands for one permission: its actions on the binding's resources, and what it also
    needs of a linked binding (the key that encrypts a secret) on that one's; none for an identity that isn't an IAM
    role or user (an Identity Center group: the simulator takes an ARN), or a resource the record names by a
    pattern."""
    ref = one(identity, "ciamProviderRef")
    linked = [(one_role(m, one(binding, attr)), needs) for attr, needs in row.related if one(binding, attr)]
    if not ref.startswith("arn:aws:iam::") or not _askable(resources(binding)) or any(
            k is None or not _askable(resources(k)) for k, _ in linked):
        return ()
    return (_simulation(ref, [alts[0] for alts in row.needs], resources(binding)),
            *(_simulation(ref, [alts[0] for alts in needs], resources(k)) for k, needs in linked))


def simulation_verdict(doc):
    """allowed, denied or unknown from simulate-principal-policy's output: allowed when each action is allowed on one
    of the resources asked about; else unknown when the simulator lacked a context value, denied otherwise; None when
    it isn't one."""
    results = doc.get("EvaluationResults") if isinstance(doc, dict) else None
    if not isinstance(results, list) or not results:
        return None
    found = [r for r in results if isinstance(r, dict)]
    actions = {r.get("EvalActionName") for r in found}
    if all(any(r.get("EvalDecision") == "allowed" for r in found if r.get("EvalActionName") == a) for a in actions):
        return ALLOWED
    return UNKNOWN if any(r.get("MissingContextValues") for r in found) else DENIED


ACCESS = AccessModel(permissions=PERMISSIONS, escalations=ESCALATIONS,
                     covers=lambda granted, binding: covered(granted, resources(binding)),
                     resource=lambda binding: next(iter(resources(binding)), None), evaluator=evaluator)
