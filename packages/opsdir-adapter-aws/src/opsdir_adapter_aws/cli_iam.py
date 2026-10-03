"""What the AWS CLI reports about IAM, normalized to the attribute names of the matching Terraform resources so the
same mapping (opsdir_adapter_aws.iam) reads them as reads Terraform state. Pure. Recognized by top-level key, as the
other AWS CLI outputs (opsdir_adapter_aws.cli):

  iam get-account-authorization-details   RoleDetailList     -> aws_iam_role (trust, inline policies, attached
                                                                policies, boundary, tags) and aws_iam_policy (each
                                                                policy's default version, AWS managed ones included);
                                                                users and groups counted, not read
  kms get-key-policy                      Policy (text)      -> aws_kms_key_policy; the output doesn't name its key:
                                                                save it as key-policy/<key id>.json
  s3api get-bucket-policy                 Policy (text)      -> aws_s3_bucket_policy; save it as
                                                                bucket-policy/<bucket>.json
  secretsmanager get-resource-policy      ResourcePolicy     -> aws_secretsmanager_secret_policy
  organizations describe-policy           Policy (object)    -> aws_organizations_policy (from the management
                                                                account: the control policies attached to the
                                                                environment's account or its organizational units)
  sso-admin describe-permission-set       PermissionSet      -> aws_ssoadmin_permission_set
  sso-admin list-account-assignments      AccountAssignments -> aws_ssoadmin_account_assignment
  sso-admin get-inline-policy-for-        InlinePolicy       -> its inline policy; save it as
    permission-set                                              sso-inline/<permission set name>.json
  sso-admin list-managed-policies-in-     AttachedManagedPolicies -> its managed policies; save it as
    permission-set                                              sso-managed/<permission set name>.json
  iam simulate-principal-policy           EvaluationResults  -> the role's ciamEvaluated, saved by the renderer's
                                                                access/evaluate.sh as evaluations/<role>/<verb>__<role>
                                                                .json (opsdir.domains.access.evaluations)
"""
from opsdir.domains.access.evaluations import evaluations_by_identity
from .access import simulation_verdict

KEYS = ("RoleDetailList", "ResourcePolicy", "PermissionSet", "AccountAssignments", "InlinePolicy",
        "AttachedManagedPolicies", "EvaluationResults", "Policy")
EVALUATOR = "aws-simulator"


def _tags(tags):
    return {t["Key"]: t.get("Value", "") for t in tags or () if isinstance(t, dict) and "Key" in t}


def _stem(path):
    return path.rsplit("/", 1)[-1].rsplit(".", 1)[0]


def _folder(path):
    return path.rsplit("/", 2)[-2] if path.count("/") >= 1 else ""


def _of(outs, key):
    return [(p, doc) for p, k, doc in outs if k == key]


def _authorization(outs):
    """Roles and policies of get-account-authorization-details; (pairs, notices for users and groups)."""
    docs = [doc for _, doc in _of(outs, "RoleDetailList")]

    def default_version(p):
        return next((v.get("Document") for v in p.get("PolicyVersionList") or () if v.get("IsDefaultVersion")), None)
    users = sum(len(doc.get("UserDetailList") or ()) for doc in docs)
    groups = sum(len(doc.get("GroupDetailList") or ()) for doc in docs)
    return ([*(("aws_iam_role", {
                "arn": r.get("Arn"), "name": r.get("RoleName"), "assume_role_policy": r.get("AssumeRolePolicyDocument"),
                "inline_policy": [{"name": p.get("PolicyName"), "policy": p.get("PolicyDocument")}
                                  for p in r.get("RolePolicyList") or ()],
                "managed_policy_arns": [a.get("PolicyArn") for a in r.get("AttachedManagedPolicies") or ()],
                "permissions_boundary": (r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                "tags": _tags(r.get("Tags"))})
               for doc in docs for r in doc.get("RoleDetailList") or ()),
             *(("aws_iam_policy", {"arn": p.get("Arn"), "name": p.get("PolicyName"), "policy": default_version(p)})
               for doc in docs for p in doc.get("Policies") or () if default_version(p))],
            (f"iam: {users} user(s) and {groups} group(s) not read (the record's identities are roles, permission "
             "sets and federated principals)",) if users or groups else ())


def _policies(outs):
    """Key, bucket and control policies (the key and bucket from the file's folder and name); (pairs, notices)."""
    def one(path, doc):
        policy = doc.get("Policy")
        if isinstance(policy, dict):
            summary = policy.get("PolicySummary") or {}
            return ("aws_organizations_policy", {"arn": summary.get("Arn"), "id": summary.get("Id"),
                                                 "name": summary.get("Name"), "type": summary.get("Type"),
                                                 "content": policy.get("Content")})
        if _folder(path) == "key-policy":
            return "aws_kms_key_policy", {"key_id": _stem(path), "policy": policy}
        if _folder(path) == "bucket-policy":
            return "aws_s3_bucket_policy", {"bucket": _stem(path), "policy": policy}
        return None
    read = [(p, one(p, doc)) for p, doc in _of(outs, "Policy")]
    return ([pair for _, pair in read if pair],
            tuple(f"{p}: a key or bucket policy that doesn't say whose (save get-key-policy as key-policy/<key id>"
                  ".json, get-bucket-policy as bucket-policy/<bucket>.json); not read" for p, pair in read if not pair))


def _identity_center(outs):
    """Permission sets, their policies (by the permission set's name in the file name) and account assignments."""
    sets = [doc.get("PermissionSet") or {} for _, doc in _of(outs, "PermissionSet")]
    by_name = {s.get("Name"): s.get("PermissionSetArn") for s in sets}
    return [*(("aws_ssoadmin_permission_set", {"arn": s.get("PermissionSetArn"), "name": s.get("Name")})
              for s in sets),
            *(("aws_ssoadmin_permission_set_inline_policy", {"permission_set_arn": by_name.get(_stem(p)),
                                                             "inline_policy": doc.get("InlinePolicy")})
              for p, doc in _of(outs, "InlinePolicy") if doc.get("InlinePolicy")),
            *(("aws_ssoadmin_managed_policy_attachment", {"permission_set_arn": by_name.get(_stem(p)),
                                                          "managed_policy_arn": a.get("Arn")})
              for p, doc in _of(outs, "AttachedManagedPolicies") for a in doc.get("AttachedManagedPolicies") or ()),
            *(("aws_ssoadmin_account_assignment", {"permission_set_arn": a.get("PermissionSetArn"),
                                                   "principal_id": a.get("PrincipalId"),
                                                   "principal_type": a.get("PrincipalType"),
                                                   "target_id": a.get("AccountId")})
              for _, doc in _of(outs, "AccountAssignments") for a in doc.get("AccountAssignments") or ())]


def _with_evaluations(pairs, outs, at):
    """The roles with the simulator's verdicts on them (a role only simulated: by its name)."""
    found = evaluations_by_identity(_of(outs, "EvaluationResults"), simulation_verdict, EVALUATOR,
                                    at.date().isoformat() if at else None)
    named = {a.get("name") for t, a in pairs if t == "aws_iam_role"}
    return [*((t, {**a, "evaluated": found.get(a.get("name"), ())}) if t == "aws_iam_role" else (t, a)
              for t, a in pairs),
            *(("aws_iam_role", {"arn": who, "name": who, "evaluated": verdicts})
              for who, verdicts in found.items() if who not in named)]


def iam_pairs(outs, at=None):
    """(pairs, notices) of the IAM outputs among an environment's recognized AWS CLI outputs ((path, key, document),
    ...); at dates the evaluator's verdicts (the import's time)."""
    roles, role_notices = _authorization(outs)
    policies, policy_notices = _policies(outs)
    pairs = [*roles, *policies, *_identity_center(outs),
             *(("aws_secretsmanager_secret_policy", {"secret_arn": doc.get("ARN"), "policy": doc["ResourcePolicy"]})
               for _, doc in _of(outs, "ResourcePolicy") if doc.get("ResourcePolicy"))]
    return _with_evaluations(pairs, outs, at), (*role_notices, *policy_notices)
