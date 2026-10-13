"""IAM, Organizations and IAM Identity Center that CloudFormation stacks declare, normalized to the Terraform attribute
names the shared mapping reads (opsdir_adapter_aws.iam.iam_resources): identities with their grants, guardrails,
permission sets and their assignments. Properties come resolved (Ref to physical IDs, Fn::GetAtt where it follows from
one); policy documents become JSON text, as a Terraform state holds them. Pure.

  AWS::IAM::Role (+ inline Policies, ManagedPolicyArns, PermissionsBoundary) -> aws_iam_role
  AWS::IAM::OIDCProvider (a federated trust's issuer)                         -> aws_iam_openid_connect_provider
  AWS::IAM::ManagedPolicy (+ the Roles it is attached to)                     -> aws_iam_policy (+ attachments)
  AWS::IAM::Policy, AWS::IAM::RolePolicy (inline, on roles)                    -> aws_iam_role_policy
  AWS::Organizations::Policy                                                   -> aws_organizations_policy
  AWS::SSO::PermissionSet (+ InlinePolicy, ManagedPolicies)                    -> aws_ssoadmin_permission_set (+ its
                                                                                  inline policy and attachments)
  AWS::SSO::Assignment                                                         -> aws_ssoadmin_account_assignment
  AWS::S3::BucketPolicy, AWS::SecretsManager::ResourcePolicy (resource         -> aws_s3_bucket_policy,
    policies: who else they let in)                                               aws_secretsmanager_secret_policy
  AWS::EC2::InstanceConnectEndpoint (a session access path; its Ref is its id) -> aws_ec2_instance_connect_endpoint
"""
import json

from .cloudformation_values import stack_arn, tag_map

IAM_TYPES = ("AWS::IAM::Role", "AWS::IAM::OIDCProvider", "AWS::IAM::ManagedPolicy", "AWS::IAM::Policy",
             "AWS::IAM::RolePolicy", "AWS::Organizations::Policy", "AWS::SSO::PermissionSet", "AWS::SSO::Assignment",
             "AWS::S3::BucketPolicy", "AWS::SecretsManager::ResourcePolicy", "AWS::EC2::InstanceConnectEndpoint")


def _text(document):
    """A policy document as JSON text (as a state holds it): a resolved Fn::Sub's text as it is, an object as JSON;
    None when it didn't resolve."""
    return document if isinstance(document, str) else json.dumps(document) if isinstance(document, dict) else None


def _of(declared, type_):
    return [(lid, p, pid) for lid, t, p, _, pid in declared if t == type_]


def _roles(declared, names):
    return [("aws_iam_role", {
        "id": pid, "name": p.get("RoleName") or pid, "arn": names.get(f"{lid}.Arn"), "path": p.get("Path"),
        "assume_role_policy": _text(p.get("AssumeRolePolicyDocument")),
        "inline_policy": [{"name": x.get("PolicyName"), "policy": _text(x.get("PolicyDocument"))}
                          for x in p.get("Policies") or () if isinstance(x, dict)],
        "managed_policy_arns": list(p.get("ManagedPolicyArns") or ()),
        "permissions_boundary": p.get("PermissionsBoundary"), "tags": tag_map(p.get("Tags"))})
        for lid, p, pid in _of(declared, "AWS::IAM::Role")]


def _oidc_providers(declared):
    return [("aws_iam_openid_connect_provider", {"arn": pid, "url": p.get("Url"),
                                                 "client_id_list": list(p.get("ClientIdList") or ()),
                                                 "thumbprint_list": list(p.get("ThumbprintList") or ()),
                                                 "tags": tag_map(p.get("Tags"))})
            for _, p, pid in _of(declared, "AWS::IAM::OIDCProvider")]


def _policies(declared):
    managed = _of(declared, "AWS::IAM::ManagedPolicy")
    return [*(("aws_iam_policy", {"arn": pid, "name": p.get("ManagedPolicyName"),
                                  "policy": _text(p.get("PolicyDocument"))}) for _, p, pid in managed),
            *(("aws_iam_role_policy_attachment", {"role": role, "policy_arn": pid})
              for _, p, pid in managed for role in p.get("Roles") or ()),
            *(("aws_iam_role_policy", {"role": role, "name": p.get("PolicyName"),
                                       "policy": _text(p.get("PolicyDocument"))})
              for _, p, _ in _of(declared, "AWS::IAM::Policy") for role in p.get("Roles") or ()),
            *(("aws_iam_role_policy", {"role": p.get("RoleName"), "name": p.get("PolicyName"),
                                       "policy": _text(p.get("PolicyDocument"))})
              for _, p, _ in _of(declared, "AWS::IAM::RolePolicy"))]


def _guardrails(declared):
    """Organizations policies: a physical id that is an ARN is the policy's ARN, its last part the policy id."""
    return [("aws_organizations_policy", {
        "id": str(pid).rsplit("/", 1)[-1], "arn": pid if str(pid).startswith("arn:") else None,
        "name": p.get("Name"), "type": p.get("Type"), "content": _text(p.get("Content")),
        "tags": tag_map(p.get("Tags"))}) for _, p, pid in _of(declared, "AWS::Organizations::Policy")]


def _identity_center(declared, names):
    sets = _of(declared, "AWS::SSO::PermissionSet")
    return [*(("aws_ssoadmin_permission_set", {"arn": names.get(f"{lid}.PermissionSetArn") or pid,
                                               "name": p.get("Name"), "instance_arn": p.get("InstanceArn"),
                                               "tags": tag_map(p.get("Tags"))}) for lid, p, pid in sets),
            *(("aws_ssoadmin_permission_set_inline_policy", {
                "permission_set_arn": names.get(f"{lid}.PermissionSetArn") or pid,
                "inline_policy": _text(p.get("InlinePolicy"))}) for lid, p, pid in sets if p.get("InlinePolicy")),
            *(("aws_ssoadmin_managed_policy_attachment", {
                "permission_set_arn": names.get(f"{lid}.PermissionSetArn") or pid, "managed_policy_arn": arn})
              for lid, p, pid in sets for arn in p.get("ManagedPolicies") or ()),
            *(("aws_ssoadmin_account_assignment", {
                "permission_set_arn": p.get("PermissionSetArn"), "principal_id": p.get("PrincipalId"),
                "principal_type": p.get("PrincipalType"), "target_id": p.get("TargetId"),
                "target_type": p.get("TargetType"), "instance_arn": p.get("InstanceArn")})
              for _, p, _ in _of(declared, "AWS::SSO::Assignment"))]


def _resource_policies(declared):
    """Buckets' and secrets' policies. A secret policy's SecretId may name the secret; its Ref is the secret's ARN."""
    return [*(("aws_s3_bucket_policy", {"bucket": p.get("Bucket"), "policy": _text(p.get("PolicyDocument"))})
              for _, p, _ in _of(declared, "AWS::S3::BucketPolicy")),
            *(("aws_secretsmanager_secret_policy", {
                "secret_arn": pid if str(pid).startswith("arn:") else p.get("SecretId"),
                "policy": _text(p.get("ResourcePolicy"))})
              for _, p, pid in _of(declared, "AWS::SecretsManager::ResourcePolicy"))]


def _access_paths(declared, names):
    return [("aws_ec2_instance_connect_endpoint", {
        "id": pid, "arn": stack_arn(names, "ec2", f"instance-connect-endpoint/{pid}"), "subnet_id": p.get("SubnetId"),
        "tags": tag_map(p.get("Tags"))}) for _, p, pid in _of(declared, "AWS::EC2::InstanceConnectEndpoint")]


def iam_stack_pairs(declared, names):
    """(Terraform resource type, attributes) pairs of IAM, Organizations and Identity Center among a stack's declared
    resources ((logical ID, type, resolved properties, raw properties, physical ID), ...); names: what references
    resolve to (for the Fn::GetAtt attributes)."""
    return [*_roles(declared, names), *_oidc_providers(declared), *_policies(declared), *_guardrails(declared),
            *_identity_center(declared, names), *_resource_policies(declared), *_access_paths(declared, names)]
