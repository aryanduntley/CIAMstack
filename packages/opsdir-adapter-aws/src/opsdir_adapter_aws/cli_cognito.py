"""The Cognito user pool outputs of the AWS CLI, normalized to the attribute names of the matching Terraform resource
(opsdir_adapter_aws.cognito reads both). Pure.

  cognito-idp describe-user-pool        UserPool          -> aws_cognito_user_pool: its id, ARN, name, tags and custom
    (projected: --query)                                     domain (custom_domain)

The collector projects the call to those fields (an allowlist), and reads no app client and no identity provider:
their descriptions carry client secrets and upstream credentials.
"""
KEYS = ("UserPool",)
# the describe-user-pool fields the reader uses (what collect.py's --query keeps)
POOL_QUERY = ("{UserPool: UserPool.{Id: Id, Name: Name, Arn: Arn, UserPoolTags: UserPoolTags, "
              "CustomDomain: CustomDomain}}")


def _pool(p):
    return "aws_cognito_user_pool", {"id": p.get("Id"), "arn": p.get("Arn"), "name": p.get("Name"),
                                     "tags": dict(p.get("UserPoolTags") or {}), "custom_domain": p.get("CustomDomain")}


def cognito_pairs(outs):
    """The (Terraform type, attributes) pairs of the Cognito outputs among the recognized CLI outputs."""
    return [_pool(doc["UserPool"]) for _, k, doc in outs if k == "UserPool" and isinstance(doc.get("UserPool"), dict)]

