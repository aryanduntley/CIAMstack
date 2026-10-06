"""Access's import kinds (core.contract.ImportKind): what the cloud importers read into identities, guardrails and
access paths (each matched by provider ref; an identity also by its short name). Pure.

  identity  -> ciamIdentityBinding  matched by provider ref, else by the identity's short name (an IAM role's name, a
                                    resource ID's last segment, a service account's account id)
  guardrail -> ciamGuardrail        a control policy, a policy assignment, a constraint
  access    -> ciamAccessPath       single sign-on, a bastion, a proxy
"""
from ...core.contract import ImportKind


def short_name(ref):
    """An identity's short name from its provider ref: an IAM role's name, a resource ID's last segment, a service
    account's account id (lowercase)."""
    return (ref or "").rsplit("/", 1)[-1].split("@", 1)[0].lower() or None


IMPORT_KINDS = (
    ImportKind("identity", "ciamIdentityBinding", (), alias=short_name),
    ImportKind("guardrail", "ciamGuardrail", ("ciamGuardrailKind",)),
    ImportKind("access", "ciamAccessPath", ("ciamAccessKind",)),
)
