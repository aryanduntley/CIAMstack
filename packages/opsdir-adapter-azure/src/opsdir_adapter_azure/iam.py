"""Azure access control in an environment's sources as the record's identities, guardrails and access paths
(opsdir.core.inventory), from (Terraform resource type, attributes) pairs like every Azure source. Pure.

  azurerm_user_assigned_identity          -> identity (kind managed-identity; federated when a federated identity
    (+ azurerm_federated_identity_           credential trusts it: '<issuer URL> <subject>'); role from its tag Role
    credential)                              (or BindingRole)
  azurerm_role_assignment,                -> its principal's grants: '<role> on <scope>', ' (if <condition>)' when the
    azurerm_pim_active_role_assignment       assignment has one; a custom role (azurerm_role_definition) as its actions
                                             and data actions, NotActions excluded ('a!b'); a principal that isn't an
                                             identity here is one of its own (kind group, user or other: its object id
                                             as its provider ref, how the landing zone names an operator's group)
  azurerm_pim_eligible_role_assignment    -> the same, eligible (' (eligible)': not active until activated)
  azurerm_key_vault access policies,      -> grants on the vault (' (resource policy)'), each permission as the data
    azurerm_key_vault_access_policy          action Key Vault's RBAC names for it
  policy assignments (subscription,       -> a guardrail per scope (kind policy-assignment): what its assignments
    resource group, management group)        prevent, by the built-in definitions the renderer assigns; role
                                             guardrail-<scope name>
  azurerm_bastion_host                    -> access path bastion (role from its tag Role, else access-bastion)
  deny assignments (the CLI's; Azure       -> denials on the principals they name ('00000000-…': every identity here,
    creates them, never Terraform)           less the excluded ones): each action and data action, its NotActions
                                             excluded, on the assignment's scope
A role named by its definition ID only (a PIM assignment's) takes its name from the azurerm_role_definition data
source in the same state; otherwise the ID is kept.
"""
from collections import defaultdict

from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.domains.access.grants import excluding, grant_text
from .guardrails import denial_of

KV = "Microsoft.KeyVault/vaults/"
# Key Vault access policy permissions as the data actions Key Vault's RBAC names them
POLICY_ACTIONS = {
    "secret": {"get": "secrets/getSecret/action", "set": "secrets/setSecret/action",
               "list": "secrets/readMetadata/action", "delete": "secrets/delete", "backup": "secrets/backup/action",
               "restore": "secrets/restore/action", "recover": "secrets/recover/action"},
    "key": {"get": "keys/read", "list": "keys/read", "decrypt": "keys/decrypt/action",
            "encrypt": "keys/encrypt/action", "unwrapkey": "keys/unwrap/action", "wrapkey": "keys/wrap/action",
            "sign": "keys/sign/action", "verify": "keys/verify/action", "rotate": "keys/rotate/action",
            "create": "keys/create/action", "update": "keys/update/action", "delete": "keys/delete",
            "import": "keys/import/action", "backup": "keys/backup/action", "restore": "keys/restore/action",
            "recover": "keys/recover/action"},
    "certificate": {"get": "certificates/read", "list": "certificates/read"}}
ASSIGNMENTS = ("azurerm_subscription_policy_assignment", "azurerm_resource_group_policy_assignment",
               "azurerm_management_group_policy_assignment", "azurerm_policy_assignment")
PRINCIPAL_KINDS = {"group": "group", "user": "user"}
EVERYONE = "00000000-0000-0000-0000-000000000000"            # a deny assignment's principal for every principal


def _tags(a):
    return a.get("tags") or {}


def _guid(definition_id):
    return (definition_id or "").rsplit("/", 1)[-1].lower() or None


def _custom_roles(found):
    """{definition GUID or name (lowercase): (role name, actions)} of custom role definitions: each action and data
    action, its NotActions excluded."""
    def actions(d):
        return tuple(a for p in d.get("permissions") or () for a in (
            *(excluding(x, p.get("not_actions") or ()) for x in p.get("actions") or ()),
            *(excluding(x, p.get("not_data_actions") or ()) for x in p.get("data_actions") or ())))
    defined = [d for d in of_types(found, "azurerm_role_definition")       # managed, or a data source's custom role
               if d.get("role_definition_resource_id") or d.get("type") == "CustomRole"]
    return {k.lower(): (d.get("name"), actions(d)) for d in defined
            for k in (_guid(d.get("role_definition_resource_id") or d.get("id")), d.get("role_definition_id"),
                      d.get("name")) if k}


def _role_names(found):
    """{definition GUID: name} of the role definitions the state looks up (data azurerm_role_definition)."""
    return {g: d.get("name") for d in of_types(found, "azurerm_role_definition") if d.get("name")
            for g in (_guid(d.get("id")), _guid(d.get("role_definition_id"))) if g}


def _assignment_grants(a, custom, names, eligible=False):
    """The grants a role assignment gives its principal."""
    name = a.get("role_definition_name") or names.get(_guid(a.get("role_definition_id")))
    defined = custom.get((name or "").lower()) or custom.get(_guid(a.get("role_definition_id")) or "")
    actions = defined[1] if defined else (name or a.get("role_definition_id"),)
    return tuple(grant_text(x, a.get("scope"), a.get("condition"), eligible=eligible) for x in actions if x)


def _vault_grants(found):
    """{object id: grants} of Key Vault access policies, inline or separate."""
    def actions(p):
        return tuple(f"{KV}{POLICY_ACTIONS[kind].get(str(x).lower(), f'{kind}s/{str(x).lower()}')}"
                     for kind in POLICY_ACTIONS for x in p.get(f"{kind}_permissions") or ())
    policies = [*((v.get("id"), p) for v in of_types(found, "azurerm_key_vault")
                  for p in v.get("access_policy") or ()),
                *((p.get("key_vault_id"), p) for p in of_types(found, "azurerm_key_vault_access_policy"))]
    out = defaultdict(tuple)
    for vault, p in policies:
        out[p.get("object_id")] += tuple(grant_text(x, vault, resource_policy=True) for x in dict.fromkeys(actions(p)))
    return out


def _denials(found):
    """[(principal ids or (EVERYONE,), excluded ids, denial texts)] of deny assignments."""
    def actions(d):
        return tuple(a for p in d.get("permissions") or () for a in (
            *(excluding(x, p.get("not_actions") or ()) for x in p.get("actions") or ()),
            *(excluding(x, p.get("not_data_actions") or ()) for x in p.get("data_actions") or ())))
    return [(tuple(d.get("principals") or ()), frozenset(d.get("exclude_principals") or ()),
             tuple(grant_text(a, d.get("scope")) for a in actions(d)))
            for d in of_types(found, "azure_deny_assignment") if d.get("scope")]


def _denied(denials, pid):
    """The denial texts that apply to a principal."""
    return sorted({t for who, excluded, texts in denials if (pid in who or EVERYONE in who) and pid not in excluded
                   for t in texts})


def _identities(found):
    """(resources, notices): managed identities and every other principal role assignments name, with their grants."""
    custom, names, denials = _custom_roles(found), _role_names(found), _denials(found)
    managed = {i.get("principal_id"): i for i in of_types(found, "azurerm_user_assigned_identity") if i.get("id")}
    trust = defaultdict(tuple)
    for c in of_types(found, "azurerm_federated_identity_credential"):
        trust[(c.get("parent_id") or "").lower()] += (f"{c.get('issuer')} {c.get('subject')}",)
    grants, kinds = defaultdict(tuple), {}
    for t, eligible in (("azurerm_role_assignment", False), ("azurerm_pim_active_role_assignment", False),
                        ("azurerm_pim_eligible_role_assignment", True)):
        for a in of_types(found, t):
            grants[a.get("principal_id")] += _assignment_grants(a, custom, names, eligible)
            if a.get("principal_type"):
                kinds.setdefault(a.get("principal_id"), str(a.get("principal_type")).lower())
    for object_id, gs in _vault_grants(found).items():
        grants[object_id] += gs
    unnamed = sorted({a.get("role_definition_id") for t in ("azurerm_pim_eligible_role_assignment",
                                                            "azurerm_pim_active_role_assignment")
                      for a in of_types(found, t) if _guid(a.get("role_definition_id")) not in names
                      and not custom.get(_guid(a.get("role_definition_id")) or "")})

    def one_managed(pid, i):
        trusted = trust.get((i.get("id") or "").lower(), ())
        return resource("identity", i.get("id"), {
            "ciamIdentityKind": "federated" if trusted else "managed-identity", "ciamTrustedBy": trusted,
            "ciamGrant": sorted(set(grants.get(pid, ()))), "ciamDenial": _denied(denials, pid)},
            name=i.get("name"), role=tagged_role(_tags(i)))
    others = [pid for pid in grants if pid and pid not in managed]
    return ((*(one_managed(pid, i) for pid, i in managed.items()),
             *(resource("identity", pid, {"ciamIdentityKind": PRINCIPAL_KINDS.get(kinds.get(pid))
                                          or ("other" if kinds.get(pid) else None),               # unknown: kept
                                          "ciamGrant": sorted(set(grants[pid])), "ciamDenial": _denied(denials, pid)},
                        name=pid) for pid in others)),
            tuple(f"role definition {d}: its name isn't in the state (add a data azurerm_role_definition); recorded by "
                  "its ID" for d in unnamed))


def _guardrails(found):
    """A guardrail per scope its policy assignments are at, with what they prevent."""
    def scope_of(a):
        return (a.get("subscription_id") or a.get("resource_group_id") or a.get("management_group_id")
                or a.get("scope") or "")
    scopes = defaultdict(list)
    for a in of_types(found, *ASSIGNMENTS):
        if scope_of(a):
            scopes[scope_of(a)].append(a)
    return tuple(resource("guardrail", f"{scope}/providers/Microsoft.Authorization/policyAssignments", {
                     "ciamGuardrailKind": "policy-assignment",
                     "ciamDenies": sorted({d for a in assigned for d in (denial_of(a.get("policy_definition_id")),)
                                           if d})},
                          name=f"policy-{scope.rstrip('/').rsplit('/', 1)[-1]}",
                          role=f"guardrail-policy-{scope.rstrip('/').rsplit('/', 1)[-1]}".lower())
                 for scope, assigned in scopes.items())


def _access_paths(found):
    return tuple(resource("access", b.get("id"), {"ciamAccessKind": "bastion"}, name=b.get("name"),
                          role=tagged_role(_tags(b)) or "access-bastion")
                 for b in of_types(found, "azurerm_bastion_host") if b.get("id"))


def iam_resources(found):
    """(resources, notices) of Azure access control in (Terraform resource type, attributes) pairs: identities,
    guardrails, access paths."""
    identities, notices = _identities(found)
    return (*identities, *_guardrails(found), *_access_paths(found)), notices
