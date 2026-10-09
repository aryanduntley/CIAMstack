"""The managed identities and role assignments Azure renderers share: role assignments from the Azure permission
table (opsdir_adapter_azure.access) at the narrowest scope (the secret or key in its vault, Key Vault's RBAC model; the
storage container; the resource a provider ref names), the data sources those scopes need, and notes for what can't be
granted. The platform's Terraform (workloads, terraform.py) and the landing zone's (deployers, operator groups,
landing.py) use them. Pure.
"""
import re

from opsdir.core.directory import is_a, one, rdn_of, rdn_value
from opsdir.core.environment import environment_of, of_class
from opsdir.domains.data.storage import kept_store
from opsdir_format_terraform.hcl import block, ref, tf_name
from .account import tagged
from .arm_ids import arm_segment

RG = ref("data.azurerm_resource_group.main.name")
LOC = ref("data.azurerm_resource_group.main.location")
GROUP = "${data.azurerm_resource_group.main.id}"        # the start of a resource ID in the environment's group


def scope(b):
    """(the narrowest scope a role assignment on a binding's resource takes, the data source it needs or None): a
    secret or key in its vault, a storage container (in the account the stack renders, when it keeps it), the
    resource ID a provider ref is; a service name's load balancer
    and a scale set named by its ref, by their IDs in the environment's resource group."""
    uri, storage = one(b, "ciamRefUri", ""), one(b, "ciamStorageRef", "")
    if uri.startswith(("azkv://", "azkv-key://")):
        vault, _, rest = uri.split("://", 1)[1].partition("/")
        child = "keys" if uri.startswith("azkv-key://") else "secrets"
        return (f"${{data.azurerm_key_vault.{tf_name(vault)}.id}}/{child}/{rest.split('/')[-1]}",
                ("azurerm_key_vault", vault))
    if storage.startswith("azblob://"):
        account, _, container = storage[9:].partition("/")
        if kept_store(b):                           # rendered in this root (storage.py): its resource, no data source
            return f"${{azurerm_storage_account.{tf_name(account)}.id}}/blobServices/default/containers/{container}", None
        return (f"${{data.azurerm_storage_account.{tf_name(account)}.id}}/blobServices/default/containers/{container}",
                ("azurerm_storage_account", account))
    ref_ = one(b, "ciamProviderRef", "")
    if ref_.startswith("/subscriptions/"):
        return ref_, None
    if is_a(b, "ciamServiceName"):                  # the load balancer the renderer names for it
        return (f"{GROUP}/providers/Microsoft.Network/loadBalancers/"
                f"lb-ciam-{rdn_of(environment_of(b))}-{rdn_value(b)}", None)
    if is_a(b, "ciamComputeGroup") and ref_:        # a scale set named by its ref
        return f"{GROUP}/providers/Microsoft.Compute/virtualMachineScaleSets/{ref_}", None
    return ref_, None


def notes(w):
    return tuple(f"# NOTE: principal {w.principal}: {note}" for note in w.notes)


def assignments(w, principal_id):
    """One role assignment per permit, at the narrowest scope, to a principal (an identity's, a group's object id)."""
    n = tf_name(w.identity_role)
    return tuple(block("resource", ["azurerm_role_assignment", f"{n}_{tf_name(permit)}"], [
        ("scope", scope(b)[0]), ("role_definition_name", role_of(row, b)), ("principal_id", principal_id)])
        for permit, b, row in w.grants)


def managed_identity(m, w):
    return block("resource", ["azurerm_user_assigned_identity", tf_name(w.identity_role)], [
        ("name", w.name), ("resource_group_name", RG), ("location", LOC),
        ("tags", tagged(m, {"Principal": w.principal, "Role": w.identity_role, "ManagedBy": "opsdir"}))])


AUDIENCE = "api://AzureADTokenExchange"     # the audience Microsoft Entra workload identity federation expects


def _aks_name(cluster):
    ref_ = one(cluster, "ciamProviderRef") or ""
    return arm_segment(ref_, "managedClusters") or ref_.rsplit("/", 1)[-1]


def _aks(cluster):
    return tf_name(_aks_name(cluster))


def aks_data(identities):
    """The AKS clusters whose service accounts the identities trust, as data sources (their OIDC issuer URL): name
    and resource group from the cluster binding's provider ref (an ARM ID), else its name in the environment's
    resource group."""
    clusters = {c.dn: c for w in identities for c in (p.cluster for p in w.pods) if c is not None}.values()
    return tuple(block("data", ["azurerm_kubernetes_cluster", _aks(c)], [
        ("name", _aks_name(c)),
        ("resource_group_name", arm_segment(one(c, "ciamProviderRef"), "resourceGroups") or RG)]) for c in clusters)


def federated_credentials(w):
    """A federated identity credential on a workload identity per Kubernetes service account that assumes it (AKS
    workload identity: its cluster's OIDC issuer, subject system:serviceaccount:<namespace>:<name>); notes for
    service accounts whose cluster the environment doesn't bind."""
    n = tf_name(w.identity_role)
    return (*(f"# NOTE: principal {w.principal}: service account {p.namespace}/{p.service_account} runs in a cluster "
              "this environment doesn't bind, so nothing trusts it" for p in w.pods if p.cluster is None),
            *(block("resource", ["azurerm_federated_identity_credential", f"{n}_{tf_name(p.namespace)}_"
                                                                          f"{tf_name(p.service_account)}"], [
                ("name", f"{w.name}-{p.namespace}-{p.service_account}"), ("resource_group_name", RG),
                ("parent_id", ref(f"azurerm_user_assigned_identity.{n}.id")), ("audience", [AUDIENCE]),
                ("issuer", ref(f"data.azurerm_kubernetes_cluster.{_aks(p.cluster)}.oidc_issuer_url")),
                ("subject", f"system:serviceaccount:{p.namespace}:{p.service_account}")])
              for p in w.pods if p.cluster is not None))


def identity(m, w):
    """A workload principal's user-assigned managed identity, the federated credentials of the Kubernetes service
    accounts that assume it, and its role assignments."""
    n = tf_name(w.identity_role)
    return (*notes(w), managed_identity(m, w), *federated_credentials(w),
            *assignments(w, ref(f"azurerm_user_assigned_identity.{n}.principal_id")))


def role_of(row, b):
    """The role a row grants: its first alternative, or for an Event Grid topic the Event Grid one."""
    alternatives = row.needs[0]
    grid = re.search(r"/providers/Microsoft\.EventGrid/", one(b, "ciamProviderRef", ""), re.IGNORECASE)
    return next((r for r in alternatives if r.startswith("EventGrid")), alternatives[0]) if grid else alternatives[0]


def scope_data(m, identities, standalone=False):
    """Data sources the role assignments' scopes need: in the platform's Terraform, those the secrets' vault checks
    don't declare already; in a standalone root (the landing zone), all of them."""
    declared = set() if standalone else {("azurerm_key_vault", one(b, "ciamRefUri").split("://", 1)[1].split("/", 1)[0])
                                         for b in of_class(m, "ciamSecretRef")}
    needed = dict.fromkeys(need for w in identities for _, b, _ in w.grants for _, need in (scope(b),) if need)
    return tuple(block("data", [kind, tf_name(name)], [("name", name), ("resource_group_name", RG)])
                 for kind, name in needed if (kind, name) not in declared)
