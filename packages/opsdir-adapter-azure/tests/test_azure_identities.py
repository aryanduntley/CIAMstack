"""A workload's identity as Azure Terraform: a user-assigned managed identity, role assignments from the Azure
permission table at the narrowest scope (the secret in its vault, the storage container), Event Grid topics given
Event Grid's sender role, the data sources those scopes need, and a federated credential per Kubernetes service
account that assumes it (AKS workload identity)."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.access.workloads import Pod, WorkloadIdentity
from opsdir_adapter_azure.access import PERMISSIONS
from opsdir_adapter_azure.identities import aks_data, identity as _identity, scope_data as _scope_data
from support import BARE

SECRET = make_entry("cn=secret,ou=bindings,env=prod", ("top", "ciamSecretRef"),
                    {"ciamBindingRole": ["pf-admin-password"], "ciamRefUri": ["azkv://kv-ciam-prod/pf-admin-password"]})
KEY = make_entry("cn=key,ou=bindings,env=prod", ("top", "ciamKeyRef"),
                 {"ciamBindingRole": ["signing"], "ciamRefUri": ["azkv-key://kv-ciam-keys/keys/signing"]})
GRID = make_entry("cn=audit,ou=bindings,env=prod", ("top", "ciamStreamBinding"),
                  {"ciamBindingRole": ["audit-events"], "ciamStreamKind": ["topic"],
                   "ciamProviderRef": ["/subscriptions/0/resourceGroups/rg/providers/Microsoft.EventGrid/topics/ciam"]})


def _row(verb, cls, kind=None):
    return next(r for r in PERMISSIONS if r.verb == verb and r.binding_class == cls and r.kind in (None, kind))


W = WorkloadIdentity("pf-engine", "identity-pf-engine", "pf-engine", "ciam-prod-pf-engine",
                     (("read-secret pf-admin-password", SECRET, _row("read-secret", "ciamSecretRef")),
                      ("use-key signing", KEY, _row("use-key", "ciamKeyRef")),
                      ("publish-stream audit-events", GRID, _row("publish-stream", "ciamStreamBinding", "topic"))), ())


def test_an_identity_with_role_assignments_at_the_narrowest_scope():
    out = "\n".join(_identity(SimpleNamespace(d=BARE), W))
    assert 'resource "azurerm_user_assigned_identity" "identity_pf_engine"' in out
    assert 'scope                = "${data.azurerm_key_vault.kv_ciam_prod.id}/secrets/pf-admin-password"' in out
    assert 'role_definition_name = "Key Vault Secrets User"' in out
    assert 'role_definition_name = "Key Vault Crypto User"' in out
    assert 'role_definition_name = "EventGrid Data Sender"' in out
    assert 'principal_id         = azurerm_user_assigned_identity.identity_pf_engine.principal_id' in out


def test_the_scopes_data_sources_not_declared_already():
    m = SimpleNamespace(d=BARE, bindings=(SECRET,))              # the secrets' vault is declared by the vault check
    assert [b.splitlines()[0] for b in _scope_data(m, (W,))] == ['data "azurerm_key_vault" "kv_ciam_keys" {']


def test_kubernetes_service_accounts_get_federated_credentials_from_their_aks_cluster():
    cluster = make_entry("cn=aks,ou=bindings,env=prod", ("top", "ciamCluster"), {
        "ciamBindingRole": ["k8s"],
        "ciamProviderRef": ["/subscriptions/0/resourceGroups/rg-aks/providers/Microsoft.ContainerService/"
                            "managedClusters/aks-ciam"]})
    w = W._replace(pods=(Pod("identity", "am", cluster), Pod("tools", "x", None)), servers=False)
    data = "\n".join(aks_data((w,)))
    assert 'data "azurerm_kubernetes_cluster" "aks_ciam"' in data and 'resource_group_name = "rg-aks"' in data
    out = "\n".join(_identity(SimpleNamespace(d=BARE), w))
    assert 'resource "azurerm_federated_identity_credential"' in out
    assert "issuer              = data.azurerm_kubernetes_cluster.aks_ciam.oidc_issuer_url" in out
    assert 'subject             = "system:serviceaccount:identity:am"' in out
    assert 'audience            = ["api://AzureADTokenExchange"]' in out
    assert "# NOTE: principal" in out and "service account tools/x runs in a cluster this environment doesn't" in out
