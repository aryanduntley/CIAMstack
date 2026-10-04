"""A workload's identity as Azure Terraform: a user-assigned managed identity, role assignments from the Azure
permission table at the narrowest scope (the secret in its vault, the storage container), Event Grid topics given
Event Grid's sender role, and the data sources those scopes need."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.access.workloads import WorkloadIdentity
from opsdir_adapter_azure.access import PERMISSIONS
from opsdir_adapter_azure.identities import identity as _identity, scope_data as _scope_data
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
    out = "\n".join(_identity(None, W))
    assert 'resource "azurerm_user_assigned_identity" "identity_pf_engine"' in out
    assert 'scope                = "${data.azurerm_key_vault.kv_ciam_prod.id}/secrets/pf-admin-password"' in out
    assert 'role_definition_name = "Key Vault Secrets User"' in out
    assert 'role_definition_name = "Key Vault Crypto User"' in out
    assert 'role_definition_name = "EventGrid Data Sender"' in out
    assert 'principal_id         = azurerm_user_assigned_identity.identity_pf_engine.principal_id' in out


def test_the_scopes_data_sources_not_declared_already():
    m = SimpleNamespace(d=BARE, bindings=(SECRET,))              # the secrets' vault is declared by the vault check
    assert [b.splitlines()[0] for b in _scope_data(m, (W,))] == ['data "azurerm_key_vault" "kv_ciam_keys" {']
