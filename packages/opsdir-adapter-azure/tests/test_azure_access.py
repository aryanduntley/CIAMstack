"""Azure RBAC read as the record's permissions: a Key Vault secret by vault or parent scope, a storage container,
broad log writes, and the roles that assign access."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir.domains.access.grants import escalating, grant_of, granted
from opsdir_adapter_azure.access import ACCESS
from support import BARE

RG = "/subscriptions/0000/resourceGroups/rg-ciam-prod"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-ciam-prod"
ENV = SimpleNamespace(d=BARE, bindings=(
    make_entry("cn=secret,ou=bindings,env=prod", ("top", "ciamSecretRef"),
               {"ciamBindingRole": ["pf-admin-password"], "ciamRefUri": ["azkv://kv-ciam-prod/pf-admin-password"]}),
    make_entry("cn=backup,ou=bindings,env=prod", ("top", "ciamBackupTarget"),
               {"ciamBindingRole": ["backup-target"], "ciamStorageRef": ["azblob://stciamprod/ds-backups"]})))


def _granted(permit, *grants):
    return granted(ACCESS, ENV, permit, tuple(grant_of(g) for g in grants))[0]


def test_permissions_through_the_azure_table():
    assert _granted("read-secret pf-admin-password", f"Key Vault Secrets User on {VAULT}")
    assert _granted("read-secret pf-admin-password", f"Key Vault Secrets User on {VAULT}/secrets/pf-admin-password")
    assert _granted("read-secret pf-admin-password", f"Key Vault Secrets Officer on {RG}")       # a parent scope
    assert not _granted("read-secret pf-admin-password", f"Key Vault Secrets User on {RG}/providers/"
                        "Microsoft.KeyVault/vaults/kv-other")
    assert not _granted("read-secret pf-admin-password", f"Reader on {VAULT}")
    assert _granted("write-storage backup-target", f"Storage Blob Data Contributor on {RG}/providers/"
                    "Microsoft.Storage/storageAccounts/stciamprod/blobServices/default/containers/ds-backups")


def test_roles_that_assign_access():
    gs = tuple(grant_of(g) for g in (f"Owner on {RG}", f"User Access Administrator on {RG}",
                                     f"Key Vault Secrets User on {VAULT}"))
    assert [g.action for g in escalating(ACCESS, gs)] == ["Owner", "User Access Administrator"]


def test_managing_a_service_name_takes_its_load_balancer_and_zone():
    svc = make_entry("cn=svc-sso,ou=bindings,env=prod", ("top", "ciamServiceName"),
                     {"ciamBindingRole": ["pf-sso-service"], "ciamDnsZone": ["example-aero.test"]})
    env = SimpleNamespace(d=BARE, bindings=(svc,))
    net = f"{RG}/providers/Microsoft.Network"
    assert granted(ACCESS, env, "manage pf-sso-service", (grant_of(f"Network Contributor on {net}/loadBalancers/"
                                                                   "lb-ciam-prod-svc-sso"),
                                                          grant_of(f"DNS Zone Contributor on {net}/dnszones/"
                                                                   "example-aero.test")))[0]
    assert granted(ACCESS, env, "manage pf-sso-service", (grant_of(f"Network Contributor on {RG}"),
                                                          grant_of(f"DNS Zone Contributor on {RG}")))[0]
