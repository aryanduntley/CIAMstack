"""Terraform state from azurerm 4.x and 5.x read in the same names: a private record's zone from its zone ID, a
federated credential's identity, a storage container's ARM ID; 4.x state passes unchanged."""
from opsdir_adapter_azure.state_names import reader_names

RG = "/subscriptions/0/resourceGroups/rg-ciam"
IDENTITY = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-ci"
CONTAINER = f"{RG}/providers/Microsoft.Storage/storageAccounts/st1/blobServices/default/containers/logs"


def test_a_5x_private_record_gets_its_zone_name_from_the_zone_id():
    a = reader_names("azurerm_private_dns_cname_record", {
        "name": "ldap", "private_dns_zone_id": f"{RG}/providers/Microsoft.Network/privateDnsZones/id.example.test"})
    assert a["zone_name"] == "id.example.test"


def test_a_5x_federated_credential_names_its_identity_as_parent():
    a = reader_names("azurerm_federated_identity_credential", {"user_assigned_identity_id": IDENTITY})
    assert a["parent_id"] == IDENTITY


def test_a_4x_container_with_a_data_plane_id_is_read_by_its_arm_id():
    a = reader_names("azurerm_storage_container", {"id": "https://st1.blob.core.windows.net/logs",
                                                   "resource_manager_id": CONTAINER})
    assert a["id"] == CONTAINER


def test_state_already_in_the_readers_names_passes_unchanged():
    for t, a in (("azurerm_private_dns_a_record", {"zone_name": "id.example.test"}),
                 ("azurerm_federated_identity_credential", {"parent_id": IDENTITY}),
                 ("azurerm_storage_container", {"id": CONTAINER}),
                 ("azurerm_private_dns_zone", {"name": "id.example.test"})):
        assert reader_names(t, a) is a
