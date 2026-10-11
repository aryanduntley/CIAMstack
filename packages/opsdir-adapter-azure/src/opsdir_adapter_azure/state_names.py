"""Terraform state from either azurerm major, in the attribute names and forms the Azure readers take (azurerm 4.x's,
which the CLI readers also produce). State keeps the names of the provider that last wrote it, so a source estate's
state may be 4.x's while a refreshed one is 5.x's:

  azurerm_private_dns_*_record             zone_name from private_dns_zone_id (5.x names the zone by ID)
  azurerm_federated_identity_credential    parent_id from user_assigned_identity_id
  azurerm_storage_container                id: its ARM ID (4.x state may hold the data-plane URL there, the ARM ID
                                           in resource_manager_id; 5.x's id is the ARM ID)

Attributes already in the readers' names pass unchanged. Pure.
"""
from .arm_ids import arm_segment

PRIVATE_RECORD = "azurerm_private_dns_"
CREDENTIAL = "azurerm_federated_identity_credential"
CONTAINER = "azurerm_storage_container"


def reader_names(type_, attributes):
    """A state resource's attributes, with the names the readers take filled in from 5.x's (a new dict when any is
    added, else the same mapping)."""
    a = attributes
    if type_.startswith(PRIVATE_RECORD) and type_.endswith("_record") and not a.get("zone_name") \
            and a.get("private_dns_zone_id"):
        return {**a, "zone_name": arm_segment(a["private_dns_zone_id"], "privateDnsZones")}
    if type_ == CREDENTIAL and not a.get("parent_id") and a.get("user_assigned_identity_id"):
        return {**a, "parent_id": a["user_assigned_identity_id"]}
    if type_ == CONTAINER and a.get("resource_manager_id") and not (a.get("id") or "").startswith("/subscriptions/"):
        return {**a, "id": a["resource_manager_id"]}
    return a
