"""Azure RBAC as the record's neutral permissions: what each verb on a binding needs (built-in roles, any of a
requirement's alternatives; the first is what the renderer assigns), the roles and actions that let an identity raise
its own access, and how Azure names a binding's resource (resource IDs; a role assigned at a parent scope covers what
is under it). Pure.

Sources: Microsoft Learn's built-in roles and Key Vault RBAC guide (checked 2026-10-02, note 450). Key Vault is read
in its RBAC permission model (Microsoft's recommendation); a vault's legacy access policies are imported as grants
too. Log ingestion is authorized on data collection rules rather than the workspace, so log writes are broad.
`manage` means a secret's lifecycle, a service name's load balancer (Network Contributor) and DNS zone, a scale set
(Virtual Machine Contributor): the built-in roles are broad. Key Vault secrets need nothing of a key on the reader's
side. After the built-in roles, each requirement names the (data) action those roles carry, so a custom role's
actions, or a vault access policy read as actions, can meet it (and a deny of that action can deny it).
"""
import re

from opsdir.core.contract import AccessModel, Permission
from opsdir.core.directory import is_a, one, rdn_of, rdn_value
from opsdir.core.environment import environment_of
from opsdir.domains.access.grants import covered

SECRET, KEY, STORAGE, STREAM, LOGS = ("ciamSecretRef", "ciamKeyRef", "ciamObjectStore", "ciamStreamBinding",
                                      "ciamLogDestination")
SERVICE, COMPUTE = "ciamServiceName", "ciamComputeGroup"
VAULT_ADMIN = "Key Vault Administrator"
KV, NET = "Microsoft.KeyVault/vaults/", "Microsoft.Network/"
BLOBS = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/"
SB = "Microsoft.ServiceBus/namespaces/messages/"
PERMISSIONS = (
    Permission("manage", SECRET, None, (("Key Vault Secrets Officer", VAULT_ADMIN, f"{KV}secrets/delete"),), False),
    Permission("manage", SERVICE, None, (("Network Contributor", f"{NET}loadBalancers/write"),
                                         ("DNS Zone Contributor", "Private DNS Zone Contributor",
                                          f"{NET}dnsZones/write", f"{NET}privateDnsZones/write")), True),
    Permission("manage", COMPUTE, None, (("Virtual Machine Contributor",
                                          "Microsoft.Compute/virtualMachineScaleSets/write"),), True),
    Permission("read-secret", SECRET, None, (("Key Vault Secrets User", "Key Vault Secrets Officer", VAULT_ADMIN,
                                            f"{KV}secrets/getSecret/action"),), False),
    Permission("write-secret", SECRET, None, (("Key Vault Secrets Officer", VAULT_ADMIN,
                                             f"{KV}secrets/setSecret/action"),), False),
    Permission("use-key", KEY, None, (("Key Vault Crypto User", "Key Vault Crypto Service Encryption User",
                                       "Key Vault Crypto Officer", VAULT_ADMIN, f"{KV}keys/unwrap/action"),), False),
    Permission("manage-key", KEY, None, (("Key Vault Crypto Officer", VAULT_ADMIN, f"{KV}keys/rotate/action"),),
               False),
    Permission("read-storage", STORAGE, None, (("Storage Blob Data Reader", "Storage Blob Data Contributor",
                                                "Storage Blob Data Owner", f"{BLOBS}read"),), False),
    Permission("write-storage", STORAGE, None, (("Storage Blob Data Contributor", "Storage Blob Data Owner",
                                                 f"{BLOBS}write"),), False),
    Permission("publish-stream", STREAM, "event-hub", (("Azure Event Hubs Data Sender", "Azure Event Hubs Data Owner",
                                                        "Microsoft.EventHub/namespaces/messages/send/action"),), False),
    Permission("publish-stream", STREAM, "queue", (("Azure Service Bus Data Sender", "Azure Service Bus Data Owner",
                                                    f"{SB}send/action"),), False),
    Permission("publish-stream", STREAM, "topic", (("Azure Service Bus Data Sender", "EventGrid Data Sender",
                                                    "Azure Service Bus Data Owner", f"{SB}send/action",
                                                    "Microsoft.EventGrid/events/send/action"),), False),
    Permission("consume-stream", STREAM, "event-hub", (("Azure Event Hubs Data Receiver", "Azure Event Hubs Data Owner",
                                                        "Microsoft.EventHub/namespaces/messages/receive/action"),),
               False),
    Permission("consume-stream", STREAM, "queue", (("Azure Service Bus Data Receiver", "Azure Service Bus Data Owner",
                                                    f"{SB}receive/action"),), False),
    Permission("write-logs", LOGS, None, (("Monitoring Metrics Publisher", "Microsoft.Insights/Telemetry/Write"),),
               True),
    Permission("read-logs", LOGS, None, (("Log Analytics Reader", "Monitoring Reader",
                                           "Microsoft.OperationalInsights/workspaces/query/read"),), True),
)
# Roles and actions that let an identity assign access (to itself or others)
ESCALATIONS = ("Owner", "User Access Administrator", "Role Based Access Control Administrator",
               "Key Vault Contributor", "Microsoft.Authorization/roleAssignments/write", "Microsoft.Authorization/*")
_PARENT = re.compile(r"^/subscriptions/[^/]+(/resourcegroups/[^/]+)?/?$", re.IGNORECASE)


def resources(binding):
    """A binding's resource as role assignment scopes name it (patterns over the subscription and resource group the
    record doesn't hold), most specific first."""
    uri = one(binding, "ciamRefUri", "")
    if uri.startswith(("azkv://", "azkv-key://")):
        vault, _, rest = uri.split("://", 1)[1].partition("/")
        name = rest.split("/")[-1]
        child = "keys" if uri.startswith("azkv-key://") else "secrets"
        base = f"/subscriptions/*/resourceGroups/*/providers/Microsoft.KeyVault/vaults/{vault}"
        return (f"{base}/{child}/{name}", base)
    if one(binding, "ciamStorageRef", "").startswith("azblob://"):
        account, _, container = one(binding, "ciamStorageRef")[9:].partition("/")
        base = f"/subscriptions/*/resourceGroups/*/providers/Microsoft.Storage/storageAccounts/{account}"
        return (f"{base}/blobServices/default/containers/{container}", base)
    if is_a(binding, "ciamServiceName"):          # as the renderer names its load balancer, and its zone
        zone = one(binding, "ciamDnsZone", "")
        return (f"/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/loadBalancers/"
                f"lb-ciam-{rdn_of(environment_of(binding))}-{rdn_value(binding)}",
                *((f"/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/dnszones/{zone}",
                   f"/subscriptions/*/resourceGroups/*/providers/Microsoft.Network/privateDnsZones/{zone}") if zone
                  else ()))
    ref = one(binding, "ciamProviderRef", "")
    return (ref,) if ref.startswith("/subscriptions/") else ()


def covers(granted, binding):
    """A scope covers a binding's resource when it is it, holds it, or is a subscription or resource group (whose
    contents the record can't tell)."""
    return covered(granted, resources(binding)) or bool(_PARENT.match(granted))


ACCESS = AccessModel(permissions=PERMISSIONS, escalations=ESCALATIONS, covers=covers,
                     resource=lambda binding: next(iter(resources(binding)), None))
