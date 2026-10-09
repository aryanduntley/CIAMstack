"""Azure for Kubernetes workloads: the user-assigned managed identity a workload's service account federates with (AKS
workload identity: annotation azure.workload.identity/client-id, tenant-id when the cloud records its tenant, pod
label azure.workload.identity/use), and how the External Secrets Operator (provider azurekv) and the Secrets Store CSI
driver (Azure Key Vault provider) read azkv://<vault>/<name> references. Pure.

The client id is the identity binding's ciamIdentityClientId (the cloud makes it; the record learns it from the
cloud), UNBOUND without it. The tenant is the cloud's ciamOrganizationRef. In Azure Government (ciamCloudEnvironment
usgovernment) vaults answer at vault.usgovcloudapi.net and both operators are told the cloud (USGovernmentCloud,
AzureUSGovernmentCloud). One SecretStore and one SecretProviderClass serve one vault.
"""
from opsdir.core.contract import K8sIdentity, SecretDelivery
from opsdir.core.directory import one
from opsdir.core.environment import UNBOUND
from opsdir.core.interchange.yaml_text import dump

CLIENT_ID, TENANT_ID, USE = ("azure.workload.identity/client-id", "azure.workload.identity/tenant-id",
                             "azure.workload.identity/use")
CLOUDS = {True: ("vault.usgovcloudapi.net", "USGovernmentCloud", "AzureUSGovernmentCloud"),
          False: ("vault.azure.net", "PublicCloud", "AzurePublicCloud")}


def _cloud(m):
    """(vault DNS suffix, ESO environmentType, CSI cloudName) of environment m's Azure cloud."""
    return CLOUDS[one(m.cloud, "ciamCloudEnvironment") == "usgovernment"]


def tenant(m):
    """The tenant environment m's cloud records (ciamOrganizationRef), or None."""
    return one(m.cloud, "ciamOrganizationRef")


def client_id(binding):
    """The client id of the managed identity an identity binding names, or UNBOUND:<role>-client-id."""
    if binding is None:
        return f"{UNBOUND}workload-identity-client-id"
    return one(binding, "ciamIdentityClientId") or f"{UNBOUND}{one(binding, 'ciamBindingRole')}-client-id"


def workload_identity(m, binding):
    """K8sIdentity: the managed identity's client id (and the tenant) on the service account, the use label on pods."""
    return K8sIdentity(annotations=((CLIENT_ID, client_id(binding)),
                                    *(((TENANT_ID, tenant(m)),) if tenant(m) else ())),
                       pod_labels=((USE, "true"),))


def vault_of(rest):
    """The Key Vault an azkv reference names."""
    return rest.split("/", 1)[0]


def eso_provider(m, store, key, service_account, cluster):
    """SecretStore spec.provider: the vault, as the service account's workload identity, in the cloud's environment."""
    suffix, environment, _ = _cloud(m)
    return {"azurekv": {"vaultUrl": f"https://{key}.{suffix}", "authType": "WorkloadIdentity",
                        "serviceAccountRef": {"name": service_account},
                        **({"tenantId": tenant(m)} if tenant(m) else {}), "environmentType": environment}}


def eso_ref(rest):
    """remoteRef: the secret's name in its vault."""
    return {"key": rest.split("/", 1)[1]}


def csi_parameters(m, store, key, objects, identity):
    """SecretProviderClass parameters for the Azure Key Vault provider: the vault, the workload's identity, the cloud,
    each secret under its alias."""
    return {"usePodIdentity": "false", "clientID": client_id(identity), "keyvaultName": key,
            "tenantId": tenant(m) or f"{UNBOUND}azure-tenant", "cloudName": _cloud(m)[2],
            "objects": dump({"array": [dump({"objectName": rest.split("/", 1)[1], "objectType": "secret",
                                             "objectAlias": name}) for name, rest in objects]})}


SECRET_DELIVERY = {"azkv": SecretDelivery(store_key=vault_of, eso_provider=eso_provider, eso_ref=eso_ref,
                                          csi_provider="azure", csi_parameters=csi_parameters)}
