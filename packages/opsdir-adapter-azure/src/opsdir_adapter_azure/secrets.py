"""Azure secrets: azkv:// references (azkv://<vault>/<name>) resolved at run time with the Azure CLI, and the Azure
credential forms the store refuses."""
from urllib.parse import urlsplit

from opsdir.core.contract import SecretPattern
from opsdir.core.directory import one
from opsdir.core.interchange import jinja

# Azure credential forms the store refuses (SPEC R4)
SECRET_PATTERNS = (
    SecretPattern("azure-storage-key", r"(?i)AccountKey=[A-Za-z0-9+/]{40,}", "An Azure storage account key"),
    SecretPattern("azure-sas-signature", r"(?i)[?&]sig=[A-Za-z0-9%+/=]{20,}", "An Azure shared access signature"),
)



def keyvault_command(rest):
    vault, name = rest.split("/", 1)
    return f"az keyvault secret show --vault-name '{vault}' --name '{name}' --query value -o tsv"


def keyvault_lookup(m, store, rest):
    """The Ansible lookup reading an azkv:// secret at run time (azure.azcollection.azure_keyvault_secret), when the
    environment's Key Vault store records its endpoint (ciamStoreEndpoint, e.g. https://<vault>.vault.azure.net/ or
    .vault.usgovcloudapi.net/ in Azure Government): the reference's vault under that endpoint's domain. None without
    one (the az CLI's own cloud setting then decides, through its resolver command)."""
    endpoint = one(store, "ciamStoreEndpoint") if store is not None else None
    host = urlsplit(endpoint).hostname if endpoint else None
    if not host or "." not in host:
        return None
    vault, name = rest.split("/", 1)
    return jinja.lookup("azure.azcollection.azure_keyvault_secret", name,
                        vault_url=f"https://{vault}.{host.split('.', 1)[1]}/")
