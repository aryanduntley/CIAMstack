"""Azure secrets: azkv:// references (azkv://<vault>/<name>) resolved at run time with the Azure CLI, and the Azure
credential forms the store refuses."""
from opsdir.core.contract import SecretPattern

# Azure credential forms the store refuses (SPEC R4)
SECRET_PATTERNS = (
    SecretPattern("azure-storage-key", r"(?i)AccountKey=[A-Za-z0-9+/]{40,}", "An Azure storage account key"),
    SecretPattern("azure-sas-signature", r"(?i)[?&]sig=[A-Za-z0-9%+/=]{20,}", "An Azure shared access signature"),
)



def keyvault_command(rest):
    vault, name = rest.split("/", 1)
    return f"az keyvault secret show --vault-name '{vault}' --name '{name}' --query value -o tsv"
