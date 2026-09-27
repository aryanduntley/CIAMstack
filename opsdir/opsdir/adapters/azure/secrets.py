"""Resolve azkv:// secret references (azkv://<vault>/<name>) at run time with the Azure CLI."""


def keyvault_command(rest):
    vault, name = rest.split("/", 1)
    return f"az keyvault secret show --vault-name '{vault}' --name '{name}' --query value -o tsv"
