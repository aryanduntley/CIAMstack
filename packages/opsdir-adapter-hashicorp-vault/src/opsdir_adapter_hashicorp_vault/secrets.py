"""Vault secrets: vault:// references resolved at run time with the Vault CLI, and the Vault token forms the store
refuses."""
from opsdir.core.contract import SecretPattern

# Vault token forms the store refuses (SPEC R4): service, batch and recovery tokens
SECRET_PATTERNS = (
    SecretPattern("vault-token", r"(^|[^A-Za-z0-9])hv[sbr]\.[A-Za-z0-9_-]{20,}", "A HashiCorp Vault token"),
)



def kv_command(rest):
    return f"vault kv get -field=value '{rest}'"
