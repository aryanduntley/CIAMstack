"""Resolve vault:// secret references at run time with the Vault CLI."""


def kv_command(rest):
    return f"vault kv get -field=value '{rest}'"
