"""Signing in to the record's own database on Azure Database for PostgreSQL flexible server with Microsoft Entra ID
(OPSDIR_DB_AUTH=azure-entra): `az account get-access-token --resource-type oss-rdbms` gets an access token for the
database audience of the cloud the CLI is set to (`az cloud set`: https://ossrdbms-aad.database.windows.net, or
https://ossrdbms-aad.database.usgovcloudapi.net in Azure Government), with the identity it runs as (the server's
managed identity, or the operator's login), and libpq sends it as the password. Its lifetime varies (5 to 60
minutes, a managed identity's up to 24 hours); one is fetched for each run. Pure."""
SCHEME = "azure-entra"


def entra_token_command(target):
    """The Azure CLI command printing an Entra access token for Azure Database for PostgreSQL (the same for every
    server of the cloud the CLI is set to; the target names none of it)."""
    return ("az", "account", "get-access-token", "--resource-type", "oss-rdbms", "--query", "accessToken",
            "--output", "tsv")
