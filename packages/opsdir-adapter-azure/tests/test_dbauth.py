"""Microsoft Entra sign-in to the record's database on Azure Database for PostgreSQL: the cloud-aware token command."""
from opsdir.core.contract import DbTarget
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.dbauth import entra_token_command


def test_the_token_command_names_the_database_resource_type_not_a_cloud():
    command = entra_token_command(DbTarget("record.postgres.database.usgovcloudapi.net", 5432, "opsdir_app", "opsdir"))
    assert command == ("az", "account", "get-access-token", "--resource-type", "oss-rdbms", "--query",
                       "accessToken", "--output", "tsv")


def test_the_adapter_declares_the_scheme():
    assert ADAPTER.db_tokens == {"azure-entra": entra_token_command}
