"""IAM database authentication to the record's database on RDS / Aurora: the region read from the endpoint, the token
command."""
import pytest

from opsdir.core.contract import DbTarget
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.dbauth import endpoint_region, rds_token_command


@pytest.mark.parametrize("host, region", [
    ("record.c9akciq32xyz.us-east-1.rds.amazonaws.com", "us-east-1"),
    ("record.cluster-c9akciq32xyz.us-gov-west-1.rds.amazonaws.com", "us-gov-west-1"),
    ("record.cluster-ro-c9akciq32xyz.eu-central-1.rds.amazonaws.com", "eu-central-1"),
    ("db.internal.example", None), ("", None)])
def test_the_region_of_an_endpoint(host, region):
    assert endpoint_region(host) == region


def test_the_token_command():
    target = DbTarget("record.c9akciq32xyz.us-gov-east-1.rds.amazonaws.com", 5432, "opsdir_app", "opsdir")
    assert rds_token_command(target) == (
        "aws", "rds", "generate-db-auth-token", "--hostname", target.host, "--port", "5432",
        "--username", "opsdir_app", "--region", "us-gov-east-1")
    assert "--region" not in rds_token_command(target._replace(host="db.internal.example"))


def test_the_adapter_declares_the_scheme():
    assert ADAPTER.db_tokens == {"aws-rds-iam": rds_token_command}
