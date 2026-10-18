"""Signing in to the record's own database on Amazon RDS or Aurora PostgreSQL with IAM database authentication
(OPSDIR_DB_AUTH=aws-rds-iam): `aws rds generate-db-auth-token` signs a token, valid 15 minutes for connecting, with
the identity the AWS CLI runs as (the server's instance role, or the operator's login), and libpq sends it as the
password. The host must be the database's own endpoint (the token is signed for it, never for a DNS alias); the
region is read from the endpoint when it is an RDS one, else left to the CLI's configuration. Pure."""
import re

SCHEME = "aws-rds-iam"
# <name>.<id>.<region>.rds.amazonaws.com (instance), <name>.cluster[-ro]-<id>.<region>.rds.amazonaws.com (Aurora)
RDS_ENDPOINT = re.compile(r"\.([a-z]{2}(?:-gov)?-[a-z]+-\d+)\.rds\.amazonaws\.com$")


def endpoint_region(host):
    """The AWS region of an RDS or Aurora endpoint, or None."""
    m = RDS_ENDPOINT.search((host or "").lower())
    return m.group(1) if m else None


def rds_token_command(target):
    """The AWS CLI command printing an IAM database authentication token for the target (core.contract.DbTarget)."""
    region = endpoint_region(target.host)
    return ("aws", "rds", "generate-db-auth-token", "--hostname", target.host, "--port", str(target.port),
            "--username", target.user, *(("--region", region) if region else ()))
