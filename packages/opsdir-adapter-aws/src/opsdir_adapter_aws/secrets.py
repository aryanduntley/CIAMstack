"""Resolve aws-sm:// secret references at run time with the AWS CLI (the value never touches disk)."""


def secretsmanager_command(rest):
    return f"aws secretsmanager get-secret-value --secret-id '{rest}' --query SecretString --output text"
