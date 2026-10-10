"""AWS secrets: aws-sm:// references resolved at run time with the AWS CLI (the value never touches disk), and the AWS
credential forms the store refuses."""
from opsdir.core.contract import SecretPattern
from opsdir.core.interchange import jinja

# AWS credential forms the store refuses (SPEC R4)
SECRET_PATTERNS = (
    SecretPattern("aws-access-key-id", r"(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}([^A-Z0-9]|$)", "An AWS access key id"),
    SecretPattern("aws-secret-access-key",
                  r"(?i)aws_secret_access_key[\"']?\s*[=:]\s*[\"']?[A-Za-z0-9/+]{40}", "An AWS secret access key"),
)



def secretsmanager_command(rest):
    return f"aws secretsmanager get-secret-value --secret-id '{rest}' --query SecretString --output text"


def secretsmanager_lookup(m, store, rest):
    """The Ansible lookup reading an aws-sm:// secret at run time, as the CLI does (amazon.aws.secretsmanager_secret:
    the secret's string; the region and credentials from the controller's AWS configuration)."""
    return jinja.lookup("amazon.aws.secretsmanager_secret", rest)
