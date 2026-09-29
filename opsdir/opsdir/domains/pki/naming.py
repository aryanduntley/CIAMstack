"""PKI domain vocabulary: its branches."""
from ...core.naming import branch

CERTIFICATES = branch("certificates")
CREDENTIALS = branch("credentials")     # keys and secrets as metadata (never their material)


def credential_dn(name):
    return f"cn={name},{CREDENTIALS}"
