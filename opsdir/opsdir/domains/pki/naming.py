"""PKI domain vocabulary: its branches."""
from ...core.naming import branch

CERTIFICATES = branch("certificates")
CREDENTIALS = branch("credentials")     # keys and secrets as metadata (never their material)
SECRET_INVENTORY = branch("secret-inventory")    # secret stores' inventories, metadata only


def credential_dn(name):
    return f"cn={name},{CREDENTIALS}"


def inventory_scheme_dn(scheme):
    """Where the inventories of one ref-uri scheme's stores are kept: ou=<scheme>,ou=secret-inventory."""
    return f"ou={scheme},{SECRET_INVENTORY}"


def inventory_dn(scheme, container):
    """The inventory of one container (a safe, a mount) of a scheme's store."""
    return f"cn={container},{inventory_scheme_dn(scheme)}"
