"""PKI domain vocabulary: its branches."""
from ...core.naming import branch

CERTIFICATES = branch("certificates")
CREDENTIALS = branch("credentials")     # keys and secrets as metadata (never their material)
SECRET_INVENTORY = branch("secret-inventory")    # secret stores' inventories, metadata only
AUTHORITIES = branch("certificate-authorities")   # certification authorities, their revocation endpoints as children
TEMPLATES = branch("certificate-templates")      # the certificate templates CAs issue from
ISSUED = branch("issued-certificates")           # each CA's issued-certificate inventory, metadata only
OBSERVATIONS = branch("revocation-observations")  # what each CA's revocation endpoints answered when observed
MANAGED = branch("managed-certificates")         # certificate managers' inventories, metadata only
TRUST_BUNDLES = branch("trust-bundles")          # outside PKIs' published CA sets as last imported
TRUST_POLICIES = branch("trust-policies")        # which certificates the platform accepts, and from whom


def credential_dn(name):
    return f"cn={name},{CREDENTIALS}"


def inventory_scheme_dn(scheme):
    """Where the inventories of one ref-uri scheme's stores are kept: ou=<scheme>,ou=secret-inventory."""
    return f"ou={scheme},{SECRET_INVENTORY}"


def inventory_dn(scheme, container):
    """The inventory of one container (a safe, a mount) of a scheme's store."""
    return f"cn={container},{inventory_scheme_dn(scheme)}"


def authority_dn(name):
    """A certification authority, by its name."""
    return f"cn={name},{AUTHORITIES}"


def template_dn(name):
    """A certificate template, by its name."""
    return f"cn={name},{TEMPLATES}"


def issued_inventory_dn(authority):
    """The issued-certificate inventory of the CA of that name."""
    return f"cn={authority},{ISSUED}"


def observation_dn(authority):
    """The observation of the revocation endpoints of the CA of that name."""
    return f"cn={authority},{OBSERVATIONS}"


def managed_inventory_dn(name):
    """The certificate manager inventory of the collection source of that name."""
    return f"cn={name},{MANAGED}"


def trust_bundle_dn(name):
    """A trust bundle, by its name (the publisher's group: dod, eca)."""
    return f"cn={name},{TRUST_BUNDLES}"
