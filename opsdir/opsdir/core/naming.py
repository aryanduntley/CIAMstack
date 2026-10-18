"""The operations directory's naming context and standard branches: one source of truth for DNs."""
import re

SUFFIX = "dc=ciam-ops"
# A database role or login name opsdir writes into SQL and DNs: nothing that needs quoting
ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def env_label(env_dn):
    """An environment's cloud/env label from its DN ('env=prod,cloud=source,…' → 'source/prod')."""
    env, cloud = (part.split("=", 1)[1] for part in env_dn.split(",")[:2])
    return f"{cloud}/{env}"


_DN_SPECIAL = re.compile(r'[,+"\\<>;=#]')


def rdn_safe(name):
    """Whether a name can be an RDN value as it is (no DN special characters, no surrounding spaces): what product
    importers check before naming an entry after something in a product's configuration."""
    return bool(name) and not _DN_SPECIAL.search(name) and name == name.strip()


def branch(name, parent=SUFFIX):
    """DN of a standard branch, e.g. branch('consumers') → ou=consumers,dc=ciam-ops."""
    return f"ou={name},{parent}"


def role_name_problem(name, what="role"):
    """Why a text can't be a database role or login name here (lowercase letters, digits and underscores, starting
    with a letter or underscore, at most 63 characters: nothing that needs quoting), or None."""
    return None if ROLE_NAME.fullmatch(name or "") else f"{what} name {name!r} isn't lowercase letters, digits and _"
