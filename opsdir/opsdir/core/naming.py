"""The operations directory's naming context and standard branches: one source of truth for DNs."""

SUFFIX = "dc=ciam-ops"


def branch(name, parent=SUFFIX):
    """DN of a standard branch, e.g. branch('consumers') → ou=consumers,dc=ciam-ops."""
    return f"ou={name},{parent}"
