"""Versions as data: what a product version value says, whether a version is in a declared range, and whether a
declaration made for some versions only (a log file, an endpoint) holds for what a role runs. Products record theirs as
`ciamProductVersion` ("<product> <version>"); ranges are PEP 440 specifiers (">=7,<9")."""
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

NEWEST = "99999"            # what a role recording no product version is taken to run: the newest release


def product_version(value):
    """(product, version) of a ciamProductVersion value: the version is its last word ("Some Product 7.5.1")."""
    name, _, version = (value or "").strip().rpartition(" ")
    return (name, version) if name else (version, "")


def in_range(version, versions):
    """Whether a version is inside a PEP 440 range (False when either doesn't parse)."""
    try:
        return SpecifierSet(versions).contains(Version(version), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return False


def holds(versions, recorded):
    """Whether a declaration made for the product versions `versions` (a PEP 440 range; None: every version) holds for
    a role whose servers and workloads record these ciamProductVersion values: one of them is in the range, or, when
    none is recorded, the newest release is."""
    if versions is None:
        return True
    found = tuple(product_version(v)[1] for v in recorded if v)
    return any(in_range(v, versions) for v in found) if found else in_range(NEWEST, versions)
