"""Versions as data: what a product version value says, and whether a version is in a declared range. Products record
theirs as `ciamProductVersion` ("<product> <version>"); ranges are PEP 440 specifiers (">=7,<9")."""
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


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
