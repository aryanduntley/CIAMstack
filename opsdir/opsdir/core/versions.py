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


def range_problem(versions):
    """Why a text isn't a PEP 440 range (">=7.2,<9"), or None."""
    try:
        SpecifierSet(versions)
        return None
    except InvalidSpecifier:
        return f"{versions!r} isn't a version range (PEP 440, such as >=7.2,<9)"


def parsed(version):
    """The version as a comparable Version, or None when it doesn't parse."""
    try:
        return Version(version)
    except InvalidVersion:
        return None


def in_any(version, ranges):
    """Whether a version is inside a PEP 440 range, or inside any of a tuple of them (parallel maintenance lines)."""
    return any(in_range(version, r) for r in ((ranges,) if isinstance(ranges, str) else ranges))


def crossed(has, older, newer):
    """Whether a change the versions `has` have lies between two versions: the older lacks it and the newer has it."""
    return not in_any(older, has) and in_any(newer, has)


def holds(versions, recorded):
    """Whether a declaration made for the product versions `versions` (a PEP 440 range; None: every version) holds for
    a role whose servers and workloads record these ciamProductVersion values: one of them is in the range, or, when
    none is recorded, the newest release is."""
    if versions is None:
        return True
    found = tuple(product_version(v)[1] for v in recorded if v)
    return any(in_range(v, versions) for v in found) if found else in_range(NEWEST, versions)
