"""Configuration domain vocabulary: its branch, and how a setting is named under its file."""
import hashlib

from ...core.naming import branch

CONFIG_FILES = branch("config-files")
BUNDLES = branch("bundles")
CENSUS = branch("census")          # files scanned for the record's values, and the values found in each


def file_dn(name):
    return f"cn={name},{CONFIG_FILES}"


def setting_rdn(locator):
    """A setting's RDN value: a digest of its locator (locators hold characters DNs would have to escape)."""
    return hashlib.sha256(locator.encode()).hexdigest()[:16]


def setting_dn(name, locator):
    return f"cn={setting_rdn(locator)},{file_dn(name)}"


def bundle_dn(name):
    return f"cn={name},{BUNDLES}"
