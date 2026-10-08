"""Generic LDAPv3 adapter: the user directory's schema and tree as standard LDIF, for any compliant server.

Declaration-only (`applies` is None): every compliant server would match it, so it is never inferred from the data.
An environment whose directory is a plain LDAP server names it in its stack. Product adapters of directory servers
build on the same renderers (`render_standard`) and add what their product configures beyond the standard.
Its importer `ldap/data-profile` records the values-free profile of any environment's directory data.
"""
from opsdir.core.contract import Adapter
from .dit import dit_ldif
from .collect import COLLECTORS
from .profile import DATA_PROFILE_IMPORTER
from .schema import schema_ldif

NAME = "ldap"
FORMATS = (("ldap/*.ldif", "ldif"),)      # the format of every file the standard base renders


def render_standard(d):
    """The standard LDAPv3 files every directory adapter renders: {path: text}, environment-neutral."""
    return {"ldap/schema.ldif": schema_ldif(d), "ldap/dit.ldif": dit_ldif(d)}


ADAPTER = Adapter(name=NAME, kind="product", applies=None, required_roles=(), render_neutral=render_standard,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label="LDAP",
                  vocabulary={}, schema=None, formats=FORMATS,
                  products=(),
                  secret_patterns=(), importers=(DATA_PROFILE_IMPORTER,), profile_terms=None, access=None,
                  collectors=COLLECTORS)
