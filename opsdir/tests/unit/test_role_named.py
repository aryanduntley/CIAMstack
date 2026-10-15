"""The binding of the role an entry's attribute names (core.environment.role_named): what the domains ask for a
destination, channel, vault, policy or secret an entry points at by role."""
from opsdir.core.directory import make_entry, one
from opsdir.core.environment import env_model, one_role, role_named
from opsdir.core.interchange.ldif import parse
import mini_estate
from support import REGISTRY, build_directory


def _model():
    return env_model(build_directory(REGISTRY, tuple(parse(mini_estate.LDIF))), "alpha/prod")


def test_the_binding_of_the_role_an_attribute_names():
    m = _model()
    e = make_entry("cn=x,dc=ciam-ops", ("top",), {"ciamFindingsRole": ["network"]})
    assert role_named(m, e, "ciamFindingsRole") == one_role(m, "network")
    assert one(role_named(m, e, "ciamFindingsRole"), "ciamBindingRole") == "network"


def test_none_when_the_entry_names_no_role_or_the_environment_binds_none():
    m = _model()
    e = make_entry("cn=x,dc=ciam-ops", ("top",), {"ciamFindingsRole": ["nothing-binds-this"]})
    assert role_named(m, e, "ciamFindingsRole") is None and role_named(m, e, "ciamAlertRole") is None
