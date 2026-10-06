"""Estate settings: domains declare them (name, kind, default, bounds); the platform's managers give them values as
governed entries under ou=settings; the record's value applies when it is valid, the default otherwise. The settings
report lists every declared setting (and entries nobody declares); setting a value is a change set."""
import pytest

from opsdir.connectors.registry import DOMAINS
from opsdir.connectors.settings import changes_for_setting, declared_settings, settings_rows
from opsdir.core.contract import Domain, Setting
from opsdir.core.directory import make_directory
from opsdir.core.settings import parse_setting, recorded_setting, setting_changes, setting_dn, setting_value

DAYS = Setting("restore-test-interval-days", "int", 90, "How often restores are tested", minimum=1, maximum=3650)
FLAG = Setting("strict-mode", "bool", False, "Whether to be strict")
NAME = Setting("estate-name", "string", "example", "What the estate is called")
DOMAIN = Domain(name="test", schema=None, required_roles=(), sql=(), reports={}, checks=(), order=1, vocabulary={},
                settings=(DAYS, FLAG, NAME))
SETTINGS = ("ou=settings,dc=ciam-ops", ("top", "organizationalUnit"), {"ou": ("settings",)})


def _d(*values):
    """A directory holding the given (name, text) settings under ou=settings."""
    return make_directory((), {}, (SETTINGS, *((setting_dn(n), ("top", "ciamEstateSetting"),
                                                {"cn": (n,), "ciamEstateValue": (t,)}) for n, t in values)))


def test_a_value_is_read_against_its_declaration():
    assert parse_setting(DAYS, "60") == (60, None)
    assert parse_setting(DAYS, "0") == (None, "0 is less than 1")
    assert parse_setting(DAYS, "9999") == (None, "9999 is more than 3650")
    assert parse_setting(DAYS, "soon") == (None, "'soon' isn't a whole number")
    assert parse_setting(FLAG, "true") == (True, None) and parse_setting(FLAG, "maybe")[0] is None
    assert parse_setting(NAME, " ") == (None, "it is empty")


def test_the_record_s_value_applies_when_valid_else_the_default():
    assert setting_value(make_directory((), {}, ()), DAYS) == 90              # nothing recorded
    assert setting_value(_d(("restore-test-interval-days", "30")), DAYS) == 30
    assert setting_value(_d(("restore-test-interval-days", "0")), DAYS) == 90  # invalid: the default
    assert setting_value(_d(("strict-mode", "TRUE")), FLAG) is True
    assert recorded_setting(_d(("estate-name", "aero")), "estate-name") == "aero"


def test_setting_a_value_adds_the_branch_once_and_changes_only_what_differs():
    empty = make_directory((), {}, ())
    added = setting_changes(empty, DAYS, "60")
    assert [(r.dn, r.changetype) for r in added] == [("ou=settings,dc=ciam-ops", "add"),
                                                     ("cn=restore-test-interval-days,ou=settings,dc=ciam-ops", "add")]
    assert added[1].attrs["ciamEstateValue"] == ("60",) and added[1].attrs["description"] == (DAYS.description,)
    assert [r.changetype for r in setting_changes(_d(), FLAG, "true")] == ["add"]          # branch already there
    assert setting_changes(_d(("strict-mode", "FALSE")), FLAG, "true")[0].mods == (
        ("replace", "ciamEstateValue", ("TRUE",)),)                                          # canonical text
    assert setting_changes(_d(("restore-test-interval-days", "60")), DAYS, "60") == ()
    with pytest.raises(ValueError, match="0 is less than 1"):
        setting_changes(empty, DAYS, "0")


def test_the_report_lists_declared_settings_then_undeclared_entries():
    d = _d(("restore-test-interval-days", "0"), ("strict-mode", "TRUE"), ("old-knob", "7"))
    rows = settings_rows(d, (DOMAIN,))
    assert rows == [
        ("estate-name", "test", "string", "example", "", "example", "default", NAME.description),
        ("restore-test-interval-days", "test", "int (min 1, max 3650)", "90", "0", "90",
         "invalid: 0 is less than 1; the default applies", DAYS.description),
        ("strict-mode", "test", "bool", "FALSE", "TRUE", "TRUE", "set", FLAG.description),
        ("old-knob", "", "", "", "7", "", "not declared by any installed domain", "")]


def test_only_declared_settings_can_be_set():
    assert [r.changetype for r in changes_for_setting(_d(), "strict-mode", "TRUE", (DOMAIN,))] == ["add"]
    with pytest.raises(ValueError, match="no installed domain declares setting old-knob"):
        changes_for_setting(_d(), "old-knob", "7", (DOMAIN,))


def test_the_data_domain_declares_the_restore_test_interval():
    domain, s = {s.name: (dm, s) for dm, s in declared_settings(DOMAINS)}["restore-test-interval-days"]
    assert (domain, s.kind, s.default, s.minimum) == ("data", "int", 90, 1)
