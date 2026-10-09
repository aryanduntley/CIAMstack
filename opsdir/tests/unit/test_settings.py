"""Estate settings: domains and installed adapters declare them (name, kind, default, bounds or choices); the
platform's managers give them values as governed entries under ou=settings; the record's value applies when it is
valid, the default otherwise. The settings report lists every declared setting (and entries nobody declares); setting
a value is a change set."""
import pytest

from opsdir.connectors.registry import DOMAINS
from opsdir.connectors.settings import changes_for_setting, declared_settings, settings_rows
from opsdir.core.contract import Adapter, Domain, Setting
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
    rows = settings_rows(d, (DOMAIN,), ())
    assert rows == [
        ("estate-name", "test", "string", "example", "", "example", "default", NAME.description),
        ("restore-test-interval-days", "test", "int (min 1, max 3650)", "90", "0", "90",
         "invalid: 0 is less than 1; the default applies", DAYS.description),
        ("strict-mode", "test", "bool", "FALSE", "TRUE", "TRUE", "set", FLAG.description),
        ("old-knob", "", "", "", "7", "", "not declared by any installed domain or adapter", "")]


def test_only_declared_settings_can_be_set():
    assert [r.changetype for r in changes_for_setting(_d(), "strict-mode", "TRUE", (DOMAIN,), ())] == ["add"]
    with pytest.raises(ValueError, match="no installed domain or adapter declares setting old-knob"):
        changes_for_setting(_d(), "old-knob", "7", (DOMAIN,), ())


def test_a_string_setting_may_list_its_choices_and_an_adapter_may_declare_it():
    kind = Setting("gateway-kind", "string", "alpha", "Which gateway", choices=("alpha", "beta"))
    assert parse_setting(kind, "beta") == ("beta", None)
    assert parse_setting(kind, "gamma") == (None, "'gamma' isn't one of alpha, beta")
    kit = Adapter(*(None,) * 19)._replace(name="kit", settings=(kind,))
    assert ("kit", kind) in declared_settings((DOMAIN,), (kit,))
    assert settings_rows(_d(("gateway-kind", "gamma")), (), (kit,)) == [
        ("gateway-kind", "kit", "string (one of alpha, beta)", "alpha", "gamma", "alpha",
         "invalid: 'gamma' isn't one of alpha, beta; the default applies", "Which gateway")]
    assert [r.changetype for r in changes_for_setting(_d(), "gateway-kind", "beta", (), (kit,))] == ["add"]


def test_the_data_domain_declares_the_restore_test_interval():
    domain, s = {s.name: (dm, s) for dm, s in declared_settings(DOMAINS)}["restore-test-interval-days"]
    assert (domain, s.kind, s.default, s.minimum) == ("data", "int", 90, 1)


def test_the_access_directory_and_pki_domains_declare_their_thresholds():
    found = {s.name: (dm, s.default) for dm, s in declared_settings(DOMAINS)}
    assert {n: found[n] for n in ("access-review-interval-days", "break-glass-test-interval-days",
                                  "consumer-review-interval-days", "consumer-unseen-days",
                                  "certificate-expiry-margin-days")} == {
        "access-review-interval-days": ("access", 365), "break-glass-test-interval-days": ("access", 180),
        "consumer-review-interval-days": ("directory", 365), "consumer-unseen-days": ("directory", 30),
        "certificate-expiry-margin-days": ("pki", 30)}


def test_recorded_thresholds_change_what_is_flagged():
    import datetime as dt
    from types import SimpleNamespace
    from opsdir.core.directory import get
    from opsdir.domains.access.principals import to_check as principal_points
    from opsdir.domains.directory.consumers import to_check as consumer_points
    from opsdir.domains.pki.checks import check_certificates
    principal, consumer = "cn=glass,ou=principals,dc=ciam-ops", "cn=app,ou=consumers,dc=ciam-ops"
    entries = ((principal, ("top", "ciamPrincipal"), {"cn": ("glass",), "ciamPrincipalKind": ("break-glass",),
                                                      "ciamReviewedOn": ("20260601000000Z",),
                                                      "ciamLastTested": ("20260501000000Z",)}),
               (consumer, ("top", "ciamConsumer"), {"cn": ("app",), "ciamLastSeen": ("20260901000000Z",),
                                                    "ciamReviewedOn": ("20260601000000Z",)}),
               ("cn=tls,ou=certificates,dc=ciam-ops", ("top", "ciamCertificate"),
                {"cn": ("tls",), "ciamNotAfter": ("20261220000000Z",)}))
    as_of = dt.date(2026, 10, 1)

    def flagged(*values):
        d = make_directory((), {}, (SETTINGS, *entries, *((setting_dn(n), ("top", "ciamEstateSetting"),
                                                           {"cn": (n,), "ciamEstateValue": (t,)}) for n, t in values)))
        ctx = SimpleNamespace(d=d, cutover=dt.date(2026, 12, 1), as_of=as_of)
        return (principal_points(d, get(d, principal), as_of), consumer_points(d, get(d, consumer), as_of),
                len(check_certificates(ctx).actions))

    glass, app, certs = flagged()          # defaults: nothing overdue; the certificate expires within cutover + 30
    assert not any("review overdue" in g or "last tested" in g for g in glass)
    assert "not seen" not in app and "review older" not in app and certs == 1
    glass, app, certs = flagged(("access-review-interval-days", "90"), ("break-glass-test-interval-days", "90"),
                                ("consumer-unseen-days", "20"), ("consumer-review-interval-days", "90"),
                                ("certificate-expiry-margin-days", "10"))
    assert "review overdue (last 2026-06-01, every 90 days)" in glass and "break-glass: last tested 2026-05-01" in glass
    assert "not seen for 30 days" in app and "review older than 90 days (2026-06-01)" in app and certs == 0
