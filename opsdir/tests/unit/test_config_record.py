"""Config files held in the record and rebuilt from it (in memory, on the mini estate): the three capture levels,
values withheld because they may be secret, links to an environment's bindings, and re-capture as a diff."""
from pathlib import Path

import pytest

from opsdir.connectors.capture import capture_changes, rebuilt_file
from opsdir.core.directory import children, get, one
from opsdir.core.formats import INI, JAVA_PROPERTIES, JSON, LDIF, XML
from opsdir.core.interchange.ldif import parse
from opsdir.domains.configuration.domain import capture_rows
from opsdir.domains.configuration.naming import file_dn, setting_dn
import mini_estate
from mini_estate import FAKE

SAMPLES = Path(__file__).resolve().parent.parent / "capture_samples"
ALPHA = "alpha/prod"


def captured(text, fmt, name="f", d=None, **options):
    """(directory with the file captured, notices)."""
    base = d or mini_estate.directory()
    changes, notices = capture_changes(base, fmt, text, name, f"repo/{name}", installed=(FAKE,), **options)
    return mini_estate.directory(changes), notices


def rebuilt(d, name="f", spec=None):
    return rebuilt_file(d, name, spec, installed=(FAKE,))[0]


def setting(d, name, locator):
    return get(d, setting_dn(name, locator))


def link(name, locator, source):
    return parse(f"dn: {setting_dn(name, locator)}\nchangetype: modify\nreplace: ciamValueFrom\n"
                 f"ciamValueFrom: {source}\n-\n")


@pytest.mark.parametrize("sample, fmt", [("run.properties", JAVA_PROPERTIES), ("tcp.xml", XML), ("sync.json", JSON),
                                         ("sssd.ini", INI), ("config.ldif", LDIF)])
def test_a_captured_file_is_rebuilt_identical_from_the_record_alone(sample, fmt):
    text = (SAMPLES / sample).read_text()
    d, notices = captured(text, fmt, "sample", accept_concerns=(sample == "config.ldif"))
    entry = get(d, file_dn("sample"))
    assert one(entry, "ciamCaptureLevel") == "settings" and notices[0].startswith("sample: ")
    assert rebuilt(d, "sample") == text


def test_values_that_may_be_secret_are_withheld_and_come_from_a_secret_reference():
    text = "pf.admin.user=admin\npf.admin.pwd=Hunter2Hunter2\n"
    d, notices = captured(text, JAVA_PROPERTIES)
    pwd = setting(d, "f", "pf.admin.pwd")
    assert (one(pwd, "ciamSecretRequired"), one(pwd, "ciamSettingValue")) == ("TRUE", None)
    assert "f: value withheld, needs a secret reference: pf.admin.pwd" in notices
    assert capture_rows(d)[0][4:6] == (2, 1)
    with pytest.raises(SystemExit, match="withheld; link it to a secret reference"):
        rebuilt(d)
    changes, _ = capture_changes(mini_estate.directory(), JAVA_PROPERTIES, text, "f", "repo/f", installed=(FAKE,))
    d2 = mini_estate.directory((*changes, *link("f", "pf.admin.pwd", "disk-encryption#ciamRefUri")))
    assert rebuilt(d2, spec=ALPHA) == "pf.admin.user=admin\npf.admin.pwd=${secret:fake://keys/alpha}\n"


def test_a_withheld_json_value_keeps_its_type():
    text = '{"client_secret": "s3cr3tS3cr3t"}'
    changes, _ = capture_changes(mini_estate.directory(), JSON, text, "f", "repo/f", installed=(FAKE,))
    d = mini_estate.directory((*changes, *link("f", "/client_secret", "disk-encryption#ciamRefUri")))
    assert rebuilt(d, spec=ALPHA) == '{"client_secret": "${secret:fake://keys/alpha}"}'


def test_a_setting_linked_to_a_binding_takes_each_environments_value():
    text = "[sso]\nhost = sso.example.test\n"
    changes, _ = capture_changes(mini_estate.directory(), INI, text, "f", "repo/f", installed=(FAKE,))
    d = mini_estate.directory((*changes, *link("f", "sso.host", "sso-service#ciamFqdn")))
    assert rebuilt(d, spec=ALPHA) == text
    assert rebuilt(d) == text                                         # without an environment: the captured literal
    with pytest.raises(SystemExit, match="binds no nothing"):
        rebuilt(mini_estate.directory((*changes, *link("f", "sso.host", "nothing#ciamFqdn"))), spec=ALPHA)


def test_a_file_that_cant_be_parsed_is_stored_whole_with_where_it_failed():
    text = "<config>\n  <a>1</a>\n  <b>2</c>\n</config>\n"
    d, notices = captured(text, XML)
    entry = get(d, file_dn("f"))
    assert one(entry, "ciamCaptureLevel") == "whole-file"
    assert one(entry, "ciamCaptureProblem") == "not parsed as xml: line 3, column 7: </c> doesn't close <b>"
    assert notices == ("f: stored whole (not setting by setting): not parsed as xml: line 3, column 7: </c> doesn't "
                       "close <b>",)
    assert rebuilt(d) == text and children(d, file_dn("f"), "ciamConfigSetting") == ()


@pytest.mark.parametrize("text, fmt, concern", [
    ("<config>\n  <admin password=\"x\"/>\n  <x>admin_password: Hunter2Hunter2\n</config>\n", XML,
     "its text may hold secret material: line 2: password is given a value; line 3: admin_password is given a "
     "value"),
    ("# old admin password: Hunter2Hunter2\npf.admin.user=admin\n", JAVA_PROPERTIES,
     "its layout may hold secret material: line 1: password is given a value"),
])
def test_a_text_that_may_hold_secrets_is_only_referenced(text, fmt, concern):
    d, notices = captured(text, fmt)
    entry = get(d, file_dn("f"))
    assert (one(entry, "ciamCaptureLevel"), one(entry, "ciamSkeleton")) == ("reference", None)
    assert one(entry, "ciamCaptureProblem") == concern and len(one(entry, "ciamSha256")) == 64
    with pytest.raises(SystemExit, match="held only as a reference: the file stays at repo/f"):
        rebuilt(d)


def test_a_reviewed_text_is_stored_when_the_operator_accepts_it():
    text = "# old admin password: Hunter2Hunter2\npf.admin.user=admin\n"
    d, _ = captured(text, JAVA_PROPERTIES, accept_concerns=True)
    assert one(get(d, file_dn("f")), "ciamCaptureLevel") == "settings" and rebuilt(d) == text


def test_recapture_changes_only_what_changed():
    d, _ = captured("a=1\nb=2\nc=3\n", JAVA_PROPERTIES)
    changes, _ = capture_changes(d, JAVA_PROPERTIES, "a=1\nb=20\nd=4\n", "f", "repo/f", installed=(FAKE,))
    kinds = sorted((r.changetype, r.dn) for r in changes)
    assert kinds == sorted([("modify", file_dn("f")), ("modify", setting_dn("f", "b")),
                            ("add", setting_dn("f", "d")), ("delete", setting_dn("f", "c"))])
    assert rebuilt(mini_estate.directory((*capture_changes(mini_estate.directory(), JAVA_PROPERTIES, "a=1\nb=2\nc=3\n",
                                                           "f", "repo/f", installed=(FAKE,))[0], *changes))) == \
        "a=1\nb=20\nd=4\n"
