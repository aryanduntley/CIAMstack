"""Config files captured into settings and rebuilt byte for byte: each codec on a realistic product file, edits
written in the format's own syntax and read back as written, and files that can't be captured refused."""
from pathlib import Path

import pytest

from opsdir.core.capture import attempt_capture, capture, changed_settings, render_captured
from opsdir.core.formats import INI, JAVA_PROPERTIES, JSON, LDIF, SHELL, XML

SAMPLES = Path(__file__).resolve().parent.parent / "capture_samples"
FILES = (("run.properties", JAVA_PROPERTIES), ("tcp.xml", XML), ("sync.json", JSON), ("sssd.ini", INI),
         ("config.ldif", LDIF))
POLICY = "cn=Default Password Policy,cn=Password Policies,cn=config"


def sample(name):
    return (SAMPLES / name).read_text()


@pytest.mark.parametrize("name, fmt", FILES)
def test_an_unchanged_file_renders_back_identical(name, fmt):
    c = capture(fmt, sample(name))
    assert c.format == fmt.name and c.settings
    assert render_captured(fmt, c, dict(c.settings)) == sample(name)


@pytest.mark.parametrize("name, fmt", FILES)
def test_windows_line_ends_and_a_missing_final_newline_are_kept(name, fmt):
    text = sample(name).replace("\n", "\r\n").rstrip("\r\n")
    c = capture(fmt, text)
    assert render_captured(fmt, c, dict(c.settings)) == text


@pytest.mark.parametrize("name, fmt, locator, value", [
    ("run.properties", JAVA_PROPERTIES, "pf.admin.https.port", "9999"),
    ("run.properties", JAVA_PROPERTIES, "pf.cluster.tcp.discovery.initial.hosts", "10.0.1.10[7600],10.0.1.11[7600]"),
    ("run.properties", JAVA_PROPERTIES, "pf.provisioner.mode", "OFF"),
    ("run.properties", JAVA_PROPERTIES, "pf.console.title", "Customer SSO — prod"),
    ("tcp.xml", XML, "/config/TCP/@bind_addr", "${pf.cluster.bind.address}"),
    ("tcp.xml", XML, "/config/pbcast.NAKACK2/@use_mcast_xmit", "false"),
    ("sync.json", JSON, "/mappings/0/properties/1/target", "mail"),
    ("sync.json", JSON, "/mappings/0/enableSync", "true"),
    ("sync.json", JSON, "/mappings/0/taskThreads", "10"),
    ("sssd.ini", INI, "domain/example.test.ldap_uri", "ldaps://ldap.id.example-aero.test:1636"),
    ("sssd.ini", INI, "domain/example.test.ldap_tls_reqcert", "demand"),
    ("sssd.ini", INI, "domain/example.test.ldap_user_extra_attrs", "mail,\n    telephoneNumber"),
    ("config.ldif", LDIF, f"{POLICY}|ds-cfg-default-password-storage-scheme",
     "cn=PBKDF2-HMAC-SHA256,cn=Password Storage Schemes,cn=config"),
    ("config.ldif", LDIF, f"{POLICY}|objectClass#3", "ds-cfg-authentication-policy"),
    ("config.ldif", LDIF, "cn=LDAPS,cn=Connection Handlers,cn=config|description",
     "LDAPS for applications — clients and partners"),
])
def test_settings_are_located_and_decoded(name, fmt, locator, value):
    assert dict(capture(fmt, sample(name)).settings)[locator] == value


@pytest.mark.parametrize("name, fmt, locator, value", [
    ("run.properties", JAVA_PROPERTIES, "pf.admin.hostname", " pf admin\n\\ é = x"),
    ("tcp.xml", XML, "/config/TCP/@bind_port", "<7700 & \"x\" 'y'>"),
    ("sync.json", JSON, "/mappings/0/name", "say \"hi\" \\ é\n"),
    ("sync.json", JSON, "/mappings/0/taskThreads", "12"),
    ("sssd.ini", INI, "sssd.domains", "example.test, other.test"),
    ("config.ldif", LDIF, f"{POLICY}|ds-cfg-lockout-duration", " leading space needs base64"),
    ("config.ldif", LDIF, "cn=LDAPS,cn=Connection Handlers,cn=config|description", "plain"),
])
def test_an_edit_is_written_in_the_format_and_reads_back_as_written(name, fmt, locator, value):
    c = capture(fmt, sample(name))
    edited = render_captured(fmt, c, {**dict(c.settings), locator: value})
    again = capture(fmt, edited)
    assert dict(again.settings)[locator] == value
    assert changed_settings(c, dict(again.settings)) == ((locator, dict(c.settings)[locator], value),)


def test_a_json_setting_keeps_its_type():
    c = capture(JSON, sample("sync.json"))
    with pytest.raises(ValueError, match="not a JSON number, true, false or null"):
        render_captured(JSON, c, {**dict(c.settings), "/mappings/0/enableSync": "yes"})


def test_a_repeated_key_is_numbered_from_its_second_occurrence():
    c = capture(JAVA_PROPERTIES, "a=1\nb=2\na=3\na=4\n")
    assert c.settings == (("a", "1"), ("b", "2"), ("a#2", "3"), ("a#3", "4"))


def test_xml_positions_appear_only_among_same_named_siblings():
    c = capture(XML, "<c><s><n>a</n></s><s><n>b</n></s><t></t></c>")
    assert c.settings == (("/c/s[1]/n/text()", "a"), ("/c/s[2]/n/text()", "b"), ("/c/t/text()", ""))


def test_comments_in_json_are_layout():
    text = '{\n  // PingIDM style comment\n  "a": 1, /* inline */ "b": [2,],\n}\n'
    assert capture(JSON, text).settings == (("/a", "1"), ("/b/0", "2"))


def test_attempt_capture_returns_the_problem_instead_of_raising():
    assert attempt_capture(XML, "<a>") == (None, "end of file: <a> is never closed")
    assert attempt_capture(INI, "k = v\n")[1] is None


def test_every_setting_needs_a_value_to_render():
    c = capture(INI, "[s]\nk = v\n")
    with pytest.raises(ValueError, match="no value for setting s.k"):
        render_captured(INI, c, {})


@pytest.mark.parametrize("fmt, text, problem", [
    (SHELL, "echo hi\n", "registers no codec"),
    (JSON, '{"a": 1}\n  @ stray', "line 2, column 3: not JSON here"),
    (XML, "<a>1</a>\n<b", "line 2, column 1: not XML here"),
    (XML, "<a><b>1</a></b>", "line 1, column 8: </a> doesn't close <b>"),
    (XML, "<a><b>1</b>", "end of file: <a> is never closed"),
])
def test_files_that_cant_be_captured_are_refused(fmt, text, problem):
    with pytest.raises(ValueError, match=problem):
        capture(fmt, text)
