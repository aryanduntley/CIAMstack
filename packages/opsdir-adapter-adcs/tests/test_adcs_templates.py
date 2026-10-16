"""The AD CS template collector and what the template reader takes from each template beyond its validity: the
signed name, enrollment and RA-signature attributes, the usages it issues (application policies from schema version 2
on), and who its nTSecurityDescriptor lets enroll (allowed and denied ACEs in their order, object ACEs scoped to
Enroll or unscoped, AutoEnroll alone not counted, inherit-only skipped, broad groups, a NULL DACL, ACEs it can't
judge, no descriptor); and the collector's one search (the SD flags control, the templates container of the source's
forest, the password on standard input)."""
import base64
from uuid import UUID

from opsdir.core.directory import get
from opsdir.domains.pki.naming import template_dn
from opsdir_adapter_adcs.adapter import ADAPTER
from opsdir_adapter_adcs.collect import problems, templates_steps
from opsdir_adapter_adcs.inventory import read_inventory
from opsdir_adapter_adcs.security import (BROAD, RESTRICTED, UNKNOWN, enrollees, is_broad, principal_label,
                                          sid_text)
from opsdir_adapter_adcs.templates import flag_value, read_templates
import mini_estate
from network_fixtures import ALPHA, entry, model
from support import after_import

ENROLL, AUTO_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55", "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
DOMAIN = "S-1-5-21-1111-2222-3333"
CLIENT, SERVER = "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"


def _sid(text):
    parts = text.split("-")
    return (bytes((int(parts[1]), len(parts) - 3)) + int(parts[2]).to_bytes(6, "big")
            + b"".join(int(x).to_bytes(4, "little") for x in parts[3:]))


def _ace(kind, mask, sid, object_type=None, flags=0):
    body = mask.to_bytes(4, "little")
    if kind in (5, 6):
        body += (1 if object_type else 0).to_bytes(4, "little") + (UUID(object_type).bytes_le if object_type else b"")
    body += _sid(sid)
    return bytes((kind, flags)) + (4 + len(body)).to_bytes(2, "little") + body


def _sd(*aces, dacl=True):
    """A self-relative security descriptor holding only a DACL of these ACEs (no DACL at all when dacl is False)."""
    body = b"".join(aces)
    acl = bytes((4, 0)) + (8 + len(body)).to_bytes(2, "little") + len(aces).to_bytes(2, "little") + b"\0\0" + body
    control = 0x8004 if dacl else 0x8000
    return bytes((1, 0)) + control.to_bytes(2, "little") + bytes(12) + (20 if dacl else 0).to_bytes(4, "little") + \
        (acl if dacl else b"")


def _template(cn, sd=None, version=2, name_flag=1, enrollment=0, signatures=0, usages=(SERVER,), policies=()):
    return "\n".join((f"dn: CN={cn},CN=Certificate Templates,CN=Public Key Services,CN=Services,"
                      "CN=Configuration,DC=corp,DC=example,DC=test", "objectClass: top",
                      "objectClass: pKICertificateTemplate", f"cn: {cn}", f"msPKI-Template-Schema-Version: {version}",
                      f"msPKI-Certificate-Name-Flag: {name_flag}", f"msPKI-Enrollment-Flag: {enrollment}",
                      f"msPKI-RA-Signature: {signatures}", *(f"pKIExtendedKeyUsage: {u}" for u in usages),
                      *(f"msPKI-Certificate-Application-Policy: {p}" for p in policies),
                      *((f"nTSecurityDescriptor:: {base64.b64encode(sd).decode()}",) if sd else ()), ""))


def test_sids_and_breadth():
    assert sid_text(_sid("S-1-5-11")) == "S-1-5-11" and sid_text(b"\x01\x05" + bytes(6)) is None
    assert principal_label(f"{DOMAIN}-513") == f"{DOMAIN}-513 (Domain Users)"
    assert principal_label(f"{DOMAIN}-1105") == f"{DOMAIN}-1105"
    assert all(map(is_broad, ("S-1-1-0", "S-1-5-11", "S-1-5-7", "S-1-5-32-545", f"{DOMAIN}-513", f"{DOMAIN}-515")))
    assert not any(map(is_broad, (f"{DOMAIN}-512", "S-1-5-18", "S-1-5-21-1-2-513", f"{DOMAIN}-1513")))


def test_who_may_enroll():
    admins, users = f"{DOMAIN}-512", f"{DOMAIN}-513"
    assert enrollees(_sd(_ace(5, 0x100, users, ENROLL), _ace(0, 0xF01FF, admins))) == (
        (f"{users} (Domain Users)", f"{admins} (Domain Admins)"), BROAD, None)
    # a deny met first stops the grant; AutoEnroll alone and read rights aren't Enroll; inherit-only doesn't apply
    assert enrollees(_sd(_ace(6, 0x100, users, ENROLL), _ace(5, 0x100, users, ENROLL),
                         _ace(5, 0x100, "S-1-5-11", AUTO_ENROLL), _ace(0, 0x20094, "S-1-5-11"),
                         _ace(0, 0x10000000, "S-1-1-0", flags=0x08))) == ((), RESTRICTED, None)
    assert enrollees(_sd(_ace(5, 0x100, f"{DOMAIN}-1105"), _ace(0, 0x10000000, "S-1-5-11", flags=0x02))) == (
        (f"{DOMAIN}-1105", "S-1-5-11 (Authenticated Users)"), BROAD, None)
    assert enrollees(_sd(dacl=False)) == (("S-1-1-0 (Everyone)",), BROAD, None)
    assert enrollees(_sd(_ace(9, 0x100, users)))[1:] == (
        UNKNOWN, "its DACL holds an ACE of type 0x09 (a callback or conditional ACE) this reader doesn't judge")
    assert enrollees(None) == ((), UNKNOWN, None) and enrollees(b"\x01")[1] == UNKNOWN


def test_flags_usages_and_rights_read_from_ldif():
    assert flag_value("-2113929216") == (0x82000000, None) and flag_value(None) == (None, None)
    assert flag_value("x")[0] is None and flag_value(str(2 ** 32))[0] is None
    sd = _sd(_ace(5, 0x100, f"{DOMAIN}-513", ENROLL))
    text = "\n".join((_template("Web", sd, usages=(SERVER,), policies=(SERVER, CLIENT)),
                      _template("Legacy", version=1, name_flag=-2113929216, enrollment=2, signatures=1,
                                usages=(CLIENT,), policies=(SERVER,))))
    templates, notices = read_templates(text)
    assert templates["Web"]["usages"] == (SERVER, CLIENT) and templates["Legacy"]["usages"] == (CLIENT,)
    assert templates["Web"]["rights"] == {
        "ciamSubjectFromRequest": True, "ciamApprovalRequired": False, "ciamRequiredSignatures": 0,
        "ciamTemplateVersion": 2, "ciamEnrollee": (f"{DOMAIN}-513 (Domain Users)",), "ciamEnrollmentScope": BROAD}
    legacy = templates["Legacy"]["rights"]
    assert (legacy["ciamSubjectFromRequest"], legacy["ciamApprovalRequired"], legacy["ciamEnrollmentScope"]) == (
        False, True, UNKNOWN)
    assert notices == (
        "template Web: its application policies (1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2) differ from its "
        "pKIExtendedKeyUsage (1.3.6.1.5.5.7.3.1): the application policies are recorded as what it issues",
        "templates: 1 template(s) (Legacy): access rights (nTSecurityDescriptor) not in the export: who may enroll "
        "is unknown")


def test_imported_into_the_record():
    text = _template("Web", _sd(_ace(5, 0x100, "S-1-5-11", ENROLL)), usages=(CLIENT,))
    d = after_import(mini_estate.directory(), read_inventory({"templates.ldif": text}, mini_estate.directory(), ()))
    t = get(d, template_dn("Web")).attrs
    assert t["ciamSubjectFromRequest"] == ("TRUE",) and t["ciamApprovalRequired"] == ("FALSE",)
    assert t["ciamEnrollee"] == ("S-1-5-11 (Authenticated Users)",) and t["ciamEnrollmentScope"] == ("broad",)
    assert t["ciamExtendedKeyUsage"] == (CLIENT,) and t["ciamTemplateVersion"] == ("2",)


SOURCE = dict(ciamBindingRole="collect-templates", ciamImporter="adcs/inventory",
              ciamSourceRef="ldaps://dc1.corp.example.test/DC=corp,DC=example,DC=test",
              ciamLoginName="svc-templates@corp.example.test", ciamCredentialRole="template-reader")


def _alpha(**over):
    _, alpha, _ = model(alpha=(entry(ALPHA, "templates", "ciamCollectionSource", **{**SOURCE, **over}),
                               entry(ALPHA, "template-reader", "ciamSecretRef", ciamBindingRole="template-reader",
                                     ciamRefUri="fake://kv/template-reader")))
    return alpha


def test_the_collector_searches_the_forests_templates():
    assert [c.importer for c in ADAPTER.collectors] == ["inventory"]
    m = _alpha()
    ((path, call),) = templates_steps(m.d, m, {}, {"ldap_ca": "/secure/ca.pem"})
    assert path == "templates.ldif"
    assert call.argv[:10] == ("ldapsearch", "-H", "ldaps://dc1.corp.example.test:636", "-x", "-D",
                              "svc-templates@corp.example.test", "-y", "/dev/stdin", "-b",
                              "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,"
                              "DC=corp,DC=example,DC=test")
    assert call.argv[10:17] == ("-s", "one", "-o", "ldif-wrap=no", "-E", "!1.2.840.113556.1.4.801=::MAMCAQc=",
                                "(objectClass=pKICertificateTemplate)")
    assert "nTSecurityDescriptor" in call.argv and "msPKI-Certificate-Application-Policy" in call.argv
    assert call.secrets == ("fake://kv/template-reader",) and call.env == (("LDAPTLS_CACERT", "/secure/ca.pem"),)
    assert call.stdin({"fake://kv/template-reader": "pw"}) == "pw" and "pw" not in call.argv
    assert problems(m.d, m, {}) == ()


def test_a_source_without_a_forest_says_so():
    m = _alpha(ciamSourceRef="ldaps://dc1.corp.example.test")
    assert templates_steps(m.d, m, {}, {}) == ()
    assert problems(m.d, m, {}) == (
        "collection source `templates`: ciamSourceRef must be ldaps://<host>:<port>/<base DN>",)
