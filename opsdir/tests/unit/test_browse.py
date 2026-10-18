"""Browsing the record by its schema (area -> kind -> entries -> fields) and editing one entry's fields: the views come
from the registry, so whatever the installed parts define shows; an edit is one modify record the store then checks."""
import pytest

from opsdir.cli import browse_text
from opsdir.connectors.browse import (area_named, area_rows, edit_record, entry_rows, field_rows, kind_rows,
                                      parsed_edits, registry_from_rows)
from opsdir.connectors.registry import DOMAINS
from opsdir.connectors.schema_docs import documented_parts
from opsdir.core.standard import CORE, attribute_oid, class_oid
from opsdir.operations import Rows
from mini_estate import directory

SSO = "cn=sso,ou=identity-services,dc=ciam-ops"
FRAGMENTS = (CORE, *(d.schema for d in DOMAINS))
STANDARD = (("cn", "string", "meta", "Common name / RDN"), ("description", "string", "meta", "Free text"),
            ("ou", "string", "meta", "Organizational unit name"), ("objectClass", "string", "meta", "LDAP classes"))


def _registry():
    attrs = (*((a.name, attribute_oid(f, a), a.value_type, a.portability, a.single_value, a.description, {}, f.origin)
               for f in FRAGMENTS for a in f.attributes),
             *((n, f"2.5.4.{i}", vt, p, False, d, {}, "RFC 4519") for i, (n, vt, p, d) in enumerate(STANDARD)))
    classes = (*((c.name, class_oid(f, c), c.sup, c.kind, c.must, c.may, c.description, f.origin)
                 for f in FRAGMENTS for c in f.classes),
               ("top", "2.5.6.0", None, "ABSTRACT", ("objectClass",), (), "Top", "RFC 4512"),
               ("organizationalUnit", "2.5.6.5", "top", "STRUCTURAL", ("ou",), ("description",), "OU", "RFC 4519"))
    return registry_from_rows(attrs, classes)


PARTS = documented_parts(DOMAINS, ())


def test_areas_kinds_and_entries_come_from_the_registry():
    d, registry = directory(), _registry()
    areas = {slug: (kind, kinds, entries) for slug, kind, kinds, entries in area_rows(d, PARTS, registry)}
    assert areas["federation"][0] == "domain" and areas["federation"][2] >= 1
    assert "standard" in areas and areas["core"][0] == "core"
    slug, _, _, classes = area_named(PARTS, registry, "Federation")
    kinds = {k: (kind, n) for k, kind, n, _ in kind_rows(d, registry, classes)}
    assert slug == "federation" and kinds["ciamIdentityService"] == ("structural", 1)
    assert entry_rows(d, "ciamidentityservice") == [(SSO,)]
    assert area_named(PARTS, registry, "nowhere") is None


def test_an_entrys_fields_say_what_each_holds_and_which_optional_ones_are_empty():
    rows, empty = field_rows(_registry(), directory().entries[SSO.lower()])
    by_field = {r[0]: r for r in rows}
    assert by_field["objectClass"][1] == "top | ciamIdentityService"
    assert by_field["ciamBaseUrl"][1:5] == ("https://sso.example.test", "url", "contract", "yes")
    assert by_field["cn"][4] == "yes"
    assert "ciamSigningAlg" in empty and "ciamBaseUrl" not in empty


def test_an_edit_is_one_modify_record_and_says_when_it_changes_nothing():
    d, registry = directory(), _registry()
    record = edit_record(d, registry, SSO, sets=(("ciambaseurl", "https://id.example.test"),),
                         adds=(("ciamScope", "openid"), ("ciamScope", "profile")), removes=(("ciamTargetRole", None),))
    assert (record.dn, record.changetype, record.mods) == (SSO, "modify", (
        ("replace", "ciamBaseUrl", ("https://id.example.test",)), ("replace", "ciamScope", ("openid", "profile")),
        ("delete", "ciamTargetRole", ())))
    kept = edit_record(d, registry, SSO, sets=(("ciamTargetRole", "api"),),
                       adds=(("ciamTargetRole", "web"), ("ciamScope", "z"), ("ciamScope", "z")))
    assert kept.mods == (("replace", "ciamTargetRole", ("api", "web")), ("replace", "ciamScope", ("z",)))
    with pytest.raises(ValueError, match="ciamScope: set and removed in one edit"):
        edit_record(d, registry, SSO, sets=(("ciamScope", "a"),), removes=(("ciamScope", None),))
    with pytest.raises(ValueError, match="changes nothing"):
        edit_record(d, registry, SSO, sets=(("ciamBaseUrl", "https://sso.example.test"),),
                    removes=(("ciamScope", None),))
    with pytest.raises(ValueError, match="object classes change by `opsdir modify`"):
        edit_record(d, registry, SSO, sets=(("objectClass", "top"),))
    with pytest.raises(ValueError, match="no attribute ciamNothing"):
        edit_record(d, registry, SSO, adds=(("ciamNothing", "x"),))
    with pytest.raises(ValueError, match="no entry"):
        edit_record(d, registry, "cn=gone,dc=ciam-ops", adds=(("cn", "x"),))


def test_edit_arguments_read_as_attribute_and_value():
    assert parsed_edits(["ciamScope=openid", "description=a=b"], "add") == (("ciamScope", "openid"),
                                                                            ("description", "a=b"))
    assert parsed_edits(["ciamScope"], "remove") == (("ciamScope", None),)
    with pytest.raises(ValueError, match="--set ciamScope: give ATTRIBUTE=VALUE"):
        parsed_edits(["ciamScope"], "set")
    with pytest.raises(ValueError, match="to clear a field: --remove ATTRIBUTE"):
        parsed_edits(["ciamScope= "], "set")
    assert parsed_edits(["ciamBaseUrl = https://x "], "set") == (("ciamBaseUrl", "https://x"),)


def test_the_table_keeps_each_cell_on_one_line():
    text = browse_text(Rows(("field", "value", "type"), (("pem", "-----BEGIN-----\nAAAA\n-----END-----", "enum:a|b"),)),
                       ("description",))
    assert "-----BEGIN----- ⏎ AAAA ⏎ -----END-----" in text and "  enum" in text
    assert text.endswith("empty, optional: description")
