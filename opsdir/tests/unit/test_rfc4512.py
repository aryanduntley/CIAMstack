import pytest

from opsdir.core.interchange.rfc4512 import (attribute_type, attribute_type_definition, name_list, object_class,
                                             object_class_definition, quote)
from opsdir.core.ldap_schema import standard_attribute, standard_class
from opsdir.core.paths import SCHEMA_FILE


def test_attribute_type_reads_standard_fields_and_x_extensions():
    a = attribute_type("( 1.2.3.1 NAME ( 'ciamPort' $ 'port' ) DESC 'It\\27s a port' EQUALITY integerMatch "
                       "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-PORTABILITY 'intent' "
                       "X-VALUE-TYPE 'port' X-ORIGIN 'opsdir' )")
    assert a == {"name": "ciamPort", "oid": "1.2.3.1", "syntax_oid": "1.3.6.1.4.1.1466.115.121.1.27",
                 "equality": "integerMatch", "value_type": "port", "portability": "intent", "single_value": True,
                 "description": "It's a port", "origin": "opsdir", "rules": {}}


def test_attribute_type_defaults():
    a = attribute_type("( 1.2.3.2 NAME 'plain' )")
    assert (a["value_type"], a["portability"], a["single_value"], a["equality"]) == ("string", "meta", False, None)


def test_object_class_reads_kind_superclass_and_attribute_lists():
    o = object_class("( 1.2.3.3 NAME 'ciamThing' DESC 'A thing' SUP ciamObject AUXILIARY "
                     "MUST cn MAY ( description $ ciamOwner ) )")
    assert o == {"name": "ciamThing", "oid": "1.2.3.3", "sup": "ciamObject", "kind": "AUXILIARY", "must": ["cn"],
                 "may": ["description", "ciamOwner"], "description": "A thing", "origin": None}


def test_object_class_defaults_to_structural_without_superclass():
    o = object_class("( 1.2.3.4 NAME 'root' )")
    assert (o["kind"], o["sup"], o["must"], o["may"]) == ("STRUCTURAL", None, [], [])


def test_malformed_definition_is_rejected():
    with pytest.raises(ValueError):
        attribute_type("1.2.3 NAME 'x'")


def test_quote_and_name_list():
    assert quote("a'b\\c") == "a\\27b\\5Cc"
    assert name_list(["cn"]) == "cn"
    assert name_list(["cn", "ou"]) == "( cn $ ou )"


def test_written_definitions_parse_back():
    at = attribute_type_definition("1.2.3.5", "ciamNote", "Owner's note", "caseIgnoreMatch", "1.3.6.1.4.1.1466.115.121.1.15",
                                   True, (("X-PORTABILITY", "meta"), ("X-VALUE-TYPE", "string")))
    assert attribute_type(at)["description"] == "Owner's note"
    assert attribute_type(at)["single_value"] is True
    oc = object_class_definition("1.2.3.6", "ciamNoted", "Has notes", "ciamObject", "AUXILIARY", ("cn",),
                                 ("ciamNote", "description"), ())
    assert object_class(oc)["may"] == ["ciamNote", "description"]
    assert object_class(oc)["sup"] == "ciamObject"


def test_description_and_matching_rules_are_optional():
    at = attribute_type_definition("1.2.3.7", "lastSeen", None, "generalizedTimeMatch", "1.3.6.1.4.1.1466.115.121.1.24",
                                   True, (), ordering="generalizedTimeOrderingMatch")
    assert at == ("( 1.2.3.7 NAME 'lastSeen' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch "
                  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )")
    bare = attribute_type_definition("1.2.3.8", "blob", None, None, "1.3.6.1.4.1.1466.115.121.1.40", False, ())
    assert bare == "( 1.2.3.8 NAME 'blob' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
    assert object_class_definition("1.2.3.9", "x", None, "top", "AUXILIARY", (), (), ()) == \
        "( 1.2.3.9 NAME 'x' SUP top AUXILIARY )"


def test_standard_definitions_in_the_published_schema_come_from_the_catalogue():
    text = SCHEMA_FILE.read_text().replace("\n ", "")
    assert f"( {standard_attribute('mail').oid} NAME 'mail'" in text and "X-ORIGIN 'RFC 4524'" in text
    assert f"( {standard_class('domain').oid} NAME 'domain'" in text


def test_value_rules_are_read_from_their_x_extensions():
    a = attribute_type("( 1.2.3.10 NAME 'xDays' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 X-VALUE-TYPE 'int' "
                       "X-MIN '7' X-MAX '90' X-PATTERN '^\\5Cd+$' X-ORIGIN 'custom' )")
    assert a["rules"] == {"X-MIN": "7", "X-MAX": "90", "X-PATTERN": "^\\d+$"}
