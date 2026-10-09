"""The opsdir standard as data, and the generators that publish it and the synthetic estate."""
import pytest

from opsdir.connectors.registry import core_fragments, schema_fragments
from opsdir.core.interchange.ldif import parse
from opsdir.core.ldap_schema import standard_attribute, standard_class
from opsdir.core.standard import (ARC, CORE, STANDARD_ATTRIBUTES, STANDARD_CLASSES, AttributeDef, ClassDef,
                                  check_fragments, equality, fragment, fragment_counts, registry_ldif, schema_ldif,
                                  syntax)
from opsdir.store.postgres import schema_rows
from support import SCHEMA

A = AttributeDef(900, "ciamTestAttr", "port", "intent", True, "test attribute")
C = ClassDef(900, "ciamTestClass", "ciamObject", "AUXILIARY", ("ciamTestAttr",), ("cn",), "test class")


def test_value_types_map_to_ldap_syntax_and_matching():
    assert syntax("port") == "1.3.6.1.4.1.1466.115.121.1.27"
    assert syntax("enum:a|b") == syntax("string")
    assert (equality("dn"), equality("int"), equality("fqdn")) == ("distinguishedNameMatch", "integerMatch",
                                                                   "caseIgnoreMatch")


def test_the_registered_fragments_compose_cleanly():
    assert check_fragments(schema_fragments()) == ()


@pytest.mark.parametrize("extra, problem", [
    (fragment((A, A._replace(name="ciamOther")), ()), f"OID reused: {ARC}.1.900"),
    (fragment((A, A._replace(number=901)), ()), "attribute name reused: ciamTestAttr"),
    (fragment((A,), (C, C._replace(name="ciamOther"))), f"OID reused: {ARC}.2.900"),
    (fragment((A,), (C._replace(may=("ciamNobody",)),)), "class ciamTestClass uses undefined attribute ciamNobody"),
    (fragment((A,), (C._replace(sup="ciamNoSuchClass"),)),
     "class ciamTestClass has undefined superclass ciamNoSuchClass"),
])
def test_fragment_problems_are_reported(extra, problem):
    assert problem in check_fragments((CORE, extra))


def test_a_package_numbers_its_definitions_under_its_own_arc():
    own = fragment((A,), (C,), "1.3.6.1.4.1.32473.3.7", "some-package")
    ats, ocs = schema_rows(registry_ldif((CORE, own)))
    at = next(a for a in ats if a["name"] == "ciamTestAttr")
    assert (at["oid"], at["origin"]) == ("1.3.6.1.4.1.32473.3.7.1.900", "some-package")
    assert next(o for o in ocs if o["name"] == "ciamTestClass")["oid"] == "1.3.6.1.4.1.32473.3.7.2.900"


def test_the_same_number_in_different_arcs_is_no_conflict_but_the_same_oid_is():
    assert check_fragments((CORE, fragment((A,), (), "1.3.6.1.4.1.32473.3.7"),
                            fragment((A._replace(name="ciamOther"),), (), "1.3.6.1.4.1.32473.3.8"))) == ()
    clash = fragment((A._replace(number=4, name="ciamOther"),), ())        # ARC.1.4 is the core's ciamOwner
    assert f"OID reused: {ARC}.1.4" in check_fragments((CORE, clash))


def test_unpublishable_fragments_stop_schema_generation():
    with pytest.raises(SystemExit):
        schema_ldif((CORE, fragment((A, A), ())))


def test_new_fragment_publishes_with_pinned_oids_that_parse_back():
    ats, ocs = schema_rows(registry_ldif((CORE, fragment((A,), (C,)))))
    at = next(a for a in ats if a["name"] == "ciamTestAttr")
    oc = next(o for o in ocs if o["name"] == "ciamTestClass")
    assert ((at["oid"], at["value_type"], at["portability"], at["single_value"])
            == (f"{ARC}.1.900", "port", "intent", True))
    assert ((oc["oid"], oc["sup"], oc["kind"], oc["must"])
            == (f"{ARC}.2.900", "ciamObject", "AUXILIARY", ["ciamTestAttr"]))


def test_published_schema_is_exactly_what_the_core_fragments_generate():
    assert schema_ldif(core_fragments()) == SCHEMA.read_text()


def test_published_schema_counts_match_the_fragments():
    (rec,) = parse(SCHEMA.read_text())
    n_attrs, n_classes = fragment_counts(core_fragments())
    assert len(rec.attrs["attributeTypes"]) == n_attrs
    assert len(rec.attrs["objectClasses"]) == n_classes


def test_the_published_schema_never_redefines_a_standard_definition():
    ats, ocs = schema_rows(registry_ldif(core_fragments()))
    (rec,) = parse(SCHEMA.read_text())
    published = " ".join(rec.attrs["attributeTypes"] + rec.attrs["objectClasses"])
    standard_oids = [standard_attribute(n).oid for n, *_ in STANDARD_ATTRIBUTES] + [
        standard_class(n).oid for n, _ in STANDARD_CLASSES]
    assert not [oid for oid in standard_oids if f"( {oid} " in published]
    assert all(a["oid"].startswith("1.3.6.1.4.1.32473.") for a in schema_rows(registry_ldif(core_fragments()))[0]
               if f"( {a['oid']} " in published)


def test_the_registry_takes_standard_definitions_as_the_standards_define_them():
    ats, ocs = schema_rows(registry_ldif(core_fragments()))
    by_name = {a["name"]: a for a in ats}
    assert (by_name["objectClass"]["syntax_oid"], by_name["objectClass"]["equality"]) == (
        "1.3.6.1.4.1.1466.115.121.1.38", "objectIdentifierMatch")
    assert (by_name["mail"]["syntax_oid"], by_name["mail"]["equality"]) == (
        "1.3.6.1.4.1.1466.115.121.1.26", "caseIgnoreIA5Match")
    assert (by_name["dc"]["single_value"], by_name["cn"]["equality"]) == (True, "caseIgnoreMatch")
    assert (by_name["cn"]["value_type"], by_name["cn"]["portability"]) == ("string", "meta")
    assert {o["name"] for o in ocs} >= {n for n, _ in STANDARD_CLASSES}
