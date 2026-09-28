"""The opsdir standard as data, and the generators that publish it and the synthetic estate."""
import pytest

from opsdir.connectors.registry import core_fragments, schema_fragments
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import (ARC, CORE, AttributeDef, ClassDef, check_fragments, equality, fragment,
                                  fragment_counts, schema_ldif, syntax)
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
    (fragment((A,), (C._replace(sup="ciamNoSuchClass"),)), "class ciamTestClass has undefined superclass ciamNoSuchClass"),
])
def test_fragment_problems_are_reported(extra, problem):
    assert problem in check_fragments((CORE, extra))


def test_a_package_numbers_its_definitions_under_its_own_arc():
    own = fragment((A,), (C,), "1.3.6.1.4.1.32473.3.7", "some-package")
    ats, ocs = schema_rows(schema_ldif((CORE, own)))
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
    ats, ocs = schema_rows(schema_ldif((CORE, fragment((A,), (C,)))))
    at = next(a for a in ats if a["name"] == "ciamTestAttr")
    oc = next(o for o in ocs if o["name"] == "ciamTestClass")
    assert (at["oid"], at["value_type"], at["portability"], at["single_value"]) == (f"{ARC}.1.900", "port", "intent", True)
    assert (oc["oid"], oc["sup"], oc["kind"], oc["must"]) == (f"{ARC}.2.900", "ciamObject", "AUXILIARY", ["ciamTestAttr"])


def test_published_schema_is_exactly_what_the_core_fragments_generate():
    assert schema_ldif(core_fragments()) == SCHEMA.read_text()


def test_published_schema_counts_match_the_fragments():
    (rec,) = parse(SCHEMA.read_text())
    n_attrs, n_classes = fragment_counts(core_fragments())
    assert len(rec.attrs["attributeTypes"]) == n_attrs + 6      # + standard LDAP attributes
    assert len(rec.attrs["objectClasses"]) == n_classes + 3
