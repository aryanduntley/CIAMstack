"""The opsdir standard as data, and the generators that publish it and the synthetic estate."""
import pytest

from fixtures.example_estate.build import build
from opsdir.connectors.registry import schema_fragments
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import (ARC, CORE, AttributeDef, ClassDef, SchemaFragment, check_fragments, equality,
                                  fragment_counts, schema_ldif, syntax)
from opsdir.store.postgres import schema_rows
from support import DATA, SCHEMA

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
    (SchemaFragment((A, A._replace(name="ciamOther")), ()), "attribute number reused: 900"),
    (SchemaFragment((A, A._replace(number=901)), ()), "attribute name reused: ciamTestAttr"),
    (SchemaFragment((A,), (C, C._replace(name="ciamOther"))), "class number reused: 900"),
    (SchemaFragment((A,), (C._replace(may=("ciamNobody",)),)), "class ciamTestClass uses undefined attribute ciamNobody"),
    (SchemaFragment((A,), (C._replace(sup="ciamNoSuchClass"),)), "class ciamTestClass has undefined superclass ciamNoSuchClass"),
])
def test_fragment_problems_are_reported(extra, problem):
    assert problem in check_fragments((CORE, extra))


def test_unpublishable_fragments_stop_schema_generation():
    with pytest.raises(SystemExit):
        schema_ldif((CORE, SchemaFragment((A, A), ())))


def test_new_fragment_publishes_with_pinned_oids_that_parse_back():
    ats, ocs = schema_rows(schema_ldif((CORE, SchemaFragment((A,), (C,)))))
    at = next(a for a in ats if a["name"] == "ciamTestAttr")
    oc = next(o for o in ocs if o["name"] == "ciamTestClass")
    assert (at["oid"], at["value_type"], at["portability"], at["single_value"]) == (f"{ARC}.1.900", "port", "intent", True)
    assert (oc["oid"], oc["sup"], oc["kind"], oc["must"]) == (f"{ARC}.2.900", "ciamObject", "AUXILIARY", ["ciamTestAttr"])


def test_published_schema_is_exactly_what_the_fragments_generate():
    assert schema_ldif(schema_fragments()) == SCHEMA.read_text()


def test_published_schema_counts_match_the_fragments():
    (rec,) = parse(SCHEMA.read_text())
    n_attrs, n_classes = fragment_counts(schema_fragments())
    assert len(rec.attrs["attributeTypes"]) == n_attrs + 6      # + standard LDAP attributes
    assert len(rec.attrs["objectClasses"]) == n_classes + 3


def test_synthetic_estate_is_exactly_what_the_fixture_builds():
    n, files = build()
    on_disk = {p.name: p.read_text() for p in DATA.iterdir() if p.suffix in (".ldif", ".json")}
    assert files == on_disk
    assert n == sum(1 for f in on_disk.values() for line in f.splitlines() if line.startswith("dn: "))
