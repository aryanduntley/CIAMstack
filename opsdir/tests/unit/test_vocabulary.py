"""Values of `vocab` attributes are defined by the installed domains and adapters, never by the core schema."""
from opsdir.connectors.registry import schema_fragments, vocabulary
from opsdir.core.standard import registry_ldif
from opsdir.store.migrations import misdeclared_vocabulary
from opsdir.store.postgres import schema_rows

VOCAB_ATTRIBUTES = {"ciamCloudProvider", "ciamCloudEnvironment", "ciamServerRole", "ciamTargetRole", "ciamFormat"}


def _attribute_rows():
    return schema_rows(registry_ldif(schema_fragments()))[0]


def test_the_core_schema_leaves_these_values_open():
    assert {a["name"] for a in _attribute_rows() if a["value_type"] == "vocab"} == VOCAB_ATTRIBUTES


def test_vocabulary_is_only_declared_for_vocab_attributes():
    assert misdeclared_vocabulary(vocabulary(), _attribute_rows()) == ()
    assert misdeclared_vocabulary((("ciamRegion", "x", "someone"),), _attribute_rows()) == (("ciamRegion", "someone"),)


def test_vocabulary_can_be_composed_from_any_parts():
    assert vocabulary(domains=(), adapters=(), formats=()) == ()


def test_the_registered_formats_are_the_values_of_ciam_format():
    formats = {v for attr, v, _ in vocabulary() if attr == "ciamFormat"}
    assert {"ldif", "json", "xml", "yaml", "shell", "c", "hcl", "dsconfig-batch"} <= formats
