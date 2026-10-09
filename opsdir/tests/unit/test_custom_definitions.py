"""Custom fields and record types, defined as entries, composed into the schema (pure)."""
import pytest

from opsdir.connectors.registry import core_fragments
from opsdir.core.directory import make_directory, make_entry
from opsdir.core.standard import CUSTOM_ARC, registry_ldif
from opsdir.domains.custom.definitions import compose, custom_fragment, problems
from opsdir.domains.custom.domain import custom_rows
from opsdir.domains.custom.naming import CUSTOM_SCHEMA
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.store.postgres import schema_phases, schema_rows


def field(name, number, vt="int", **attrs):
    return make_entry(f"cn={name},{CUSTOM_SCHEMA}", ("top", "ciamFieldDefinition"),
                      {"cn": [name], "ciamDefinitionNumber": [str(number)], "ciamValueType": [vt],
                       "ciamPortability": ["intent"],
                       **{k: v if isinstance(v, list) else [v] for k, v in attrs.items()}})


def record_type(name, number, **attrs):
    return make_entry(f"cn={name},{CUSTOM_SCHEMA}", ("top", "ciamRecordTypeDefinition"),
                      {"cn": [name], "ciamDefinitionNumber": [str(number)],
                       **{k: v if isinstance(v, list) else [v] for k, v in attrs.items()}})


RETENTION = field("xRetentionDays", 1, ciamMinValue="7", ciamMaxValue="90", ciamCarriedBy="ciamServer",
                  ciamPurpose="Soft-delete retention of the secret store", ciamUnit="days")
QUEUE = record_type("xMessageQueue", 1, ciamRequiredField="xBroker", ciamOptionalField="description")
BROKER = field("xBroker", 2, "fqdn", ciamCarriedBy="xMessageQueue")
TAGGED = record_type("xTagged", 2, ciamRecordKind="auxiliary", ciamOptionalField="xTag")
TAG = field("xTag", 3, "string", ciamMultiValued="TRUE", ciamPattern="^[a-z-]+$", ciamMaxLength="40")
ALL = (RETENTION, QUEUE, BROKER, TAGGED, TAG)


def _rows(entries):
    return schema_rows(registry_ldif(compose(core_fragments(), entries)))


def test_fields_become_attribute_types_under_the_custom_arc_with_their_rules():
    ats, _ = _rows(ALL)
    at = next(a for a in ats if a["name"] == "xRetentionDays")
    assert ((at["oid"], at["value_type"], at["single_value"], at["origin"])
            == (f"{CUSTOM_ARC}.1.1", "int", True, "custom"))
    assert (at["rules"] == {"X-MIN": "7", "X-MAX": "90"}
            and at["description"] == "Soft-delete retention of the secret store")
    tag = next(a for a in ats if a["name"] == "xTag")
    assert tag["single_value"] is False and tag["rules"] == {"X-PATTERN": "^[a-z-]+$", "X-MAX-LENGTH": "40"}


def test_a_field_joins_the_record_types_it_applies_to():
    _, ocs = _rows(ALL)
    assert "xRetentionDays" in next(o for o in ocs if o["name"] == "ciamServer")["may"]
    assert "xRetentionDays" not in next(o for o in ocs if o["name"] == "ciamBackend")["may"]


def test_record_types_become_classes():
    frag = custom_fragment(ALL)
    queue, tagged = frag.classes
    assert (queue.name, queue.sup, queue.kind, queue.must, queue.may) == (
        "xMessageQueue", "ciamObject", "STRUCTURAL", ("cn", "xBroker"), ("description",))
    assert (tagged.sup, tagged.kind, tagged.must, tagged.may) == ("top", "AUXILIARY", (), ("xTag",))


def test_valid_definitions_compose_cleanly():
    assert problems(core_fragments(), ALL) == ()
    assert compose(core_fragments(), ()) == core_fragments()


@pytest.mark.parametrize("entries, problem", [
    ((field("retention", 9),), "retention: custom names start with 'x'"),
    ((field("xBad", 9, "number"),), "field xBad: value type 'number' is not one of"),
    ((field("xBad", 9, "vocab"),), "field xBad: value type 'vocab' is not one of"),
    ((field("xBad", 9, "string", ciamMinValue="1"),), "field xBad: min/max apply to int and port fields, not string"),
    ((field("xBad", 9, ciamMinValue="9", ciamMaxValue="1"),), "field xBad: min 9 is above max 1"),
    ((field("xBad", 9, "string", ciamPattern="(unclosed"),),
     "field xBad: pattern '(unclosed' is not a regular expression"),
    ((field("xBad", 9, "bool", ciamMaxLength="3"),), "field xBad: pattern and max length don't apply to bool fields"),
    ((field("xBad", 9, ciamCarriedBy="ciamNothing"),), "field xBad applies to unknown record type ciamNothing"),
    ((field("xBad", 9, ciamCarriedBy="organizationalUnit"),),
     "field xBad can't apply to the standard class organizationalUnit"),
    ((field("xOne", 9), field("xTwo", 9)), f"OID reused: {CUSTOM_ARC}.1.9"),
    ((record_type("xThing", 9, ciamRequiredField="xNobody"),), "class xThing uses undefined attribute xNobody"),
    ((record_type("xThing", 9, ciamParentType="xNoParent"),), "class xThing has undefined superclass xNoParent"),
])
def test_definitions_that_cant_be_built_are_refused(entries, problem):
    assert any(p.startswith(problem) for p in problems(core_fragments(), entries)), problems(core_fragments(), entries)


def rec(dn, op="add"):
    return LdifRecord(dn, op, {}, ())


def test_a_change_to_definitions_runs_in_phases():
    records = (rec("cn=a,ou=x,dc=ciam-ops"), rec(f"cn=xOld,{CUSTOM_SCHEMA}", "delete"), rec("dc=ciam-ops"),
               rec(f"cn=xNew,{CUSTOM_SCHEMA}"), rec(CUSTOM_SCHEMA), rec("cn=b,ou=x,dc=ciam-ops", "modify"))
    first, rest, last = schema_phases(records, CUSTOM_SCHEMA)
    assert [r.dn for r in first] == ["dc=ciam-ops", f"cn=xNew,{CUSTOM_SCHEMA}", CUSTOM_SCHEMA]
    assert [r.dn for r in rest] == ["cn=a,ou=x,dc=ciam-ops", "cn=b,ou=x,dc=ciam-ops"]
    assert [r.dn for r in last] == [f"cn=xOld,{CUSTOM_SCHEMA}"]


def test_the_custom_report_says_where_each_definition_is_used():
    queue_entry = make_entry("cn=orders,ou=queues,dc=ciam-ops", ("top", "xMessageQueue"),
                             {"cn": ["orders"], "xBroker": ["mq.example.test"]})
    d = make_directory((), {}, [(e.dn, e.classes, dict(e.attrs)) for e in (*ALL, queue_entry)])
    assert custom_rows(d) == [
        ("field", "xBroker", "fqdn", "xMessageQueue", "-", "active", "**NO OWNER**", "1"),
        ("field", "xRetentionDays", "int", "ciamServer", "-", "active", "**NO OWNER**", "0"),
        ("field", "xTag", "string", "xTagged", "-", "active", "**NO OWNER**", "0"),
        ("record type", "xMessageQueue", "structural", "-", "-", "active", "**NO OWNER**", "1"),
        ("record type", "xTagged", "auxiliary", "-", "-", "active", "**NO OWNER**", "0")]


def test_the_custom_report_says_where_a_fields_value_lives():
    setting = "cn=1a2b,cn=run.properties,ou=config-files,dc=ciam-ops"
    config = (make_entry("cn=run.properties,ou=config-files,dc=ciam-ops", ("top", "ciamConfigFile"),
                         {"cn": ["run.properties"]}),
              make_entry(setting, ("top", "ciamConfigSetting"), {"cn": ["1a2b"], "ciamLocator": ["pf.session.ttl"]}))
    linked = tuple(e._replace(attrs={**e.attrs, "ciamSettingRef": (setting,),
                                     "ciamValueSource": ("console: session settings",)})
                   if e.dn.startswith("cn=xRetentionDays,") else e for e in ALL)
    d = make_directory((), {}, [(e.dn, e.classes, dict(e.attrs)) for e in (*linked, *config)])
    row = next(r for r in custom_rows(d) if r[1] == "xRetentionDays")
    assert row[4] == "run.properties:pf.session.ttl; console: session settings"
