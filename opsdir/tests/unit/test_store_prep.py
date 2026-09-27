"""The store's pure preparation: schema registry rows, entry rows and LDAP modify semantics (no connection)."""
import pytest

from opsdir.core.interchange.ldif import parse
from opsdir.store.postgres import apply_mods, entry_rows, schema_rows, split_record

CANON = {"cn": "cn", "ciamport": "ciamPort", "description": "description"}


def _schema(*definitions):
    return "dn: cn=schema\n" + "".join(f"{kind}: {d}\n" for kind, d in definitions)


AT = [("attributeTypes", "( 1.1 NAME 'cn' )"), ("attributeTypes", "( 1.2 NAME 'description' )")]


def test_schema_rows_order_superclasses_before_subclasses():
    text = _schema(*AT, ("objectClasses", "( 2.3 NAME 'leaf' SUP mid MUST cn )"),
                   ("objectClasses", "( 2.2 NAME 'mid' SUP top MAY description )"),
                   ("objectClasses", "( 2.1 NAME 'top' ABSTRACT )"))
    ats, ocs = schema_rows(text)
    assert [a["name"] for a in ats] == ["cn", "description"]
    assert [o["name"] for o in ocs] == ["top", "mid", "leaf"]


@pytest.mark.parametrize("classes", [
    [("objectClasses", "( 2.1 NAME 'a' MUST nosuch )")],                                    # undefined attribute
    [("objectClasses", "( 2.1 NAME 'a' SUP b )"), ("objectClasses", "( 2.2 NAME 'b' SUP a )")],   # cycle
    [("objectClasses", "( 2.1 NAME 'a' SUP missing )")]])                                   # unknown superclass
def test_schema_rows_reject_unusable_schemas(classes):
    with pytest.raises(SystemExit):
        schema_rows(_schema(*AT, *classes))


def test_split_record_separates_classes_and_canonicalizes_attribute_names():
    classes, attrs = split_record(CANON, {"objectClass": ("top",), "OBJECTCLASS": ("x",), "CN": ("a",),
                                          "cn": ("b",), "ciamPORT": ("1",), "unknownAttr": ("u",)})
    assert classes == ["top", "x"]
    assert attrs == {"cn": ["a", "b"], "ciamPort": ["1"], "unknownAttr": ["u"]}


def test_entry_rows_put_parents_before_children():
    records = parse("dn: cn=c,ou=b,dc=a\ncn: c\n\ndn: dc=a\nobjectClass: top\n\ndn: ou=b,dc=a\nobjectClass: top\n")
    assert [dn for dn, _, _ in entry_rows(CANON, records)] == ["dc=a", "ou=b,dc=a", "cn=c,ou=b,dc=a"]


@pytest.mark.parametrize("mods, expected", [
    ((("add", "description", ("y", "x")),), {"cn": ["a"], "description": ["x", "y"]}),            # no duplicates
    ((("replace", "description", ("z",)),), {"cn": ["a"], "description": ["z"]}),
    ((("delete", "description", ("x",)),), {"cn": ["a"]}),                                         # empty -> gone
    ((("delete", "description", ()),), {"cn": ["a"]}),                                             # all values
    ((("replace", "CiamPort", ("636",)), ("add", "ciamPort", ("1636",))), {"cn": ["a"], "description": ["x"],
                                                                           "ciamPort": ["636", "1636"]}),
])
def test_apply_mods(mods, expected):
    classes, attrs = apply_mods(CANON, ["top"], {"cn": ["a"], "description": ["x"]}, mods)
    assert (classes, attrs) == (["top"], expected)


def test_apply_mods_changes_object_classes_and_leaves_inputs_alone():
    classes, attrs = ["top"], {"cn": ["a"]}
    new_classes, _ = apply_mods(CANON, classes, attrs, (("add", "objectClass", ("aux",)),))
    assert new_classes == ["top", "aux"] and classes == ["top"]


def test_apply_mods_rejects_unknown_operations():
    with pytest.raises(SystemExit):
        apply_mods(CANON, [], {}, (("increment", "ciamPort", ("1",)),))
