import datetime as dt

import pytest

from opsdir.core.directory import (children, classes_with_supers, follow, follow_all, get, gtime_date, in_scope, make_directory,
                                   norm_dn, one, rdn_value, referrers, subtree, value_type, values)

TYPES = (("cn", "string", "meta"), ("ciamOwner", "dn", "meta"), ("ciamPort", "port", "intent"),
         ("description", "string", "meta"))
CLASSES = (("top", None), ("ciamObject", "top"), ("ciamServer", "ciamObject"), ("organizationalUnit", "top"))
ENTRIES = (("dc=x", ["top"], {}),
           ("ou=owners,dc=x", ["top", "organizationalUnit"], {}),
           ("cn=team,ou=owners,dc=x", ["top", "ciamObject"], {"cn": ["team"]}),
           ("ou=servers,dc=x", ["top", "organizationalUnit"], {}),
           ("cn=ds-2,ou=servers,dc=x", ["top", "ciamServer"],
            {"cn": ["ds-2"], "ciamPort": ["1636"], "ciamOwner": ["CN=Team, OU=Owners, DC=x"]}),
           ("cn=ds-1,ou=servers,dc=x", ["top", "ciamServer"], {"cn": ["ds-1"], "description": ["a", "b"]}))


@pytest.fixture(scope="module")
def d():
    return make_directory(TYPES, CLASSES, ENTRIES)


def test_norm_dn_ignores_case_and_spaces_around_separators():
    assert norm_dn(" CN=A , OU = B,dc=X ") == "cn=a,ou=b,dc=x"


def test_entries_are_read_only(d):
    e = get(d, "cn=ds-1,ou=servers,dc=x")
    with pytest.raises(TypeError):
        e.attrs["cn"] = ("changed",)
    with pytest.raises(TypeError):
        d.entries["x"] = e


def test_attribute_access(d):
    e = get(d, "CN=DS-1, OU=servers, DC=x")
    assert (one(e, "cn"), values(e, "description"), one(e, "missing", "dflt"), values(e, "missing")) == \
        ("ds-1", ("a", "b"), "dflt", ())
    assert rdn_value(e) == "ds-1"
    assert value_type(d, "ciamPort") == "port" and value_type(d, "unknown") is None


def test_follow_dn_references(d):
    ds2 = get(d, "cn=ds-2,ou=servers,dc=x")
    assert follow(d, ds2, "ciamOwner").dn == "cn=team,ou=owners,dc=x"
    assert follow(d, get(d, "cn=ds-1,ou=servers,dc=x"), "ciamOwner") is None
    assert [e.dn for e in follow_all(d, ds2, "ciamOwner")] == ["cn=team,ou=owners,dc=x"]


def test_classes_include_every_superclass(d):
    assert classes_with_supers(d, get(d, "cn=ds-1,ou=servers,dc=x")) == {"top", "ciamObject", "ciamServer"}


@pytest.mark.parametrize("scope, expected", [
    ("base", {"ou=servers,dc=x"}),
    ("one", {"cn=ds-1,ou=servers,dc=x", "cn=ds-2,ou=servers,dc=x"}),
    ("sub", {"ou=servers,dc=x", "cn=ds-1,ou=servers,dc=x", "cn=ds-2,ou=servers,dc=x"})])
def test_scopes(d, scope, expected):
    assert {e.dn for e in in_scope(d, "OU=Servers,DC=x", scope)} == expected


def test_children_and_subtree_are_sorted_and_filter_by_class(d):
    assert [e.dn for e in children(d, "ou=servers,dc=x")] == ["cn=ds-1,ou=servers,dc=x", "cn=ds-2,ou=servers,dc=x"]
    assert [e.dn for e in subtree(d, "dc=x", "ciamServer")] == ["cn=ds-1,ou=servers,dc=x", "cn=ds-2,ou=servers,dc=x"]
    assert children(d, "ou=owners,dc=x", "ciamServer") == ()


def test_referrers_follow_only_dn_valued_attributes(d):
    found = [(attr, e.dn) for attr, e in referrers(d, "cn=team,ou=owners,dc=x")]
    assert found == [("ciamOwner", "cn=ds-2,ou=servers,dc=x")]
    assert list(referrers(d, get(d, "cn=team,ou=owners,dc=x"), "description")) == []


def test_gtime_date():
    assert gtime_date("20261102000000Z") == dt.date(2026, 11, 2)
