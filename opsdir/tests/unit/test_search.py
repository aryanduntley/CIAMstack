import pytest

from opsdir.core.directory import make_directory
from opsdir.core.search import parse_filter, search

TYPES = (("cn", "string", "meta"), ("ciamPort", "port", "intent"), ("ciamOwner", "dn", "meta"),
         ("ciamMigrationStatus", "string", "meta"))
CLASSES = (("top", None), ("ciamObject", "top"), ("ciamConsumer", "ciamObject"))
ENTRIES = (("ou=c,dc=x", ["top"], {}),
           ("cn=portal,ou=c,dc=x", ["top", "ciamConsumer"],
            {"cn": ["portal"], "ciamPort": ["636"], "ciamMigrationStatus": ["tested"],
             "ciamOwner": ["cn=Team,ou=owners,dc=x"]}),
           ("cn=batch-export,ou=c,dc=x", ["top", "ciamConsumer"],
            {"cn": ["batch-export"], "ciamPort": ["1636"], "ciamMigrationStatus": ["identified"]}),
           ("cn=legacy,ou=c,dc=x", ["top", "ciamConsumer"], {"cn": ["legacy"]}))


@pytest.fixture(scope="module")
def d():
    return make_directory(TYPES, CLASSES, ENTRIES)


def names(d, filt, base="ou=c,dc=x", scope="sub"):
    return [e.dn.split(",")[0][3:] for e in search(d, base, filt, scope)]


@pytest.mark.parametrize("filt, expected", [
    ("(cn=PORTAL)", ["portal"]),                                    # equality ignores case
    ("(ciamMigrationStatus=*)", ["batch-export", "portal"]),        # presence
    ("(cn=*export)", ["batch-export"]),                             # substring
    ("(cn=b*-*t)", ["batch-export"]),
    ("(ciamPort>=1000)", ["batch-export"]),                         # typed: 636 < 1000 as integers
    ("(ciamPort<=700)", ["portal"]),
    ("(ciamOwner=CN=team, OU=owners, DC=x)", ["portal"]),           # dn values compare normalized
    ("(objectClass=ciamObject)", ["batch-export", "legacy", "portal"]),   # superclasses match
    ("(objectclass=top)", ["batch-export", "legacy", "portal", "c"]),    # sub scope includes the base
    ("(&(objectClass=ciamConsumer)(!(ciamMigrationStatus=tested)))", ["batch-export", "legacy"]),
    ("(|(cn=legacy)(ciamPort=636))", ["legacy", "portal"]),
    ("(&(cn=legacy)(|(ciamPort=1)(ciamPort=2)))", []),
])
def test_filters(d, filt, expected):
    assert names(d, filt) == expected


def test_search_scope_and_ordering(d):
    assert names(d, "(objectClass=top)", scope="one") == ["batch-export", "legacy", "portal"]
    assert names(d, "(objectClass=top)", base="cn=legacy,ou=c,dc=x", scope="base") == ["legacy"]


@pytest.mark.parametrize("bad", ["cn=x", "(cn~=x)", "(=x)"])
def test_malformed_filters_are_rejected(bad):
    with pytest.raises(ValueError):
        parse_filter(bad)
