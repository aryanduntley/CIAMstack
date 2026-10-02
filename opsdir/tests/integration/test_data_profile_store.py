"""A data profile in the store, against Postgres: its entries pass the store's rules (types, name=count patterns, the
environment and user-schema links), the reports read them back, and a distribution value that isn't name=count is
refused."""
import datetime as dt

import pytest

from opsdir.connectors.registry import store_parts
from opsdir.core.interchange.ldif import parse, write_entry
from opsdir.domains.directory.profile import attribute_rows, profile, profile_entries, profile_rows
from opsdir.store import migrations, postgres as db

pytestmark = pytest.mark.integration

ENV = "env=prod,cloud=home,ou=environments,dc=ciam-ops"
BASE = f"""dn: dc=ciam-ops
objectClass: top
objectClass: domain
dc: ciam-ops

dn: ou=changes,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: changes

dn: cn=CHG-1,ou=changes,dc=ciam-ops
objectClass: top
objectClass: ciamChange
cn: CHG-1
ciamTitle: Profile the data
ciamChangeStatus: approved

dn: ou=environments,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: environments

dn: cloud=home,ou=environments,dc=ciam-ops
objectClass: top
objectClass: ciamCloud
cloud: home
ciamCloudProvider: aws
ciamRegion: region-1

dn: {ENV}
objectClass: top
objectClass: ciamEnvironment
env: prod

dn: ou=user-schema,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: user-schema

dn: cn=mail,ou=user-schema,dc=ciam-ops
objectClass: top
objectClass: ciamUserAttribute
cn: mail
ciamLdapName: mail
ciamPiiClass: moderate

dn: ou=data-profile,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: data-profile
"""
PEOPLE = "ou=people,dc=example,dc=com"
DATA = (
    (PEOPLE, {"objectClass": ("top", "organizationalUnit"), "ou": ("people",)}),
    (f"uid=ann,{PEOPLE}", {"objectClass": ("top", "inetOrgPerson"), "uid": ("ann",), "mail": ("ann@example.test",),
                           "userPassword": ("{SSHA512}c2VjcmV0",), "pwdLastSuccess": ("20260920000000Z",)}),
    (f"cn=staff,{PEOPLE}", {"objectClass": ("top", "groupOfNames"), "cn": ("staff",),
                            "member": (f"uid=ann,{PEOPLE}",)}))


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    migrations.init(c, *store_parts())
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def _ldif(entries):
    return "\n".join(write_entry(e.dn, e.classes, e.attrs) for e in entries)


def test_a_profile_is_stored_and_reported(conn):
    d = db.load_directory(conn)
    _, entries = profile_entries(d, "home/prod", profile(iter(DATA), dt.date(2026, 9, 23)),
                                 dt.datetime(2026, 9, 23, 12))
    db.load_records(conn, parse(_ldif(entries)))
    stored = db.load_directory(conn)
    assert profile_rows(stored)[0][:5] == ("home/prod", "20260923", "3", "SSHA512=1", "<30d=1")
    assert {r[1]: r[-1] for r in attribute_rows(stored)}["mail"] == "yes"


def test_a_distribution_value_must_be_name_equals_count(conn):
    d = db.load_directory(conn)
    head, *_ = profile_entries(d, "home/prod", profile(iter(DATA), dt.date(2026, 9, 23)),
                               dt.datetime(2026, 9, 23, 12))[1]
    wrong = head._replace(attrs={**head.attrs, "ciamHashSchemeCount": ("SSHA512",)})
    with pytest.raises(Exception) as refused:
        db.load_records(conn, parse(write_entry(wrong.dn, wrong.classes, wrong.attrs)))
    assert "ciamHashSchemeCount" in str(refused.value)
