"""The record's identity against Postgres: set under an approved change through the operations layer, its org code and
record ID fixed once set, the entry not removable, and once it exists every new change record named with its org
code; change records made before stay as they are, and exports and evidence carry the identity."""
import pytest

from opsdir import operations as ops
from opsdir.connectors.registry import store_parts
from opsdir.core.interchange.ldif import parse
from opsdir.store import migrations, postgres as db

pytestmark = pytest.mark.integration

BASE = """dn: dc=ciam-ops
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
ciamTitle: Before the identity
ciamChangeStatus: approved
"""


def new_change(name):
    return (f"dn: cn={name},ou=changes,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: ciamChange\n"
            f"cn: {name}\nciamTitle: A change\nciamChangeStatus: proposed\n")


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    migrations.init(c, *store_parts())
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def write(conn, text, change="CHG-1"):
    return db.apply_records(conn, tuple(parse(text)), change)


def with_identity(conn, org="collins", parent="rtx", name="Collins Aerospace"):
    ops.apply_preview(conn, ops.preview_identity(conn, org, parent, name), "CHG-1")
    return ops.identity(conn)


def test_an_identity_is_set_under_an_approved_change_and_read_back(conn):
    assert ops.identity(conn) is None
    held = with_identity(conn)
    assert (held.org, held.parent, held.name) == ("collins", "rtx", "Collins Aerospace")
    assert len(held.record_id) == 36
    assert ops.preview_identity(conn, "collins", "rtx", "Collins Aerospace").changes == ()   # nothing to do again


def test_the_org_code_and_record_id_are_fixed_even_bypassing_the_operations(conn):
    held = with_identity(conn)
    for attr, value in (("ciamOrgCode", "pratt"), ("ciamRecordId", "00000000-0000-4000-8000-000000000000")):
        with pytest.raises(Exception) as refused:
            write(conn, f"dn: cn=record,dc=ciam-ops\nchangetype: modify\nreplace: {attr}\n{attr}: {value}\n-\n")
        assert "org code (collins) and record ID are fixed once set" in str(refused.value)
    with pytest.raises(Exception) as refused:
        write(conn, "dn: cn=record,dc=ciam-ops\nchangetype: delete\n")
    assert "identity (cn=record,dc=ciam-ops) can't be removed" in str(refused.value)
    assert ops.identity(conn) == held


def test_the_group_and_name_may_change_as_when_a_company_leaves_its_group(conn):
    with_identity(conn)
    ops.apply_preview(conn, ops.preview_identity(conn, "collins", "", "Collins"), "CHG-1")
    held = ops.identity(conn)
    assert (held.parent, held.name) == (None, "Collins")


def test_once_set_new_change_records_are_named_with_the_org_code(conn):
    with_identity(conn)
    with pytest.raises(Exception) as refused:
        write(conn, new_change("CHG-2"))
    assert 'isn\'t named collins-...' in str(refused.value)
    write(conn, new_change("COLLINS-CHG-2"))                                   # any case
    write(conn, "dn: cn=CHG-1,ou=changes,dc=ciam-ops\nchangetype: modify\nreplace: ciamTitle\n"
                "ciamTitle: Made before the identity\n-\n")                   # earlier change records stay
    assert conn.execute("select count(*) from opsdir.entry where 'ciamChange' = any (object_classes)"
                        ).fetchone()[0] == 2


def test_without_an_identity_any_change_name_is_accepted(conn):
    write(conn, new_change("CHG-2"))


def test_exports_are_headed_by_the_identity(conn):
    assert not ops.export(conn, "dc=ciam-ops").startswith("#")
    held = with_identity(conn)
    text = ops.export(conn, "dc=ciam-ops")
    assert text.splitlines()[0] == f"# record collins {held.record_id} in rtx"
    assert any(r.dn == "cn=record,dc=ciam-ops" for r in parse(text))         # the comment doesn't break reading

