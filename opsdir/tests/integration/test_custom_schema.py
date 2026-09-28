"""Custom fields and record types in a live store: defined and used under governed changes, their value rules
enforced, and a definition that would strand stored entries refused (against Postgres)."""
import pytest

from opsdir.connectors.registry import schema_sync, store_parts
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
ciamTitle: Custom fields
ciamChangeStatus: approved

dn: ou=owners,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: owners

dn: cn=team-a,ou=owners,dc=ciam-ops
objectClass: top
objectClass: ciamParty
cn: team-a
ciamOwnerKind: team

dn: ou=custom-schema,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: custom-schema

dn: ou=queues,dc=ciam-ops
objectClass: top
objectClass: organizationalUnit
ou: queues
"""
COST_CENTER = """dn: cn=xCostCenter,ou=custom-schema,dc=ciam-ops
changetype: add
objectClass: top
objectClass: ciamFieldDefinition
cn: xCostCenter
ciamDefinitionNumber: 1
ciamValueType: string
ciamPortability: meta
ciamPattern: ^CC-[0-9]{4}$
ciamCarriedBy: ciamParty
ciamPurpose: Cost center billed for the team's usage
"""


def use_cost_center(value):
    return f"""dn: cn=team-a,ou=owners,dc=ciam-ops
changetype: modify
add: xCostCenter
xCostCenter: {value}
-
"""


QUEUE_TYPE = """dn: cn=xRetentionDays,ou=custom-schema,dc=ciam-ops
changetype: add
objectClass: top
objectClass: ciamFieldDefinition
cn: xRetentionDays
ciamDefinitionNumber: 2
ciamValueType: int
ciamPortability: intent
ciamMinValue: 7
ciamMaxValue: 90
ciamUnit: days

dn: cn=xMessageQueue,ou=custom-schema,dc=ciam-ops
changetype: add
objectClass: top
objectClass: ciamRecordTypeDefinition
cn: xMessageQueue
ciamDefinitionNumber: 1
ciamRequiredField: xRetentionDays
"""


def queue(days):
    return f"""dn: cn=orders,ou=queues,dc=ciam-ops
changetype: add
objectClass: top
objectClass: xMessageQueue
cn: orders
xRetentionDays: {days}
"""


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    migrations.init(c, *store_parts())
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def change(conn, *ldif_texts):
    return db.apply_records(conn, tuple(r for t in ldif_texts for r in parse(t)), "CHG-1", schema_sync())


def cost_center(conn):
    return conn.execute("select attrs -> 'xCostCenter' ->> 0 from opsdir.entry where dn = %s",
                        ("cn=team-a,ou=owners,dc=ciam-ops",)).fetchone()[0]


def test_a_field_is_defined_and_used_in_one_change(conn):
    change(conn, COST_CENTER, use_cost_center("CC-0042"))
    assert cost_center(conn) == "CC-0042"
    rules = conn.execute("select rules from opsdir.attribute_type where name = 'xCostCenter'").fetchone()[0]
    assert rules == {"X-PATTERN": "^CC-[0-9]{4}$"}


def test_values_are_held_to_the_fields_rules(conn):
    change(conn, COST_CENTER)
    with pytest.raises(Exception, match="breaks its rules"):
        change(conn, use_cost_center("CC-42"))


def test_a_definition_that_would_strand_stored_entries_is_refused(conn):
    change(conn, COST_CENTER, use_cost_center("CC-0042"))
    tighten = """dn: cn=xCostCenter,ou=custom-schema,dc=ciam-ops
changetype: modify
replace: ciamPattern
ciamPattern: ^CC-[0-9]{5}$
-
"""
    with pytest.raises(SystemExit, match="would no longer accept stored entries: .*team-a"):
        change(conn, tighten)
    assert conn.execute("select rules ->> 'X-PATTERN' from opsdir.attribute_type where name = 'xCostCenter'"
                        ).fetchone()[0] == "^CC-[0-9]{4}$"


def test_custom_record_types_hold_records(conn):
    change(conn, QUEUE_TYPE, queue(30))
    with pytest.raises(Exception, match="breaks its rules"):
        change(conn, queue(3).replace("orders", "billing"))


def test_a_field_in_use_cant_be_deleted_until_nothing_uses_it(conn):
    change(conn, COST_CENTER, use_cost_center("CC-0042"))
    drop = "dn: cn=xCostCenter,ou=custom-schema,dc=ciam-ops\nchangetype: delete\n"
    with pytest.raises(SystemExit, match="no installed part defines any more .*xCostCenter"):
        change(conn, drop)
    stop_using = "dn: cn=team-a,ou=owners,dc=ciam-ops\nchangetype: modify\ndelete: xCostCenter\n-\n"
    change(conn, drop, stop_using)                       # one change: the use goes first, the definition last
    assert conn.execute("select count(*) from opsdir.attribute_type where name = 'xCostCenter'").fetchone()[0] == 0


def test_upgrade_keeps_the_records_definitions(conn):
    change(conn, COST_CENTER, use_cost_center("CC-0042"))
    migrations.upgrade(conn, *store_parts())
    assert cost_center(conn) == "CC-0042"


def test_definitions_that_dont_compose_are_refused(conn):
    with pytest.raises(SystemExit, match="custom definitions don't compose: costCenter: custom names start with 'x'"):
        change(conn, COST_CENTER.replace("xCostCenter", "costCenter"))
