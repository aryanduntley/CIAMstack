"""The store refuses secret material (SPEC R4), against Postgres: every registered pattern works in the database as it
does in Python, a write carrying a secret is refused without the refusal repeating it, and installing a pattern that
stored entries match is refused."""
import pytest

from opsdir.connectors.registry import secret_patterns, store_parts
from opsdir.core.interchange.ldif import parse
from opsdir.core.secrets import scan
from opsdir.core.contract import SecretPattern
from opsdir.store import migrations, postgres as db
from secret_samples import CLEAN, SECRETS

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
ciamTitle: Runbook notes
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
description: Owns the platform
"""
SECRET = "db.password=changeit"


def describe(text, dn="cn=team-a,ou=owners,dc=ciam-ops"):
    return f"dn: {dn}\nchangetype: modify\nreplace: description\ndescription: {text}\n-\n"


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    migrations.init(c, *store_parts())
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def change(conn, text):
    return db.apply_records(conn, tuple(parse(text)), "CHG-1")


def test_the_database_and_python_agree_on_every_pattern(conn):
    patterns = [SecretPattern(name, pattern, d) for name, pattern, _, d in secret_patterns()]
    for text in [t for t, _ in SECRETS] + list(CLEAN):
        in_db = [r[0] for r in conn.execute("select name from opsdir.secret_pattern where %s ~ pattern "
                                            "order by name", (text,)).fetchall()]
        assert in_db == sorted(scan(text, patterns)), text


def test_a_write_carrying_a_secret_is_refused_without_repeating_it(conn):
    with pytest.raises(Exception) as refused:
        change(conn, describe(f"see {SECRET}"))
    message = str(refused.value)
    assert 'holds what looks like secret material in description (secret-assignment)' in message
    assert "changeit" not in message
    assert conn.execute("select attrs -> 'description' ->> 0 from opsdir.entry where dn = %s",
                        ("cn=team-a,ou=owners,dc=ciam-ops",)).fetchone()[0] == "Owns the platform"


def test_a_secret_in_an_entry_name_is_refused_without_repeating_it(conn):
    add = ("dn: cn=AKIAIOSFODNN7EXAMPLE,ou=owners,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
           "objectClass: ciamParty\ncn: AKIAIOSFODNN7EXAMPLE\nciamOwnerKind: team\n")
    with pytest.raises(Exception) as refused:
        change(conn, add)
    assert "an entry name holds what looks like secret material (aws-access-key-id)" in str(refused.value)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(refused.value)


def test_the_secret_check_comes_before_every_message_that_repeats_a_value(conn):
    with pytest.raises(Exception) as refused:                         # ciamOwnerKind is a vocab: its refusal quotes
        change(conn, "dn: cn=team-a,ou=owners,dc=ciam-ops\nchangetype: modify\nreplace: ciamOwnerKind\n"
                     f"ciamOwnerKind: {SECRET}\n-\n")
    assert "secret material in ciamOwnerKind" in str(refused.value) and "changeit" not in str(refused.value)


def test_installing_a_pattern_that_stored_entries_match_is_refused(conn):
    change(conn, describe("ticket XQ-99812 closed"))
    *rest, patterns = store_parts()
    ticket = ("ticket-code", "XQ-[0-9]{5}", "test", "A made-up credential form")
    with pytest.raises(SystemExit) as refused:
        migrations.upgrade(conn, *rest, (*patterns, ticket))
    assert "secret material in description (ticket-code)" in str(refused.value)
    assert "XQ-99812" not in str(refused.value)
    assert conn.execute("select count(*) from opsdir.secret_pattern").fetchone()[0] == len(patterns)   # rolled back
