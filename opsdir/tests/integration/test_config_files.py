"""Config files captured into a live store under a governed change and rebuilt from what the store holds (against
Postgres); the store's secret guard still refuses a text an operator accepted."""
from pathlib import Path

import pytest

from opsdir.connectors.capture import capture_changes, rebuilt_file
from opsdir.connectors.registry import schema_sync, store_parts
from opsdir.core.formats import INI, JAVA_PROPERTIES, JSON, LDIF, XML
from opsdir.core.interchange.ldif import parse
from opsdir.store import migrations, postgres as db

pytestmark = pytest.mark.integration

SAMPLES = Path(__file__).resolve().parent.parent / "capture_samples"
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
ciamTitle: Hold the platform's config files in the record
ciamChangeStatus: approved
"""


@pytest.fixture
def conn(dsn):
    c = db.connect(dsn)
    migrations.init(c, *store_parts())
    db.load_records(c, parse(BASE))
    yield c
    c.close()


def capture(conn, fmt, text, name, **options):
    changes, notices = capture_changes(db.load_directory(conn), fmt, text, name, f"config/{name}", **options)
    db.apply_records(conn, changes, "CHG-1", schema_sync())
    return notices


@pytest.mark.parametrize("sample, fmt", [("run.properties", JAVA_PROPERTIES), ("tcp.xml", XML), ("sync.json", JSON),
                                         ("sssd.ini", INI), ("config.ldif", LDIF)])
def test_every_sample_is_held_and_rebuilt_identical_from_the_store(conn, sample, fmt):
    text = (SAMPLES / sample).read_text()
    capture(conn, fmt, text, sample, accept_concerns=(sample == "config.ldif"))
    assert rebuilt_file(db.load_directory(conn), sample)[0] == text


def test_a_whole_file_is_held_and_a_recapture_upgrades_it_to_settings(conn):
    broken, fixed = "<a>\n  <b>1</c>\n</a>\n", "<a>\n  <b>1</b>\n</a>\n"
    capture(conn, XML, broken, "f.xml")
    assert rebuilt_file(db.load_directory(conn), "f.xml")[0] == broken
    capture(conn, XML, fixed, "f.xml")
    d = db.load_directory(conn)
    assert rebuilt_file(d, "f.xml")[0] == fixed
    level = conn.execute("select attrs -> 'ciamCaptureLevel' ->> 0 from opsdir.entry where dn = %s",
                         ("cn=f.xml,ou=config-files,dc=ciam-ops",)).fetchone()[0]
    assert level == "settings"


def test_a_file_with_a_withheld_password_is_held_as_settings(conn):
    notices = capture(conn, JAVA_PROPERTIES, "pf.admin.https.port=9999\npf.admin.pwd=Hunter2Hunter2\n", "run")
    assert notices == ("run: 2 settings", "run: value withheld, needs a secret reference: pf.admin.pwd")
    stored = conn.execute("select string_agg(attrs::text, ' ') from opsdir.entry").fetchone()[0]
    assert "Hunter2" not in stored


def test_the_store_refuses_secret_material_an_operator_accepted(conn):
    with pytest.raises(Exception, match="secret material in ciamSkeleton \\(private-key\\)"):
        capture(conn, XML, "<k>\n-----BEGIN PRIVATE KEY-----\n</k", "k.xml", accept_concerns=True)
