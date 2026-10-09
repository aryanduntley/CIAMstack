"""The operations layer against Postgres: every result is a record or rows (never text for a terminal), and a
preview computes a write without making it."""
import pytest

from opsdir import operations as ops
from opsdir.core.interchange.ldif import parse

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
ciamTitle: Hold run.properties in the record
ciamChangeStatus: approved
"""


@pytest.fixture
def conn(dsn):
    from opsdir.store import postgres as db
    c = db.connect(dsn)
    initialized = ops.init(c)
    assert initialized.attribute_types > 0 and initialized.object_classes > 0
    assert ops.load(c, parse(BASE)) == ops.Loaded(3, 0)
    yield c
    c.close()


def test_a_capture_preview_writes_nothing_and_capture_applies_it(conn):
    preview = ops.preview_capture(conn, "a=1\nb=2\n", "app", "app/app.properties")
    assert preview.notices == ("app: 2 settings",) and len(preview.changes) == 4      # branch, file, two settings
    assert ops.report(conn, "capture").rows == ()
    applied = ops.apply_preview(conn, preview, "CHG-1")
    assert applied.change_id == "CHG-1" and len(applied.lines) == 4
    assert ops.rebuild_file(conn, "app") == ops.Rebuilt("app", "app/app.properties", "a=1\nb=2\n")
    assert ops.report(conn, "capture").rows == (("app", "settings", "java-properties", "app/app.properties", 2, 0, ""),)


def test_reads_return_records_and_rows(conn):
    assert [e.dn for e in ops.search(conn, "dc=ciam-ops", "(objectClass=ciamChange)")] == \
        ["cn=CHG-1,ou=changes,dc=ciam-ops"]
    edit = "dn: cn=CHG-1,ou=changes,dc=ciam-ops\nchangetype: modify\nreplace: ciamTitle\nciamTitle: Renamed\n-\n"
    assert ops.modify(conn, parse(edit), "CHG-1").change_id == "CHG-1"
    history = ops.history(conn)
    assert history.headers == ("at", "change", "op", "dn")
    assert [row[1:] for row in history.rows] == [("CHG-1", "update", "cn=CHG-1,ou=changes,dc=ciam-ops")]
    assert ops.check(conn) == ops.StackCheck(ops.check(conn).headers, (), 0)
    assert ops.upgrade(conn).applied == ()


def test_a_bundle_is_recorded_from_its_content_and_verified_against_a_checkout(conn):
    content = {"login.html": b"<html>Sign in</html>\n"}
    preview = ops.preview_bundle(conn, "login-ui", "am/ui/login", "template", content, "html", "2.4.0")
    assert len(ops.apply_preview(conn, preview, "CHG-1").lines) == 2                     # branch and bundle
    assert ops.verify_paths(conn) == ("am/ui/login",)
    assert ops.verify(conn, {"am/ui/login": content}).rows == (("bundle", "login-ui", "am/ui/login", "unchanged", ""),)
    assert ops.report(conn, "bundles").rows[0][:3] == ("login-ui", "template", "2.4.0")


def _restore_interval(conn):
    return next(r for r in ops.report(conn, "settings").rows if r[0] == "restore-test-interval-days")


def test_an_estate_setting_is_set_under_a_change_and_read_back(conn):
    preview = ops.preview_setting(conn, "restore-test-interval-days", "60")
    assert [r.dn for r in preview.changes] == ["ou=settings,dc=ciam-ops",
                                                 "cn=restore-test-interval-days,ou=settings,dc=ciam-ops"]
    assert _restore_interval(conn)[4:7] == ("", "90", "default")
    ops.apply_preview(conn, preview, "CHG-1")
    assert _restore_interval(conn)[4:7] == ("60", "60", "set")
    assert ops.preview_setting(conn, "restore-test-interval-days", "60").changes == ()
    with pytest.raises(ValueError, match="no installed domain or adapter declares"):
        ops.preview_setting(conn, "nonsense", "1")
