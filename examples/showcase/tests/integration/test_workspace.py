"""Migration workspaces against Postgres: copy the live record, change the copy, apply it back at cutover."""
import psycopg
import pytest

from opsdir.connectors import workspace
from opsdir.connectors.registry import schema_sync, store_parts
from opsdir.core.interchange.export import export_text
from opsdir.core.naming import SUFFIX
from opsdir.store import migrations, postgres as db
from showcase_support import APPROVED, DATA, import_exports

pytestmark = pytest.mark.integration

SVC = "cn=svc-ldaps,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops"


def _edit(dn, text):
    return f"dn: {dn}\nchangetype: modify\nreplace: description\ndescription: {text}\n-\n"


@pytest.fixture
def stores(dsn, workspace_dsn):
    """(live, workspace) connections; live freshly holds the showcase, the workspace is a fresh copy of it."""
    live, ws = db.connect(dsn), db.connect(workspace_dsn)
    migrations.init(live, *store_parts())
    db.load_ldif(live, sorted(DATA.glob("*.ldif")), schema_sync=schema_sync())
    import_exports(live)
    workspace.create(live, ws, store_parts(), dsn, replace=True, schema_sync=schema_sync())
    yield live, ws
    live.close()
    ws.close()


def _modify(conn, tmp_path, name, text, change_id):
    path = tmp_path / name
    path.write_text(text)
    return db.apply_changes(conn, path, change_id)


def test_a_new_workspace_is_the_live_record_with_no_changes(stores):
    live, ws = stores
    assert export_text(db.load_directory(ws), SUFFIX) == export_text(db.load_directory(live), SUFFIX)
    assert workspace.diff_text(live, ws) == ""
    assert workspace.status(live, ws).endswith("live record: unchanged since the copy")


def test_creating_over_an_existing_store_needs_replace(stores, dsn):
    live, ws = stores
    with pytest.raises(SystemExit, match="--replace"):
        workspace.create(live, ws, store_parts(), dsn, schema_sync=schema_sync())


def test_workspace_changes_reach_live_only_at_cutover(stores, dsn):
    live, ws = stores
    for change_id, path in APPROVED:
        db.apply_changes(ws, path, change_id)
    assert workspace.diff_text(live, ws).count("changetype:") == 4          # a firewall rule, two connectors, a name
    assert "dn: cn=fw-mro-batch,ou=bindings,env=prod,cloud=target" not in export_text(db.load_directory(live), SUFFIX)
    applied = workspace.cutover(live, ws, store_parts(), dsn, APPROVED[1][0], schema_sync())
    assert [line.split(" ", 1)[0] for line in applied] == ["add", "modify", "modify", "modify"]
    assert export_text(db.load_directory(live), SUFFIX) == export_text(db.load_directory(ws), SUFFIX)
    assert workspace.diff_text(live, ws) == ""                                   # re-copied after cutover


def test_cutover_merges_when_live_changed_other_entries(stores, dsn, tmp_path):
    live, ws = stores
    _modify(ws, tmp_path, "ws.ldif", _edit(SVC, "workspace edit"), APPROVED[1][0])
    _modify(live, tmp_path, "live.ldif", _edit("cn=legacy-rptuser,ou=consumers,dc=ciam-ops", "live edit"), APPROVED[0][0])
    assert "changed since the copy" in workspace.status(live, ws)
    workspace.cutover(live, ws, store_parts(), dsn, APPROVED[1][0], schema_sync())
    text = export_text(db.load_directory(live), SUFFIX)
    assert "description: workspace edit" in text and "description: live edit" in text


def test_cutover_refuses_entries_changed_on_both_sides(stores, dsn, tmp_path):
    live, ws = stores
    _modify(ws, tmp_path, "ws.ldif", _edit(SVC, "workspace edit"), APPROVED[1][0])
    _modify(live, tmp_path, "live.ldif", _edit(SVC, "live edit"), APPROVED[1][0])
    with pytest.raises(SystemExit, match="both changed: cn=svc-ldaps"):
        workspace.cutover(live, ws, store_parts(), dsn, APPROVED[1][0], schema_sync())
    assert "description: live edit" in export_text(db.load_directory(live), SUFFIX)   # live untouched


def test_cutover_needs_an_approved_change_in_the_live_record(stores, dsn, tmp_path):
    live, ws = stores
    _modify(ws, tmp_path, "ws.ldif", _edit(SVC, "workspace edit"), APPROVED[1][0])
    with pytest.raises(psycopg.Error, match="not an approved change record"):
        workspace.cutover(live, ws, store_parts(), dsn, "CHG-9999", schema_sync())
