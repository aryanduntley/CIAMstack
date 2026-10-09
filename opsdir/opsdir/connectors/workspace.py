"""Migration workspaces: a copy of the live record where a migration target is declared without touching live data,
and the cutover that applies the workspace's changes to the live record as one approved change set.

The workspace records the live snapshot it started from (its base). Its changes are diff(base, workspace). At cutover
the live record may have moved on: if live and workspace changed different entries the workspace's changes still
apply (a three-way merge); if both changed the same entry the cutover is refused and names them. After a cutover the
workspace is rebuilt from the new live record. The pure functions decide; the effect functions below them only read
and write the two stores.
"""
import hashlib
import os
import re

from ..core.changeset import diff
from ..core.directory import make_directory, norm_dn
from ..core.interchange.export import export_text
from ..core.interchange.ldif import parse, write_records
from ..core.naming import SUFFIX
from ..store import migrations
from ..store.postgres import apply_records, entry_rows, fetch_directory_rows, load_directory, load_records
from ..store.workspace import has_schema, read_base, record_base

WORKSPACE_DSN_VAR = "OPSDIR_WORKSPACE_DSN"


# ------------------------------------------------------------------ pure
def fingerprint(text):
    return hashlib.sha256(text.encode()).hexdigest()


def safe_source(dsn):
    """A DSN fit to record: its password removed."""
    return re.sub(r"password=\S+", "password=***", dsn)


def base_directory(type_rows, class_rows, base_ldif):
    """The workspace's base snapshot as a Directory, read with the workspace's schema registry."""
    canon = {name.lower(): name for name, _, _ in type_rows}
    return make_directory(type_rows, class_rows, entry_rows(canon, parse(base_ldif)))


def _touched(records):
    return frozenset(norm_dn(r.dn) for r in records)


def cutover_changes(base, live, workspace):
    """(the workspace's change records, DNs changed on both sides since the base). The records are safe to apply to
    the live record only when no DN was changed on both sides."""
    ws_changes = diff(base, workspace)
    return ws_changes, tuple(sorted(_touched(diff(base, live)) & _touched(ws_changes)))


def status_text(base, changes, live_changed):
    counts = {t: sum(r.changetype == t for r in changes) for t in ("add", "modify", "delete")}
    return "\n".join((f"workspace copied from {base.source} at {base.created_at:%Y-%m-%d %H:%M:%S}",
                      f"changes since then: {counts['add']} added, {counts['modify']} modified, "
                      f"{counts['delete']} deleted",
                      "live record: changed since the copy" if live_changed
                      else "live record: unchanged since the copy"))


# ------------------------------------------------------------------ effects
def workspace_dsn():
    """Effect: the workspace database from OPSDIR_WORKSPACE_DSN."""
    dsn = os.environ.get(WORKSPACE_DSN_VAR)
    if not dsn:
        raise SystemExit(f"{WORKSPACE_DSN_VAR} is not set (./opsdir.sh sets the local dev workspace; see README)")
    return dsn


def _live_text(live):
    return export_text(load_directory(live), SUFFIX)


def create(live, ws, parts, source, replace=False, schema_sync=None):
    """Effect: copy the live record into the workspace database (rebuilt from nothing) and record the base.
    schema_sync (registry.schema_sync()) composes the record's custom definitions as they load."""
    if has_schema(ws) and not replace:
        raise SystemExit("the workspace database already holds an opsdir store; `workspace create --replace` rebuilds "
                         "it (its data is dropped)")
    text = _live_text(live)
    migrations.init(ws, *parts)
    n = load_records(ws, parse(text), schema_sync=schema_sync)
    record_base(ws, safe_source(source), fingerprint(text), text)
    return n


def _snapshots(live, ws):
    base = read_base(ws)
    if base is None:
        raise SystemExit("not a migration workspace: run `opsdir workspace create` first")
    types, classes, _ = fetch_directory_rows(ws)
    return base, base_directory(types, classes, base.ldif), load_directory(ws)


def state(live, ws):
    """Effect: (the workspace's base, its change records since the copy, whether the live record changed since)."""
    base, base_d, ws_d = _snapshots(live, ws)
    return base, diff(base_d, ws_d), fingerprint(_live_text(live)) != base.fingerprint


def status(live, ws):
    """Effect: what the workspace changed, and whether the live record moved on since the copy, as text."""
    return status_text(*state(live, ws))


def diff_text(live, ws):
    """Effect: the workspace's changes as LDIF change records."""
    return write_records(state(live, ws)[1])


def cutover(live, ws, parts, source, change_id, schema_sync=None):
    """Effect: apply the workspace's changes to the live record under an approved change, then rebuild the workspace
    from the new live record. Refuses when live and workspace changed the same entries since the copy."""
    _, base_d, ws_d = _snapshots(live, ws)
    changes, conflicts = cutover_changes(base_d, load_directory(live), ws_d)
    if conflicts:
        raise SystemExit("the live record and the workspace both changed: " + ", ".join(conflicts)
                         + ". Resolve in the workspace (or recreate it) before cutover.")
    applied = apply_records(live, changes, change_id, schema_sync) if changes else []
    create(live, ws, parts, source, replace=True, schema_sync=schema_sync)
    return applied
