"""The pure decisions behind migration workspaces: bases, change sets at cutover, conflicts."""
import datetime as dt

from opsdir.connectors.workspace import base_directory, cutover_changes, fingerprint, safe_source, status_text
from opsdir.core.interchange.export import export_text
from opsdir.core.naming import SUFFIX
from opsdir.store.workspace import Base


def _rows(d):
    return ([(n, t["value_type"], t["portability"]) for n, t in d.types.items()], list(d.supers.items()))


def test_fingerprint_and_safe_source():
    assert fingerprint("a") == fingerprint("a") != fingerprint("b")
    assert safe_source("host=h user=u password=s3cret dbname=x") == "host=h user=u password=*** dbname=x"


def test_the_base_snapshot_reads_back_as_the_same_directory(estate):
    text = export_text(estate["before"], SUFFIX)
    assert export_text(base_directory(*_rows(estate["before"]), text), SUFFIX) == text


def test_workspace_changes_apply_when_live_did_not_move(estate):
    changes, conflicts = cutover_changes(estate["before"], estate["before"], estate["after"])
    assert [r.changetype for r in changes] == ["add", "modify", "modify", "modify"] and conflicts == ()


def test_the_same_entries_changed_on_both_sides_are_conflicts(estate):
    changes, conflicts = cutover_changes(estate["before"], estate["after"], estate["after"])
    assert [c.split(",")[0] for c in conflicts] == ["cn=fw-mro-batch", "cn=hrdb", "cn=ldap", "cn=svc-ldaps"]


def test_status_counts_changes_and_reports_live_movement(estate):
    base = Base("host=h password=***", dt.datetime(2026, 9, 27, 12, 0), "f", "")
    changes, _ = cutover_changes(estate["before"], estate["before"], estate["after"])
    assert status_text(base, changes, True).splitlines() == [
        "workspace copied from host=h password=*** at 2026-09-27 12:00:00",
        "changes since then: 1 added, 3 modified, 0 deleted",
        "live record: changed since the copy"]
