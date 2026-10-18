"""The record's identity, pure: valid org codes, the change records that set or update it, a fixed org code, the
change-name rule and the export line."""
import json
from types import SimpleNamespace

import pytest

from opsdir.core.directory import make_directory
from opsdir.domains.estate.evidence import manifest
from opsdir.domains.governance.identity import (IDENTITY_DN, Identity, change_name_problem, code_problem,
                                               identity_changes, identity_line, record_identity)

UUID = "3f2b9c1e-8d4a-4c6b-9e2f-1a7d5c3b8e90"


def directory(*records):
    rows = [(r.dn, r.attrs.get("objectClass", ()), {k: v for k, v in r.attrs.items() if k != "objectClass"})
            for r in records]
    return make_directory((), (), [(dn, tuple(classes), attrs) for dn, classes, attrs in rows])


def identified(**kw):
    return directory(*identity_changes(directory(), "collins", UUID, **kw))


@pytest.mark.parametrize("code", ["collins", "pw", "raytheon-2", "rtx"])
def test_valid_org_codes(code):
    assert code_problem(code) is None


@pytest.mark.parametrize("code", ["Collins", "2rtx", "rtx-", "a--b", "has space", "x" * 33])
def test_invalid_org_codes(code):
    assert code_problem(code)


def test_a_new_identity_is_one_entry():
    (record,) = identity_changes(directory(), "collins", UUID, "rtx", "Collins Aerospace")
    assert record.dn == IDENTITY_DN and record.changetype == "add"
    assert record.attrs["ciamOrgCode"] == ("collins",) and record.attrs["ciamRecordId"] == (UUID,)
    assert record.attrs["ciamParentOrgCode"] == ("rtx",) and record.attrs["description"] == ("Collins Aerospace",)


def test_the_identity_reads_back():
    assert record_identity(directory()) is None
    assert record_identity(identified(parent="rtx")) == Identity("collins", UUID, "rtx", None)


def test_the_org_code_is_fixed_once_set():
    with pytest.raises(ValueError, match="fixed once set"):
        identity_changes(identified(), "pratt", UUID)


def test_group_and_name_update_and_none_leaves_them():
    d = identified(parent="rtx", name="Collins")
    assert identity_changes(d, "collins", "unused") == ()
    (left,) = identity_changes(d, "collins", "unused", parent="")
    assert left.changetype == "modify" and left.mods == (("delete", "ciamParentOrgCode", ("rtx",)),)
    (renamed,) = identity_changes(d, "collins", "unused", name="Collins Aerospace")
    assert renamed.mods == (("replace", "description", ("Collins Aerospace",)),)


def test_bad_inputs_are_refused():
    with pytest.raises(ValueError, match="isn't lowercase letters"):
        identity_changes(directory(), "Collins", UUID)
    with pytest.raises(ValueError, match="record's own org code"):
        identity_changes(directory(), "rtx", UUID, parent="rtx")
    with pytest.raises(ValueError, match="isn't a lowercase UUID"):
        identity_changes(directory(), "rtx", "not-a-uuid")


def test_change_names_start_with_the_org_code_once_there_is_an_identity():
    held = Identity("collins", UUID, None, None)
    assert change_name_problem(None, "CHG-1") is None
    assert change_name_problem(held, "collins-CHG-1") is None and change_name_problem(held, "COLLINS-2") is None
    assert "isn't named collins-..." in change_name_problem(held, "CHG-1")
    assert change_name_problem(held, "collinsx-1")


def test_the_export_line():
    assert identity_line(None) is None
    assert identity_line(Identity("collins", UUID, "rtx", "Collins")) == f"record collins {UUID} in rtx"
    assert identity_line(Identity("rtx", UUID, None, None)) == f"record rtx {UUID}"



def test_an_evidence_manifest_names_the_record_only_when_it_has_an_identity():
    boundary = SimpleNamespace(dn="cn=b,ou=boundaries,dc=ciam-ops")
    assert "record" not in json.loads(manifest(boundary, "2026-10-18", {}, (), {}))
    doc = json.loads(manifest(boundary, "2026-10-18", {}, (), {}, Identity("collins", UUID, "rtx", None)))
    assert doc["record"] == {"org": "collins", "record_id": UUID, "parent": "rtx"}
    assert list(doc)[0] == "record"
