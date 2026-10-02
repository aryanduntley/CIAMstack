"""Helpers every package's importers and renderers share: tolerant parsing, files grouped by folder, the container
entry an importer adds, DNs below a base, times as the record holds them, JSON as opsdir writes and holds it, a
cloud resource's role tags, a CI job's environment, a product file captured."""
import datetime as dt
import json

from opsdir.core.directory import gtime, gtime_of_iso, make_entry, one, ou_entry, rdn_of, within
from opsdir.core.formats import JSON
from opsdir.core.inventory import of_types, tagged_role
from opsdir.core.jsondata import held_json, indented
from opsdir.core.sources import by_folder, folders, json_document, parsed, under
from opsdir.domains.automation.pipelines import environment_name
from opsdir.domains.configuration.naming import file_dn
from opsdir.domains.configuration.record import captured_file

FILES = {"web-1/etc/crontab": "a", "web-1/etc/cron.d/x": "b", "web-2/etc/crontab": "c", "README": "top"}
KNOWN = {"ok": "OK"}


def test_parsed_is_none_when_the_text_is_not_the_format_or_not_the_kind():
    assert parsed(json.loads, '{"a": 1}') == {"a": 1}
    assert parsed(json.loads, "{nope") is None
    assert parsed(json.loads, "[1]", kind=dict) is None
    assert parsed(KNOWN.__getitem__, "ok", (KeyError,)) == "OK"        # the caller's loader and its errors
    assert parsed(KNOWN.__getitem__, "other", (KeyError,)) is None


def test_json_document():
    assert json_document('{"a": [1]}', dict) == {"a": [1]}
    assert json_document("") is None
    assert json_document('"text"', dict) is None
    assert json_document("false") is False


def test_files_grouped_by_folder():
    assert under(FILES, "web-1") == {"etc/crontab": "a", "etc/cron.d/x": "b"}
    assert by_folder(FILES) == {"web-1": {"etc/crontab": "a", "etc/cron.d/x": "b"}, "web-2": {"etc/crontab": "c"}}
    assert list(folders(FILES, ("web-2", "web-1"))) == ["web-2", "web-1"]
    assert folders(FILES, ("web-1/etc",))["web-1/etc"] == {"crontab": "a", "cron.d/x": "b"}


def test_ou_entry_is_named_by_its_rdn():
    e = ou_entry("ou=jobs,dc=ciam-ops")
    assert rdn_of("cn=web-1,ou=servers,dc=ciam-ops") == "web-1"
    assert (e.dn, e.classes, one(e, "ou")) == ("ou=jobs,dc=ciam-ops", ("top", "organizationalUnit"), "jobs")


def test_json_as_written_and_as_held():
    assert indented({"b": 1}) == '{\n  "b": 1\n}\n'
    assert JSON.write({"b": 1}) == indented({"b": 1})
    e = make_entry("cn=x", ("top",), {"xConfig": ('{"a":1}',)})
    assert held_json(e, "xConfig") == {"a": 1}
    assert held_json(e, "xMissing") == {}


def test_environment_name_as_ci_systems_write_it():
    assert environment_name("prod") == "prod"
    assert environment_name({"name": "prod", "url": "https://x"}) == "prod"
    assert environment_name(None) is None
    assert environment_name(["prod"]) is None


def test_captured_file_is_named_by_prefix_and_path():
    dn, entries, _ = captured_file(JSON, "ig", "pinggateway", "config/admin.json", '{"a": 1}\n', (), "gateway")
    assert dn == file_dn("ig.config.admin.json")
    assert one(entries[0], "ciamRepoPath") == "pinggateway/config/admin.json"
    assert one(entries[0], "ciamTargetRole") == "gateway"


def test_within_a_base():
    assert within("cn=a,ou=Jobs,dc=ciam-ops", "ou=jobs, dc=ciam-ops")
    assert within("ou=jobs,dc=ciam-ops", "ou=jobs,dc=ciam-ops")
    assert not within("ou=myjobs,dc=ciam-ops", "ou=jobs,dc=ciam-ops")


def test_times_as_the_record_holds_them():
    assert gtime(dt.datetime(2026, 11, 2, 1, 2, 3)) == "20261102010203Z"                  # naive: UTC
    assert gtime(dt.datetime(2026, 11, 2, 1, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))) == "20261101230000Z"
    assert gtime_of_iso("2026-11-02T01:02:03Z") == "20261102010203Z"
    assert gtime_of_iso("2026-11-02T01:02:03") == "20261102010203Z"
    assert gtime_of_iso("soon") is None
    assert gtime_of_iso(None) is None


def test_cloud_role_tags_and_resource_types():
    assert tagged_role({"Role": "web", "BindingRole": "x"}) == "web"
    assert tagged_role({"BindingRole": "subnet-web"}) == "subnet-web"
    assert tagged_role({}) is None
    found = (("vm", {"n": 1}), ("disk", {"n": 2}), ("vm", {"n": 3}))
    assert of_types(found, "vm") == ({"n": 1}, {"n": 3})
    assert of_types(found, "vm", "disk") == ({"n": 1}, {"n": 2}, {"n": 3})
