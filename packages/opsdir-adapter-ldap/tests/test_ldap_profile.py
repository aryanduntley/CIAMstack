"""The importer ldap/data-profile: profile files written by `opsdir data-profile` become each environment's data
profile, one per environment (a newer file wins, re-importing changes nothing); files that aren't profiles, or
describe an environment the record doesn't have, are named and not imported."""
import datetime as dt
import json

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one
from opsdir.core.interchange.ldif import parse
from opsdir.domains.directory.profile import profile, profile_dn, profile_json
from opsdir_adapter_ldap.adapter import ADAPTER
import mini_estate
from support import REGISTRY, build_directory

PEOPLE = "ou=people,dc=example,dc=com"
DATA = ((f"uid=ann,{PEOPLE}", {"objectClass": ("inetOrgPerson",), "uid": ("ann",)}),
        (f"uid=bob,{PEOPLE}", {"objectClass": ("inetOrgPerson",), "uid": ("bob",)}))


def _file(label, n, day):
    return profile_json(profile(iter(DATA[:n]), dt.date(2026, 9, day)), label,
                        dt.datetime(2026, 9, day, 12, tzinfo=dt.timezone.utc))


def _import(files, records=()):
    base = build_directory(REGISTRY, (*parse(mini_estate.LDIF), *records))
    changes, notices = preview_import(base, "ldap/data-profile", files, (ADAPTER,))
    return build_directory(REGISTRY, (*parse(mini_estate.LDIF), *records), changes), changes, notices


def test_a_profile_file_becomes_the_environments_data_profile():
    d, changes, notices = _import({"alpha.json": _file("alpha/prod", 2, 20)})
    p = get(d, profile_dn("alpha/prod"))
    assert (one(p, "ciamEntryCount"), one(p, "ciamCapturedAt"), notices) == ("2", "20260920120000Z", ())
    assert preview_import(d, "ldap/data-profile", {"alpha.json": _file("alpha/prod", 2, 20)}, (ADAPTER,))[0] == ()


def test_the_latest_file_per_environment_wins():
    d, _, notices = _import({"old.json": _file("alpha/prod", 2, 20), "new.json": _file("alpha/prod", 1, 22)})
    assert one(get(d, profile_dn("alpha/prod")), "ciamEntryCount") == "1"
    assert notices == ("old.json: alpha/prod is also described by new.json, taken later (20260922120000Z); not "
                       "imported",)


def test_what_cant_be_recorded_is_named():
    tampered = json.loads(_file("alpha/prod", 2, 20))
    tampered["branches"] = {f"uid=ann,{PEOPLE}": {"entries": 1, "classes": {}}}
    _, changes, notices = _import({"t.json": json.dumps(tampered), "gamma.json": _file("gamma/prod", 1, 20),
                                   "people.ldif": "dn: uid=ann"})
    assert changes == ()
    assert notices == ("t.json: not a data profile (a branch names a value (only containers and attr=* may appear) "
                       "or isn't counted); not imported",
                       "gamma.json: environment gamma/prod isn't in the record; not imported",
                       "people.ldif: not a profile file (.json); skipped")
