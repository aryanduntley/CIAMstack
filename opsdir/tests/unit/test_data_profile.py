"""The data profile: an environment's user data read once as a stream and reduced to counts (branches with
non-container RDNs masked, password schemes only by known names, ages in buckets, group health), the profile file
`opsdir data-profile` writes without a database and what reading it back refuses, the record's entries for it, its
reports, and the planner's findings about the source's data."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse, write_entry
from opsdir.domains.directory.naming import DECLARED, USER_SCHEMA
import json

import pytest

from opsdir import cli
from opsdir.connectors.profiling import profile_file, profile_terms
from opsdir.domains.directory.profile import (NO_SCHEME, STANDARD, UNRECOGNIZED, Terms, age_bucket,
                                              attribute_rows, branch_of, check_data_profile, combined,
                                              defined_terms, entry_facts, masked, profile, profile_dn, profile_entries,
                                              profile_json, profile_rows, read_profile, scheme_of)
import mini_estate
from support import REGISTRY, build_directory

AS_OF = dt.date(2026, 9, 23)
PEOPLE, GROUPS = "ou=people,dc=example,dc=com", "ou=groups,dc=example,dc=com"
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"


def _person(uid, **attrs):
    return (f"uid={uid},{PEOPLE}", {"objectClass": ("top", "inetOrgPerson"), "uid": (uid,), **attrs})


DATA = (
    ("dc=example,dc=com", {"objectClass": ("top", "domain"), "dc": ("example",)}),
    (PEOPLE, {"objectClass": ("top", "organizationalUnit"), "ou": ("people",)}),
    _person("ann", mail=("ann@example.test",), userPassword=("{SSHA512}c2VjcmV0",),
            pwdChangedTime=("20260101000000Z",), pwdLastSuccess=("20260920101010Z",)),
    _person("bob", userPassword=(b"{PBKDF2-HMAC-SHA256}100:abc",), pwdLastSuccess=("20240101000000Z",),
            pwdAccountLockedTime=("20260901000000Z",)),
    _person("cy", userPassword=("{Summer2024}hunter2",)),          # not a scheme: a clear-text password with braces
    _person("dee", userPassword=("plain-text",), pwdLastSuccess=("not-a-time",)),
    (f"ou=devices,uid=bob,{PEOPLE}", {"objectClass": ("top", "organizationalUnit"), "ou": ("devices",)}),
    (GROUPS, {"objectClass": ("top", "organizationalUnit"), "ou": ("groups",)}),
    (f"cn=admins,{GROUPS}", {"objectClass": ("top", "groupOfNames"), "cn": ("admins",),
                             "member": (f"uid=ann,{PEOPLE}", f"UID=Bob, {PEOPLE}", f"uid=gone,{PEOPLE}")}),
    (f"cn=empty,{GROUPS}", {"objectClass": ("top", "groupOfUniqueNames"), "cn": ("empty",)}),
)


def test_a_branch_masks_every_rdn_that_is_not_a_container():
    assert branch_of(f"uid=ann,{PEOPLE}") == PEOPLE
    assert branch_of(f"cn=phone,ou=devices,uid=bob,{PEOPLE}") == f"ou=devices,uid=*,{PEOPLE}"
    assert branch_of("dc=com") is None


def test_only_known_schemes_are_named():
    assert scheme_of("userpassword", "{ssha512}abc", STANDARD.schemes) == "SSHA512"
    assert scheme_of("userpassword", "{Summer2024}hunter2", STANDARD.schemes) == UNRECOGNIZED
    assert scheme_of("userpassword", b"plain", STANDARD.schemes) == NO_SCHEME
    assert scheme_of("authpassword", "SHA256$c2FsdA==$aGFzaA==", STANDARD.schemes) == "SHA256"


def test_ages_fall_into_buckets():
    assert [age_bucket(s, AS_OF) for s in ("20260920000000Z", "20260701000000Z", "20260101000000Z",
                                           "20250101000000Z", "20200101000000Z", None, "yesterday")] == \
        ["<30d", "30-90d", "90-365d", "1-2y", ">2y", "never", "unreadable"]


def test_one_entry_keeps_no_value():
    facts = entry_facts(DATA[2], AS_OF)
    assert (facts.branch, facts.schemes, facts.login, facts.changed, facts.members) == \
        (PEOPLE, ("SSHA512",), "<30d", "90-365d", None)
    assert "ann" not in repr(facts) and "c2VjcmV0" not in repr(facts)
    assert entry_facts(DATA[1], AS_OF).login is None               # a container is not an account


def test_the_profile_counts_the_stream():
    p = profile(iter(DATA), AS_OF)
    assert p.entries == len(DATA)
    assert p.branches[PEOPLE].entries == 4 and dict(p.branches[PEOPLE].classes) == {"inetOrgPerson": 4, "top": 4}
    assert p.branches[f"uid=*,{PEOPLE}"].entries == 1
    assert dict(p.schemes) == {NO_SCHEME: 1, "PBKDF2-HMAC-SHA256": 1, "SSHA512": 1, UNRECOGNIZED: 1}
    assert dict(p.last_login) == {"<30d": 1, ">2y": 1, "never": 1, "unreadable": 1}
    assert (p.locked, p.groups, p.empty_groups, p.largest_group, p.dangling_members) == (1, 2, 1, 3, 1)
    assert p.attributes["mail"] == (1, 1, len("ann@example.test")) and p.attributes["member"].most_values == 3
    assert "hunter2" not in repr(p) and "Summer2024" not in repr(p) and "ann@example.test" not in repr(p)


def test_counting_in_chunks_changes_nothing():
    assert profile(iter(DATA), AS_OF, chunk=3) == profile(iter(DATA), AS_OF)
    assert profile(iter(()), AS_OF).entries == 0


def test_a_product_extends_what_attributes_mean():
    ds = Terms(password=(), schemes=frozenset({"SUMMER2024"}), last_login=("ds-pwp-last-login-time",),
               password_changed=(), locked=(), disabled=(("ds-pwp-account-disabled", "true"),), pending=(), kba=(),
               member=(), group_classes=(), operational=())
    terms = combined(STANDARD, ds)
    assert terms.last_login == ("pwdLastSuccess", "ds-pwp-last-login-time") and "SUMMER2024" in terms.schemes
    disabled = _person("eve", **{"ds-pwp-account-disabled": ("TRUE",), "ds-pwp-last-login-time": ("20260915000000Z",)})
    p = profile(iter((disabled,)), AS_OF, terms)
    assert (p.disabled, dict(p.last_login)) == (1, {"<30d": 1})


# ------------------------------------------------------------------ the record
RECORDS = "\n".join((
    f"dn: cn=ds-1,{ALPHA}\nobjectClass: top\nobjectClass: ciamServer\ncn: ds-1\nciamServerRole: ds\n"
    f"ciamHostname: ds-1.alpha.example.test\nciamSubnet: cn=net,ou=bindings,{ALPHA}\n",
    f"dn: {USER_SCHEMA}\nobjectClass: top\nobjectClass: organizationalUnit\nou: user-schema\n",
    f"dn: cn=mail,{USER_SCHEMA}\nobjectClass: top\nobjectClass: ciamUserAttribute\ncn: mail\nciamLdapName: mail\n"
    "ciamPiiClass: moderate\n",
    f"dn: cn=uid,{USER_SCHEMA}\nobjectClass: top\nobjectClass: ciamUserAttribute\ncn: uid\nciamLdapName: uid\n"
    "ciamPiiClass: low\n",
    f"dn: {DECLARED}\nobjectClass: top\nobjectClass: organizationalUnit\nou: declared\n",
    f"dn: ou=password-policies,{DECLARED}\nobjectClass: top\nobjectClass: organizationalUnit\nou: password-policies\n",
    f"dn: cn=default,ou=password-policies,{DECLARED}\nobjectClass: top\nobjectClass: ciamPasswordPolicy\ncn: default\n"
    "ciamStorageScheme: PBKDF2-HMAC-SHA256\n",
    "dn: ou=data-profile,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: data-profile\n"))


def _record(with_profile=True):
    base = tuple(parse(mini_estate.LDIF + "\n" + RECORDS))
    d = build_directory(REGISTRY, base)
    if not with_profile:
        return d
    _, entries = profile_entries(d, "alpha/prod", profile(iter(DATA), AS_OF), dt.datetime(2026, 9, 23, 12))
    return build_directory(REGISTRY, (*base, *parse("\n".join(write_entry(e.dn, e.classes, e.attrs) for e in entries))))


def test_the_profile_becomes_entries_the_record_accepts():
    d = _record()
    p = get(d, profile_dn("alpha/prod"))
    assert (one(p, "ciamProfiledEnvironment"), one(p, "ciamEntryCount"), one(p, "ciamCapturedAt")) == \
        (ALPHA, str(len(DATA)), "20260923120000Z")
    assert values(p, "ciamHashSchemeCount") == ("PBKDF2-HMAC-SHA256=1", "SSHA512=1", "none=1", "unrecognized=1")
    mail = get(d, f"cn=mail,ou=attributes,{p.dn}")
    assert (one(mail, "ciamHolderCount"), one(mail, "ciamProfiledAttribute")) == ("1", f"cn=mail,{USER_SCHEMA}")
    assert one(get(d, f"cn=uid-any.people.example.com,ou=branches,{p.dn}"), "ciamProfiledBranch") == \
        f"uid=*,{PEOPLE}"


def test_the_reports():
    d = _record()
    assert profile_rows(d)[0][:3] == ("alpha/prod", "20260923", str(len(DATA)))
    rows = {r[1]: r for r in attribute_rows(d)}
    assert rows["mail"][2:] == ("1", "10.0%", "1", str(len("ann@example.test")), "yes")
    assert rows["cn"][-1] == "no"


def _plan(d):
    return check_data_profile(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None,
                                          dt.date(2026, 10, 1), {}, {}, ()))


def test_the_planner_reads_the_sources_data():
    f = _plan(_record())
    texts = [t for _, t, _, _ in f.actions]
    assert "1 password value(s) in alpha/prod are hashed with SSHA512, which no declared password policy uses as " \
           "its default storage scheme: keep SSHA512 enabled on beta/prod's servers, or rehash on login (a " \
           "deprecated storage scheme)." in texts
    assert not any("PBKDF2-HMAC-SHA256" in t for t in texts)      # the default policy's scheme
    assert any(t.startswith("1 password value(s) in alpha/prod carry no storage scheme") for t in texts)
    assert any(t.startswith("1 password value(s) in alpha/prod use a storage scheme the profile doesn't know")
               for t in texts)
    assert "1 attribute(s) in alpha/prod's user data have no ou=user-schema record, so no PII class: cn (2). " \
           "Describe them before the move." in texts                     # ou, dc, member, ... are structure
    assert "1 member DN(s) of alpha/prod's groups name entries that don't exist (or weren't profiled): clean them " \
           "up before the move." in texts
    assert f.ok == ("alpha/prod's user data was profiled on 20260923: 10 entries, 1 not logged in for a year or "
                    "more, 1 never.",)


def test_no_profile_is_an_action_when_the_source_has_a_directory():
    assert [t for _, t, _, _ in _plan(_record(with_profile=False)).actions] == [
        "The shape of alpha/prod's user data is unknown: profile it (ldapsearch ... | opsdir data-profile) to size "
        "the move and find legacy password schemes and attributes the record doesn't describe."]


# ------------------------------------------------------------------ the profile file
CAPTURED = dt.datetime(2026, 9, 23, 12, tzinfo=dt.timezone.utc)


def test_the_profile_file_reads_back_as_written():
    p = profile(iter(DATA), AS_OF)
    f, why = read_profile(profile_json(p, "alpha/prod", CAPTURED))
    assert (why, f.label, f.captured, f.profile) == (None, "alpha/prod", CAPTURED, p)


@pytest.mark.parametrize("edit, why", [
    (lambda d: d["branches"].update({f"uid=ann,{PEOPLE}": {"entries": 1, "classes": {}}}), "a branch names a value"),
    (lambda d: d["schemes"].update({"hunter2!": 1}), "a password scheme isn't a scheme name"),
    (lambda d: d["attributes"].update({"mail: ann@example.test": {"holders": 1, "most_values": 1,
                                                                  "largest_bytes": 1}}), "an attribute isn't a name"),
    (lambda d: d.update(locked="many"), "a count is not a number"),
    (lambda d: d.update(environment="prod"), "environment is not cloud/env"),
    (lambda d: d["last_login"].update({"yesterday": 1}), "an age bucket is unknown"),
])
def test_a_profile_file_holding_anything_but_counts_is_refused(edit, why):
    doc = json.loads(profile_json(profile(iter(DATA), AS_OF), "alpha/prod", CAPTURED))
    edit(doc)
    assert read_profile(json.dumps(doc))[1].startswith(why)
    assert masked(f"uid=*,{PEOPLE}") and not masked(f"cn=Ann Smith,{PEOPLE}")


def test_installed_adapters_extend_the_standard_terms():
    terms = profile_terms()
    assert {"pwdLastSuccess", "ds-last-login-time"} <= set(terms.last_login)       # opsdir-base-ds's, via PingDS
    assert ("ds-pwp-account-disabled", "true") in terms.disabled


def test_data_profile_reads_ldif_and_needs_no_database(tmp_path, monkeypatch):
    ldif = tmp_path / "people.ldif"
    ldif.write_text("version: 1\n\ndn: uid=ann,ou=people,dc=example,dc=com\nobjectClass: inetOrgPerson\nuid: ann\n"
                    "ds-last-login-time: 20260922101010Z\nds-pwp-account-disabled: TRUE\n\nsearch: 2\nresult: 0\n")
    monkeypatch.setattr(cli.db, "connect", lambda *a: pytest.fail("data-profile must not open the database"))
    out = tmp_path / "profile.json"
    cli.main(["--as-of", "2026-09-23", "data-profile", "--env", "alpha/prod", str(ldif), "--at", "20260923120000Z",
              "-o", str(out)])
    f, why = read_profile(out.read_text())
    assert (why, f.profile.entries, dict(f.profile.last_login), f.profile.disabled) == (None, 1, {"<30d": 1}, 1)
    assert out.read_text() == profile_file(ldif.read_text().splitlines(True), "alpha/prod", AS_OF, CAPTURED)


def test_an_estate_defines_its_own_terms():
    terms, refused = defined_terms(("last-login=lastLoginTime", "pending=registrationStatus=pending",
                                    "kba=challengeAnswer", "scheme=legacy1", "colour=blue", "kba="))
    assert (terms.last_login, terms.pending, terms.kba, terms.schemes, refused) == \
        (("lastLoginTime",), (("registrationStatus", "pending"),), ("challengeAnswer",), frozenset({"LEGACY1"}),
         ("colour=blue", "kba="))
    person = _person("fay", lastLoginTime=("20260901000000Z",), registrationStatus=("PENDING",),
                     challengeAnswer=("x",), createTimestamp=("20200101000000Z",))
    p = profile(iter((person,)), AS_OF, combined(STANDARD, terms))
    assert (dict(p.last_login), p.pending, p.kba) == ({"<30d": 1}, 1, 1)
    assert "createtimestamp" not in p.attributes                      # operational: not user data


def test_an_unknown_term_is_refused_before_anything_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.db, "connect", lambda *a: pytest.fail("data-profile must not open the database"))
    with pytest.raises(SystemExit, match="--term: not a term .*colour=blue"):
        cli.main(["data-profile", "--env", "alpha/prod", "--term", "colour=blue", str(tmp_path / "missing.ldif")])
