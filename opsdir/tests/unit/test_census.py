"""The census: the record's values found in files as whole tokens (an address not inside a longer one, a name not
inside a longer name, a DN whatever its spacing, a fingerprint with or without colons), each occurrence pointing at
the entry the value belongs to; secret material flagged by line, never stored; a file taken from a server attributed
to it; an unchanged file changing nothing; and the planner asking to change the files that hard-code a value of the
source environment the target doesn't keep."""
import datetime as dt
from types import SimpleNamespace

from opsdir.connectors.importing import import_changes
from opsdir.core.contract import Imported
from opsdir.core.directory import make_directory
from opsdir.core.secrets import CORE_PATTERNS as GENERIC
from opsdir.domains.configuration.census import census_groups, census_rows, check_census, found_in, needles

SRC = "env=prod,cloud=source,ou=environments,dc=ciam-ops"
DST = "env=prod,cloud=target,ou=environments,dc=ciam-ops"
TYPES = (("ciamHostname", "fqdn", "binding"), ("ciamPrivateIp", "ip", "binding"), ("ciamFqdn", "fqdn", "contract"),
         ("ciamBindDn", "extdn", "intent"), ("ciamFingerprint", "string", "meta"), ("ciamOccurrenceOf", "dn", "observed"),
         ("ciamOnServer", "dn", "observed"), ("ciamObservedSource", "cidr", "observed"))


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record(*extra):
    return make_directory(TYPES, {}, (
        _row(f"cn=ds-1,{SRC}", ("ciamServer",), cn="ds-1", ciamHostname="ds-1.src.example.test",
             ciamPrivateIp="10.20.1.1"),
        _row(f"cn=ds-1,{DST}", ("ciamServer",), cn="ds-1", ciamHostname="ds-1.dst.example.test",
             ciamPrivateIp="10.60.1.1"),
        _row(f"cn=svc-ldaps,ou=bindings,{SRC}", ("ciamServiceName",), cn="svc-ldaps", ciamFqdn="ldap.example.test"),
        _row(f"cn=svc-ldaps,ou=bindings,{DST}", ("ciamServiceName",), cn="svc-ldaps", ciamFqdn="ldap.example.test"),
        _row("cn=app,ou=consumers,dc=ciam-ops", ("ciamConsumer",), cn="app",
             ciamBindDn="uid=app,ou=service-accounts,dc=example,dc=test", ciamObservedSource="10.99.0.0/16"),
        _row("cn=tls,ou=certificates,dc=ciam-ops", ("ciamCertificate",), cn="tls",
             ciamFingerprint="AB:CD:EF:01:23:45:67:89"),
        *extra))


FILES = {"ds-1.src.example.test/opt/sync.sh": (
             "ldapsearch -H ldaps://ds-1.src.example.test:1636 -D 'uid=app, ou=service-accounts, dc=example, dc=test'\n"
             "scp out.ldif ops@10.20.1.1:/in/   # not 10.20.1.10, nor ds-1.src.example.test.old\n"),
         "apps/web/app.properties": ("ldap.url=ldaps://ldap.example.test:1636\npin.sha256=abcdef0123456789\n"
                                     "ldap.password=Wint3rIsC0ming!2026\n")}


def _found(d, text):
    return {(owner.split(",")[0], attr): lines for (owner, attr), lines in found_in(text, needles(d)).items()}


def test_values_are_found_as_whole_tokens_and_point_at_their_entries():
    d = _record()
    assert _found(d, FILES["ds-1.src.example.test/opt/sync.sh"]) == {
        ("cn=ds-1", "ciamHostname"): (1,), ("cn=ds-1", "ciamPrivateIp"): (2,), ("cn=app", "ciamBindDn"): (1,)}
    assert _found(d, "a 10.20.1.10 and 110.20.1.1 and ds-1.src.example.test.old and xds-1.src.example.test") == {}
    assert _found(d, FILES["apps/web/app.properties"]) == {("cn=svc-ldaps", "ciamFqdn"): (1,), ("cn=tls",
                                                                                                "ciamFingerprint"): (2,)}


def test_observed_values_are_not_looked_for():
    assert not any(n.attr == "ciamObservedSource" for n in needles(_record()))


def test_a_scanned_file_is_recorded_with_its_server_its_occurrences_and_its_concerns_by_line_only():
    d = _record()
    groups, notices = census_groups(d, FILES, GENERIC)
    entries = {e.dn: e for _, es in groups for e in es}
    sync = next(e for e in entries.values() if e.attrs.get("ciamRepoPath") == ("opt/sync.sh",))
    assert sync.attrs["ciamOnServer"] == (f"cn=ds-1,{SRC}",)
    web = next(e for e in entries.values() if e.attrs.get("ciamRepoPath") == ("apps/web/app.properties",))
    assert all(c.startswith("line 3: ") for c in web.attrs["ciamConcern"])
    assert "Wint3r" not in str([dict(e.attrs) for e in entries.values()])
    assert notices == ("2 file(s) scanned for 8 values of the record: 6 found",
                       "apps/web/app.properties: may hold secret material (see its concerns; nothing of it is stored)")


def _after(d, groups):
    scopes = [s.lower() for s, _ in groups]
    kept = {n: e for n, e in d.entries.items() if not any(n == s or n.endswith("," + s) for s in scopes)}
    return d._replace(entries={**kept, **{e.norm: e for _, es in groups for e in es}})


def test_scanning_an_unchanged_file_again_changes_nothing():
    d = _record()
    after = _after(d, census_groups(d, FILES, GENERIC)[0])
    assert not import_changes(after, Imported((), census_groups(after, FILES, GENERIC)[0], ()))


def test_the_report_lists_every_value_found_or_one_entrys():
    d = _record()
    after = _after(d, census_groups(d, FILES, GENERIC)[0])
    assert len(census_rows(after)) == 6        # the service name belongs to both environments' bindings
    assert [r[:5] for r in census_rows(after, f"cn=ds-1,{SRC}")] == [
        ("opt/sync.sh", "ds-1", f"cn=ds-1,{SRC}", "ciamHostname", "1"),
        ("opt/sync.sh", "ds-1", f"cn=ds-1,{SRC}", "ciamPrivateIp", "2")]


def test_the_planner_asks_to_change_files_that_hard_code_source_values_the_target_doesnt_keep():
    d = _record()
    after = _after(d, census_groups(d, FILES, GENERIC)[0])
    env = lambda dn: SimpleNamespace(label=dn.split(",")[1].split("=")[1] + "/prod", env=None,  # noqa: E731
                                     servers=tuple(e for e in after.entries.values() if "ciamServer" in e.classes
                                                   and e.norm.endswith(dn)),
                                     bindings=tuple(e for e in after.entries.values() if "ciamServiceName" in e.classes
                                                    and e.norm.endswith(dn)))
    ctx = SimpleNamespace(d=after, src=env(SRC), dst=env(DST), as_of=dt.date(2026, 9, 23))
    (action,) = check_census(ctx).actions
    assert action[0] == "Hard-coded" and action[1] == (
        "`opt/sync.sh` on ds-1 holds source/prod values that change in target/prod: ds-1 ciamHostname (line 1); "
        "ds-1 ciamPrivateIp (line 2).")                  # the service name is kept in the target: nothing to change


def test_branches_excluded_are_not_looked_for():
    d = _record(_row("cn=snap,ou=observed,ou=config,dc=ciam-ops", ("ciamServer",), cn="snap",
                     ciamHostname="copy.example.test"))
    assert any(n.value == "copy.example.test" for n in needles(d))
    assert not any(n.value == "copy.example.test" for n in needles(d, ("ou=observed,ou=config,dc=ciam-ops",)))
