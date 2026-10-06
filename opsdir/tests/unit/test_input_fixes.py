"""Fixes that take inputs: values the operator gives (a provider reference, a DNS name, a bucket), never guessed.
Nothing is proposed or applied until every input without a default has its values; an input given none leaves its
attribute out. A role the target lacks offers its source binding as a template: what is bound to the source's place is
given for the target's, contracts default to the source's, observed facts and dates are left out."""
from types import MappingProxyType

import pytest

from opsdir.cli import _fix_lines, _fix_size, _given
from opsdir.connectors.fixes import chosen, find_fix, previewed, proposal
from opsdir.connectors.plan import _check_roles
from opsdir.core.changeset import new_entry, set_values
from opsdir.core.directory import Directory, make_entry
from opsdir.core.environment import published_role
from opsdir.core.findings import Fix, Input, Option, filled_records, fix_inputs, templated_entry
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.infrastructure.external import (external_host_fix, external_hosts_fix, hosts_role, jdbc_hosts,
                                                    role_hosts, with_jdbc_hosts)
from network_fixtures import ALPHA, BETA, context, entry, model

HOST = make_entry(f"cn=h,ou=bindings,{BETA}", ("ciamThing",), {})
NAME = Input("name", "the DNS name", (), ("a.example.test",))
SIZE = Input("size", "how many", ("3",))
BUCKET = Input("bucket", "the bucket", (), (), r"s3://[a-z0-9.-]+")
FIX = Fix("k", "A", "Do it", (new_entry(HOST.dn, ("top", "ciamThing"), {"cn": ("h",), "ciamFqdn": (NAME,),
                                                                       "ciamSize": (SIZE,)}),
                              set_values(HOST, "ciamStorageRef", (BUCKET,))), (), ())


def test_inputs_are_found_once_in_order_and_previewed_by_key():
    assert fix_inputs((*FIX.records, *FIX.records)) == (NAME, SIZE, BUCKET)
    add, mod = previewed(FIX.records)
    assert (add.attrs["ciamFqdn"], add.attrs["ciamSize"], mod.mods) == (
        ("<name>",), ("<size>",), (("replace", "ciamStorageRef", ("<bucket>",)),))


def test_a_fix_with_inputs_needs_their_values_and_checks_them():
    with pytest.raises(ValueError, match=r"needs values: --input name=… \(e.g. a.example.test\), --input bucket=…"):
        chosen(FIX)
    with pytest.raises(ValueError, match="has no input colour"):
        chosen(FIX, given={"colour": ("red",)})
    with pytest.raises(ValueError, match=r"bucket=gs://b doesn't match s3://\[a-z0-9.-\]\+"):
        chosen(FIX, given={"name": ("b.example.test",), "bucket": ("gs://b",)})
    with pytest.raises(ValueError, match="offers no options"):
        chosen(FIX, "one", {"name": ("b.example.test",)})
    add, mod = chosen(FIX, given={"name": ("b.example.test",), "bucket": ("s3://b",)}).records
    assert (add.attrs["ciamFqdn"], add.attrs["ciamSize"], mod.mods) == (           # size: its default
        ("b.example.test",), ("3",), (("replace", "ciamStorageRef", ("s3://b",)),))
    assert "s3://b" in proposal(chosen(FIX, given={"name": ("n",), "bucket": ("s3://b",)}), "CHG-1").attrs[
        "ciamChangeRecords"][0]


def test_an_input_given_no_values_leaves_its_attribute_out():
    add, = chosen(FIX, given={"name": ("b.example.test",), "size": (), "bucket": ()}).records   # the modify: dropped
    assert "ciamSize" not in add.attrs
    kept = LdifRecord(HOST.dn, "modify", {}, (("delete", "ciamOld", ()), ("replace", "ciamFqdn", (NAME,))))
    assert filled_records((kept,), {"name": ()}) == (kept._replace(mods=(("delete", "ciamOld", ()),)),)


def test_an_options_inputs_are_given_after_choosing_it():
    choice = Fix("k", "A", "Do it", (), (), (), (Option("plain", "no inputs", (set_values(HOST, "ciamSize", ("1",)),),
                                                         ()),
                                                  Option("named", "a name", (set_values(HOST, "ciamFqdn", (NAME,)),),
                                                         ())))
    assert chosen(choice, "plain").records[0].mods == (("replace", "ciamSize", ("1",)),)
    with pytest.raises(ValueError, match="needs values: --input name"):
        chosen(choice, "named")
    assert chosen(choice, "named", {"name": ("n.example.test",)}).records[0].mods == (
        ("replace", "ciamFqdn", ("n.example.test",)),)


def _types(**kinds):
    return MappingProxyType({a: MappingProxyType({"value_type": vt, "portability": p}) for a, (vt, p) in kinds.items()})


def test_a_template_gives_what_is_bound_to_the_source_place_and_keeps_the_rest():
    d = Directory(_types(cn=("string", "meta"), ciamBindingRole=("string", "meta"), ciamPort=("port", "intent"),
                         ciamProviderRef=("string", "binding"), ciamRefUri=("ref-uri", "secret-ref"),
                         ciamFqdn=("fqdn", "contract"), ciamAllowsConsumer=("dn", "binding"),
                         ciamSubnet=("dn", "meta"), ciamReviewedOn=("time", "meta"), ciamSeen=("string", "observed"),
                         ciamChangeRef=("dn", "meta"), ciamOwner=("dn", "meta"), ciamPeer=("extdn", "intent")),
                  {}, {}, {})
    src = make_entry(f"cn=x,ou=bindings,{ALPHA}", ("top", "ciamThing"), {
        "cn": ("x",), "ciamBindingRole": ("x",), "ciamPort": ("1636",), "ciamProviderRef": ("vnet-alpha",),
        "ciamRefUri": ("vault://alpha/x",), "ciamFqdn": ("x.example.test",),
        "ciamAllowsConsumer": ("cn=app,ou=consumers,dc=ciam-ops",), "ciamSubnet": (f"cn=s,ou=bindings,{ALPHA}",),
        "ciamReviewedOn": ("20260101000000Z",), "ciamSeen": ("yes",),
        "ciamChangeRef": ("cn=CHG-1,ou=changes,dc=ciam-ops",), "ciamOwner": ("cn=net,ou=owners,dc=ciam-ops",),
        "ciamPeer": (f"cn=peer,ou=bindings,{ALPHA}",)})
    r = templated_entry(d, src, f"cn=x,ou=bindings,{BETA}", ALPHA, "x.")
    assert (r.dn, r.attrs["objectClass"]) == (f"cn=x,ou=bindings,{BETA}", ("top", "ciamThing"))
    assert {k: v for k, v in r.attrs.items() if not isinstance(v[0], Input)} == {
        "objectClass": ("top", "ciamThing"), "cn": ("x",), "ciamBindingRole": ("x",), "ciamPort": ("1636",),
        "ciamOwner": ("cn=net,ou=owners,dc=ciam-ops",)}         # not the change that made alpha's: that is alpha's
    assert [(i.key, i.default, i.example) for i in fix_inputs((r,))] == [
        ("x.ciamProviderRef", (), ("vnet-alpha",)),                         # bound to alpha's place: given
        ("x.ciamRefUri", (), ("vault://alpha/x",)),
        ("x.ciamFqdn", ("x.example.test",), ("x.example.test",)),           # a contract: alpha's unless changed
        ("x.ciamAllowsConsumer", ("cn=app,ou=consumers,dc=ciam-ops",),     # names something outside alpha
         ("cn=app,ou=consumers,dc=ciam-ops",)),
        ("x.ciamSubnet", (), (f"cn=s,ou=bindings,{ALPHA}",)),               # names something in alpha: given
        ("x.ciamPeer", (), (f"cn=peer,ou=bindings,{ALPHA}",))]


def _store(env, cn, ref, retention="35"):
    return entry(env, cn, "ciamBackupTarget", ciamBindingRole="backup-target", ciamStorageRef=ref,
                 ciamRetentionDays=retention)


def test_a_role_the_target_lacks_is_bound_like_the_source_with_the_targets_values():
    d, alpha, beta = model(alpha=(_store(ALPHA, "backup", "s3://alpha-backups"),))
    fix = find_fix(_check_roles(context(d, alpha, beta)).fixes, "binding:backup-target")
    assert (fix.key, fix.title, _fix_size(fix)) == (
        "binding:backup-target", "Bind `backup-target` in beta/prod like alpha/prod does", "1 (1 input)")
    (add,) = fix.records
    assert (add.dn, add.attrs["ciamRetentionDays"]) == (f"cn=backup,ou=bindings,{BETA}", ("35",))
    assert "  ciamStorageRef: this environment's own (the source's names its place) (e.g. s3://alpha-backups)" in \
           _fix_lines(fix)
    with pytest.raises(ValueError, match="needs values: --input ciamStorageRef=… \\(e.g. s3://alpha-backups\\)"):
        chosen(fix)
    records = chosen(fix, given=_given(["ciamStorageRef=azblob://beta/backups"])).records
    d, alpha, beta = model(alpha=(_store(ALPHA, "backup", "s3://alpha-backups"),), changes=records)
    assert "binding:backup-target" not in [f.key for f in _check_roles(context(d, alpha, beta)).fixes]


def test_several_bindings_of_the_role_are_told_apart_by_name():
    d, alpha, beta = model(alpha=(_store(ALPHA, "backup-a", "s3://a"), _store(ALPHA, "backup-b", "s3://b")))
    fix = find_fix(_check_roles(context(d, alpha, beta)).fixes, "binding:backup-target")
    assert [i.key for i in fix_inputs(fix.records)] == ["backup-a.ciamStorageRef", "backup-b.ciamStorageRef"]


def test_input_arguments():
    assert _given(["a=1", "a=2", "b=", "c=x=y"]) == {"a": ("1", "2"), "b": (), "c": ("x=y",)}
    with pytest.raises(SystemExit, match="--input a: give KEY=VALUE"):
        _given(["a"])
    assert _given([]) == {}


def test_a_fix_without_inputs_takes_none():
    plain = Fix("k", "A", "Do it", (set_values(HOST, "ciamSize", ("1",)),), (), ())
    with pytest.raises(ValueError, match="has no input name \\(inputs: none\\)"):
        chosen(plain, given={"name": ("n",)})
    assert chosen(plain) == plain


def test_two_different_inputs_may_not_share_a_key():
    clash = FIX._replace(records=(*FIX.records, set_values(HOST, "ciamOther", (NAME._replace(label="another"),))))
    with pytest.raises(ValueError, match="has two different inputs named name"):
        chosen(clash, given={"name": ("n",), "bucket": ("s3://b",)})


def test_an_external_host_is_recorded_under_a_role_the_operator_gives():
    d, alpha, _ = model()
    fix = external_host_fix(alpha, "hr.corp.example.test", "connector `hr`", "external-host:connector/hr",
                            "product/importer", 8443)
    assert [i.key for i in fix_inputs(fix.records)] == ["role"] and fix_inputs(fix.records)[0].example == ("hr",)
    (add,) = chosen(fix, given={"role": ("hr-database",)}).records
    assert (add.dn, add.attrs["ciamPort"], add.attrs["ciamBindingRole"]) == (
        f"cn=ext-hr-corp-example-test,ou=bindings,{ALPHA}", ("8443",), ("hr-database",))
    with pytest.raises(ValueError, match="role=HR doesn't match"):
        chosen(fix, given={"role": ("HR",)})
    d, _, _ = model(changes=(add,))
    assert published_role(d, "HR.corp.example.test") == "hr-database"


def test_several_hosts_are_one_role_in_the_settings_order_and_one_host_is_the_single_host_fix():
    d, alpha, _ = model()
    one_host = external_hosts_fix(alpha, ("hr.corp.example.test:5432",), "connector `hr`", "k", "product/importer")
    assert one_host == external_host_fix(alpha, "hr.corp.example.test", "connector `hr`", "k", "product/importer")
    assert external_hosts_fix(alpha, (), "connector `hr`", "k", "product/importer") is None
    fix = external_hosts_fix(alpha, ("zz.corp.example.test:5432", "aa.corp.example.test:5433"), "connector `hr`",
                             "k", "product/importer")
    assert [i.key for i in fix_inputs(fix.records)] == ["role"]                   # one role for every host
    adds = chosen(fix, given={"role": ("hr-database",)}).records
    d, alpha, beta = model(changes=adds)
    assert hosts_role(d, ("zz.corp.example.test:5432", "AA.corp.example.test:5433")) == ("hr-database", None)
    assert role_hosts(alpha, "hr-database") == ("zz.corp.example.test:5432", "aa.corp.example.test:5433")
    assert role_hosts(alpha, "hr-database", 6000) == ("zz.corp.example.test:6000", "aa.corp.example.test:6000")
    assert role_hosts(beta, "hr-database", 5432) == ("UNBOUND:hr-database:5432",)


def test_jdbc_urls_give_and_take_their_hosts():
    url = "jdbc:postgresql://a.example.test:5432,b.example.test:5433/hr?ssl=true"
    assert jdbc_hosts(url) == ("a.example.test:5432", "b.example.test:5433")
    assert with_jdbc_hosts(url, ()) == "jdbc:postgresql:///hr?ssl=true"
    assert with_jdbc_hosts("jdbc:postgresql:///hr?ssl=true", ("c.example.test",)) == \
        "jdbc:postgresql://c.example.test/hr?ssl=true"
    assert (jdbc_hosts("https://x.example.test/"), jdbc_hosts(None), with_jdbc_hosts(None, ("h",))) == ((), (), None)
