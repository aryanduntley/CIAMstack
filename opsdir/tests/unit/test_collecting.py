"""Collecting an export from the live system (connectors.collecting, live, governance collection sources and import
runs): rounds until the collector asks for nothing new, complete or not imported (a failing call, a collector asking
past its bounds, a debug switch), the evidence a complete one leaves, credentials resolved once and only ever on
standard input or in a GET's header, masked in error output; estate collectors derived from importers' provider
commands; collection sources resolved against their environment."""
import datetime as dt
import http.server
import threading
from types import SimpleNamespace

from opsdir import live
from opsdir.connectors import collecting
from opsdir.connectors.collecting import MASK, chosen, collect, collectors, evidence, first_calls, provenance, redact
from opsdir.core.contract import Collector, Command, Importer, Request
from opsdir.domains.governance.collection import collection_sources
from opsdir.domains.governance.attempts import Attempt, attempt_dn, attempt_records, attempt_rows
from opsdir.domains.governance.imports import run_records
from network_fixtures import ALPHA, entry, model

AT = dt.datetime(2026, 10, 8, 12, 0, tzinfo=dt.timezone.utc)
ENV = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"


def _lists(d, m, done, options):
    """A two-stage collector: zones.json lists zones, then one records file per zone."""
    first = (("zones.json", Command(("tool", "list-zones"))),)
    zones = done.get("zones.json", "").split()
    return (*first, *((f"records/{z}.json", Command(("tool", "list-records", "--zone", z))) for z in zones))


TWO_STAGE = Collector("dns", "environment", _lists)


def _runner(outputs, failing=()):
    seen = []

    def run(call):
        seen.append(call.argv)
        key = " ".join(call.argv)
        return (None, "denied") if key in failing else (outputs.get(key, ""), None)
    return run, seen


def test_rounds_until_nothing_new_and_the_evidence():
    run, seen = _runner({"tool list-zones": "z1 z2", "tool list-records --zone z1": "[1]",
                         "tool list-records --zone z2": "[2]"})
    c = collect("cloud/dns", TWO_STAGE, None, None, run, identity="arn:aws:iam::111122223333:role/reader")
    assert c.problems == () and c.files == {"zones.json": "z1 z2", "records/z1.json": "[1]", "records/z2.json": "[2]"}
    assert len(seen) == 3                                       # each call once
    ev = evidence(c)
    assert ev["ciamCollectionIdentity"] == ("arn:aws:iam::111122223333:role/reader",)
    assert ev["ciamCollectedCall"][0].endswith(" zones.json <- tool list-zones") and len(ev["ciamCollectedCall"]) == 3
    assert ev["ciamCollectionCredential"] == ()


def test_a_failing_call_leaves_it_incomplete_and_not_imported():
    run, _ = _runner({"tool list-zones": "z1 z2"}, failing=("tool list-records --zone z2",))
    c = collect("cloud/dns", TWO_STAGE, None, None, run)
    assert c.files is None
    assert c.problems == ("records/z2.json (tool list-records --zone z2): denied",)
    assert [x.problem for x in c.calls] == [None, None, "denied"] and c.calls[2].sha256 is None


def test_bounds_and_debug_switches():
    endless = Collector("x", "environment", lambda d, m, done, o: ((f"f{len(done)}", Command(("tool", "next"))),))
    run, _ = _runner({})
    c = collect("cloud/x", endless, None, None, run)
    assert c.files is None and "still asking for more after 8 rounds" in c.problems[0]
    stop = Collector("z", "environment", lambda d, m, done, o: (("a", Command(("tool", "who"))),
                                                                 *((("b", "signed in elsewhere"),) if "a" in done else ())))
    c = collect("cloud/z", stop, None, None, run)
    assert (c.files, c.problems, len(c.calls)) == (None, ("signed in elsewhere",), 1)      # a step naming a problem
    noisy = Collector("y", "environment", lambda d, m, done, o: (("a", Command(("aws", "ec2", "x", "--debug"))),))
    assert collect("cloud/y", noisy, None, None, run).problems == (
        "aws ec2 x --debug: debug switches are never run (--debug)",)


def test_provenance_never_holds_a_credential():
    call = Command(("ldapsearch", "-y", "/dev/stdin", "-b", "cn=config"), ("vault://kv/ds#pw",),
                   lambda s: s["vault://kv/ds#pw"])
    assert provenance(call) == "ldapsearch -y /dev/stdin -b cn=config (credentials on standard input)"
    assert provenance(Request("https://pf:9999/pf-admin-api/v1/bulk/export",
                              credential=("basic", "vault://kv/pf#pw", "reader"))) == \
        "GET https://pf:9999/pf-admin-api/v1/bulk/export"
    assert collecting.credential_refs(Request("https://x", credential=("bearer", "r1", None), ca="r2")) == ("r1", "r2")
    assert redact("bad password hunter22 for AKIAABCDEFGHIJKLMNOP", ("hunter22",), (r"AKIA[A-Z0-9]{16}",)) == \
        f"bad password {MASK} for {MASK}"


def test_estate_collectors_come_from_importers_provider_commands():
    imp = Importer("regions", "region list", None, (("regions.json", ("tool", "regions")),))
    adapter = type("A", (), {"name": "cloud", "collectors": (TWO_STAGE,),
                             "importers": (imp, Importer("files", "f", None))})()
    found = collectors(adapter)
    assert [(c.importer, c.scope) for c in found] == [("dns", "environment"), ("regions", "estate")]
    assert first_calls(found[1], None, None) == (("regions.json", Command(("tool", "regions"))),)
    assert [c.importer for _, c in chosen((adapter,), "estate")] == ["regions"]
    assert chosen((adapter,), "environment", "cloud/regions") == ()


def test_commands_run_with_credentials_on_standard_input_only():
    resolve = lambda ref: ({"fake://pw": ("s3cret-value", None)}).get(ref, (None, f"unknown {ref}"))
    out, problem = live.run_call(Command(("cat",), ("fake://pw",), lambda s: f"password={s['fake://pw']}"), resolve)
    assert (out, problem) == ("password=s3cret-value", None)
    out, problem = live.run_call(Command(("sh", "-c", "cat >&2; exit 3"), ("fake://pw",),
                                         lambda s: s["fake://pw"]), resolve)
    assert out is None and problem == f"exit 3: {MASK}"                 # its error output, the credential masked
    assert live.run_call(Command(("no-such-tool-here",)), resolve) == (None, "no-such-tool-here is not installed here")
    assert live.run_call(Command(("cat",), ("fake://other",), None), resolve) == (None, "unknown fake://other")


def test_requests_are_gets_with_the_credential_in_the_header():
    got = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            got.append((self.command, self.path, self.headers.get("Authorization"), self.headers.get("X-XSRF-Header")))
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    resolve = lambda ref: ("pw", None)
    url = f"http://127.0.0.1:{server.server_port}/pf-admin-api/v1/bulk/export"
    out, problem = live.run_call(Request(url, (("X-XSRF-Header", "PingFederate"),), ("basic", "fake://pw", "reader")),
                                 resolve)
    server.server_close()
    assert (out, problem) == ('{"ok": true}', None)
    assert got == [("GET", "/pf-admin-api/v1/bulk/export", "Basic cmVhZGVyOnB3", "PingFederate")]   # reader:pw


def test_the_resolver_resolves_each_reference_once():
    resolve = live.resolver()
    assert resolve("nosuch://x")[0] is None and "no resolver for secret scheme nosuch" in resolve("nosuch://x")[1]
    assert resolve.cache_info().hits == 1


def test_collection_sources_resolve_against_their_environment():
    _, alpha, _ = model(alpha=(
        entry(ALPHA, "pf-admin", "ciamCollectionSource", ciamBindingRole="collect-pf", ciamImporter="pingfederate/bulk",
              ciamTargetRole="web", ciamPort="9999", ciamCredentialRole="pf-reader", ciamLoginName="reader",
              ciamCaRole="pf-ca"),
        entry(ALPHA, "pf-reader", "ciamSecretRef", ciamBindingRole="pf-reader", ciamRefUri="fake://kv/pf-reader"),
        entry(ALPHA, "state", "ciamCollectionSource", ciamBindingRole="collect-state",
              ciamImporter="cloud/terraform-state", ciamSourceRef="s3://tf-state/env:/prod/ciam.tfstate")))
    (pf,) = collection_sources(alpha, "pingfederate/bulk")
    assert pf.locations == ("https://web-1.example.test:9999",)
    assert pf.credential == "fake://kv/pf-reader" and pf.login == "reader" and pf.ca is None
    assert pf.problems == ("collection source `pf-admin`: role `pf-ca` (its trust anchor) isn't bound in alpha/prod",)
    (state,) = collection_sources(alpha, "cloud/terraform-state")
    assert state.locations == ("s3://tf-state/env:/prod/ciam.tfstate",) and state.problems == ()


def test_an_import_run_records_how_it_was_collected_and_a_later_file_import_clears_it():
    d, *_ = model()
    scope = "ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
    proof = {"ciamCollectionIdentity": ("arn:x",), "ciamCollectedCall": ("abc f.json <- tool list",),
             "ciamCollectionCredential": ()}
    first = run_records(d, "cloud/inventory", (scope,), AT, "CHG-1", proof)
    new = first[-1]
    assert new.changetype == "add" and new.attrs["ciamCollectionIdentity"] == ("arn:x",)
    assert "ciamCollectionCredential" not in new.attrs
    held, *_ = model(changes=first)
    (again,) = run_records(held, "cloud/inventory", (scope,), AT, "CHG-2")      # read off disk: no evidence
    assert [m for m in again.mods if m[1].startswith("ciamCollect")] == [
        ("replace", "ciamCollectionIdentity", ()), ("replace", "ciamCollectedCall", ())]
    (plain,) = run_records(model(changes=run_records(d, "cloud/inventory", (scope,), AT, "CHG-1"))[0],
                           "cloud/inventory", (scope,), AT, "CHG-2")
    assert not [m for m in plain.mods if m[1].startswith("ciamCollect")]      # nothing held, nothing to clear


def _fake_adapter(check_output="fake-account"):
    steps = lambda d, m, done, options: (("services/login.url", Command(("printf", "https://login.example.test"))),)
    verify = lambda d, m: (Command(("printf", check_output)),
                           lambda out: None if out == "fake-account" else f"signed in as {out}, the record names "
                                                                            "fake-account")
    return type("A", (), {"name": "fake-cloud", "importers": (),
                          "collectors": (Collector("services", "environment", steps, verify),)})()


def _collect_cli(monkeypatch, adapter, **given):
    import argparse
    from opsdir import cli
    from opsdir.connectors.importing import ImportPlan
    applied, recorded = [], []
    monkeypatch.setattr(cli.db, "load_directory", lambda conn: None)
    monkeypatch.setattr(cli.registry, "environment",
                        lambda d, spec: (SimpleNamespace(bindings=(), dn=ENV), (adapter,)))
    monkeypatch.setattr(cli.ops, "record_attempts", lambda conn, attempts, at, change: recorded.extend(attempts))
    monkeypatch.setattr(cli, "declared_adapters", lambda m: ())
    monkeypatch.setattr(cli.ops, "preview_import",
                        lambda conn, spec, files, at: ImportPlan(spec, ("change",), (f"read {sorted(files)}",), (),
                                                                 (), at))
    monkeypatch.setattr(cli.ops, "apply_import",
                        lambda conn, plan, change, take, keep, ev: applied.append(ev) or type("R", (), {"lines": (1,)})())
    monkeypatch.setattr(cli, "_not_applied", lambda notes, changes, dry: "\n".join((*notes, "not applied")))
    a = argparse.Namespace(**{"env": "alpha/prod", "adapter": None, "list": False, "dry_run": False,
                              "change": "CHG-9", "save": None, "terraform_dir": None, "amster_key": None,
                              "ldapsearch": None, "ldap_truststore": None, "ldap_ca": None,
                              "at": "20261008120000Z", "take": [], "keep": [], **given})
    return cli._cmd_collect(None, a, None), applied, recorded


def test_collect_checks_the_login_then_imports_the_complete_export_with_its_evidence(monkeypatch):
    (text, status), applied, recorded = _collect_cli(monkeypatch, _fake_adapter())
    assert status == 0 and "fake-cloud/services: 1 call(s) as fake-account" in text
    assert "read ['services/login.url']" in text and "CHG-9: 1 change(s) applied for fake-cloud/services" in text
    assert applied[0]["ciamCollectionIdentity"] == ("fake-account",)
    assert applied[0]["ciamCollectedCall"][0].endswith(" services/login.url <- printf https://login.example.test")
    assert [(x.importer, x.environment, x.outcome, x.problems) for x in recorded] == [
        ("fake-cloud/services", ENV, "complete", ())]
    assert text.endswith("CHG-9: 1 collection attempt(s) recorded (opsdir report collections)")


def test_collect_reads_nothing_when_the_login_isnt_the_records_account_and_records_the_skip(monkeypatch):
    (text, status), applied, recorded = _collect_cli(monkeypatch, _fake_adapter("someone-else"))
    why = "fake-cloud: signed in as someone-else, the record names fake-account: nothing read"
    assert status == 1 and applied == []
    assert text == (f"fake-cloud/services: skipped: {why}\n"
                    "CHG-9: 1 collection attempt(s) recorded (opsdir report collections)")
    assert recorded == [Attempt("fake-cloud/services", ENV, "skipped", (why,), {})]


def test_a_failed_collection_without_a_change_or_in_a_dry_run_is_said_not_recorded(monkeypatch):
    (text, status), _, recorded = _collect_cli(monkeypatch, _fake_adapter("someone-else"), change=None)
    assert status == 1 and recorded == [] and text.endswith("1 failed collection(s) not recorded (no --change)")
    (text, _), _, recorded = _collect_cli(monkeypatch, _fake_adapter("someone-else"), dry_run=True)
    assert recorded == [] and text.endswith("1 failed collection(s) not recorded (dry run)")
    (text, status), _, recorded = _collect_cli(monkeypatch, _fake_adapter(), change=None)
    assert status == 0 and recorded == [] and "not recorded" not in text           # nothing failed: nothing to say


def test_an_attempt_is_complete_incomplete_or_skipped_with_its_calls_and_problems():
    run, _ = _runner({"tool list-zones": "a b", "tool list-records --zone a": "{}"},
                     failing=("tool list-records --zone b",))
    failed = collect("cloud/dns", TWO_STAGE, None, None, run, identity="acct-1")
    got = collecting.attempt("cloud/dns", failed, ENV)
    assert (got.outcome, got.environment) == ("incomplete", ENV)
    assert got.problems == ("records/b.json (tool list-records --zone b): denied",)
    assert got.evidence["ciamCollectionIdentity"] == ("acct-1",)
    assert got.evidence["ciamCollectedCall"][-1] == "failed records/b.json <- tool list-records --zone b"
    whole, _ = _runner({"tool list-zones": "a", "tool list-records --zone a": "{}"})
    assert collecting.attempt("cloud/dns", collect("cloud/dns", TWO_STAGE, None, None, whole), None).outcome == \
        "complete"
    blocked = Collector("x", "environment", lambda d, m, done, o: (), problems=lambda d, m, o: ("give --amster-key",))
    assert collecting.attempt("am/x", collect("am/x", blocked, None, None, whole)).outcome == "skipped"
    assert collecting.attempt("am/x", "identity check failed").problems == ("identity check failed",)
    nothing = Collector("x", "environment", lambda d, m, done, o: ())
    assert collecting.attempt("am/x", collect("am/x", nothing, None, None, whole)) is None    # nothing to collect


def test_attempt_records_add_then_replace_and_the_report_lists_them():
    d, *_ = model()
    failed = Attempt("cloud/dns", ENV, "incomplete", ("records/b.json (tool x): exit 1:\n  denied",),
                     {"ciamCollectionIdentity": ("acct-1",), "ciamCollectedCall": ("failed b <- tool x",),
                      "ciamCollectionCredential": ()})
    container, new = attempt_records(d, (failed,), AT, "CHG-1")
    assert container.dn.startswith("ou=imports,") and new.changetype == "add"
    assert new.dn == attempt_dn("cloud/dns", ENV) == f"cn=collection.cloud.dns.alpha.prod,{container.dn}"
    assert new.attrs["ciamCollectionOutcome"] == ("incomplete",) and new.attrs["ciamCollectedEnvironment"] == (ENV,)
    assert new.attrs["ciamCollectionProblem"] == ("records/b.json (tool x): exit 1: denied",)   # one line
    assert "ciamCollectionCredential" not in new.attrs
    held, *_ = model(changes=(container, new))
    assert attempt_rows(held) == [("cloud/dns", "alpha/prod", "incomplete", "20261008120000Z",
                                   "records/b.json (tool x): exit 1: denied", "CHG-1")]
    (again,) = attempt_records(held, (Attempt("cloud/dns", ENV, "complete", (), {}),), AT, "CHG-2")
    assert again.changetype == "modify" and ("replace", "ciamCollectionOutcome", ("complete",)) in again.mods
    assert ("replace", "ciamCollectionProblem", ()) in again.mods
    assert ("replace", "ciamCollectedCall", ()) in again.mods and ("replace", "ciamCollectionIdentity", ()) in again.mods
    assert attempt_records(d, (), AT, "CHG-1") == ()
    assert attempt_dn("aws/regions") == "cn=collection.aws.regions.estate,ou=imports,dc=ciam-ops"


def test_nothing_there_is_left_out_and_work_files_stay_out_of_the_export():
    def steps(d, m, done, options):
        listed = done.get("_work/items.json", "").split()
        return (("_work/items.json", Command(("tool", "items"))),
                *((f"item-{i}.json", Command(("tool", "get", i), absent=("NotFound",))) for i in listed))
    run, _ = _runner({"tool items": "a b", "tool get a": "{}"})
    gone = lambda call: (None, None) if call.argv[-1] == "b" else run(call)
    c = collect("cloud/items", Collector("items", "environment", steps), None, None, gone)
    assert c.problems == () and c.files == {"item-a.json": "{}"}
    assert [x.path for x in c.calls] == ["_work/items.json", "item-a.json", "item-b.json"]
    assert evidence(c)["ciamCollectedCall"][2] == "absent item-b.json <- tool get b"


def test_a_command_saying_nothing_is_there_is_absent_not_failed():
    absent = Command(("sh", "-c", "echo 'An error occurred (NoSuchBucketPolicy)' >&2; exit 254"),
                     absent=("NoSuchBucketPolicy",))
    assert live.run_call(absent, lambda ref: (None, None)) == (None, None)
    other = absent._replace(absent=("SomethingElse",))
    assert live.run_call(other, lambda ref: (None, None))[1].startswith("exit 254:")


def test_keep_trims_an_output_before_the_export_and_the_evidence_see_it():
    trim = lambda out: out.replace("startup-script=secret", "")
    steps = lambda d, m, done, o: (("instances.json", Command(("tool", "instances"), keep=trim)),)
    run, _ = _runner({"tool instances": "role=ds startup-script=secret"})
    c = collect("cloud/x", Collector("x", "environment", steps), None, None, run)
    assert c.files == {"instances.json": "role=ds "}
    assert c.calls[0].sha256 == collecting.sha256("role=ds ")


def test_a_workdir_command_runs_in_a_private_directory_and_its_files_are_the_output():
    script = "mkdir -p {dir}/export/realms && printf '{\"a\": 1}' > {dir}/export/realms/one.json && printf x > {dir}/export/two.txt"
    call = Command(("sh", "{dir}/run.sh"), workdir=True, inputs=(("run.sh", script),))
    out, problem = live.run_call(call, lambda ref: (None, None))
    assert problem is None and out == {"realms/one.json": '{"a": 1}', "two.txt": "x"}
    steps = lambda d, m, done, o: (("am", call),)
    c = collect("am/amster", Collector("amster", "environment", steps), None, None,
                lambda c: live.run_call(c, lambda ref: (None, None)))
    assert c.problems == () and c.files == {"am/realms/one.json": '{"a": 1}', "am/two.txt": "x"}
    assert len(c.calls) == 2                                          # each file its own evidence line


def test_a_collector_saying_why_it_cant_collect_runs_nothing():
    run, seen = _runner({})
    blocked = Collector("x", "environment", lambda d, m, done, o: (("a", Command(("tool",))),),
                        problems=lambda d, m, o: ("give --amster-key",))
    c = collect("cloud/x", blocked, None, None, run)
    assert (c.files, c.problems, seen) == (None, ("give --amster-key",), [])


def test_a_header_pair_credential():
    got = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            got.append((self.headers.get("X-OpenIDM-Username"), self.headers.get("X-OpenIDM-Password"),
                        self.headers.get("Authorization")))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.handle_request, daemon=True).start()
    call = Request(f"http://127.0.0.1:{server.server_port}/openidm/config",
                   credential=("headers", "fake://pw", "reader", ("X-OpenIDM-Username", "X-OpenIDM-Password")))
    assert live.run_call(call, lambda ref: ("s3cret", None)) == ("{}", None)
    server.server_close()
    assert got == [("reader", "s3cret", None)]


def test_a_digest_command_streams_its_output_through_the_digest_only():
    count = lambda lines: f"{sum(1 for line in lines if line.startswith('dn:'))} entries"
    call = Command(("sh", "-c", "cat >/dev/null; printf 'dn: a\\nmail: x@example.test\\n\\ndn: b\\n'"),
                   ("fake://pw",), lambda s: s["fake://pw"], digest=count)
    assert live.run_call(call, lambda ref: ("pw", None)) == ("2 entries", None)
    failing = call._replace(argv=("sh", "-c", "cat >&2; exit 3"))
    assert live.run_call(failing, lambda ref: ("s3cret", None)) == (None, f"exit 3: {MASK}")
