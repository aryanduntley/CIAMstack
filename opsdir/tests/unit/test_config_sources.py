"""Configuration sources any importer's collection may read (domains.governance.config_sources): a Git repository, a
Kubernetes ConfigMap, files over SSH, each only once its estate setting allows it (off by default: the problem names
the setting to turn on); the exact calls each makes (a shallow clone, kubectl get configmap, ssh in batch mode with
strict host keys running find, then cat or zcat, on quoted paths that must look like paths); what a clone or a
ConfigMap gives placed under the source's prefix, .git never read, a link or binary file kept failing the collection;
every adapter's importers read their sources, in the importer's one collection."""
import json

from opsdir import live
from opsdir.connectors.collecting import collect, collectors
from opsdir.core.contract import Collector, Command, Importer
from opsdir.domains.governance.config_sources import (configmap_files, git_files, manifest_files, source_kind,
                                                      source_problems, source_steps)
from network_fixtures import ALPHA, entry, model

SETTINGS = "dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n"


def _setting(name):
    return f"dn: cn={name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamEstateSetting\ncn: {name}\n" \
           "ciamEstateValue: TRUE\n"


def _source(cn, ref, importer="gw/config"):
    return entry(ALPHA, cn, "ciamCollectionSource", ciamBindingRole=f"collect-{cn}", ciamImporter=importer,
                 ciamSourceRef=ref)


REFS = {"repo": "git+https://git.example.test/ciam/gateway.git?ref=main&dir=config&prefix=routes/",
        "cm": "k8s://prod-east/ciam/configmap/gateway-routes?prefix=routes/",
        "host": "ssh://ops@gw-1.example.test:2222/opt/gateway?dir=config&match=*.json"}


def _model(allowed=(), refs=REFS):
    tree = (SETTINGS, *(_setting(f"collect-from-{k}") for k in allowed)) if allowed else ()
    d, alpha, _ = model(alpha=tuple(_source(cn, ref) for cn, ref in refs.items()), tree=tree)
    return d, alpha


def test_each_kind_is_read_only_once_its_setting_allows_it():
    assert [source_kind(r) for r in (*REFS.values(), "s3://b/k", None)] == ["git", "kubernetes", "ssh", None, None]
    d, alpha = _model()
    assert source_steps("gw/config")(d, alpha, {}, {}) == ()
    assert source_problems("gw/config")(d, alpha, {}) == (
        "collection source `cm` (kubernetes): not allowed: `opsdir setting collect-from-kubernetes TRUE --change "
        "CHG-…` allows reading kubernetes sources",
        "collection source `host` (ssh): not allowed: `opsdir setting collect-from-ssh TRUE --change CHG-…` allows "
        "reading ssh sources",
        "collection source `repo` (git): not allowed: `opsdir setting collect-from-git TRUE --change CHG-…` allows "
        "reading git sources")
    d, alpha = _model(("git",))
    assert [c.argv[0] for _, c in source_steps("gw/config")(d, alpha, {}, {})] == ["git"]
    assert len(source_problems("gw/config")(d, alpha, {})) == 2


def test_the_exact_calls_each_source_makes():
    d, alpha = _model(("git", "kubernetes", "ssh"))
    assert source_problems("gw/config")(d, alpha, {}) == ()
    (_, cm), (listing, find), (_, clone) = source_steps("gw/config")(d, alpha, {}, {})
    assert clone.argv == ("git", "clone", "--depth", "1", "--single-branch", "--branch", "main",
                          "https://git.example.test/ciam/gateway.git", "{dir}/export/repo") and clone.workdir
    assert cm.argv == ("kubectl", "--context", "prod-east", "-n", "ciam", "get", "configmap", "gateway-routes",
                       "-o", "json")
    ssh = ("ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-p", "2222", "ops@gw-1.example.test")
    assert listing == "_work/ssh-1.txt"
    assert find.argv == (*ssh, "find", "/opt/gateway/config", "-type", "f", "-name", "'*.json'")
    found = "/opt/gateway/config/a.json\n/opt/gateway/config/sub/b.json.gz\n/etc/shadow\n/opt/gateway/config/$(id)\n"
    reads = {p: c.argv for p, c in source_steps("gw/config")(d, alpha, {listing: found}, {})[2:-1]}
    assert reads == {"gw-1.example.test/config/a.json": (*ssh, "cat", "--", "/opt/gateway/config/a.json"),
                     "gw-1.example.test/config/sub/b.json": (*ssh, "zcat", "--", "/opt/gateway/config/sub/b.json.gz")}


def test_listed_files_and_refs_that_cant_be_read_safely():
    files = {"host": "ssh://gw-1.example.test/opt/pf?files=bin/run.properties,server/default/data/x.xml&prefix=pf/"}
    d, alpha = _model(("ssh",), files)
    assert [(p, c.argv[-4:]) for p, c in source_steps("gw/config")(d, alpha, {}, {})] == [
        ("pf/bin/run.properties", ("gw-1.example.test", "cat", "--", "/opt/pf/bin/run.properties")),
        ("pf/server/default/data/x.xml", ("gw-1.example.test", "cat", "--", "/opt/pf/server/default/data/x.xml"))]
    bad = {"a": "ssh://h.example.test/opt?files=../../etc/shadow", "b": "ssh://h.example.test/opt;rm?dir=x",
           "c": "k8s://ctx/ns/secret/creds", "d": "ssh://h.example.test/opt?match=$(id)",
           "e": "ssh://-oProxyCommand=sh@h.example.test/opt?dir=x", "f": "k8s://ctx/ns/configmap/-o=yaml"}
    d, alpha = _model(("ssh", "kubernetes"), bad)
    assert source_steps("gw/config")(d, alpha, {}, {}) == ()
    assert [p.split(":")[0] for p in source_problems("gw/config")(d, alpha, {})] == \
        [f"collection source `{cn}`" for cn in "abcdef"]


def test_a_clone_and_a_configmap_become_files_under_the_prefix():
    clone = {"repo/config/a.json": "{}", "repo/config/sub/b.json": "[]", "repo/README.md": "x",
             "repo/config/.git/HEAD": "ref"}
    assert git_files("config", "routes/")(clone) == {"routes/a.json": "{}", "routes/sub/b.json": "[]"}
    assert git_files("", "")(clone) == {"config/a.json": "{}", "config/sub/b.json": "[]", "README.md": "x"}
    assert configmap_files("routes/")('{"data": {"a.json": "{}", "b.json": "[]"}, "binaryData": {"k": "AA=="}}') == \
        {"routes/a.json": "{}", "routes/b.json": "[]"}
    assert configmap_files("")("not json") == {}


def test_every_importer_reads_its_sources_in_its_one_collection():
    d, alpha = _model(("kubernetes",), {"cm": REFS["cm"]})
    declared = Collector("config", "environment", lambda d, m, done, o: (("gw/one.json", Command(("tool",))),))
    adapter = type("A", (), {"name": "gw", "collectors": (declared,),
                             "importers": (Importer("config", "c", None), Importer("routes", "r", None))})()
    assert [c.importer for c in collectors(adapter, alpha)] == ["config"]       # routes: no sources declared
    (config,) = collectors(adapter, alpha)
    answers = {"tool": "{}", "kubectl": '{"data": {"a.json": "{\\"r\\": 1}"}}'}
    c = collect("gw/config", config, d, alpha, lambda call: (answers[call.argv[0]], None))
    assert c.problems == () and c.files == {"gw/one.json": "{}", "routes/a.json": '{"r": 1}'}
    plain = type("A", (), {"name": "gw", "collectors": (), "importers": (Importer("config", "c", None),)})()
    assert [(c.importer, c.scope) for c in collectors(plain, alpha)] == [("config", "environment")]
    assert collectors(plain) == ()


def test_a_work_directory_never_reads_git_and_a_link_or_binary_kept_fails(tmp_path):
    (tmp_path / "secret").write_text("key")
    script = ("mkdir -p {dir}/export/repo/.git {dir}/export/repo/config && printf ref > {dir}/export/repo/.git/HEAD"
              " && printf '{}' > {dir}/export/repo/config/a.json && printf '\\377\\376' > {dir}/export/repo/logo.png"
              f" && ln -s {tmp_path}/secret {{dir}}/export/repo/config/link.json")
    call = Command(("sh", "{dir}/run.sh"), workdir=True, inputs=(("run.sh", script),))
    out, problem = live.run_call(call, lambda ref: (None, None))
    assert problem is None and out == {"repo/config/a.json": "{}", "repo/config/link.json": None, "repo/logo.png": None}
    kept = call._replace(keep=git_files("config", ""))
    c = collect("gw/config", Collector("config", "environment", lambda d, m, done, o: (("", kept),)), None, None,
                lambda c: live.run_call(c, lambda ref: (None, None)))
    assert c.files is None and c.problems == ("link.json (sh '{dir}/run.sh'): not a regular UTF-8 text file",)


def test_a_failing_source_call_is_reported_with_its_error_output_and_nothing_imported(tmp_path):
    fake = tmp_path / "kubectl"
    fake.write_text('#!/bin/sh\necho "error: context was not found for specified context: prod-east" >&2\nexit 1\n')
    fake.chmod(0o755)
    d, alpha = _model(("kubernetes",), {"cm": REFS["cm"]})
    adapter = type("A", (), {"name": "gw", "collectors": (), "importers": (Importer("config", "c", None),)})()
    (config,) = collectors(adapter, alpha)
    run = lambda call: live.run_call(call._replace(argv=(str(fake), *call.argv[1:])), lambda ref: (None, None))
    c = collect("gw/config", config, d, alpha, run)
    assert c.files is None and len(c.problems) == 1
    assert c.problems[0].endswith(": exit 1: error: context was not found for specified context: prod-east")


def test_a_namespaces_workloads_are_read_as_manifests_never_secrets_and_trimmed():
    d, alpha = _model(("kubernetes",), {"ns": "k8s://prod-east/identity/workloads"})
    assert source_problems("gw/config")(d, alpha, {}) == ()
    (objects, listed), (namespace, ns) = source_steps("gw/config")(d, alpha, {}, {})
    assert (objects, namespace) == ("prod-east/identity/objects.json", "prod-east/identity/namespace.json")
    assert listed.argv == ("kubectl", "--context", "prod-east", "-n", "identity", "get",
                           "statefulsets,deployments,daemonsets,cronjobs,services,ingresses,networkpolicies,"
                           "serviceaccounts", "-o", "json")
    assert "secret" not in " ".join(listed.argv)
    assert ns.argv == ("kubectl", "--context", "prod-east", "get", "namespace", "identity", "-o", "json")
    raw = {"kind": "List", "items": [{"kind": "Deployment", "metadata": {
        "name": "am", "managedFields": [{"manager": "kubectl"}],
        "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{\"spec\": \"PASSWORD=hunter2\"}",
                        "opsdir.io/role": "am"}},
        "spec": {"template": {"spec": {"containers": [{"name": "am", "env": [
            {"name": "JAVA_OPTS", "value": "-Dpassword=hunter2"},
            {"name": "ADMIN", "valueFrom": {"secretKeyRef": {"name": "am-admin", "key": "pw"}}}]}]}}}}]}
    kept = listed.keep(json.dumps(raw))
    assert "hunter2" not in kept and "managedFields" not in kept and "last-applied" not in kept
    assert json.loads(kept)["items"][0]["spec"]["template"]["spec"]["containers"][0]["env"] == [
        {"name": "JAVA_OPTS"}, {"name": "ADMIN", "valueFrom": {"secretKeyRef": {"key": "pw", "name": "am-admin"}}}]
    assert json.loads(kept)["items"][0]["metadata"]["annotations"] == {"opsdir.io/role": "am"}
    assert manifest_files("not json") == "not json"
    bad = {"a": "k8s://prod-east/identity/workloads/extra", "b": "k8s://prod-east/-n/workloads"}
    d, alpha = _model(("kubernetes",), bad)
    assert source_steps("gw/config")(d, alpha, {}, {}) == () and len(source_problems("gw/config")(d, alpha, {})) == 2
