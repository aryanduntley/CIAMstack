"""Configuration sources end to end: `opsdir collect` reading a Git repository and servers over SSH for the installed
adapters' real importers (pinggateway/config, linux/jobs) in the example estate. The calls are the ones the collector
builds, run by live.run_call: a real `git clone` (of a local repository standing in for the remote one) and an `ssh`
standing in for the remote shell (it gets the remote command line as ssh would send it, and serves the showcase's
copies of the servers' files). What is collected must be the export the operator would have saved by hand, and its
import plan the same."""
import pathlib
import shlex
import shutil
import subprocess
import sys

import pytest

from opsdir import live
from opsdir.cli import import_time
from opsdir.connectors import importing
from opsdir.connectors.collecting import collect, collectors
from opsdir.connectors.registry import ADAPTERS
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.store.postgres import read_ldif_files
from showcase_support import DATA, SHOWCASE, export_files
from support import build_directory, schema_for

ENV = "env=prod,cloud=source,ou=environments,dc=ciam-ops"
AT = import_time("20261008120000Z")
IG, HOSTS = SHOWCASE / "exports" / "ig", SHOWCASE / "exports" / "hosts"
JOB_DIRS = ("etc/cron.d", "etc/systemd/system")
# An ssh standing in for the remote shell: options, then the target, then the remote command line, which the remote
# shell splits; it serves <root>/<host>/<path> for find, cat and zcat, and fails like they do.
FAKE_SSH = '''import gzip, os, shlex, sys
args = sys.argv[1:]
assert args[:4] == ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"], args
while args[0] in ("-o", "-p"):
    args = args[2:]
host, remote = args[0].split("@")[-1], shlex.split(" ".join(args[1:]))
root = os.path.join(ROOT, host)
if remote[0] == "find":
    top, name = remote[1], (remote[remote.index("-name") + 1] if "-name" in remote else None)
    if not os.path.isdir(root + top):
        sys.exit(f"find: '{top}': No such file or directory")
    for d, _, files in sorted(os.walk(root + top)):
        for f in sorted(files):
            print(os.path.join(d, f)[len(root):])
elif remote[0] == "command":                          # command -v java keytool rpm dpkg-query || true
    tools = {"java": "java/version.txt", "keytool": "java/cacerts.txt", "rpm": "packages.txt"}
    for tool in remote[2:remote.index("||")]:
        if os.path.isfile(os.path.join(root, tools.get(tool, "-"))):
            print(f"/usr/bin/{tool}")
elif remote[0] in ("java", "keytool", "rpm"):         # their output, as saved by hand
    sys.stdout.write(open(os.path.join(root, {"java": "java/version.txt", "keytool": "java/cacerts.txt",
                                              "rpm": "packages.txt"}[remote[0]])).read())
else:
    path = root + remote[2]
    if not os.path.isfile(path):
        sys.exit(f"{remote[0]}: {remote[2]}: No such file or directory")
    data = gzip.open(path).read() if remote[0] == "zcat" else open(path, "rb").read()
    sys.stdout.write(data.decode())
'''


def _role_sources(importer, d_m):
    """One collection source per server role of source/prod: read its servers over SSH as `ops`."""
    roles = sorted({s.attrs["ciamServerRole"][0] for s in d_m[1].servers})
    return tuple((f"{importer.split('/')[1]}-{r}", importer, None, r) for r in roles)


def _estate(sources, settings):
    """The example estate as loaded (no imports yet), with collection sources in source/prod and estate settings on."""
    extra = "\n".join((
        "dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n",
        *(f"dn: cn={s},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamEstateSetting\ncn: {s}\n"
          "ciamEstateValue: TRUE\n" for s in settings),
        *(f"dn: cn={cn},ou=bindings,{ENV}\nobjectClass: top\nobjectClass: ciamCollectionSource\ncn: {cn}\n"
          f"ciamBindingRole: {cn}\nciamImporter: {importer}\n"
          + (f"ciamSourceRef: {ref}\n" if ref else f"ciamTargetRole: {role[0]}\nciamLoginName: ops\n")
          for cn, importer, ref, *role in sources)))
    records = (*read_ldif_files(sorted(DATA.glob("*.ldif"))), *parse(extra))
    d = build_directory(schema_for(records), records)
    return d, env_model(d, "source/prod")


def _collector(adapter_name, importer, m):
    adapter = next(a for a in ADAPTERS if a.name == adapter_name)
    return next(c for c in collectors(adapter, m) if c.importer == importer and c.scope == "environment")


def _same_plan(d, spec, collected, saved):
    live_plan = importing.import_plan(d, spec, collected, at=AT)
    assert live_plan.changes and live_plan.changes == importing.import_plan(d, spec, saved, at=AT).changes
    assert live_plan.notices == importing.import_plan(d, spec, saved, at=AT).notices


@pytest.mark.skipif(not shutil.which("git"), reason="needs git")
def test_a_gateway_configuration_in_git_is_collected_and_imported_like_the_saved_export(tmp_path):
    repo = tmp_path / "gateway.git"
    shutil.copytree(IG, repo / "gateway")
    git = ("git", "-c", "user.name=ops", "-c", "user.email=ops@example.test", "-C", str(repo))
    for step in (("init", "-q", "-b", "main"), ("add", "."), ("commit", "-q", "-m", "gateway")):
        subprocess.run((*git, *step), check=True, capture_output=True)
    url = "https://git.example.test/ciam/gateway.git"
    d, m = _estate((("gateway-repo", "pinggateway/config", f"git+{url}?ref=main&dir=gateway"),), ("collect-from-git",))
    clone = lambda call: call._replace(argv=tuple(str(repo) if a == url else a for a in call.argv))
    c = collect("pinggateway/config", _collector("pinggateway", "config", m), d, m,
                lambda call: live.run_call(clone(call), lambda ref: (None, None)))
    assert c.problems == () and [x.provenance.split()[:2] for x in c.calls] == [["git", "clone"]] * len(c.calls)
    assert c.files == export_files(IG)
    _same_plan(d, "pinggateway/config", c.files, export_files(IG))


def test_servers_crontabs_and_timers_over_ssh_are_collected_and_imported_like_the_saved_export(tmp_path):
    hosts = sorted(p.name for p in HOSTS.iterdir() if p.is_dir())
    for host in hosts:
        for sub in JOB_DIRS:
            (tmp_path / "remote" / host / sub).mkdir(parents=True)          # every server has both directories
            if (HOSTS / host / sub).is_dir():
                shutil.copytree(HOSTS / host / sub, tmp_path / "remote" / host / sub, dirs_exist_ok=True)
    ssh = tmp_path / "ssh"
    ssh.write_text(f"#!{sys.executable} -I\nROOT = {str(tmp_path / 'remote')!r}\n{FAKE_SSH}")
    ssh.chmod(0o755)
    sources = tuple((f"jobs-{host.split('.')[0]}-{n}", "linux/jobs", f"ssh://ops@{host}/?dir={sub}")
                    for host in hosts for n, sub in enumerate(JOB_DIRS))
    d, m = _estate(sources, ("collect-from-ssh",))
    c = collect("linux/jobs", _collector("linux", "jobs", m), d, m,
                lambda call: live.run_call(call._replace(argv=(str(ssh), *call.argv[1:])), lambda ref: (None, None)))
    assert c.problems == ()
    saved = export_files(HOSTS)
    assert c.files == {p: t for p, t in saved.items() if any(f"/{sub}/" in p for sub in JOB_DIRS)}
    assert "ds-2.aws.internal.example-aero.test/etc/cron.d/mro-export" in c.files
    _same_plan(d, "linux/jobs", c.files, saved)


def test_a_server_missing_a_directory_leaves_the_collection_incomplete(tmp_path):
    host = "ds-2.aws.internal.example-aero.test"
    ssh = tmp_path / "ssh"
    ssh.write_text(f"#!{sys.executable} -I\nROOT = {str(tmp_path / 'remote')!r}\n{FAKE_SSH}")
    ssh.chmod(0o755)
    (tmp_path / "remote" / host).mkdir(parents=True)
    d, m = _estate((("jobs-ds-2", "linux/jobs", f"ssh://ops@{host}/?dir=etc/cron.d"),), ("collect-from-ssh",))
    c = collect("linux/jobs", _collector("linux", "jobs", m), d, m,
                lambda call: live.run_call(call._replace(argv=(str(ssh), *call.argv[1:])), lambda ref: (None, None)))
    assert c.files is None
    assert [p.split(": ", 1)[1] for p in c.problems] == ["exit 1: find: '/etc/cron.d': No such file or directory"]


def _remote_hosts(tmp_path):
    """The showcase's saved server files as the stand-in ssh serves them, and that ssh."""
    shutil.copytree(HOSTS, tmp_path / "remote", ignore=shutil.ignore_patterns("README.md"))
    ssh = tmp_path / "ssh"
    ssh.write_text(f"#!{sys.executable} -I\nROOT = {str(tmp_path / 'remote')!r}\n{FAKE_SSH}")
    ssh.chmod(0o755)
    return lambda call: live.run_call(call._replace(argv=(str(ssh), *call.argv[1:])), lambda ref: (None, None))


@pytest.mark.parametrize("importer", ["linux/baseline", "linux/jobs"])
def test_every_server_of_the_named_roles_collected_over_ssh_imports_like_the_saved_hosts(tmp_path, importer):
    run = _remote_hosts(tmp_path)
    d, m = _estate(_role_sources(importer, _estate((), ())), ("collect-from-ssh",))
    c = collect(importer, _collector("linux", importer.split("/")[1], m), d, m, run)
    assert c.problems == ()
    ran = {shlex.split(x.provenance)[6].split()[0] for x in c.calls}             # the remote command's program
    assert ran <= {"cat", "find", "command", "java", "keytool", "rpm"}            # fixed commands only
    assert all(" BatchMode=yes " in f" {x.provenance} " and "StrictHostKeyChecking=yes" in x.provenance
               for x in c.calls)
    saved = export_files(HOSTS)
    _same_plan(d, importer, c.files, saved)


def test_ssh_role_sources_need_the_setting_and_servers():
    d, m = _estate((("baseline-ds", "linux/baseline", None, "ds"), ("baseline-x", "linux/baseline", None, "nobody")),
                   ())
    collector = _collector("linux", "baseline", m)
    assert collector.problems(d, m, {}) == ("linux/baseline: reading servers over SSH is not allowed: `opsdir setting "
                                            "collect-from-ssh TRUE --change CHG-…` allows it",)
    d, m = _estate((("baseline-x", "linux/baseline", None, "nobody"),), ("collect-from-ssh",))
    assert _collector("linux", "baseline", m).problems(d, m, {}) == (
        "collection source `baseline-x`: role `nobody` has no servers with host names in source/prod",)


def test_a_debian_server_without_java_gets_dpkg_and_no_java_calls_and_a_missing_file_is_absent():
    d, m = _estate((("baseline-ig", "linux/baseline", None, "ig"),), ("collect-from-ssh",))
    host = next(s.attrs["ciamHostname"][0] for s in m.servers if s.attrs["ciamServerRole"][0] == "ig")

    def run(call):
        remote = shlex.split(" ".join(call.argv[6:]))
        if remote[0] == "command":
            return "/usr/bin/dpkg-query\n", None
        if remote[0] == "dpkg-query":
            return "falcon-sensor 7.10\nopenssl 3.0\n", None
        if remote[:3] == ["cat", "--", "/etc/os-release"]:
            return 'ID=ubuntu\nID_LIKE="debian"\nVERSION_ID="22.04"\n', None
        return live.run_call(call._replace(argv=("sh", "-c", f"echo \"cat: {remote[-1]}: No such file or directory\" >&2;"
                                                             " exit 1")), lambda ref: (None, None))
    c = collect("linux/baseline", _collector("linux", "baseline", m), d, m, run)
    assert c.problems == ()
    assert sorted(c.files) == [f"{host}/etc/os-release", f"{host}/packages.txt"]       # the rest absent, not failed
    programs = [shlex.split(x.provenance)[6].split()[0] for x in c.calls]
    assert "dpkg-query" in programs and not {"java", "keytool", "rpm"} & set(programs)
    assert {x.sha256 for x in c.calls if x.path.endswith("selinux/config")} == {None}
