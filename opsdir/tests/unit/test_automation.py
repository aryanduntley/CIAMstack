"""The automation domain: jobs as entries (cron on a server role, a function realized by a binding, the roles they
use), the jobs report, a function realization read from a cloud as a job binding, and the planner's findings about
jobs the target can't run or nobody owns; pipelines a CI package found, named as their system shows them and removed
once a repository the import read no longer defines them (only that CI system's, only the repositories read)."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.inventory import environment_groups, resource
from opsdir.domains.automation.jobs import check_jobs, job_rows
from opsdir.domains.automation.naming import JOBS, job_dn
from opsdir.domains.automation.pipelines import FoundPipeline, ReadRepository, gone_pipelines, pipeline_groups
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"


def _job(cn, kind, extra=""):
    return (f"dn: cn={cn},{JOBS}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamJob\ncn: {cn}\n"
            f"ciamJobKind: {kind}\n{extra}")


RECORDS = "\n".join((
    f"dn: cn=subnet-web,ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: ciamSubnetBinding\ncn: subnet-web\n"
    "ciamBindingRole: subnet-web\nciamCidr: 10.1.1.0/24\n",
    f"dn: cn=web-1,{ALPHA}\nobjectClass: top\nobjectClass: ciamServer\ncn: web-1\nciamServerRole: web\n"
    f"ciamHostname: web-1.alpha.example.test\nciamSubnet: cn=subnet-web,ou=bindings,{ALPHA}\n",
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    "dn: cn=ops,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n",
    f"dn: {JOBS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: jobs\n",
    _job("nightly-export", "cron", "ciamSchedule: 30 2 * * *\nciamTargetRole: web\nciamRunsAs: export\n"
         "ciamCommand: /opt/scripts/nightly-export.sh\nciamUsesRole: export-password\n"
         "ciamOwner: cn=ops,ou=owners,dc=ciam-ops\n"),
    _job("cert-check", "function", "ciamSchedule: rate(1 day)\nciamJobRole: cert-check-function\n"
         "ciamRuntime: python3.12\nciamTrigger: manual\n"),
    _job("orphan", "timer", "")))


def directory(extra=""):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + RECORDS + "\n" + extra)))


def plan(d, src="alpha/prod", dst="beta/prod"):
    return check_jobs(PlanContext(d, env_model(d, src), env_model(d, dst), None, dt.date(2026, 10, 1), {}, {}, ()))


def test_the_jobs_report():
    rows = {r[0]: r for r in job_rows(directory())}
    assert rows["nightly-export"] == ("nightly-export", "cron", "30 2 * * *", "servers: web", "every environment",
                                      "ops", "", "export-password", "")
    assert rows["cert-check"][2:4] == ("rate(1 day); manual", "binding: cert-check-function")


def test_the_planner_names_what_the_target_cant_run_and_what_nobody_owns():
    f = plan(directory())
    assert [t for _, t, _ in f.blockers] == [
        "Job `cert-check` is realized by role `cert-check-function`, which neither alpha/prod nor beta/prod binds: "
        "record where it runs.",
        "Job `nightly-export` runs on servers of role `web`, which beta/prod has none of.",
        "Job `nightly-export` uses role `export-password`, which neither alpha/prod nor beta/prod binds."]
    assert [t for _, t, _, _ in f.actions] == [
        "Job `cert-check` has no owner: automation nobody owns breaks silently after a move. Name who owns it.",
        "Job `orphan` has no owner: automation nobody owns breaks silently after a move. Name who owns it.",
        "Job `orphan` (timer) records neither the server role it runs on nor the role that realizes it: record where "
        "it runs."]


def test_a_function_realization_is_a_job_binding_a_cloud_reads():
    d = directory()
    arn = "arn:aws:lambda:region-1:111122223333:function:cert-check"
    groups, notices = environment_groups(d, "alpha/prod", (
        resource("job", arn, {"ciamRuntime": "python3.12"}, name="cert-check", role="cert-check-function"),
        resource("job", "arn:aws:lambda:region-1:111122223333:function:untagged", name="untagged")))
    (dn, (entry,)), = groups
    assert (dn, entry.classes, one(entry, "ciamBindingRole"), one(entry, "ciamProviderRef")) == \
        (f"cn=cert-check,ou=bindings,{ALPHA}", ("top", "ciamJobBinding"), "cert-check-function", arn)
    assert any("untagged" in n for n in notices)
    after = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + RECORDS)))
    assert not any("cert-check-function" in t for _, t, _ in plan(after._replace(
        entries={**after.entries, entry.norm: entry})).blockers)          # alpha binds it: no longer nobody's


def test_a_job_scoped_to_the_source_is_named_not_asked_of_the_target():
    scoped = _job("alpha-only", "cron", f"ciamSchedule: @daily\nciamTargetRole: web\nciamInEnvironment: {ALPHA}\n"
                  "ciamOwner: cn=ops,ou=owners,dc=ciam-ops\n")
    f = plan(directory(scoped))
    assert not any("alpha-only" in t for _, t, _ in f.blockers)
    assert "Job `alpha-only` applies in alpha/prod, not in beta/prod: it won't run there. Scope it to beta/prod too " \
        "if it should (ciamInEnvironment, ciamOnProvider)." in [t for _, t, _, _ in f.actions]
    assert {r[0]: r[4] for r in job_rows(directory(scoped))}["alpha-only"] == "alpha/prod"
    backwards = plan(directory(scoped), src="beta/prod", dst="alpha/prod")      # applies in neither the source: skipped
    assert not any("alpha-only" in t for _, t, *_ in (*backwards.blockers, *backwards.actions))


X_URL = "https://ci.example.test/o/x"


def _pipeline(cn, system, path, url=X_URL):
    return _job(cn, "pipeline", (f"ciamCiSystem: {system}\n" if system else "") + f"ciamRepoPath: {path}\n"
                + (f"ciamRepoUrl: {url}\n" if url else ""))


HELD = "\n".join((
    _pipeline("gh-x-deploy", "github-actions", ".github/workflows/deploy.yml"),         # gone from o/x: removed
    _pipeline("gh-x-build", "github-actions", ".github/workflows/build.yml"),           # found again: kept
    _pipeline("gh-x-broken", "github-actions", ".github/workflows/broken.yml"),         # unreadable this time: kept
    _pipeline("gl-x", "gitlab-ci", ".gitlab-ci.yml"),                                    # another system: kept
    _pipeline("gh-x-legacy", None, ".github/workflows/old.yml"),                         # no ciamCiSystem yet: kept
    _pipeline("gh-y-deploy", "github-actions", ".github/workflows/deploy.yml",
              "https://ci.example.test/o/y"),                                            # repository not read: kept
    _pipeline("gh-z-nightly", "github-actions", "z/.github/workflows/nightly.yml", None),  # no URL, gone from z
    _pipeline("gh-zz-nightly", "github-actions", "zz/.github/workflows/nightly.yml", None),  # zz, not z: kept
    _job("k8s-backup", "cron", "ciamRepoPath: z/backup.yaml\n")))                      # not a pipeline: kept


def test_a_pipeline_records_its_name_and_ci_system():
    found = FoundPipeline("github-actions", "o/x", X_URL, ".github/workflows/build.yml", "Build and test", (),
                          ("push",), (), (), ())
    (dn, (entry,)), = pipeline_groups(directory(), (found,))[0]
    assert (one(entry, "ciamJobName"), one(entry, "ciamCiSystem")) == ("Build and test", "github-actions")
    held = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + RECORDS + "\n" + HELD)))
    assert {one(get(held, job_dn(n)), "ciamCiSystem") for n in ("gh-x-build", "gl-x")} == {"github-actions",
                                                                                            "gitlab-ci"}


def test_only_the_systems_pipelines_gone_from_a_read_repository_are_removed():
    d = directory(HELD)
    found = FoundPipeline("github-actions", "o/x", X_URL, ".github/workflows/build.yml", "build", (), (), (), (), ())
    read = (ReadRepository("github-actions", "o/x", X_URL, (".github/workflows/broken.yml",)),
            ReadRepository("github-actions", "z", None, ()))
    groups, notices = pipeline_groups(d, (found,), read)
    assert [dn for dn, entries in groups if not entries] == [job_dn("gh-x-deploy"), job_dn("gh-z-nightly")]
    assert [dn for dn, entries in groups if entries] == [job_dn("gh-x-build")]
    assert notices == (
        f"pipeline gh-x-deploy (github-actions, {X_URL}, .github/workflows/deploy.yml): no longer defined in its "
        "repository; removed",
        "pipeline gh-z-nightly (github-actions, no repository URL, z/.github/workflows/nightly.yml): no longer "
        "defined in its repository; removed")
    assert gone_pipelines(d, frozenset(), ()) == ()                                    # nothing read: nothing removed
