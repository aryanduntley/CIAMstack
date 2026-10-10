"""The automation domain: jobs as entries (cron on a server role, a function realized by a binding, the roles they
use), the jobs report, a function realization read from a cloud as a job binding, and the planner's findings about
jobs the target can't run or nobody owns."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.directory import one
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.inventory import environment_groups, resource
from opsdir.domains.automation.jobs import check_jobs, job_rows
from opsdir.domains.automation.naming import JOBS
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
