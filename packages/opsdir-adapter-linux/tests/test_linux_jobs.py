"""Linux servers' crontabs and systemd timers read as jobs: the same job on a role's servers is one job for that role,
found on each; a job on some of them is named; schedules that differ are named; commands and environment lines
holding secrets are never recorded; a command run from a recorded bundle links it; a re-import changes nothing and
keeps what the record adds (an owner)."""
import pytest

from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.automation.naming import job_dn
from opsdir_adapter_linux.adapter import ADAPTER
import mini_estate
from support import REGISTRY, build_directory

ALPHA, BETA = ("env=prod,cloud=alpha,ou=environments,dc=ciam-ops", "env=prod,cloud=beta,ou=environments,dc=ciam-ops")


def _server(env, cn, host):
    return (f"dn: cn={cn},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: web\n"
            f"ciamHostname: {host}\nciamSubnet: cn=subnet-web,ou=bindings,{env}\n")


def _subnet(env):
    return (f"dn: cn=subnet-web,ou=bindings,{env}\nobjectClass: top\nobjectClass: ciamSubnetBinding\ncn: subnet-web\n"
            "ciamBindingRole: subnet-web\nciamCidr: 10.1.1.0/24\n")


RECORDS = "\n".join((
    _subnet(ALPHA), _subnet(BETA),
    _server(ALPHA, "web-1", "web-1.alpha.example.test"), _server(ALPHA, "web-2", "web-2.alpha.example.test"),
    _server(BETA, "web-b1", "web-b1.beta.example.test"),
    "dn: ou=bundles,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: bundles\n",
    "dn: cn=ops-scripts,ou=bundles,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamBundle\n"
    "cn: ops-scripts\nciamRepoPath: ops/scripts\nciamBundleKind: script\nciamDeployPath: /opt/scripts\n"
    f"ciamSha256: {'a' * 64}\n"))
CRONTAB = "SHELL=/bin/sh\nMAILTO=ops@example.test\n30 2 * * * root /opt/scripts/nightly-export.sh --to s3\n"
FILES = {
    "web-1.alpha.example.test/etc/crontab": CRONTAB + "@reboot root /usr/local/bin/warm-cache\n",
    "web-2.alpha.example.test/etc/crontab": CRONTAB,
    "web-b1.beta.example.test/etc/crontab": CRONTAB.replace("30 2", "45 3"),
    "web-1.alpha.example.test/var/spool/cron/crontabs/svc":
        "DB_PASSWORD=Hunter2-not-a-real-one\n*/5 * * * * /usr/local/bin/check --password=Hunter2-not-a-real-one\n",
    "web-1.alpha.example.test/etc/systemd/system/rotate-logs.timer": "[Timer]\nOnCalendar=daily\nOnBootSec=5min\n",
    "web-1.alpha.example.test/etc/systemd/system/rotate-logs.service":
        "[Service]\nUser=logs\nExecStart=/opt/scripts/rotate.sh --keep 7\n",
    "unknown.example.test/etc/crontab": CRONTAB}
OWNER = tuple(parse(f"dn: {job_dn('web-nightly-export')}\nchangetype: modify\nadd: ciamOwner\n"
                    "ciamOwner: cn=ops,ou=owners,dc=ciam-ops\n-\n"))
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n\n"
          "dn: cn=ops,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n")


def records():
    return tuple(parse(mini_estate.LDIF + "\n" + RECORDS + "\n" + OWNERS))


def imported(changes=(), files=None):
    base = build_directory(REGISTRY, records())
    import_changes, notices = preview_import(base, "linux/jobs", files or FILES, (ADAPTER,))
    return build_directory(REGISTRY, records(), (*import_changes, *changes)), import_changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def test_the_same_job_on_a_roles_servers_is_one_job(after):
    d, _ = after
    job = get(d, job_dn("web-nightly-export"))
    assert (one(job, "ciamJobKind"), values(job, "ciamSchedule"), one(job, "ciamTargetRole"), one(job, "ciamRunsAs"),
            one(job, "ciamCommand")) == ("cron", ("30 2 * * *",), "web", "root", "/opt/scripts/nightly-export.sh --to s3")
    assert values(job, "ciamFoundOn") == tuple(sorted((f"cn=web-1,{ALPHA}", f"cn=web-2,{ALPHA}", f"cn=web-b1,{BETA}")))
    assert one(job, "ciamCodeBundle") == "cn=ops-scripts,ou=bundles,dc=ciam-ops"


def test_reboot_jobs_and_timers(after):
    d, _ = after
    warm, rotate = get(d, job_dn("web-warm-cache")), get(d, job_dn("web-rotate-logs"))
    assert (values(warm, "ciamTrigger"), values(warm, "ciamSchedule")) == (("boot",), ())
    assert (one(rotate, "ciamJobKind"), values(rotate, "ciamSchedule"), values(rotate, "ciamTrigger"),
            one(rotate, "ciamRunsAs"), one(rotate, "ciamCommand"), one(rotate, "ciamCodeBundle")) == \
        ("timer", ("OnCalendar=daily",), ("boot",), "logs", "/opt/scripts/rotate.sh --keep 7",
         "cn=ops-scripts,ou=bundles,dc=ciam-ops")


def test_secrets_are_never_recorded(after):
    d, notices = after
    check = get(d, job_dn("web-check"))
    assert (one(check, "ciamCommand"), one(check, "ciamRunsAs")) == (None, "svc")
    assert "Hunter2" not in repr([dict(e.attrs) for e in d.entries.values()])
    assert {"job web-check (var/spool/cron/crontabs/svc:2 on web-1): its command holds secret material; not "
            "recorded, record what it runs by hand",
            "web-1 var/spool/cron/crontabs/svc:1: DB_PASSWORD is given a secret value in the crontab; not recorded: "
            "move it to a secret store"} <= set(notices)
    assert not any("MAILTO" in n for n in notices)


def test_partial_and_differing_jobs_and_unknown_folders_are_named(after):
    _, notices = after
    assert {"job warm-cache of role web is on web-1 but not web-2 in alpha/prod: one server runs it, or the others "
            "drifted",
            "job web-nightly-export (etc/crontab:3 on web-1): its schedule differs between servers (web-1: 30 2 * * *, "
            "web-2: 30 2 * * *, web-b1: 45 3 * * *); recorded the first",
            "unknown.example.test: no server in the record has this hostname or name; not imported"} <= set(notices)


def test_a_reimport_changes_nothing_and_keeps_the_owner():
    d, _, _ = imported(OWNER)
    again, _ = preview_import(d, "linux/jobs", FILES, (ADAPTER,))
    assert again == ()
    assert one(get(d, job_dn("web-nightly-export")), "ciamOwner") == "cn=ops,ou=owners,dc=ciam-ops"
