"""The recovery domain: recovery objectives (RTO/RPO per role), standby environments and failover drills. The planner
holds both environments of a move to every objective for the roles they run (best recovery point within the RPO, the
recovery time shown within the RTO, a drill's data loss within the RPO), moves the standbys of the source with it
(re-pointed at the target, a fix), flags a standby in its primary's region or without a failover runbook, and a name
failing over from the source."""
from opsdir.domains.recovery.checks import check_recovery
from opsdir.domains.recovery.evidence import Evidence, recovery_point, recovery_time, regional_points, server_role
from opsdir.domains.recovery.intent import joining, objectives, primary_of, region_of, standbys_of
from opsdir.domains.recovery.reports import drill_rows, recovery_rows, standby_rows
from opsdir.core.environment import env_model
from network_fixtures import ALPHA, BETA, context, entry, model

GAMMA = "env=prod,cloud=gamma,ou=environments,dc=ciam-ops"
DELTA = "env=prod,cloud=delta,ou=environments,dc=ciam-ops"
DR = "env=dr,cloud=alpha,ou=environments,dc=ciam-ops"
RUNBOOK = "cn=WI-9,ou=runbooks,dc=ciam-ops"
VOLUME = dict(ciamBindingRole="volume-ds-data", ciamTargetRole="ds", ciamVolumeKind="data", ciamVolumeSizeGb="200")
PLAN = dict(ciamBindingRole="backup-daily", ciamProtectsRole="volume-ds-data", ciamBackupVaultRole="vault-main",
            ciamBackupEveryHours="24", ciamRetentionDays="35")
OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"
BOOK = (f"dn: {RUNBOOK}\nobjectClass: top\nobjectClass: ciamRunbook\ncn: WI-9\nciamTitle: Fail over\n"
        "ciamLastValidated: 20260901000000Z\n")


def _standby(env, cloud_region=None, runbook=True, of=ALPHA, joins=ALPHA):
    """A standby environment (its cloud when cloud_region is given) with two directory servers."""
    cloud, name = env.split(",")[1].split("=")[1], env.split(",")[0].split("=")[1]
    head = (f"dn: cloud={cloud},ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCloud\ncloud: {cloud}\n"
            f"ciamCloudProvider: fakecloud\nciamRegion: {cloud_region}\n\n") if cloud_region else ""
    extra = "".join((f"ciamJoinsDeploymentOf: {joins}\n" if joins else "",
                     f"ciamRunbookRef: {RUNBOOK}\n" if runbook else ""))
    return (f"{head}dn: {env}\nobjectClass: top\nobjectClass: ciamEnvironment\nobjectClass: ciamStandby\nenv: {name}\n"
            f"ciamStandbyOf: {of}\nciamStandbyMode: warm\n{extra}",
            *(entry(env, n, "ciamServer", ciamServerRole="ds", ciamHostname=f"{n}.{name}.test")
              for n in ("ds-1", "ds-2")))


def _objective(rto="120", rpo="60", runbook=True):
    attrs = {k: v for k, v in dict(ciamRecoversRole="volume-ds-data", ciamRtoMinutes=rto, ciamRpoMinutes=rpo,
                                    ciamRunbookRef=RUNBOOK if runbook else None).items() if v is not None}
    return entry("ou=recovery,dc=ciam-ops", "directory-data", "ciamRecoveryObjective", **attrs)


def _restore(env, minutes, result="passed"):
    return entry("ou=restore-tests,dc=ciam-ops", f"rt-{env.split(',')[1]}", "ciamRestoreTest",
                 ciamTestedOn="20260814000000Z", ciamTestEnvironment=env, ciamRestoredRole="volume-ds-data",
                 ciamRestoreLevel="application", ciamTestResult=result, ciamRestoreMinutes=minutes)


def _drill(minutes, lost, frm=ALPHA, to=GAMMA):
    return entry("ou=failover-drills,dc=ciam-ops", "fd-1", "ciamFailoverDrill", ciamDrilledOn="20260910000000Z",
                 ciamDrillFrom=frm, ciamDrillTo=to, ciamDrillResult="passed", ciamServiceMinutes=minutes,
                 ciamDataLossMinutes=lost)


def _pair(standbys=None, objective=None, beta_plan=True, records=(), alpha_extra=(), beta_extra=(), plan=None):
    """(ctx, d, alpha, beta): both with the directory data volume; alpha's GAMMA standby (region-2) joins it; beta
    backs the volume up daily (beta_plan) in its own region (plan: changes to it)."""
    d, alpha, beta = model(
        alpha=(entry(ALPHA, "vol-ds-data", "ciamVolume", **VOLUME), *alpha_extra),
        beta=(entry(BETA, "vol-ds-data", "ciamVolume", **VOLUME),
              *((entry(BETA, "backup-daily", "ciamBackupPlan", **{**PLAN, **(plan or {})}),) if beta_plan else ()),
              *beta_extra),
        tree=(*(OU.format(o) for o in ("recovery", "failover-drills", "restore-tests", "runbooks")), BOOK,
              *(standbys if standbys is not None else _standby(GAMMA, "region-2")),
              *((objective or _objective(),) if objective is not False else ()), *records))
    return context(d, alpha, beta, cutover="2026-12-01"), d, alpha, beta


def _texts(found):
    return [a[1] for a in found.actions]


def test_objectives_standbys_and_regions():
    _, d, alpha, beta = _pair()
    assert [o.dn for o in objectives(d)] == ["cn=directory-data,ou=recovery,dc=ciam-ops"]
    assert [e.dn for e in standbys_of(d, ALPHA)] == [GAMMA] and standbys_of(d, BETA) == ()
    gamma = standbys_of(d, ALPHA)[0]
    assert primary_of(d, gamma).dn == ALPHA and primary_of(d, alpha.env) is None
    assert [e.dn for e in joining(d, ALPHA)] == [GAMMA]
    assert (region_of(d, ALPHA), region_of(d, GAMMA)) == ("region-1", "region-2")
    assert server_role(alpha, "volume-ds-data") == "ds" and server_role(alpha, "ds") == "ds"


def test_best_recovery_point():
    ctx, d, alpha, beta = _pair()
    assert recovery_point(d, alpha, "volume-ds-data") == Evidence(0, "replicated to gamma/prod in region-2")
    # a backup kept in the environment's own region is lost with it
    assert recovery_point(d, beta, "volume-ds-data") is None
    assert regional_points(d, beta, "volume-ds-data") == (Evidence(1440, "backup plan `backup-daily` every 24 hours"),)
    _, d, _, beta = _pair(plan={"ciamCopyRegion": ("region-1", "region-2")})
    assert recovery_point(d, beta, "volume-ds-data") == Evidence(
        1440, "backup plan `backup-daily` every 24 hours, copied to region-2")
    _, d, _, beta = _pair(beta_plan=False)
    assert recovery_point(d, beta, "volume-ds-data") is None and regional_points(d, beta, "volume-ds-data") == ()
    # a standby in the same region keeps no copy a regional disaster spares
    _, d, alpha, _ = _pair(standbys=_standby(DR))
    assert recovery_point(d, alpha, "volume-ds-data") is None
    # a database restorable to a point in time: out of the region only when its backups are copied to another
    db = dict(ciamBindingRole="pf-db", ciamDbEngine="postgresql", ciamDbPointInTime="TRUE")
    _, d, _, beta = _pair(beta_extra=(entry(BETA, "pf-db", "ciamDatabase", **db),))
    assert recovery_point(d, beta, "pf-db") is None
    assert regional_points(d, beta, "pf-db") == (Evidence(5, "point-in-time restore"),)
    _, d, _, beta = _pair(beta_extra=(entry(BETA, "pf-db", "ciamDatabase", **db, ciamCopyRegion="region-2"),))
    assert recovery_point(d, beta, "pf-db") == Evidence(5, "point-in-time restore, backups copied to region-2")


def test_recovery_time_from_restore_tests_and_drills():
    _, d, alpha, beta = _pair(records=(_restore(ALPHA, "95"),))
    assert recovery_time(d, alpha, "volume-ds-data") == Evidence(95, "restore test 2026-08-14")
    assert recovery_time(d, beta, "volume-ds-data") is None
    _, d, alpha, _ = _pair(records=(_restore(ALPHA, "95"), _drill("30", "0")))
    assert recovery_time(d, alpha, "volume-ds-data") == Evidence(30, "failover drill 2026-09-10 to gamma/prod")


def test_a_target_nothing_stands_by_for():
    ctx, *_ = _pair(records=(_restore(ALPHA, "95"), _restore(BETA, "100")))
    found = check_recovery(ctx)
    assert _texts(found)[0] == (
        "Recovery objective `directory-data` allows `volume-ds-data` to lose 60 minutes of changes; in beta/prod "
        "nothing copies it out of its region (backup plan `backup-daily` every 24 hours stays there): a disaster "
        "taking the region loses all of it.")
    assert [f.key for f in found.fixes] == ["recovery:repoint:gamma/prod"]      # copying more often wouldn't help
    ctx, *_ = _pair(records=(_restore(ALPHA, "95"), _restore(BETA, "100")), plan={"ciamCopyRegion": "region-2"})
    found = check_recovery(ctx)
    assert _texts(found) == [
        "Recovery objective `directory-data` allows `volume-ds-data` to lose 60 minutes of changes; in beta/prod its "
        "best recovery point is backup plan `backup-daily` every 24 hours, copied to region-2 (1440 minutes).",
        "gamma/prod stands by for alpha/prod (warm, region-2); nothing stands by for beta/prod: after cutover a "
        "disaster there has nowhere to fail over to. Re-point gamma/prod at beta/prod, or build a standby for it."]
    interval, repoint = found.fixes
    assert interval.key == "recovery:directory-data:backup-daily:ciamBackupEveryHours"
    assert interval.records[0].mods == (("replace", "ciamBackupEveryHours", ("1",)),)
    assert interval.title == "Back up `volume-ds-data` every hour in beta/prod"
    assert repoint.key == "recovery:repoint:gamma/prod"
    assert [r.mods for r in repoint.records] == [(("replace", "ciamStandbyOf", (BETA,)),),
                                                 (("replace", "ciamJoinsDeploymentOf", (BETA,)),)]


def test_objectives_met_after_the_standby_follows_the_target():
    ctx, *_ = _pair(standbys=_standby(GAMMA, "region-2", of=BETA, joins=BETA),
                    records=(_restore(ALPHA, "95"), _restore(BETA, "100")),
                    alpha_extra=(entry(ALPHA, "backup-hourly", "ciamBackupPlan",
                                       **{**PLAN, "ciamBindingRole": "backup-hourly", "ciamBackupEveryHours": "1",
                                          "ciamCopyRegion": "region-2"}),))
    found = check_recovery(ctx)
    assert _texts(found) == [] and found.ok == ("1 recovery objective(s) met in alpha/prod and beta/prod.",)


def test_recovery_too_slow_and_a_drill_losing_too_much():
    ctx, *_ = _pair(records=(_restore(ALPHA, "150"), _drill("130", "90")), beta_plan=False,
                    standbys=(*_standby(GAMMA, "region-2"), *_standby(DELTA, "region-3", of=BETA, joins=None)))
    texts = _texts(check_recovery(ctx))
    assert ("Recovery objective `directory-data` wants `volume-ds-data` back within 120 minutes; in alpha/prod its "
            "failover drill 2026-09-10 to gamma/prod took 130 minutes.") in texts
    assert ("The failover drill from alpha/prod on 2026-09-10 lost 90 minutes of `volume-ds-data`'s changes; recovery "
            "objective `directory-data` allows 60.") in texts
    assert ("Recovery objective `directory-data` allows `volume-ds-data` to lose 60 minutes of changes; in beta/prod "
            "nothing copies it: a disaster loses all of it.") in texts
    assert ("Recovery objective `directory-data` wants `volume-ds-data` back within 120 minutes; in beta/prod no "
            "restore test or failover drill records how long recovering it takes.") in texts
    assert ("gamma/prod stands by for alpha/prod: at cutover re-point it at beta/prod or retire it (beta/prod has "
            "delta/prod).") in texts


def test_standbys_in_the_same_region_or_without_a_runbook_and_objectives_without_one():
    ctx, *_ = _pair(standbys=_standby(DR, runbook=False), objective=_objective(runbook=False),
                    records=(_restore(ALPHA, "95"), _restore(BETA, "100")))
    texts = _texts(check_recovery(ctx))
    assert ("alpha/dr stands by for alpha/prod in the same region (region-1): a disaster in that region takes both."
            in texts)
    assert "No runbook says how to fail over to alpha/dr from alpha/prod (ciamRunbookRef on its environment)." in texts
    assert ("Recovery objective `directory-data` names no runbook that recovers `volume-ds-data` (ciamRunbookRef)."
            in texts)


def test_a_name_failing_over_from_the_source():
    primary = entry(ALPHA, "sso-primary", "ciamDnsRecord", ciamBindingRole="sso-primary",
                    ciamRecordName="login.example.test", ciamRecordType="A", ciamRecordValue="192.0.2.1",
                    ciamRoutingPolicy="failover-primary")
    ctx, *_ = _pair(objective=False, alpha_extra=(primary,), standbys=())
    assert _texts(check_recovery(ctx)) == [
        "`login.example.test` fails over from alpha/prod (the primary) to nothing: at cutover make beta/prod's answer "
        "the primary (ciamRoutingPolicy failover-primary) and retire alpha/prod's."]


def test_nothing_to_say_without_objectives_standbys_or_failover():
    ctx, *_ = _pair(objective=False, standbys=())
    found = check_recovery(ctx)
    assert (found.blockers, found.actions, found.ok, found.fixes) == ((), (), (), ())


def test_reports():
    _, d, *_ = _pair(records=(_restore(ALPHA, "95"), _drill("30", "0")))
    assert recovery_rows(d) == [
        ("directory-data", "volume-ds-data", "alpha/prod", "120", "30 (failover drill 2026-09-10 to gamma/prod)", "60",
         "0 (replicated to gamma/prod in region-2)", "gamma/prod", "WI-9"),
        ("directory-data", "volume-ds-data", "beta/prod", "120", "none recorded", "60",
         "none out of its region (backup plan `backup-daily` every 24 hours)", "", "WI-9")]
    assert standby_rows(d) == [("gamma/prod", "alpha/prod", "warm", "region-2", "region-1", "alpha/prod", "WI-9")]
    assert drill_rows(d) == [("2026-09-10", "alpha/prod", "gamma/prod", "all", "passed", "30", "0", "", "")]
