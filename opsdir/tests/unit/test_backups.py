"""Backup vaults, backup plans and restore tests (the data domain). A move keeps every role the source backs up backed
up in the target (an action whose fix adds it to the target's plan or copies the source's), each plan as often and as
long and copied to another region, whichever mechanism each environment uses (a snapshot policy in one, a backup plan
in the other), and each vault locked, keyed and restorable as well. Restore tests are records: the target must have a
passed application-level test of every role the source protects before cutover (a failed latest test blocks), and
the source's are due every restore-test-interval-days (an estate setting) unless a plan says otherwise."""
from opsdir.domains.data.backups import backup_rows, check_backups, holds_role, plan_vault, protected_roles
from opsdir.domains.data.restores import check_restores, restore_interval, restore_rows, tests_of as restores_of
from opsdir.domains.data.volumes import check_volumes
from network_fixtures import ALPHA, BETA, context, entry, model

VOLUME = dict(ciamBindingRole="volume-ds-data", ciamTargetRole="ds", ciamVolumeKind="data", ciamVolumeSizeGb="200")
PLAN = dict(ciamBindingRole="backup-daily", ciamProtectsRole="volume-ds-data", ciamBackupVaultRole="vault-main",
            ciamBackupEveryHours="24", ciamBackupAt="05:00", ciamRetentionDays="35", ciamCopyRegion="region-2")
VAULT = dict(ciamBindingRole="vault-main", ciamStorageImmutability="compliance", ciamStorageLockDays="35",
             ciamEncryptedByRole="disk-encryption", ciamCrossRegionRestore="TRUE")
KEY = dict(ciamBindingRole="disk-encryption", ciamRefUri="fake://keys/disk")
TESTS = "ou=restore-tests,dc=ciam-ops"
TREE = f"dn: {TESTS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: restore-tests\n"


def _changed(base, change):
    return {k: v for k, v in {**base, **(change or {})}.items() if v is not None}


def _test(cn, env, on, result="passed", level="application", role="volume-ds-data"):
    return entry(TESTS, cn, "ciamRestoreTest", ciamTestedOn=on, ciamTestEnvironment=env, ciamRestoredRole=role,
                 ciamRestoredFromRole="backup-daily", ciamRestoreLevel=level, ciamTestResult=result)


def _pair(plan=None, vault=None, with_plan=True, beta_extra=(), tests=(), tree=()):
    """(ctx, d, alpha, beta): alpha with the volume, PLAN, VAULT and its key; beta with the volume, its key, and PLAN /
    VAULT changed (None values left out; with_plan False: neither)."""
    d, alpha, beta = model(
        alpha=(entry(ALPHA, "vol-ds-data", "ciamVolume", **VOLUME),
               entry(ALPHA, "backup-daily", "ciamBackupPlan", **PLAN),
               entry(ALPHA, "vault-main", "ciamBackupVault", **VAULT), entry(ALPHA, "key-disk", "ciamKeyRef", **KEY)),
        beta=(entry(BETA, "vol-ds-data", "ciamVolume", **VOLUME), entry(BETA, "key-disk", "ciamKeyRef", **KEY),
              *((entry(BETA, "backup-daily", "ciamBackupPlan", **_changed(PLAN, plan)),
                 entry(BETA, "vault-main", "ciamBackupVault", **_changed(VAULT, vault))) if with_plan else ()),
              *beta_extra),
        tree=(TREE, *tests, *tree))
    return context(d, alpha, beta, cutover="2026-12-01"), d, alpha, beta


def _texts(found):
    return [a[1] for a in found.actions]


def test_what_an_environment_protects_and_where_it_keeps_it():
    _, d, alpha, beta = _pair(with_plan=False)
    assert list(protected_roles(alpha)) == ["volume-ds-data"]
    assert protected_roles(beta) == {}
    assert plan_vault(alpha, protected_roles(alpha)["volume-ds-data"][0]).dn.startswith("cn=vault-main,")
    assert holds_role(beta, "volume-ds-data") and holds_role(beta, "ds") and not holds_role(beta, "pf-admin")


def test_a_role_the_source_backs_up_and_the_target_doesn_t():
    ctx, *_ = _pair(with_plan=False)
    found = check_backups(ctx)
    assert _texts(found) == ["Role `volume-ds-data` is backed up by `backup-daily` (every 24 hours, kept 35 days) in "
                             "alpha/prod, but nothing backs it up in beta/prod: what it holds can't be restored there."]
    fix, = found.fixes
    assert fix.key == "backup:volume-ds-data" and fix.records[-1].dn == f"cn=backup-daily,ou=bindings,{BETA}"
    # the target binds the plan but it protects something else: the fix adds the role to it
    ctx, *_ = _pair(plan={"ciamProtectsRole": "ds"})
    fix, = check_backups(ctx).fixes
    assert fix.records[0].mods == (("add", "ciamProtectsRole", ("volume-ds-data",)),)


def test_a_target_plan_that_backs_up_less_often_keeps_less_and_copies_nowhere():
    ctx, *_ = _pair(plan={"ciamBackupEveryHours": "48", "ciamRetentionDays": "7", "ciamCopyRegion": None})
    found = check_backups(ctx)
    assert _texts(found) == [
        "Backup plan `backup-daily` backs up every 48 hours in beta/prod; `backup-daily` does every 24 in alpha/prod: "
        "a restore loses more.",
        "Backup plan `backup-daily` keeps recovery points 7 days in beta/prod; `backup-daily` keeps them 35 in "
        "alpha/prod: restores reach back less far.",
        "Backup plan `backup-daily` copies each recovery point to region-2 in alpha/prod; `backup-daily` copies none "
        "in beta/prod: losing its region loses the recovery points too."]
    assert [f.key for f in found.fixes] == ["backup-plan:backup-daily:ciamBackupEveryHours",
                                            "backup-plan:backup-daily:ciamRetentionDays",
                                            "backup-plan:backup-daily:ciamCopyRegion"]
    assert found.fixes[0].records[0].mods == (("replace", "ciamBackupEveryHours", ("24",)),)


def test_a_target_vault_locked_less_keyed_by_nobody_and_restorable_in_one_region():
    ctx, *_ = _pair(vault={"ciamStorageImmutability": "governance", "ciamEncryptedByRole": None,
                           "ciamCrossRegionRestore": None})
    found = check_backups(ctx)
    assert _texts(found) == [
        "Backup vault `vault-main` locks recovery points (compliance 35 days) in alpha/prod; beta/prod governance 35 "
        "days: ransomware or a mistake could delete or change what it holds.",
        "Backup vault `vault-main` is encrypted with key `disk-encryption` in alpha/prod; in beta/prod nothing names "
        "its key, so the provider's own default key encrypts it, which nobody here controls or can revoke.",
        "Backup vault `vault-main` restores in another region in alpha/prod but not in beta/prod: losing its region "
        "loses the recovery points too."]
    assert found.fixes[0].risks and found.fixes[1].options[0].key == "disk-encryption"


def test_a_source_snapshot_policy_against_a_target_backup_plan_of_the_same_role():
    policy = dict(ciamBindingRole="snapshots-daily", ciamRetentionDays="7", ciamSnapshotEveryHours="24",
                  ciamCopyRegion="region-2")
    plan = dict(ciamBindingRole="snapshots-daily", ciamProtectsRole="volume-ds-data", ciamBackupVaultRole="vault-main",
                ciamRetentionDays="3", ciamBackupEveryHours="24")
    d, alpha, beta = model(
        alpha=(entry(ALPHA, "vol-ds-data", "ciamVolume", **VOLUME, ciamSnapshotPolicyRole="snapshots-daily"),
               entry(ALPHA, "snapshots-daily", "ciamSnapshotPolicy", **policy)),
        beta=(entry(BETA, "vol-ds-data", "ciamVolume", **VOLUME, ciamSnapshotPolicyRole="snapshots-daily"),
              entry(BETA, "snapshots-daily", "ciamBackupPlan", **plan), entry(BETA, "key-disk", "ciamKeyRef", **KEY)))
    found = check_volumes(context(d, alpha, beta))
    assert _texts(found) == [
        "Backup plan `snapshots-daily` keeps recovery points 3 days in beta/prod; `snapshots-daily` keeps them 7 in "
        "alpha/prod: restores reach back less far.",
        "Snapshot policy `snapshots-daily` copies each snapshot to region-2 in alpha/prod; `snapshots-daily` copies "
        "none in beta/prod: losing its region loses the recovery points too."]
    assert [f.key for f in found.fixes] == ["backup-plan:snapshots-daily:ciamRetentionDays",
                                            "backup-plan:snapshots-daily:ciamCopyRegion"]


def test_the_target_needs_a_passed_application_level_restore_before_cutover():
    ctx, *_ = _pair(tests=(_test("rt-alpha", ALPHA, "20260801000000Z"),
                           _test("rt-beta", BETA, "20260901000000Z", level="disk")))
    found = check_restores(ctx)
    assert found.blockers == ()
    assert _texts(found) == ["Before cutover, restore `volume-ds-data`'s data in beta/prod from its backups and verify "
                             "the application works with it, then record the test: nothing shows beta/prod can recover "
                             "it (a disk mounted isn't enough)."]
    assert found.actions[0][3] == "2026-12-01"
    ctx, *_ = _pair(tests=(_test("rt-alpha", ALPHA, "20260801000000Z"),
                           _test("rt-beta", BETA, "20260901000000Z")))
    assert check_restores(ctx).ok == ("1 protected role(s) restore-tested in alpha/prod and beta/prod.",)


def test_a_failed_latest_restore_in_the_target_blocks():
    ctx, *_ = _pair(tests=(_test("rt-alpha", ALPHA, "20260801000000Z"),
                           _test("rt-beta-1", BETA, "20260801000000Z"),
                           _test("rt-beta-2", BETA, "20260910000000Z", result="failed")))
    found = check_restores(ctx)
    assert [b[1] for b in found.blockers] == ["The latest restore test of `volume-ds-data` in beta/prod (2026-09-10) "
                                              "failed: nothing shows its data can be recovered there."]


def test_the_source_s_restores_are_due_on_the_estate_setting_or_the_plan_s_own_interval():
    old = (_test("rt-alpha", ALPHA, "20260601000000Z"), _test("rt-beta", BETA, "20260901000000Z"))
    ctx, d, alpha, _ = _pair(tests=old)
    assert restore_interval(d, alpha, "volume-ds-data") == 90                     # the setting's default
    assert _texts(check_restores(ctx)) == ["`volume-ds-data` was last restore-tested in alpha/prod on 2026-06-01; "
                                           "tests are due every 90 days."]
    setting = ("dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n",
               "dn: cn=restore-test-interval-days,ou=settings,dc=ciam-ops\nobjectClass: top\n"
               "objectClass: ciamEstateSetting\ncn: restore-test-interval-days\nciamEstateValue: 180\n")
    ctx, d, alpha, _ = _pair(tests=old, tree=setting)
    assert restore_interval(d, alpha, "volume-ds-data") == 180 and _texts(check_restores(ctx)) == []
    d, alpha, _ = model(alpha=(entry(ALPHA, "backup-daily", "ciamBackupPlan", **PLAN, ciamRestoreTestDays="30"),),
                        tree=setting)
    assert restore_interval(d, alpha, "volume-ds-data") == 30                  # the plan's own, over the setting


def test_the_source_never_tested_or_failed():
    ctx, *_ = _pair(tests=(_test("rt-beta", BETA, "20260901000000Z"),))
    assert _texts(check_restores(ctx)) == ["Role `volume-ds-data` is backed up in alpha/prod but no restore of it has "
                                           "been tested: nothing shows its backups can be restored."]
    ctx, *_ = _pair(tests=(_test("rt-alpha", ALPHA, "20260915000000Z", result="failed"),
                           _test("rt-beta", BETA, "20260901000000Z")))
    assert _texts(check_restores(ctx)) == ["The latest restore test of `volume-ds-data` in alpha/prod (2026-09-15) "
                                           "failed: its backups may not restore."]


def test_the_reports():
    _, d, alpha, _ = _pair(tests=(_test("rt-alpha", ALPHA, "20260801000000Z"),))
    assert backup_rows(d)[0] == ("alpha/prod", "backup-daily", "volume-ds-data", "vault-main", "24", "05:00", "", "35",
                                 "region-2", "compliance 35 days", "disk-encryption", "TRUE", "")
    assert restore_rows(d) == [("2026-08-01", "alpha/prod", "volume-ds-data", "backup-daily", "application", "passed",
                                "", "", "")]
    assert [t.dn for t in restores_of(d, ALPHA, "volume-ds-data")] == [f"cn=rt-alpha,{TESTS}"]
