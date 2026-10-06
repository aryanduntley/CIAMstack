"""Volumes and snapshot policies (the data domain): each server role's disks in an environment, compared by role. A
move keeps a disk no smaller (a blocker), encrypted with a key the target binds, snapshotted as often and as long and
copied to another region as the source does (actions with fixes); a volume the source has and the target's servers
lack is an action whose fix copies it. The volumes report lists each with its snapshot policy."""
from opsdir.connectors.fixes import chosen
from opsdir.domains.data.volumes import (boot_volume, check_volumes, data_volumes, is_encrypted, role_volumes,
                                         volume_key_role, volume_policy, volume_rows)
from network_fixtures import ALPHA, BETA, context, entry, model

DATA = dict(ciamBindingRole="volume-ds-data", ciamTargetRole="ds", ciamVolumeKind="data", ciamMountPath="/opt/ds/db",
            ciamVolumeSizeGb="200", ciamVolumeClass="ssd", ciamIops="6000", ciamVolumeEncrypted="TRUE",
            ciamSnapshotPolicyRole="snapshots-daily")
BOOT = dict(ciamBindingRole="volume-ds-boot", ciamTargetRole="ds", ciamVolumeKind="boot", ciamVolumeSizeGb="50",
            ciamVolumeClass="ssd")
POLICY = dict(ciamBindingRole="snapshots-daily", ciamRetentionDays="7", ciamSnapshotEveryHours="24",
              ciamSnapshotAt="03:00", ciamCopyRegion="region-2", ciamSnapshotConsistency="crash")
BETA_KEY = entry(BETA, "key-disk", "ciamKeyRef", ciamBindingRole="disk-encryption", ciamRefUri="fake://keys/beta")


def _pair(volume=None, policy=None, beta_extra=(BETA_KEY,), with_volume=True, with_policy=True):
    """(ctx) alpha -> beta, alpha with DATA, BOOT and POLICY, beta with them changed by volume and policy (None values
    left out)."""
    def changed(base, change):
        return {k: v for k, v in {**base, **(change or {})}.items() if v is not None}
    d, alpha, beta = model(
        alpha=(entry(ALPHA, "vol-ds-data", "ciamVolume", **DATA), entry(ALPHA, "vol-ds-boot", "ciamVolume", **BOOT),
               entry(ALPHA, "snapshots-daily", "ciamSnapshotPolicy", **POLICY)),
        beta=(*((entry(BETA, "vol-ds-data", "ciamVolume", **changed(DATA, volume)),) if with_volume else ()),
              entry(BETA, "vol-ds-boot", "ciamVolume", **BOOT),
              *((entry(BETA, "snapshots-daily", "ciamSnapshotPolicy", **changed(POLICY, policy)),)
                if with_policy else ()), *beta_extra))
    return context(d, alpha, beta)


def _texts(rows):
    return [r[1] for r in rows]


def test_a_roles_volumes_boot_first_with_their_key_and_policy():
    ctx = _pair()
    assert [v.dn.split(",")[0] for v in role_volumes(ctx.src, "ds")] == ["cn=vol-ds-boot", "cn=vol-ds-data"]
    assert boot_volume(ctx.src, "ds").attrs["ciamVolumeSizeGb"] == ("50",) and boot_volume(ctx.src, "web") is None
    (data,) = data_volumes(ctx.src, "ds")
    assert volume_key_role(data) == "disk-encryption" and is_encrypted(data)
    assert volume_policy(ctx.src, data).attrs["ciamRetentionDays"] == ("7",)
    assert volume_policy(ctx.src, boot_volume(ctx.src, "ds")) is None


def test_the_same_volumes_and_policies_are_ok():
    f = check_volumes(_pair())
    assert (f.blockers, f.actions, f.fixes) == ((), (), ())
    assert f.ok == ("2 volume(s) keep their size, encryption and snapshots in beta/prod.",)


def test_a_smaller_target_volume_blocks_and_its_fix_carries_the_size():
    f = check_volumes(_pair({"ciamVolumeSizeGb": "100"}))
    assert _texts(f.blockers) == ["Volume `volume-ds-data` is 200 GB in alpha/prod but 100 GB in beta/prod: what "
                                  "the source keeps on it doesn't fit."]
    (fix,) = f.fixes
    assert fix.key == "volume:volume-ds-data:ciamVolumeSizeGb"
    assert fix.records[0].mods == (("replace", "ciamVolumeSizeGb", ("200",)),)
    assert check_volumes(_pair({"ciamVolumeSizeGb": "400"})).blockers == ()       # bigger is fine


def test_a_volume_the_targets_servers_lack_is_copied_with_its_binding_values_as_inputs():
    f = check_volumes(_pair(with_volume=False))
    assert _texts(f.actions) == ["Volume `volume-ds-data` (data disk of the ds servers mounted at /opt/ds/db) is "
                                 "recorded in alpha/prod but not in beta/prod: nothing says what disk the servers "
                                 "there keep that on."]
    (fix,) = f.fixes
    added = fix.records[-1]
    assert added.dn == f"cn=vol-ds-data,ou=bindings,{BETA}" and added.attrs["ciamMountPath"] == ("/opt/ds/db",)
    assert added.attrs["ciamVolumeSizeGb"][0].key == "ciamVolumeSizeGb"        # the target's own size: given


def test_an_unencrypted_target_volume_or_an_unbound_key_is_an_action():
    off = check_volumes(_pair({"ciamVolumeEncrypted": "FALSE"}))
    assert _texts(off.actions) == ["Volume `volume-ds-data` is encrypted in alpha/prod but not in beta/prod: what the "
                                   "servers keep on it is readable to anyone who gets the disk or a snapshot of it."]
    assert off.fixes[0].records[0].mods == (("replace", "ciamVolumeEncrypted", ("TRUE",)),)
    unbound = check_volumes(_pair(beta_extra=()))
    assert sorted(_texts(unbound.actions)) == [
        "Volume `volume-ds-boot` is encrypted with key role `disk-encryption`, which beta/prod doesn't bind: nothing "
        "says which key encrypts it there.",
        "Volume `volume-ds-data` is encrypted with key role `disk-encryption`, which beta/prod doesn't bind: nothing "
        "says which key encrypts it there."]


def test_no_snapshot_policy_in_the_target_is_an_action_its_fix_a_policy_like_the_sources():
    f = check_volumes(_pair({"ciamSnapshotPolicyRole": None}, with_policy=False))
    assert _texts(f.actions) == ["Volume `volume-ds-data` is snapshotted by `snapshots-daily` (every 24 hours, kept 7 "
                                 "days) in alpha/prod but has no snapshot policy in beta/prod: a lost or damaged disk "
                                 "there can't be restored from a snapshot."]
    (fix,) = f.fixes
    added = next(r for r in fix.records if r.changetype == "add" and "ciamSnapshotPolicy" in r.attrs["objectClass"])
    assert added.dn == f"cn=snapshots-daily,ou=bindings,{BETA}" and added.attrs["ciamRetentionDays"] == ("7",)
    assert added.attrs["ciamCopyRegion"][0].key == "ciamCopyRegion"            # the target's own region: given
    assert fix.records[-1].mods == (("replace", "ciamSnapshotPolicyRole", ("snapshots-daily",)),)
    named = check_volumes(_pair(with_policy=False))
    assert "names snapshot policy `snapshots-daily`, which beta/prod doesn't bind" in named.actions[0][1]


def test_a_target_policy_of_its_own_is_a_choice():
    other = entry(BETA, "snapshots-hourly", "ciamSnapshotPolicy", ciamBindingRole="snapshots-hourly",
                  ciamRetentionDays="2", ciamSnapshotEveryHours="1")
    f = check_volumes(_pair({"ciamSnapshotPolicyRole": None}, with_policy=False, beta_extra=(BETA_KEY, other)))
    (fix,) = f.fixes
    assert [o.key for o in fix.options] == ["snapshots-hourly"]
    assert chosen(fix, "snapshots-hourly").records[0].mods == (("replace", "ciamSnapshotPolicyRole",
                                                                 ("snapshots-hourly",)),)


def test_less_often_shorter_or_no_copy_in_the_targets_policy_are_actions_once_per_policy():
    f = check_volumes(_pair(policy={"ciamSnapshotEveryHours": "48", "ciamRetentionDays": "3",
                                    "ciamCopyRegion": None}))
    assert _texts(f.actions) == [
        "Snapshot policy `snapshots-daily` snapshots every 48 hours in beta/prod; `snapshots-daily` does every 24 in "
        "alpha/prod: a restore loses more.",
        "Snapshot policy `snapshots-daily` keeps snapshots 3 days in beta/prod; `snapshots-daily` keeps them 7 in "
        "alpha/prod: restores reach back less far.",
        "Snapshot policy `snapshots-daily` copies each snapshot to region-2 in alpha/prod; `snapshots-daily` copies "
        "none in beta/prod: losing its region loses the snapshots too."]
    assert [x.key for x in f.fixes] == ["snapshot-policy:snapshots-daily:ciamSnapshotEveryHours",
                                        "snapshot-policy:snapshots-daily:ciamRetentionDays",
                                        "snapshot-policy:snapshots-daily:ciamCopyRegion"]
    assert f.fixes[2].records[0].mods[0][2][0].example == ("region-2",)


def test_the_volumes_report():
    ctx = _pair({"ciamVolumeEncrypted": "FALSE"})
    rows = volume_rows(ctx.d)
    assert rows[0] == ("alpha/prod", "volume-ds-boot", "ds", "boot", "", "50", "ssd", "", "", "disk-encryption", "",
                       "", "", "", "")
    assert rows[1] == ("alpha/prod", "volume-ds-data", "ds", "data", "/opt/ds/db", "200", "ssd", "6000", "",
                       "disk-encryption", "snapshots-daily", "24", "03:00", "7", "region-2")
    assert rows[3][9] == "not encrypted"
