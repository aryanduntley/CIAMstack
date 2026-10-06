"""Object stores (the data domain): how a bucket or container keeps what it holds, compared by role. A move keeps
versioning, the public access block, the lock (as strong and as long), encryption and a copy elsewhere (actions with
fixes: exact, a choice of key, or the target's own replica as an input); a backup target whose lifecycle deletes
backups before their retention is named in either environment."""
from opsdir.connectors.fixes import chosen
from opsdir.core.environment import of_class
from opsdir.core.findings import Input
from opsdir.domains.data.storage import (LifecycleRule, check_object_stores, has_depth, lifecycle_rules,
                                         lifecycle_value, object_store_rows, parse_lifecycle)
from network_fixtures import ALPHA, BETA, context, entry, model

SOURCE = dict(ciamBindingRole="backup-target", ciamStorageRef="s3://alpha-backups", ciamRetentionDays="35",
              ciamStorageVersioning="TRUE", ciamStorageImmutability="compliance", ciamStorageLockDays="35",
              ciamEncryptedByRole="db-key", ciamStoragePublicBlocked="TRUE",
              ciamStorageReplicaRef="s3://alpha-backups-dr",
              ciamStorageLifecycle=("30 cold", "400 delete", "noncurrent 30 delete"))
KEY = "ciamKeyRef", dict(ciamBindingRole="disk-key-beta", ciamRefUri="fake://beta-key")


def _pair(target=None, beta_extra=(), source=None):
    """(ctx) with alpha's backup target as SOURCE (changed by source) and beta's as SOURCE changed by target (None
    values left out)."""
    def attrs(changes, ref):
        return {k: v for k, v in {**SOURCE, "ciamStorageRef": ref, **(changes or {})}.items() if v is not None}
    d, alpha, beta = model(alpha=(entry(ALPHA, "backup", "ciamBackupTarget", **attrs(source, "s3://alpha-backups")),),
                           beta=(entry(BETA, "backup", "ciamBackupTarget", **attrs(target, "azblob://beta/backups")),
                                 *beta_extra))
    return context(d, alpha, beta)


def _texts(rows):
    return [r[1] for r in rows]


def test_lifecycle_rules_parse_and_order_current_objects_first():
    assert parse_lifecycle("noncurrent 30 delete") == LifecycleRule(True, 30, "delete")
    assert parse_lifecycle("30 freeze") is None and parse_lifecycle("delete") is None
    assert lifecycle_value(LifecycleRule(False, 365, "archive")) == "365 archive"
    (store,) = of_class(_pair().src, "ciamBackupTarget")
    assert [lifecycle_value(r) for r in lifecycle_rules(store)] == ["30 cold", "400 delete", "noncurrent 30 delete"]
    assert has_depth(store)
    (bare,) = of_class(_pair(source={a: None for a in SOURCE if a.startswith("ciamStorage") and a != "ciamStorageRef"}
                    | {"ciamEncryptedByRole": None}).src, "ciamBackupTarget")
    assert not has_depth(bare)


def test_the_same_store_in_both_is_ok():
    f = check_object_stores(_pair())
    assert (f.blockers, f.actions, f.fixes) == ((), (), ())
    assert f.ok == ("1 object store(s) keep their versioning, locks, encryption, public access block and copies in "
                    "beta/prod.",)


def test_what_the_source_kept_is_named_with_a_fix():
    f = check_object_stores(_pair({"ciamStorageVersioning": "FALSE", "ciamStoragePublicBlocked": None,
                                   "ciamStorageImmutability": None, "ciamStorageLockDays": None,
                                   "ciamEncryptedByRole": None, "ciamStorageReplicaRef": None},
                                  beta_extra=(entry(BETA, "key-disk", KEY[0], **KEY[1]),)))
    assert f.blockers == ()
    assert _texts(f.actions) == [
        "Object store `backup-target` has versioning in alpha/prod but not in beta/prod: an overwritten or deleted "
        "object can't be got back.",
        "Object store `backup-target` has public access blocked in alpha/prod but not in beta/prod: a policy or ACL "
        "could make it public.",
        "Object store `backup-target` locks objects (compliance 35 days) in alpha/prod; beta/prod doesn't lock them: "
        "ransomware or a mistake could delete or change what it holds.",
        "Object store `backup-target` is encrypted with key `db-key` in alpha/prod; in beta/prod nothing names its "
        "key, so the provider's own default key encrypts it, which nobody here controls or can revoke.",
        "Object store `backup-target` is copied to `s3://alpha-backups-dr` from alpha/prod; nothing copies "
        "beta/prod's: losing its region loses what it holds."]
    fixes = {x.key: x for x in f.fixes}
    lock = fixes["object-store:backup-target:ciamStorageImmutability"]     # one fix carries the mode and its days
    assert [r.mods for r in lock.records] == [(("replace", "ciamStorageImmutability", ("compliance",)),),
                                              (("replace", "ciamStorageLockDays", ("35",)),)]
    assert "can't be shortened" in lock.risks[0]
    assert chosen(fixes["object-store:backup-target:ciamEncryptedByRole"], "disk-key-beta").records[0].mods == (
        ("replace", "ciamEncryptedByRole", ("disk-key-beta",)),)
    ((_, attr, (replica,)),) = fixes["object-store:backup-target:ciamStorageReplicaRef"].records[0].mods
    assert attr == "ciamStorageReplicaRef" and isinstance(replica, Input) and replica.example == ("s3://alpha-backups-dr",)


def test_a_weaker_or_shorter_lock_is_named_and_a_stronger_one_is_not():
    weaker = check_object_stores(_pair({"ciamStorageImmutability": "governance"}))
    assert _texts(weaker.actions) == [
        "Object store `backup-target` locks objects (compliance 35 days) in alpha/prod; beta/prod governance 35 days: "
        "ransomware or a mistake could delete or change what it holds."]
    shorter = check_object_stores(_pair({"ciamStorageLockDays": "7"}))
    assert len(shorter.actions) == 1 and "beta/prod compliance 7 days" in shorter.actions[0][1]
    stronger = check_object_stores(_pair({"ciamStorageLockDays": "90"}, source={"ciamStorageImmutability": "governance"}))
    assert stronger.actions == ()


def test_a_lifecycle_deleting_backups_before_their_retention_is_named_in_either_environment():
    f = check_object_stores(_pair({"ciamStorageLifecycle": ("30 cool", "14 delete")}))
    assert _texts(f.actions) == ["Object store `backup-target` in beta/prod deletes backups after 14 days but must keep "
                                 "them 35: its lifecycle undoes its retention."]
    source = check_object_stores(_pair(source={"ciamStorageLifecycle": "noncurrent 7 delete"}))
    assert source.actions == ()                          # noncurrent versions only: the backups themselves are kept


def test_the_report_lists_every_environments_object_stores():
    rows = object_store_rows(_pair({"ciamStorageImmutability": "none", "ciamStorageLockDays": None,
                                    "ciamStorageLifecycle": None}).d)
    assert rows == [
        ("alpha/prod", "backup-target", "backup target", "s3://alpha-backups", "yes", "compliance 35 days", "db-key",
         "30 cold; 400 delete; noncurrent 30 delete", "yes", "s3://alpha-backups-dr", "35", ""),
        ("beta/prod", "backup-target", "backup target", "azblob://beta/backups", "yes", "none", "db-key", "", "yes",
         "s3://alpha-backups-dr", "35", "")]
