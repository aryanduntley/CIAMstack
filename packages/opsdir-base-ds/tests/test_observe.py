"""A DS-lineage server's configuration read into the record: config.ldif mapped to the directory configuration model
(database backends and their indexes, password policies, connection handlers under the record's names, log
publishers), observed snapshots placed by server and dated (re-importing an unchanged configuration adds nothing;
archived configurations dated by their names), drift against the declared configuration, and the declared
configuration set from one server while keeping what the importer doesn't own."""
import datetime as dt

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one, subtree, values
from opsdir.domains.directory.drift import drift
from opsdir.domains.directory.naming import DECLARED, OBSERVED, USER_SCHEMA
from opsdir_base_ds.importers import declared_reader, snapshot_reader
from opsdir_base_ds.observe import config_entries, server_id
from opsdir_base_ds.product import DsProduct

PRODUCT = DsProduct(name="SomeDS", root_dn="uid=admin", dsconfig_apply=(), handler_names={"LDAPS": "Secure Handler"},
                    builtin_policies=("Default Password Policy",))
AT = dt.datetime(2026, 9, 30, 14, 15, 0, tzinfo=dt.timezone.utc)
SOURCE = "env=prod,cloud=source,ou=environments,dc=ciam-ops"
TARGET = "env=prod,cloud=target,ou=environments,dc=ciam-ops"
DS1 = f"cn=ds-1,{SOURCE}"

# A server's config.ldif as the DS lineage writes it (an excerpt: the parts the record models, and some it doesn't)
CONFIG = """\
dn: cn=config
objectClass: top
objectClass: ds-cfg-root-config
cn: config
ds-cfg-server-id: ds-1

dn: ds-cfg-backend-id=userData,cn=Backends,cn=config
objectClass: top
objectClass: ds-cfg-backend
objectClass: ds-cfg-pluggable-backend
objectClass: ds-cfg-je-backend
ds-cfg-backend-id: userData
ds-cfg-base-dn: dc=example,dc=test
ds-cfg-enabled: true
ds-cfg-db-directory: db

dn: ds-cfg-attribute=mail,cn=Indexes,ds-cfg-backend-id=userData,cn=Backends,cn=config
objectClass: top
objectClass: ds-cfg-backend-index
ds-cfg-attribute: mail
ds-cfg-index-type: equality
ds-cfg-index-type: substring

dn: ds-cfg-attribute=uid,cn=Indexes,ds-cfg-backend-id=userData,cn=Backends,cn=config
objectClass: top
objectClass: ds-cfg-backend-index
ds-cfg-attribute: uid
ds-cfg-index-type: equality
ds-cfg-index-type: extensible

dn: ds-cfg-attribute=objectClass,cn=Indexes,ds-cfg-backend-id=userData,cn=Backends,cn=config
objectClass: top
objectClass: ds-cfg-backend-index
ds-cfg-attribute: objectClass
ds-cfg-index-type: equality

dn: ds-cfg-attribute=entryUUID,cn=Indexes,ds-cfg-backend-id=userData,cn=Backends,cn=config
objectClass: top
objectClass: ds-cfg-backend-index
ds-cfg-attribute: entryUUID
ds-cfg-index-type: equality

dn: ds-cfg-backend-id=rootUser,cn=Backends,cn=config
objectClass: top
objectClass: ds-cfg-backend
objectClass: ds-cfg-ldif-backend
ds-cfg-backend-id: rootUser
ds-cfg-base-dn: uid=admin

dn: ds-cfg-backend-id=schema,cn=Backends,cn=config
objectClass: top
objectClass: ds-cfg-backend
objectClass: ds-cfg-schema-backend
ds-cfg-backend-id: schema
ds-cfg-base-dn: cn=schema

dn: cn=customers,cn=Password Policies,cn=config
objectClass: top
objectClass: ds-cfg-authentication-policy
objectClass: ds-cfg-password-policy
cn: customers
ds-cfg-password-attribute: userPassword
ds-cfg-default-password-storage-scheme: cn=PBKDF2-HMAC-SHA256,cn=Password Stor
 age Schemes,cn=config
ds-cfg-lockout-failure-count: 5
ds-cfg-lockout-duration: 15 m
ds-cfg-password-history-count: 5

dn: cn=Secure Handler,cn=Connection Handlers,cn=config
objectClass: top
objectClass: ds-cfg-connection-handler
objectClass: ds-cfg-ldap-connection-handler
cn: Secure Handler
ds-cfg-enabled: true
ds-cfg-listen-port: 1636
ds-cfg-use-ssl: true

dn: cn=LDAP,cn=Connection Handlers,cn=config
objectClass: top
objectClass: ds-cfg-connection-handler
objectClass: ds-cfg-ldap-connection-handler
cn: LDAP
ds-cfg-enabled: false
ds-cfg-listen-port: 1389

dn: cn=Json File-Based Access Logger,cn=Loggers,cn=config
objectClass: top
objectClass: ds-cfg-log-publisher
objectClass: ds-cfg-access-log-publisher
cn: Json File-Based Access Logger
ds-cfg-enabled: true
"""
EARLIER = CONFIG.replace("ds-cfg-lockout-failure-count: 5", "ds-cfg-lockout-failure-count: 3")


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record(*extra):
    return make_directory((), {}, (
        *(_row(f"cn={a},{USER_SCHEMA}", ("ciamUserAttribute",), cn=a, ciamLdapName=a, ciamPiiClass="none")
          for a in ("mail", "uid")),
        _row(DS1, ("ciamServer",), cn="ds-1", ciamServerRole="ds", ciamHostname="ds-1.source.example.test"),
        _row(f"cn=ds-1,{TARGET}", ("ciamServer",), cn="ds-1", ciamServerRole="ds",
             ciamHostname="ds-1.target.example.test"),
        _row(f"cn=ds-2,{SOURCE}", ("ciamServer",), cn="ds-2", ciamServerRole="ds",
             ciamHostname="ds-2.source.example.test"),
        _row(f"cn=pf-1,{SOURCE}", ("ciamServer",), cn="pf-1", ciamServerRole="pf-engine",
             ciamHostname="pf-1.source.example.test"),
        *extra))


def _after(d, imported):
    """The record after applying what an import says (containers and groups), as the store would."""
    rows = {e.norm: e for e in d.entries.values()}
    scoped = {e.norm for scope, _ in imported.groups for e in d.entries.values()
              if e.norm == scope.lower() or e.norm.endswith("," + scope.lower())}
    kept = {n: e for n, e in rows.items() if n not in scoped}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in rows),
                                 *(e for _, entries in imported.groups for e in entries))}
    return d._replace(entries={**kept, **added})


def _snapshots(d):
    return sorted(e.dn.split(",", 1)[0] for e in subtree(d, OBSERVED, "ciamSnapshot"))


def test_the_configuration_is_read_as_the_record_models_it():
    entries, notices = config_entries(PRODUCT, _record(), CONFIG, DECLARED, "ds-1")
    by = {e.dn.split(f",{DECLARED}")[0]: e for e in entries}
    assert sorted(by) == ["cn=Json File-Based Access Logger,ou=log-publishers", "cn=LDAP,ou=connection-handlers",
                          "cn=LDAPS,ou=connection-handlers", "cn=customers,ou=password-policies",
                          "cn=mail,cn=userData,ou=backends", "cn=uid,cn=userData,ou=backends",
                          "cn=userData,ou=backends", "ou=backends", "ou=connection-handlers", "ou=log-publishers",
                          "ou=password-policies"]
    assert (one(by["cn=userData,ou=backends"], "ciamBackendType"), one(by["cn=userData,ou=backends"], "ciamBaseDn")) \
        == ("je", "dc=example,dc=test")
    mail = by["cn=mail,cn=userData,ou=backends"]
    assert one(mail, "ciamIndexedAttribute") == f"cn=mail,{USER_SCHEMA}"
    assert values(mail, "ciamIndexType") == ("equality", "substring")
    policy = by["cn=customers,ou=password-policies"]
    assert {k: v for k, v in policy.attrs.items()} == {
        "cn": ("customers",), "ciamStorageScheme": ("PBKDF2-HMAC-SHA256",), "ciamLockoutFailureCount": ("5",),
        "ciamLockoutDuration": ("15 m",), "ciamPasswordHistoryCount": ("5",)}
    ldaps = by["cn=LDAPS,ou=connection-handlers"]           # the product's "Secure Handler", under the record's name
    assert (one(ldaps, "ciamEnabled"), one(ldaps, "ciamListenPort")) == ("TRUE", "1636")
    assert one(by["cn=LDAP,ou=connection-handlers"], "ciamEnabled") == "FALSE"
    assert notices == ("ds-1: backend userData: indexes on attributes with no user-schema record, not recorded: "
                       "entryUUID, objectClass",
                       "ds-1: backend userData: index types the record doesn't model, not recorded: uid (extensible)")


def test_the_server_id_is_read_from_the_global_configuration():
    assert server_id(CONFIG) == "ds-1" and server_id("dn: cn=x,cn=config\ncn: x\n") is None


def test_each_server_folder_becomes_a_dated_snapshot_of_that_server():
    d = _record()
    imported = snapshot_reader(PRODUCT)({"ds-1.source.example.test/config/config.ldif": CONFIG,
                                         "ds-2/config.ldif": CONFIG, "ds-2/keystore.pin.txt": "x"}, d, (), AT)
    after = _after(d, imported)
    assert _snapshots(after) == ["snap=source-prod-ds-1-20260930141500Z", "snap=source-prod-ds-2-20260930141500Z"]
    snap = get(after, f"snap=source-prod-ds-1-20260930141500Z,{OBSERVED}")
    assert (one(snap, "ciamServerRef"), one(snap, "ciamCapturedAt")) == (DS1, "20260930141500Z")
    assert "ds-2: 1 other file(s) not read (only config.ldif and archived-configs/)" in imported.notices


def test_importing_an_unchanged_configuration_again_adds_nothing():
    d = _record()
    first = _after(d, snapshot_reader(PRODUCT)({"ds-1.source.example.test/config.ldif": CONFIG}, d, (), AT))
    again = snapshot_reader(PRODUCT)({"ds-1.source.example.test/config.ldif": CONFIG}, first, (),
                                     AT + dt.timedelta(days=1))
    assert again.groups == () and not import_changes(first, again)
    assert again.notices[-1] == ("source/prod ds-1: configuration unchanged since snapshot "
                                 "source-prod-ds-1-20260930141500Z; no new snapshot")
    changed = snapshot_reader(PRODUCT)({"ds-1.source.example.test/config.ldif": EARLIER}, first, (),
                                       AT + dt.timedelta(days=1))
    assert [scope.split(",", 1)[0] for scope, _ in changed.groups] == ["snap=source-prod-ds-1-20261001141500Z"]


def test_archived_configurations_are_snapshots_dated_by_their_names():
    d = _record()
    imported = snapshot_reader(PRODUCT)({"ds-1.source.example.test/archived-configs/config-20260920030000Z": EARLIER,
                                         "ds-1.source.example.test/config.ldif": CONFIG}, d, (), AT)
    after = _after(d, imported)
    assert _snapshots(after) == ["snap=source-prod-ds-1-20260920030000Z", "snap=source-prod-ds-1-20260930141500Z"]
    archived = get(after, f"snap=source-prod-ds-1-20260920030000Z,{OBSERVED}")
    assert one(archived, "description") == ("archived by the server at 20260920030000Z: the configuration in effect "
                                            "until then")
    assert not import_changes(after, snapshot_reader(PRODUCT)(
        {"ds-1.source.example.test/archived-configs/config-20260920030000Z": EARLIER}, after, (), AT))


def test_a_folder_must_name_one_directory_server():
    d = _record()
    imported = snapshot_reader(PRODUCT)({"ds-1/config.ldif": CONFIG, "pf-1/config.ldif": CONFIG,
                                         "nobody/config.ldif": CONFIG}, d, (), AT)
    assert imported.groups == ()
    assert imported.notices == (
        "ds-1: names directory servers in several environments (source/prod, target/prod); name the folder by the "
        "server's hostname; not imported",
        "nobody: no directory server in the record has this hostname or name; not imported",
        "pf-1: no directory server in the record has this hostname or name; not imported")


def test_a_config_ldif_on_its_own_is_placed_by_its_server_id():
    d = _record()
    alone = snapshot_reader(PRODUCT)({"config.ldif": CONFIG.replace("ds-cfg-server-id: ds-1",
                                                                    "ds-cfg-server-id: ds-2")}, d, (), AT)
    assert [scope.split(",", 1)[0] for scope, _ in alone.groups] == ["snap=source-prod-ds-2-20260930141500Z"]
    no_id = snapshot_reader(PRODUCT)({"config.ldif": CONFIG.replace("ds-cfg-server-id: ds-1\n", "")}, d, (), AT)
    assert no_id.groups == () and no_id.notices[0].startswith("config.ldif: its global configuration records no "
                                                              "server ID")


def test_without_an_import_time_the_current_configuration_is_not_dated():
    imported = snapshot_reader(PRODUCT)({"ds-2/config.ldif": CONFIG}, _record(), (), None)
    assert imported.groups == () and imported.notices == (
        "ds-2: no import time given, so config.ldif can't be dated; not imported",)


def test_drift_compares_the_imported_snapshot_with_the_declared_configuration():
    """Everything the server runs that the record doesn't declare is an unrecorded change."""
    declared = (_row(f"ou=password-policies,{DECLARED}", ("organizationalUnit",), ou="password-policies"),
                _row(f"cn=customers,ou=password-policies,{DECLARED}", ("ciamPasswordPolicy",), cn="customers",
                     ciamStorageScheme="PBKDF2-HMAC-SHA256", ciamLockoutFailureCount="5", ciamLockoutDuration="15 m",
                     ciamPasswordHistoryCount="5", ciamPopulation="customers", ciamOwner="cn=team,ou=owners"))
    d = _record(*declared)
    after = _after(d, snapshot_reader(PRODUCT)({"ds-1.source.example.test/config.ldif": EARLIER}, d, (), AT))
    found = drift(after)
    assert ("ds-1", "differs", "cn=customers,ou=password-policies",
            "ciamLockoutFailureCount: declared ['5'] observed ['3']") in found         # ciamPopulation isn't config
    assert {rel for _, finding, rel, _ in found if finding == "not declared (unrecorded change)"} == {
        "cn=userData,ou=backends", "cn=mail,cn=userData,ou=backends", "cn=uid,cn=userData,ou=backends",
        "cn=LDAPS,ou=connection-handlers", "cn=LDAP,ou=connection-handlers",
        "cn=Json File-Based Access Logger,ou=log-publishers", "ou=backends", "ou=connection-handlers",
        "ou=log-publishers"}


def test_the_declared_configuration_is_set_from_one_server_keeping_what_the_importer_doesnt_own():
    declared = (_row(f"ou=password-policies,{DECLARED}", ("organizationalUnit",), ou="password-policies"),
                _row(f"cn=customers,ou=password-policies,{DECLARED}", ("ciamPasswordPolicy",), cn="customers",
                     ciamStorageScheme="SSHA512", ciamPopulation="customers", ciamOwner="cn=team,ou=owners"),
                _row(f"cn=retired,ou=password-policies,{DECLARED}", ("ciamPasswordPolicy",), cn="retired",
                     ciamStorageScheme="SSHA512"))
    d = _record(*declared)
    imported = declared_reader(PRODUCT)({"ds-1/config.ldif": CONFIG}, d, (), AT)
    after = _after(d, imported)
    policy = get(after, f"cn=customers,ou=password-policies,{DECLARED}")
    assert (one(policy, "ciamStorageScheme"), one(policy, "ciamPopulation"), one(policy, "ciamOwner")) == \
        ("PBKDF2-HMAC-SHA256", "customers", "cn=team,ou=owners")
    assert get(after, f"cn=retired,ou=password-policies,{DECLARED}") is None       # the server has no such policy
    assert get(after, f"cn=userData,ou=backends,{DECLARED}") is not None


def test_the_declared_configuration_comes_from_exactly_one_server():
    imported = declared_reader(PRODUCT)({"ds-1/config.ldif": CONFIG, "ds-2/config.ldif": CONFIG}, _record(), (), AT)
    assert imported.groups == () and imported.notices == (
        "the declared configuration comes from one server's config.ldif; the export holds 2: ds-1/config.ldif, "
        "ds-2/config.ldif; nothing imported",)
