"""The lineage's own render read back (the `rendered` importer): the dsconfig batch as the declared configuration
(backends named by its own lines with the record's type, indexes, password policies, handlers under the record's
names, log publishers, the topology's purge delay) and the ACI LDIF as the ACIs (owners and justification kept); a
render reads back unchanged, an edited one says what changed, and what can't be read is named."""
from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one, values
from opsdir.domains.directory.naming import ACIS, CONFIG, CONSUMERS, DECLARED, USER_SCHEMA
from opsdir_base_ds.config import acis_ldif, dsconfig_batch
from opsdir_base_ds.importers import TOPOLOGY, rendered_reader
from opsdir_base_ds.product import DsProduct
from opsdir_base_ds.rendered import aci_entries, batch_records, purge_delay

PRODUCT = DsProduct(name="SomeDS", root_dn="uid=admin", dsconfig_apply=(), handler_names={"LDAPS": "Secure Handler"},
                    builtin_policies=("Default Password Policy",))
READ = rendered_reader(PRODUCT)
BACKEND = f"cn=userData,ou=backends,{DECLARED}"
ACI = f"cn=aci-sync,{ACIS}"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _ou(dn):
    return _row(dn, ("organizationalUnit",), ou=dn.split(",", 1)[0].split("=", 1)[1])


def _record(*extra):
    return make_directory((), {}, (
        *(_row(f"cn={a},{USER_SCHEMA}", ("ciamUserAttribute",), cn=a, ciamLdapName=a, ciamPiiClass="none")
          for a in ("mail", "uid")),
        _ou(CONFIG), _ou(DECLARED),
        *(_ou(f"ou={b},{DECLARED}") for b in ("backends", "password-policies", "connection-handlers",
                                              "log-publishers", "replication")),
        _row(BACKEND, ("ciamBackend",), cn="userData", ciamBackendType="je", ciamBaseDn="dc=example,dc=test"),
        _row(f"cn=mail,{BACKEND}", ("ciamIndex",), cn="mail", ciamIndexedAttribute=f"cn=mail,{USER_SCHEMA}",
             ciamIndexType=("equality", "substring")),
        _row(f"cn=customers,ou=password-policies,{DECLARED}", ("ciamPasswordPolicy",), cn="customers",
             ciamStorageScheme="PBKDF2-HMAC-SHA256", ciamLockoutFailureCount="5", ciamLockoutDuration="15 m",
             ciamOwner="cn=platform,ou=owners,dc=ciam-ops"),
        _row(f"cn=Default Password Policy,ou=password-policies,{DECLARED}", ("ciamPasswordPolicy",),
             cn="Default Password Policy", ciamStorageScheme="PBKDF2-HMAC-SHA256"),
        _row(f"cn=LDAPS,ou=connection-handlers,{DECLARED}", ("ciamConnectionHandler",), cn="LDAPS",
             ciamEnabled="TRUE", ciamListenPort="1636"),
        _row(f"cn=Json File-Based Access Logger,ou=log-publishers,{DECLARED}", ("ciamLogPublisher",),
             cn="Json File-Based Access Logger", ciamEnabled="TRUE"),
        _row(TOPOLOGY, ("ciamReplicationTopology",), cn="topology", ciamReplicaCount="3",
             ciamReplicationPurgeDelay="3 d"),
        _ou(CONSUMERS), _ou(ACIS),
        _row(f"cn=idm-sync,{CONSUMERS}", ("ciamConsumer",), cn="idm-sync",
             ciamBindDn="uid=idm,ou=apps,dc=example,dc=test"),
        _row(ACI, ("ciamAci",), cn="aci-sync", ciamAciTargetDn="ou=people,dc=example,dc=test",
             ciamAciTargetAttr=(f"cn=uid,{USER_SCHEMA}", f"cn=mail,{USER_SCHEMA}"), ciamAciRight=("read", "write"),
             ciamAciGrantee=f"cn=idm-sync,{CONSUMERS}", ciamOwner="cn=platform,ou=owners,dc=ciam-ops",
             ciamJustification="Identity sync"),
        *extra))


def _rendered(d):
    return {"dsconfig.batch": dsconfig_batch(PRODUCT, d), "acis.ldif": acis_ldif(d)}


def _changes(d, files):
    return import_changes(d, READ(files, d, ()))


def test_a_render_reads_back_unchanged():
    d = _record()
    imported = READ(_rendered(d), d, ())
    assert import_changes(d, imported) == () and imported.notices == ()


def test_an_edited_render_says_what_changed():
    d = _record()
    files = _rendered(d)
    edited = {"dsconfig.batch": files["dsconfig.batch"].replace("lockout-failure-count:5", "lockout-failure-count:3")
              .replace('replication-purge-delay:"3 d"', 'replication-purge-delay:"7 d"'),
              "acis.ldif": files["acis.ldif"].replace("allow (read,write)", "allow (read)")}
    changed = {(c.dn, m[1], m[2]) for c in _changes(d, edited) for m in c.mods}
    assert changed == {(f"cn=customers,ou=password-policies,{DECLARED}", "ciamLockoutFailureCount", ("3",)),
                       (TOPOLOGY, "ciamReplicationPurgeDelay", ("7 d",)), (ACI, "ciamAciRight", ("read",))}


def test_what_the_render_doesnt_carry_is_the_records():
    d = _record()
    after = READ(_rendered(d), d, ())
    entries = {e.dn: e for _, es in after.groups for e in es}
    assert one(entries[BACKEND], "ciamBackendType") == "je"                        # not in the batch
    assert one(entries[f"cn=customers,ou=password-policies,{DECLARED}"], "ciamOwner") == \
        "cn=platform,ou=owners,dc=ciam-ops"
    assert (one(entries[ACI], "ciamOwner"), one(entries[ACI], "ciamJustification")) == \
        ("cn=platform,ou=owners,dc=ciam-ops", "Identity sync")
    assert one(entries[TOPOLOGY], "ciamReplicaCount") == "3"


def test_what_cant_be_read_is_named():
    d = _record()
    batch = ("# backend archive (dc=archive,dc=test)\n"
             "create-backend-index --backend-name archive --index-name mail --set index-type:equality\n"
             "create-replication-domain --provider-name x\n")
    records, notices = batch_records(d, batch)
    assert notices == ("ds/dsconfig.batch: backend archive: the record holds no type for it (setup creates it); "
                       "not read",
                       "ds/dsconfig.batch: create-replication-domain: not read (opsdir doesn't render it)")
    aci = ('dn: ou=people,dc=example,dc=test\nchangetype: modify\nadd: aci\n'
           'aci: (targetattr = "mail || pager")(version 3.0; acl "aci-x"; allow (read) '
           'userdn = "ldap:///uid=nobody,dc=example,dc=test";)\n-\n\n'
           'dn: ou=people,dc=example,dc=test\nchangetype: modify\nadd: aci\naci: (targetfilter="(x=y)")(deny all)\n-\n')
    (entry,), notices = aci_entries(d, aci, "ds/acis.ldif")
    assert values(entry, "ciamAciTargetAttr") == (f"cn=mail,{USER_SCHEMA}",) and not values(entry, "ciamAciGrantee")
    assert notices[0].endswith("attribute pager has no user-schema record; not recorded")
    assert notices[1].endswith("no consumer binds as uid=nobody,dc=example,dc=test; grantee not recorded")
    assert "isn't in the form opsdir renders" in notices[2]


def test_the_purge_delay_and_absent_files():
    assert purge_delay('set-synchronization-provider-prop --provider-name "Multimaster Synchronization" '
                       '--set replication-purge-delay:"3 d"\n') == "3 d"
    assert READ({"setup-ds-1.sh": "#!/bin/sh\n"}, _record(), ()).notices == \
        ("no dsconfig.batch or acis.ldif (the files opsdir renders under ds/); nothing imported",)
    assert get(_record(), TOPOLOGY) is not None
