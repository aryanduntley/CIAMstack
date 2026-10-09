"""The directory's consumers mined from DS JSON access logs: operations attributed to the identity that performed
them, identities that only bind (end users) counted and never recorded, TLS from LDAPS or StartTLS, base-scope reads
recorded as the entry's container (values-free), attributes linked to user-schema records, a consumer the record has
keeping what the logs don't say, and importing the same logs again changing nothing."""
import json

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import get, make_directory, one, values
from opsdir.domains.directory.naming import CONSUMERS, USER_SCHEMA
from opsdir_base_ds.access_log import operations
from opsdir_base_ds.importers import access_log_reader

USERS = "dc=example,dc=test"
PEOPLE = f"ou=people,{USERS}"
PF = f"uid=pf-svc,ou=service-accounts,{USERS}"
PORTAL = f"uid=portal-svc,ou=service-accounts,{USERS}"
REPORTS = f"uid=reports,ou=service-accounts,{USERS}"


def _event(conn, op, at, ip="10.20.4.21", protocol="LDAPS", user=None, status="SUCCESSFUL", **request):
    e = {"eventName": "DJ-LDAP", "client": {"ip": ip, "port": 40000 + conn},
         "server": {"ip": "10.20.1.11", "port": 1636},
         "request": {"protocol": protocol, "operation": op, "connId": conn, "msgId": 1, **request},
         "transactionId": "0", "response": {"status": status, "statusCode": "0", "elapsedTime": 1,
                                            "elapsedTimeUnits": "MILLISECONDS"},
         "timestamp": at, "_id": f"id-{conn}-{op}-{at}"}
    return {**e, **({"userId": user} if user else {})}


def _unindexed(e):
    return {**e, "response": {**e["response"], "additionalItems": {"unindexed": True}}}


EVENTS = (
    # PingFederate's service account over LDAPS, from two engines: binds, then searches people
    _event(1, "CONNECT", "2026-09-20T03:00:00.000Z"),
    _event(1, "BIND", "2026-09-20T03:00:00.010Z", dn=PF, authType="SIMPLE"),
    _event(1, "SEARCH", "2026-09-20T03:00:00.100Z", user=PF, dn=PEOPLE, scope="sub", filter="(uid=alice@example.test)",
           attrs=["uid", "mail", "companyId", "entryUUID"]),
    _event(1, "SEARCH", "2026-09-20T03:00:00.200Z", user=PF, dn=PEOPLE, scope="sub", filter="(mail=bob@example.test)",
           attrs=["mail"]),
    _unindexed(_event(2, "SEARCH", "2026-09-21T03:00:00.300Z", ip="10.20.4.22", user=PF, dn=PEOPLE, scope="sub",
                      filter="(description=x)", attrs=["mail"])),
    # an end user's password checked by binding as them: authentication only
    _event(3, "BIND", "2026-09-20T03:00:00.150Z", ip="10.20.4.21", dn=f"uid=alice,{PEOPLE}", authType="SIMPLE"),
    # the portal over LDAP with StartTLS first: TLS all the same
    _event(4, "CONNECT", "2026-09-20T04:00:00.000Z", ip="10.30.8.5", protocol="LDAP"),
    _event(4, "EXTENDED", "2026-09-20T04:00:00.001Z", ip="10.30.8.5", protocol="LDAP", oid="1.3.6.1.4.1.1466.20037"),
    _event(4, "BIND", "2026-09-20T04:00:00.002Z", ip="10.30.8.5", protocol="LDAP", dn=PORTAL, authType="SIMPLE"),
    _event(4, "MODIFY", "2026-09-20T04:00:00.003Z", ip="10.30.8.5", protocol="LDAP", user=PORTAL,
           dn=f"uid=carol,{PEOPLE}"),
    # a reporting job in clear text, reading one person's entry and asking for every attribute
    _event(5, "BIND", "2026-09-20T05:00:00.000Z", ip="10.40.7.22", protocol="LDAP", dn=REPORTS, authType="SIMPLE"),
    _event(5, "SEARCH", "2026-09-20T05:00:00.500Z", ip="10.40.7.22", protocol="LDAP", user=REPORTS,
           dn=f"uid=dave,{PEOPLE}", scope="base", filter="(objectClass=*)", attrs=["*", "telephoneNumber"]),
    # an anonymous search
    _event(6, "SEARCH", "2026-09-20T06:00:00.000Z", ip="10.50.0.9", protocol="LDAP", dn="", scope="base",
           filter="(objectClass=*)", attrs=["namingContexts"]),
)
FILES = {"ds-1/logs/ldap-access.audit.json": "\n".join(json.dumps(e) for e in EVENTS[:4]) + "\nnot json\n",
         "ds-2/logs/ldap-access.audit.json-20260921": "\n".join(json.dumps(e) for e in EVENTS[4:]) + "\n",
         "ds-1/logs/access": "[20/Sep/2026:03:00:00 +0000] CONNECT conn=1 ...\n"}


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return make_directory((), {}, (
        *(_row(f"cn={a},{USER_SCHEMA}", ("ciamUserAttribute",), cn=a, ciamLdapName=a, ciamPiiClass="low")
          for a in ("uid", "mail", "companyId")),
        _row(f"cn=pf-ds-svc,{CONSUMERS}", ("ciamConsumer",), cn="pf-ds-svc", ciamBindDn=PF,
             ciamOwner="cn=team,ou=owners",
             ciamCriticality="critical", ciamMigrationStatus="tested", ciamFirstSeen="20240103000000Z",
             ciamObservedSource="10.99.0.0/16"),
        _row(f"cn=idle,{CONSUMERS}", ("ciamConsumer",), cn="idle", ciamBindDn=f"uid=idle,{USERS}")))


def _after(d, imported):
    kept = {n: e for n, e in d.entries.items() if all(n != s.lower() for s, _ in imported.groups)}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in d.entries),
                                 *(e for _, es in imported.groups for e in es))}
    return d._replace(entries={**kept, **added})


def test_operations_are_attributed_to_who_performed_them_and_anonymous_ones_counted():
    ops, unreadable, anonymous = operations(FILES)
    assert (unreadable, anonymous) == (1, 1)
    assert {o.identity for o in ops} == {PF, f"uid=alice,{PEOPLE}", PORTAL, REPORTS}
    assert [o.tls for o in ops if o.identity == PORTAL] == [True, True]                 # StartTLS came first


def test_a_consumer_the_record_has_is_updated_keeping_what_the_logs_dont_say():
    d = _record()
    imported = access_log_reader(FILES, d, ())
    pf = get(_after(d, imported), f"cn=pf-ds-svc,{CONSUMERS}")
    assert values(pf, "ciamObservedSource") == ("10.20.4.0/24",)
    assert one(pf, "ciamOperationMix") == "search 75%, bind 25%"
    assert values(pf, "ciamSubtreeRead") == (PEOPLE,)
    assert values(pf, "ciamAttrRead") == tuple(f"cn={a},{USER_SCHEMA}" for a in ("uid", "mail", "companyId"))
    assert (one(pf, "ciamUnindexedSearchesPerDay"), one(pf, "ciamTlsOnly"), one(pf, "ciamPeakOpsPerSec")) == \
        ("0", "TRUE", "3")                                            # 1 unindexed over 2 days rounds to 0
    assert (one(pf, "ciamFirstSeen"), one(pf, "ciamLastSeen")) == ("20240103000000Z", "20260921030000Z")
    assert (one(pf, "ciamOwner"), one(pf, "ciamCriticality"), one(pf, "ciamMigrationStatus")) == \
        ("cn=team,ou=owners", "critical", "tested")
    assert "consumer pf-ds-svc: asks for attributes with no user-schema record, not recorded: entryUUID" \
        in imported.notices


def test_new_consumers_are_found_values_free_and_end_users_are_only_counted():
    d = _record()
    imported = access_log_reader(FILES, d, ())
    after = _after(d, imported)
    portal, reports = get(after, f"cn=portal-svc,{CONSUMERS}"), get(after, f"cn=reports,{CONSUMERS}")
    assert (one(portal, "ciamBindDn"), one(portal, "ciamTlsOnly"), one(portal, "ciamMigrationStatus")) == \
        (PORTAL, "TRUE", "unknown")
    assert one(portal, "ciamOperationMix") == "bind 50%, modify 50%"
    assert values(reports, "ciamSubtreeRead") == (PEOPLE,)            # dave's entry read: its container recorded
    assert (one(reports, "ciamTlsOnly"), values(reports, "ciamObservedSource")) == ("FALSE", ("10.40.7.22/32",))
    assert get(after, f"cn=alice,{CONSUMERS}") is None
    dump = str([dict(e.attrs) for e in after.entries.values()])
    assert "alice" not in dump and "dave" not in dump and "bob@" not in dump
    assert set(imported.notices) >= {
        "consumer reports: asks for all attributes (* or +)",
        "consumer reports: asks for attributes with no user-schema record, not recorded: telephoneNumber",
        "consumer portal-svc: new, found in the access logs (migration status unknown, no owner)",
        "1 identities only authenticated (binds, e.g. end users whose passwords were checked); not recorded",
        f"consumer idle (uid=idle,{USERS}) not seen in these logs; unchanged",
        "1 anonymous operations (no bound identity); not attributed",
        "1 lines are not JSON access log events; not read",
        "not a JSON access log, not read: ds-1/logs/access (read the JSON access log, logs/ldap-access.audit.json)"}


def test_importing_the_same_logs_again_changes_nothing():
    d = _record()
    after = _after(d, access_log_reader(FILES, d, ()))
    assert not import_changes(after, access_log_reader(FILES, after, ()))


def test_a_new_consumer_never_takes_a_name_the_record_uses():
    d = _record()
    clash = {"logs/ldap-access.audit.json": json.dumps(
        _event(9, "SEARCH", "2026-09-20T03:00:00Z", user=f"uid=pf-ds-svc,ou=other,{USERS}", dn=PEOPLE, scope="sub",
               attrs=["mail"]))}
    imported = access_log_reader(clash, d, ())
    assert [e.dn for _, es in imported.groups for e in es] == [f"cn=pf-ds-svc-2,{CONSUMERS}"]
