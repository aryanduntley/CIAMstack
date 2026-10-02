"""Access log fixture: three days of the production directory servers' JSON access logs (exports/ds-access-logs), the
way PingDS writes them (logs/ldap-access.audit.json: one DJ-LDAP event per line). The demo imports them to find the
directory's consumers; what operators know about each consumer (owner, criticality, migration status, reviews) stays
in the data (55-consumers).

Each consumer's traffic is planted to show what the importer reads: where it connects from, its operations, the
attributes it asks for, unindexed searches (the MRO export and the legacy report account), plain-text connections
(the legacy account), StartTLS (the customer portal), and a burst that sets its peak. End users whose passwords
PingFederate checks bind as themselves (counted by the importer, never recorded), and a monitor reads the root DSE
anonymously. Filters carry fictional values the importer never reads."""
import datetime as dt
import json
from itertools import chain
from types import MappingProxyType

from .common import PEOPLE, USERS
from .directory import SERVERS

DAYS = ("2026-09-20", "2026-09-21", "2026-09-22")
SERVER_IPS = MappingProxyType({"ds-1": "10.20.1.11", "ds-2": "10.20.2.11", "ds-3": "10.20.3.11"})
START_TLS = "1.3.6.1.4.1.1466.20037"
# consumer bind DN (under the user directory) → (client addresses, transport, starting hour, operations per day,
# attributes it asks for, unindexed searches per day, peak operations in one second)
TRAFFIC = (
    ("uid=pf-svc,ou=service-accounts", ("10.20.4.21", "10.20.4.22", "10.20.5.21", "10.20.5.22"), "LDAPS", 6,
     (("BIND", 12), ("SEARCH", 30), ("MODIFY", 1)),
     ("uid", "mail", "givenName", "sn", "companyId", "appEntitlement", "registrationStatus"), 0, 20),
    ("uid=portal-svc,ou=service-accounts", ("10.30.8.14", "10.30.8.15"), "STARTTLS", 8,
     (("BIND", 4), ("SEARCH", 14), ("MODIFY", 5), ("ADD", 1)),
     ("mail", "registrationStatus", "telephoneNumber", "companyId", "challengeAnswer"), 0, 8),
    ("uid=supplier-svc,ou=service-accounts", ("10.31.2.40", "10.31.2.41"), "LDAPS", 9,
     (("BIND", 2), ("SEARCH", 9), ("MODIFY", 1)), ("mail", "companyId", "soldToAccount"), 0, 4),
    ("uid=mro-export,ou=service-accounts", ("10.40.12.8", "10.40.12.9"), "LDAPS", 2,
     (("BIND", 1), ("SEARCH", 12)), ("mail", "companyId", "soldToAccount", "exportScreeningStatus", "description"), 4, 6),
    ("uid=rptuser,ou=customers,ou=people", ("10.40.7.22",), "LDAP", 1,
     (("BIND", 1), ("SEARCH", 12)),
     ("uid", "mail", "givenName", "sn", "telephoneNumber", "challengeAnswer", "exportScreeningStatus"), 12, 3),
    ("uid=idm-sync,ou=service-accounts", ("10.20.6.21", "10.20.6.22"), "LDAPS", 4,
     (("BIND", 3), ("SEARCH", 11), ("MODIFY", 9)),
     ("uid", "mail", "companyId", "appEntitlement", "registrationStatus", "lastLoginTime"), 0, 10),
)
END_USERS_PER_DAY = 8           # customers whose passwords PingFederate checks, binding from its engines
MONITOR = "10.20.9.5"           # reads the root DSE anonymously, once a day per server


def _at(day, hour, second, ms=0):
    return (dt.datetime.fromisoformat(day) + dt.timedelta(hours=hour, seconds=second, milliseconds=ms)) \
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _event(server, conn, op, at, ip, protocol, user=None, **request):
    port = 1636 if protocol == "LDAPS" else 1389
    event = {"eventName": "DJ-LDAP", "client": {"ip": ip, "port": 40000 + conn % 20000},
             "server": {"ip": SERVER_IPS[server], "port": port},
             "request": {"protocol": protocol, "operation": op, "connId": conn, "msgId": 1, **request},
             "transactionId": "0", "response": {"status": "SUCCESSFUL", "statusCode": "0", "elapsedTime": 1,
                                                "elapsedTimeUnits": "MILLISECONDS"}}
    return {**event, **({"userId": user} if user else {}), "timestamp": at, "_id": f"{server}-{conn}-{at}"}


def _unindexed(e):
    return {**e, "response": {**e["response"], "additionalItems": {"unindexed": True}}}


def _operation(server, conn, kind, at, ip, protocol, bind_dn, attrs, n):
    """One operation: a bind as the consumer, or work as it (searches of people with a fictional filter value)."""
    if kind == "BIND":
        return _event(server, conn, "BIND", at, ip, protocol, dn=bind_dn, authType="SIMPLE")
    if kind == "SEARCH":
        return _event(server, conn, "SEARCH", at, ip, protocol, user=bind_dn, dn=PEOPLE, scope="sub",
                      filter=f"(mail=customer-{n}@example-aero.test)", attrs=list(attrs))
    return _event(server, conn, kind, at, ip, protocol, user=bind_dn, dn=f"uid=customer-{n},ou=customers,{PEOPLE}")


def _consumer_day(index, day, traffic):
    """(server, event) of one consumer's traffic on one day: a connection per address, round the servers; its
    operations one a second, except a burst of `peak` operations in one second; the first searches unindexed."""
    bind, ips, transport, hour, per_day, attrs, unindexed, peak = traffic
    bind_dn = f"{bind},{USERS}"
    protocol = "LDAP" if transport in ("LDAP", "STARTTLS") else "LDAPS"
    kinds = tuple(chain.from_iterable((k,) * n for k, n in per_day))
    conns = tuple((SERVERS[(index + i) % len(SERVERS)][0], 1000 * (index + 1) + 100 * DAYS.index(day) + i, ip)
                  for i, ip in enumerate(ips))
    opening = tuple(e for server, conn, ip in conns for e in (
        (server, _event(server, conn, "CONNECT", _at(day, hour, 0), ip, protocol)),
        *(((server, _event(server, conn, "EXTENDED", _at(day, hour, 0, 1), ip, protocol, oid=START_TLS)),)
          if transport == "STARTTLS" else ())))
    seconds = tuple(1 if i < peak else 1 + i - peak + 1 for i in range(len(kinds)))
    searches = [i for i, k in enumerate(kinds) if k == "SEARCH"][:unindexed]
    ops = tuple((server, (_unindexed if i in searches else (lambda e: e))(
                 _operation(server, conn, kind, _at(day, hour, seconds[i], i % 1000), ip, protocol, bind_dn, attrs,
                            i + 1)))
                for i, kind in enumerate(kinds) for server, conn, ip in (conns[i % len(conns)],))
    return (*opening, *ops)


def _end_users(day):
    """PingFederate checking customers' passwords: each binds as the customer, from an engine, on its own connection."""
    return tuple((SERVERS[n % len(SERVERS)][0],
                  _event(SERVERS[n % len(SERVERS)][0], 9000 + 100 * DAYS.index(day) + n, "BIND",
                         _at(day, 12, n * 7), "10.20.4.21", "LDAPS", dn=f"uid=customer-{n},ou=customers,{PEOPLE}",
                         authType="SIMPLE"))
                 for n in range(1, END_USERS_PER_DAY + 1))


def _monitor(day):
    return tuple((srv, _event(srv, 8000 + 100 * DAYS.index(day) + i, "SEARCH", _at(day, 0, 5), MONITOR, "LDAP",
                              dn="", scope="base", filter="(objectClass=*)", attrs=["namingContexts"]))
                 for i, (srv, _, _) in enumerate(SERVERS))


def access_logs():
    """{path under exports/ds-access-logs: text}: each production directory server's JSON access log, in time order."""
    events = tuple(chain.from_iterable((*chain.from_iterable(_consumer_day(i, day, t) for i, t in enumerate(TRAFFIC)),
                                        *_end_users(day), *_monitor(day)) for day in DAYS))
    return {f"{host}/logs/ldap-access.audit.json":
            "".join(json.dumps(e, separators=(",", ":")) + "\n"
                    for e in sorted((e for s, e in events if s == srv), key=lambda e: (e["timestamp"], e["_id"])))
            for srv, host, _ in SERVERS}
