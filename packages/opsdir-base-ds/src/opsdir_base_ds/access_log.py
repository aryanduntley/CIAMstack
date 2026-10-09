"""The directory's clients, mined from a DS-lineage server's JSON access log (logs/ldap-access.audit.json and its
rotated files: one JSON object per line, eventName DJ-LDAP). Pure and values-free: search filters, entry DNs other
than search bases, and attribute values are never read.

Every operation is attributed to the identity that performed it (userId; for a bind, the DN it bound as). An identity
that does more than authenticate is a consumer of the directory, recorded or updated (matched by its bind DN) with:

  ciamObservedSource           the client addresses it connects from (a /24, or /64, where several share one)
  ciamOperationMix             its operations by kind, e.g. "search 70%, bind 25%, modify 5%"
  ciamSubtreeRead              its search bases (a base-scope read of one entry records the entry's parent)
  ciamAttrRead                 the attributes it asks for, as the user-schema records that describe them
  ciamUnindexedSearchesPerDay  its unindexed searches (response.additionalItems.unindexed) per day of the logs
  ciamTlsOnly                  whether every connection it used was TLS (LDAPS, or StartTLS before it operated)
  ciamPeakOpsPerSec            the most operations it performed in one second
  ciamFirstSeen, ciamLastSeen  widened by what the logs show, never narrowed
An identity that only binds is an end user whose password is being checked, not a client: it is counted, never
recorded, unless the record already names it as a consumer. What the record says about a consumer beyond this
(owner, criticality, migration status) is kept; a new consumer's migration status is unknown.
"""
import datetime as dt
import ipaddress
import re
from collections import Counter
from functools import reduce
from itertools import groupby
from typing import NamedTuple

from opsdir.core.directory import children, gtime, make_entry, norm_dn, one
from opsdir.core.sources import json_document
from opsdir.domains.directory.naming import CONSUMERS
from .observe import user_attributes

LOG_FILE = re.compile(r"(?:^|/)[^/]*access[^/]*\.json(?:[-.][^/]*)?$")
WORK = ("SEARCH", "MODIFY", "ADD", "DELETE", "MODIFYDN", "COMPARE", "EXTENDED")   # beyond authenticating
COUNTED = ("BIND", *WORK)
START_TLS = "1.3.6.1.4.1.1466.20037"
NO_ATTRS = ("1.1",)
ALL_ATTRS = ("*", "+", "ALL")
OWNED = ("ciamObservedSource", "ciamOperationMix", "ciamSubtreeRead", "ciamAttrRead", "ciamUnindexedSearchesPerDay",
         "ciamTlsOnly", "ciamPeakOpsPerSec", "ciamFirstSeen", "ciamLastSeen")
_UNSAFE = re.compile(r'[^A-Za-z0-9._-]')

# One operation from the log, reduced to what the record may hold.
Op = NamedTuple("Op", [("identity", str), ("kind", str), ("source", str), ("tls", bool), ("at", dt.datetime),
                       ("base", str), ("attrs", tuple), ("unindexed", bool)])


# ------------------------------------------------------------------ reading the log
def _time(v):
    try:
        return dt.datetime.fromisoformat((v or "").replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except ValueError:
        return None


def _events(files):
    """(connection key, event) of every DJ-LDAP event, in file order; and the lines that aren't JSON events."""
    parsed = tuple((path, json_document(line, dict)) for path in sorted(files) if LOG_FILE.search(path)
                   for line in files[path].splitlines() if line.strip())
    events = tuple(((path.rsplit("/", 1)[0] if "/" in path else "", (e.get("request") or {}).get("connId")), e)
                   for path, e in parsed if e and str(e.get("eventName", "")).startswith("DJ-LDAP"))
    return events, sum(1 for _, e in parsed if e is None)


def _tls_connections(events):
    """Connection keys that were TLS: LDAPS, or a StartTLS on the connection."""
    return {key for key, e in events if (e.get("request") or {}).get("protocol") == "LDAPS"
            or (e.get("request") or {}).get("oid") == START_TLS}


def _identity(e):
    request, response = e.get("request") or {}, e.get("response") or {}
    if e.get("userId"):
        return e["userId"]
    if request.get("operation") == "BIND" and response.get("status") == "SUCCESSFUL":
        return request.get("dn") or None
    return None


def _attrs(request):
    raw = request.get("attrs")
    names = tuple(raw) if isinstance(raw, list) else tuple(a.strip() for a in raw.split(",")) if raw else ()
    return tuple(a for a in names if a and a not in NO_ATTRS)


def _base(request):
    dn = request.get("dn") or ""
    return dn.split(",", 1)[1].strip() if request.get("scope") == "base" and "," in dn else dn


def operations(files):
    """(operations, unreadable line count, anonymous operation count) from the access log files among files."""
    events, unreadable = _events(files)
    tls = _tls_connections(events)
    ops = tuple(Op(identity=_identity(e), kind=(e.get("request") or {}).get("operation"),
                   source=(e.get("client") or {}).get("ip") or "", tls=key in tls, at=_time(e.get("timestamp")),
                   base=_base(e.get("request") or {}) if (e.get("request") or {}).get("operation") == "SEARCH" else "",
                   attrs=(_attrs(e.get("request") or {})
                          if (e.get("request") or {}).get("operation") == "SEARCH" else ()),
                   unindexed="unindexed" in ((e.get("response") or {}).get("additionalItems") or {}))
                for key, e in events if (e.get("request") or {}).get("operation") in COUNTED
                and (e.get("request") or {}).get("oid") != START_TLS)          # StartTLS sets up the connection
    return (tuple(o for o in ops if o.identity and o.at), unreadable,
            sum(1 for o in ops if not o.identity and o.kind in WORK))


# ------------------------------------------------------------------ what one identity did
def _sources(addresses):
    """Client addresses as CIDRs: a /24 (IPv4) or /64 (IPv6) when several addresses share it, else the address."""
    ips = sorted({ipaddress.ip_address(a) for a in addresses if _is_ip(a)}, key=lambda ip: (ip.version, ip))
    nets = Counter(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False) for ip in ips)
    return tuple(dict.fromkeys(str(n) if nets[n] > 1 else f"{ip}/{ip.max_prefixlen}"
                               for ip in ips for n in (ipaddress.ip_network(
                                   f"{ip}/{24 if ip.version == 4 else 64}", strict=False),)))


def _is_ip(a):
    try:
        ipaddress.ip_address(a)
        return True
    except ValueError:
        return False


def _mix(ops):
    counts = Counter(o.kind.lower() for o in ops)
    total = sum(counts.values())
    shares = sorted(counts.items(), key=lambda kc: (-kc[1], kc[0]))
    return ", ".join(f"{k} {round(100 * n / total) or '<1'}%" for k, n in shares)


def _peak(ops):
    return max(Counter(o.at.replace(microsecond=0) for o in ops).values())


def observed(ops, days, user_attrs):
    """(attributes the record observes of one identity, attribute names it asked for that have no user-schema record,
    whether it asked for all attributes)."""
    names = tuple(dict.fromkeys(a for o in ops for a in o.attrs if a not in ALL_ATTRS))
    records = tuple(dict.fromkeys(user_attrs[n.lower()].dn for n in names if n.lower() in user_attrs))
    attrs = {"ciamObservedSource": _sources(o.source for o in ops),
             "ciamOperationMix": (_mix(ops),),
             "ciamSubtreeRead": tuple(dict.fromkeys(o.base for o in ops if o.base)),
             "ciamAttrRead": records,
             "ciamUnindexedSearchesPerDay": (str(round(sum(o.unindexed for o in ops) / days)),),
             "ciamTlsOnly": ("TRUE" if all(o.tls for o in ops) else "FALSE",),
             "ciamPeakOpsPerSec": (str(_peak(ops)),),
             "ciamFirstSeen": (gtime(min(o.at for o in ops)),),
             "ciamLastSeen": (gtime(max(o.at for o in ops)),)}
    return ({k: v for k, v in attrs.items() if v},
            tuple(n for n in names if n.lower() not in user_attrs), any(a in ALL_ATTRS for o in ops for a in o.attrs))


# ------------------------------------------------------------------ consumer entries
def _widened(held, seen):
    """First and last seen, widened by what the record already holds (never narrowed)."""
    first = min(filter(None, (one(held, "ciamFirstSeen") if held else None, seen["ciamFirstSeen"][0])))
    last = max(filter(None, (one(held, "ciamLastSeen") if held else None, seen["ciamLastSeen"][0])))
    return {**seen, "ciamFirstSeen": (first,), "ciamLastSeen": (last,)}


def _name(bind_dn, taken):
    base = _UNSAFE.sub("-", bind_dn.split(",", 1)[0].split("=", 1)[-1]).strip("-") or "consumer"
    return next(n for n in (base, *(f"{base}-{i}" for i in range(2, 1000))) if n.lower() not in taken)


def consumer_entries(d, ops):
    """(entries, notices): a consumer for every identity that does more than authenticate, merged with the record's
    consumer of the same bind DN; identities that only bind are counted."""
    consumers = {norm_dn(one(c, "ciamBindDn")): c
                 for c in children(d, CONSUMERS, "ciamConsumer") if one(c, "ciamBindDn")}
    key = lambda o: norm_dn(o.identity)  # noqa: E731
    by_identity = {k: tuple(g) for k, g in groupby(sorted(ops, key=key), key=key)}
    days = max(1, len({o.at.date() for o in ops}))
    user_attrs = user_attributes(d)
    clients = sorted(k for k, mine in by_identity.items() if k in consumers or any(o.kind in WORK for o in mine))
    only_bind = len(by_identity) - len(clients)
    taken = frozenset(one(c, "cn").lower() for c in consumers.values())
    new_names = reduce(lambda names, k: {**names, k: _name(by_identity[k][0].identity,
                                                          taken | {n.lower() for n in names.values()})},
                       (k for k in clients if k not in consumers), {})
    results = tuple(_consumer(d, consumers.get(k), new_names.get(k), by_identity[k], days, user_attrs) for k in clients)
    return (tuple(e for e, _ in results),
            (*(n for _, ns in results for n in ns),
             *((f"{only_bind} identities only authenticated (binds, e.g. end users whose passwords were checked); "
                f"not recorded",) if only_bind else ()),
             *(f"consumer {one(c, 'cn')} ({one(c, 'ciamBindDn')}) not seen in these logs; unchanged"
               for k, c in sorted(consumers.items()) if k not in by_identity)))


def _consumer(d, held, new_name, ops, days, user_attrs):
    seen, unrecorded, all_attrs = observed(ops, days, user_attrs)
    seen = _widened(held, seen)
    if held is None:
        dn = f"cn={new_name},{CONSUMERS}"
        entry = make_entry(dn, ("top", "ciamConsumer"), {"cn": (new_name,), "ciamBindDn": (ops[0].identity,),
                                                         "ciamMigrationStatus": ("unknown",), **seen})
    else:
        entry = make_entry(held.dn, held.classes, {**{k: v for k, v in held.attrs.items() if k not in OWNED}, **seen})
    name = one(entry, "cn")
    notices = (*((f"consumer {name}: asks for attributes with no user-schema record, not recorded: "
                  f"{', '.join(unrecorded)}",) if unrecorded else ()),
               *((f"consumer {name}: asks for all attributes (* or +)",) if all_attrs else ()),
               *((f"consumer {name}: new, found in the access logs (migration status unknown, no owner)",)
                 if held is None else ()))
    return entry, notices


def read_access_logs(files, d, patterns, at=None):
    """(consumer entries, notices) from the access log files among files."""
    ops, unreadable, anonymous = operations(files)
    entries, notices = consumer_entries(d, ops) if ops else ((), ())
    others = sorted(p for p in files if not LOG_FILE.search(p))
    return entries, (*notices,
                     *((f"{anonymous} anonymous operations (no bound identity); not attributed",) if anonymous else ()),
                     *((f"{unreadable} lines are not JSON access log events; not read",) if unreadable else ()),
                     *((f"not a JSON access log, not read: {', '.join(others)} (read the JSON access log, "
                        f"logs/ldap-access.audit.json)",) if others else ()),
                     *(("no access log events found",) if not ops else ()))
