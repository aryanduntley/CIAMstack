"""PingFederate data stores: the Admin API's /dataStores read into the record, and rendered back for each environment.
Pure.

A data store becomes a pingfedDataStore entry (cn: its id) holding its settings as the Admin API writes them, less what
differs per environment:

  hosts         LDAP hostnames, the host of a JDBC connection URL: when every host is the same service name in the
                record, the store names that binding's role (pingfedTargetRole) and port, and each environment renders
                its own host; otherwise the hosts are kept as they are (a fixed host, named in the notices)
  credentials   withheld (opsdir_adapter_pingfederate.withheld); each environment renders the reference of the
                store's credential role (pingfedCredentialRole), which a change sets: it is never guessed
  bind account  an LDAP store's user DN is linked to the directory consumer record with that bind DN

What the record adds to a data store (its credential role, owners) is kept on import. The rendered file
(pingfederate/data-stores.json) imports back unchanged.
"""
import json
import re

from opsdir.core.directory import get, make_entry, merged_attrs, one, rdn_value
from opsdir.core.environment import UNBOUND, bound, published_role
from opsdir.core.jsondata import canonical, held_json
from opsdir.core.naming import rdn_safe
from opsdir.domains.directory.consumers import consumer_by_bind_dn
from .naming import DATA_STORES, named

from .withheld import filled, withheld_settings

OUTPUT = "pingfederate/data-stores.json"
OWNED = ("cn", "pingfedStoreType", "pingfedTargetRole", "pingfedPort", "pingfedConsumer", "pingfedConfig",
         "pingfedWithheld")
_JDBC = re.compile(r"^(jdbc:[^/]*//)([^/;?]*)(.*)$", re.S)     # prefix, hosts, the rest of a JDBC URL


# ------------------------------------------------------------------ hosts
def _endpoint(hostport):
    """(host, port or None) of host[:port] (a rendered UNBOUND:<role>[:port] too)."""
    host, _, port = hostport.rpartition(":")
    return (host, int(port)) if host and port.isdigit() else (hostport, None)


def store_hosts(store):
    """The host[:port] values a data store reaches: an LDAP store's hostnames, a JDBC URL's hosts."""
    if store.get("type") == "LDAP":
        return tuple(h for h in store.get("hostnames") or () if isinstance(h, str) and h)
    found = _JDBC.match(store.get("connectionUrl") or "") if store.get("type") == "JDBC" else None
    return tuple(h for h in found.group(2).split(",") if h) if found else ()


def _role_of(d, host):
    return host[len(UNBOUND):] if host.startswith(UNBOUND) else published_role(d, host)


def target(d, hosts):
    """(role, port): the role of the service name every host is (and their common port), else (None, None)."""
    ends = [_endpoint(h) for h in hosts]
    roles = {_role_of(d, h) for h, _ in ends}
    ports = {p for _, p in ends}
    if not ends or len(roles) != 1 or None in roles:
        return None, None
    return roles.pop(), (ports.pop() if len(ports) == 1 else None)


def _without_hosts(store):
    """The settings without the hosts, which each environment renders."""
    if store.get("type") == "LDAP":
        return {k: v for k, v in store.items() if k != "hostnames"}
    found = _JDBC.match(store.get("connectionUrl") or "")
    return {**store, "connectionUrl": found.group(1) + found.group(3)} if found else store


def _with_host(kind, config, host):
    """The settings with the host each environment renders put back."""
    if kind == "LDAP":
        return {**config, "hostnames": [host]}
    found = _JDBC.match(config.get("connectionUrl") or "")
    return {**config, "connectionUrl": found.group(1) + host + found.group(3)} if found else config


# ------------------------------------------------------------------ import
def _notices(d, store, label, hosts, role, consumer, held, credential):
    servers = {one(e, "ciamHostname").lower() for e in d.entries.values()
               if "ciamServer" in e.classes and one(e, "ciamHostname")}
    names = [_endpoint(h)[0].lower() for h in hosts if not h.startswith(UNBOUND)]
    bind = store.get("userDN")
    return (*((f"{label}: binds as {bind}, which no consumer records",) if bind and consumer is None else ()),
            *(f"{label}: reaches server {h} by its hostname, not a service name (it changes when servers are replaced "
              f"or moved)" for h in names if h in servers),
            *(f"{label}: reaches {h}, which is neither a service name nor a server in the record" for h in names
              if h not in servers and published_role(d, h) is None),
            *((f"{label}: no single service name for its hosts, so it reaches the same place from every environment",)
              if hosts and role is None else ()),
            *((f"{label}: connects without TLS",) if store.get("type") == "LDAP" and store.get("useSsl") is False
              and not store.get("useStartTLS") else ()),
            *((f"{label}: its credentials are withheld; set pingfedCredentialRole to the secret role that holds them",)
              if held and not credential else ()))


def data_store_entry(d, store, patterns):
    """(DN, entry, notices) for one data store of the export, or (None, None, notices) when its id can't name one."""
    sid, kind = store.get("id"), store.get("type") or "unknown"
    label = f"{kind} data store {store.get('name') or sid}"
    if not rdn_safe(sid or ""):
        return None, None, (f"{label}: its id can't name an entry, not imported",)
    hosts = store_hosts(store)
    role, port = target(d, hosts)
    kept = {k: v for k, v in (_without_hosts(store) if role else store).items() if k not in ("id", "type")}
    config, held = withheld_settings(kept, patterns)
    consumer = consumer_by_bind_dn(d, store.get("userDN")) if kind == "LDAP" else None
    dn = named(DATA_STORES, sid)
    existing = get(d, dn)
    owned = {"cn": (sid,), "pingfedStoreType": (kind,), "pingfedTargetRole": (role,),
             "pingfedPort": (str(port) if port else None,), "pingfedConsumer": (consumer.dn if consumer else None,),
             "pingfedConfig": (canonical(config),), "pingfedWithheld": held}
    entry = make_entry(dn, ("top", "ciamObject", "pingfedDataStore"), merged_attrs(existing, owned, OWNED))
    return dn, entry, _notices(d, store, label, hosts, role, consumer, held, one(entry, "pingfedCredentialRole"))


def data_store_groups(d, stores, patterns):
    """(groups, notices): an entry for every data store of the export."""
    parts = [data_store_entry(d, s, patterns) for s in stores]
    return tuple((dn, (e,)) for dn, e, _ in parts if dn), tuple(n for _, _, ns in parts for n in ns)


# ------------------------------------------------------------------ render
def data_store_view(m, store):
    """A data store as the Admin API takes it, for environment m: its host from the binding of its target role, its
    withheld values as the reference of its credential role (UNBOUND:<role> or ${withheld} where nothing supplies
    one; the planner blocks on both)."""
    kind, role, port = one(store, "pingfedStoreType"), one(store, "pingfedTargetRole"), one(store, "pingfedPort")
    config = held_json(store, "pingfedConfig")
    host = bound(m, role, "ciamFqdn") if role else None
    placed = _with_host(kind, config, f"{host}:{port}" if port else host) if host else config
    return {"type": kind, "id": rdn_value(store), **filled(m, store, placed)}


def data_stores_file(m, stores):
    """{path: text}: the data stores for environment m (nothing when there are none)."""
    return {OUTPUT: json.dumps([data_store_view(m, s) for s in stores], indent=2) + "\n"} if stores else {}
