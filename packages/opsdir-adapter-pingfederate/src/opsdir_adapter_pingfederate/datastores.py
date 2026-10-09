"""PingFederate data stores: the Admin API's /dataStores read into the record, and rendered back for each environment.
Pure.

A data store becomes a pingfedDataStore entry (cn: its id) holding its settings as the Admin API writes them, less what
differs per environment:

  hosts         LDAP hostnames, the hosts of a JDBC connection URL: when every host is the same role in the record
                (a service name, or the external hosts of one system), the store names that role (pingfedTargetRole)
                and their common port, and each environment renders its own hosts (one, usually; every binding of
                the role, in host order, when it binds several); otherwise the hosts are kept as they are (fixed
                hosts, named in the notices)
  credentials   withheld (opsdir_adapter_pingfederate.withheld); each environment renders the reference of the
                store's credential role (pingfedCredentialRole), which a change sets: it is never guessed
  bind account  an LDAP store's user DN is linked to the directory consumer record with that bind DN

What the record adds to a data store (its credential role, owners) is kept on import. The rendered request
(opsdir_adapter_pingfederate.admin_api) imports back unchanged.
"""

from opsdir.core.directory import get, make_entry, merged_attrs, one, rdn_value
from opsdir.core.environment import UNBOUND, published_role
from opsdir.core.jsondata import canonical, held_json
from opsdir.core.naming import rdn_safe
from opsdir.domains.directory.consumers import consumer_by_bind_dn
from opsdir.domains.infrastructure.external import endpoint, hosts_role, jdbc_hosts, role_hosts, with_jdbc_hosts
from .naming import DATA_STORES, named

from .withheld import filled, withheld_settings

OWNED = ("cn", "pingfedStoreType", "pingfedTargetRole", "pingfedPort", "pingfedConsumer", "pingfedConfig",
         "pingfedWithheld")


# ------------------------------------------------------------------ hosts
def store_hosts(store):
    """The host[:port] values a data store reaches: an LDAP store's hostnames, a JDBC URL's hosts."""
    if store.get("type") == "LDAP":
        return tuple(h for h in store.get("hostnames") or () if isinstance(h, str) and h)
    return jdbc_hosts(store.get("connectionUrl") or "") if store.get("type") == "JDBC" else ()


def _without_hosts(store):
    """The settings without the hosts, which each environment renders."""
    if store.get("type") == "LDAP":
        return {k: v for k, v in store.items() if k != "hostnames"}
    return {**store, "connectionUrl": with_jdbc_hosts(store.get("connectionUrl"), ())} \
        if jdbc_hosts(store.get("connectionUrl") or "") else store


def _with_hosts(kind, config, hosts):
    """The settings with the hosts each environment renders put back."""
    if kind == "LDAP":
        return {**config, "hostnames": list(hosts)}
    return {**config, "connectionUrl": with_jdbc_hosts(config.get("connectionUrl"), hosts)} \
        if "connectionUrl" in config else config


# ------------------------------------------------------------------ import
def _notices(d, store, label, hosts, role, consumer, held, credential):
    servers = {one(e, "ciamHostname").lower() for e in d.entries.values()
               if "ciamServer" in e.classes and one(e, "ciamHostname")}
    names = [endpoint(h)[0].lower() for h in hosts if not h.startswith(UNBOUND)]
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
    role, port = hosts_role(d, hosts)
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
    """A data store as the Admin API takes it, for environment m: its hosts from the bindings of its target role (one,
    usually; every one, in host order, when m binds the role several times), its withheld values as the reference of
    its credential role (UNBOUND:<role> or ${withheld} where nothing supplies one; the planner blocks on both)."""
    kind, role, port = one(store, "pingfedStoreType"), one(store, "pingfedTargetRole"), one(store, "pingfedPort")
    config = held_json(store, "pingfedConfig")
    placed = _with_hosts(kind, config, role_hosts(m, role, port)) if role else config
    return {"type": kind, "id": rdn_value(store), **filled(m, store, placed)}
