"""What a DS-lineage server listens on for the ports matrix: the handlers the declared configuration enables (their
ports, else the defaults), the lineage defaults when none is declared, the administration and replication ports."""
from opsdir.core.contract import Listener
from opsdir_base_ds.listeners import ds_listeners, enabled_handlers
from network_fixtures import entry, model

DECL = "ou=declared,ou=config,dc=ciam-ops"
CONTAINERS = tuple(f"dn: {dn}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {dn.split(',')[0][3:]}\n"
                   for dn in ("ou=config,dc=ciam-ops", DECL, f"ou=connection-handlers,{DECL}"))


def _handler(name, enabled, port=None):
    return entry(f"ou=connection-handlers,{DECL}", name, "ciamConnectionHandler", ciamEnabled=enabled,
                 **({"ciamListenPort": port} if port else {}))


def test_enabled_handlers_with_their_ports():
    d, m, _ = model(tree=(*CONTAINERS, _handler("LDAP", "TRUE"), _handler("LDAPS", "TRUE", "636"),
                          _handler("HTTPS", "FALSE", "8443"), _handler("LDIF", "TRUE")))
    assert enabled_handlers(d) == {"LDAP": None, "LDAPS": "636", "LDIF": None}
    assert ds_listeners(m) == (Listener("ds", 1389, "tcp", "LDAP", ("clients",)),
                               Listener("ds", 636, "tcp", "LDAPS", ("clients",)),
                               Listener("ds", 4444, "tcp", "administration", ("admin",)),
                               Listener("ds", 8989, "tcp", "replication", ("peers",)))


def test_the_lineage_defaults_when_nothing_is_declared():
    _, m, _ = model()
    assert [(lst.purpose, lst.port, lst.peers) for lst in ds_listeners(m)] == [
        ("LDAPS", 1636, ("clients",)), ("HTTPS", 8443, ("admin",)), ("administration", 4444, ("admin",)),
        ("replication", 8989, ("peers",))]
