"""What every DS-lineage server listens on, for the ports matrix: the connection handlers the declared configuration
enables (LDAP and LDAPS for clients, HTTPS for the operators and monitoring), the administration connector, and the
replication port its peers connect to. Each product adapter declares these as its listeners. Pure."""
from types import MappingProxyType

from opsdir.core.contract import Listener
from opsdir.core.directory import children, one, rdn_value
from opsdir.domains.directory.naming import DECLARED as DECL, DIRECTORY_SERVER_ROLE
from .replication import REPLICATION_PORT
from .setup import ADMIN_PORT, DEFAULT_PORTS

HANDLER_PEERS = MappingProxyType({"LDAP": ("clients",), "LDAPS": ("clients",), "HTTPS": ("admin",)})
UNDECLARED = ("LDAPS", "HTTPS")      # what a server listens on when the record declares no connection handler


def enabled_handlers(d):
    """{connection handler record name: declared port or None} of the handlers the declared configuration enables;
    the lineage's default handlers when it declares none."""
    handlers = children(d, f"ou=connection-handlers,{DECL}")
    if not handlers:
        return {name: None for name in UNDECLARED}
    return {rdn_value(h): one(h, "ciamListenPort") for h in handlers if one(h, "ciamEnabled") == "TRUE"}


def ds_listeners(m):
    """The listeners of environment m's directory servers: enabled handlers, the administration connector, the
    replication port."""
    handlers = enabled_handlers(m.d)
    return (*(Listener(DIRECTORY_SERVER_ROLE, int(port or DEFAULT_PORTS[name]), "tcp", name, HANDLER_PEERS[name])
              for name, port in handlers.items() if name in HANDLER_PEERS),
            Listener(DIRECTORY_SERVER_ROLE, ADMIN_PORT, "tcp", "administration", ("admin",)),
            Listener(DIRECTORY_SERVER_ROLE, int(REPLICATION_PORT), "tcp", "replication", ("peers",)))
