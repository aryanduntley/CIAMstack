"""What every DS-lineage setup script is built from: the user backend, the listener ports, the directory servers of
an environment, and secret references turned into run-time lookups. Each product writes its own script from these."""
from types import MappingProxyType
from typing import NamedTuple

from opsdir.core.directory import children, one, rdn_value, subtree
from opsdir.core.environment import secret, servers_with_role
from opsdir.domains.directory.naming import DECLARED as DECL, DIRECTORY_SERVER_ROLE

DEFAULT_PORTS = MappingProxyType({"LDAP": 1389, "LDAPS": 1636, "HTTPS": 8443})

# One server's script inputs: the server entry, the user backend, {handler record name: port},
# replication bootstrap hosts, {secret role: shell expression}
SetupInputs = NamedTuple("SetupInputs", [("server", object), ("backend", object), ("ports", dict), ("peers", tuple),
                                         ("secrets", dict)])


def user_backend(d):
    """The declared backend that holds the user directory (the first in DN order)."""
    return subtree(d, f"ou=backends,{DECL}", "ciamBackend")[0]


def handler_ports(d):
    """{connection handler record name: listen port} from the declared configuration."""
    return {rdn_value(h): one(h, "ciamListenPort") for h in children(d, f"ou=connection-handlers,{DECL}")}


def port(ports, name):
    """A handler's declared port, else the lineage default."""
    return ports.get(name) or DEFAULT_PORTS[name]


def secret_expr(m, services, role):
    """Shell expression that resolves a secret-bound role at run time, or a variable the operator must set when the
    environment doesn't bind it (never a value)."""
    uri = secret(m, role)
    return f'"$({services.secret_command(uri)})"' if uri else f'"${{UNBOUND_{role.upper().replace("-", "_")}}}"'


def directory_servers(m):
    """The environment's servers that serve the user directory."""
    return servers_with_role(m, DIRECTORY_SERVER_ROLE)


def setup_inputs(m, services, peers, secret_roles):
    """SetupInputs for every directory server of the environment, in DN order."""
    be, ports = user_backend(m.d), handler_ports(m.d)
    secrets = {role: secret_expr(m, services, role) for role in secret_roles}
    return tuple(SetupInputs(s, be, ports, peers, secrets) for s in directory_servers(m))
