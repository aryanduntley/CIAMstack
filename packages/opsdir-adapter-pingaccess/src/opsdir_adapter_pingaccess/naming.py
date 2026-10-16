"""Where PingAccess's objects live in the record, and how one names another. Pure.

  ou=pingaccess
    ou=applications       cn=<application>  (paApplication), its resources below it: cn=<resource>,cn=<application>
    ou=sites, ou=virtual-hosts, ou=web-sessions, ou=identity-mappings, ou=rules, ou=rule-sets
    ou=held               ou=<collection, '/' as '.'>  cn=<name>  (paHeld; a settings object: cn=settings)

Entries are named by PingAccess's names (a virtual host by host:port as it was read), never by its numeric ids, which
each PingAccess assigns itself. In settings, an object named by id is written as ${pingaccess-id:<collection>/<name>},
the reference the operator's pipeline replaces with the id the object has where it applies the requests.
"""
import re
from types import MappingProxyType

from opsdir.core.contract import Endpoint
from opsdir.core.naming import branch, rdn_safe
from .api import ENGINE_PORT, HEARTBEAT, ADMIN_PORT, RESOURCES

PINGACCESS = branch("pingaccess")
HELD = branch("held", PINGACCESS)
# kind -> (branch, object class)
KINDS = MappingProxyType({
    "application": (branch("applications", PINGACCESS), "paApplication"),
    "resource": (None, "paResource"),                                   # below its application
    "site": (branch("sites", PINGACCESS), "paSite"),
    "virtual-host": (branch("virtual-hosts", PINGACCESS), "paVirtualHost"),
    "web-session": (branch("web-sessions", PINGACCESS), "paWebSession"),
    "identity-mapping": (branch("identity-mappings", PINGACCESS), "paIdentityMapping"),
    "rule": (branch("rules", PINGACCESS), "paRule"),
    "rule-set": (branch("rule-sets", PINGACCESS), "paRule"),
    "held": (HELD, "paHeld"),
})
SERVER_ROLES = ("pa-admin", "pa-engine")   # ciamServerRole / ciamTargetRole values this adapter defines
ADMIN, ENGINE = SERVER_ROLES
SETTINGS = "settings"                      # the name of a settings object (one per PingAccess)
# What the edge treats specially (contract.Endpoint): the heartbeat, on the engines' and the admin node's ports
ENDPOINTS = (Endpoint("health", HEARTBEAT, ENGINE, None, ENGINE_PORT),
             Endpoint("health", HEARTBEAT, ADMIN, None, ADMIN_PORT))
REFERENCE = re.compile(r"^\$\{pingaccess-id:(.+)\}$")


def usable_name(name):
    """Whether a PingAccess name can name an entry and a reference (no DN special character, no slash)."""
    return isinstance(name, str) and bool(name) and rdn_safe(name) and "/" not in name


def type_slug(path):
    """A collection's path as an RDN value: pingfederate/runtime -> pingfederate.runtime."""
    return path.strip("/").replace("/", ".")


def held_base(path):
    """The container of a collection's objects held as is: ou=<collection>,ou=held,ou=pingaccess."""
    return f"ou={type_slug(path)},{HELD}"


def entry_dn(kind, name, path=None, application=None):
    """The DN of a PingAccess object of a kind: a resource's below its application's, one held as is below its
    collection's container."""
    if kind == "resource":
        return f"cn={name},{entry_dn('application', application)}"
    if kind == "held":
        return f"cn={name},{held_base(path)}"
    return f"cn={name},{KINDS[kind][0]}"


def reference(path, name):
    """How settings name an object: ${pingaccess-id:<collection>/<name>}."""
    return "${pingaccess-id:" + f"{path}/{name}" + "}"


def resources_path(application):
    """The collection of an application's resources, the application named as settings name it."""
    return RESOURCES.replace("{application}", reference("applications", application))


def referenced(value):
    """(collection, name) a ${pingaccess-id:...} reference names, or None: the name after the last slash (names
    holding a slash aren't imported: usable_name), the collection before it."""
    found = REFERENCE.match(value) if isinstance(value, str) else None
    if not found:
        return None
    path, _, name = found.group(1).rpartition("/")
    return (path, name) if path and name else None
