"""Systems the platform reaches but doesn't run (a database, a corporate directory): each environment records its host
as a ciamExternalHost binding of a role, so a product that reaches one names the role and each environment renders its
own host (core.environment.published_role is how importers turn the host into the role). Pure.

One host is the usual case. A product setting that lists several (an LDAP store's two domain controllers, a JDBC URL
naming a primary and a standby) is several bindings of one role, ordered by ciamHostOrder, and renders every one of
them (role_hosts); a single binding renders exactly as core.environment.bound does.
"""
import re

from ...core.changeset import new_entry
from ...core.directory import is_kind, one
from ...core.environment import UNBOUND, published_role, role_bindings
from ...core.findings import Fix, Input, bindings_container

ROLE_PATTERN = r"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
_JDBC = re.compile(r"^(jdbc:[^/]*//)([^/;?]*)(.*)$", re.S)     # prefix, hosts, the rest of a JDBC URL


# ------------------------------------------------------------------ hosts in product settings
def endpoint(hostport):
    """(host, port or None) of host[:port] (a rendered UNBOUND:<role>[:port] too)."""
    host, _, port = hostport.rpartition(":")
    return (host, int(port)) if host and port.isdigit() else (hostport, None)


def is_jdbc_url(url):
    """Whether a value is a JDBC connection URL (its hosts there or not)."""
    return isinstance(url, str) and _JDBC.match(url) is not None


def jdbc_hosts(url):
    """The host[:port] values of a JDBC connection URL (jdbc:<driver>://h1[:p1],h2[:p2]/...), none when it isn't one."""
    found = _JDBC.match(url) if isinstance(url, str) else None
    return tuple(h for h in found.group(2).split(",") if h) if found else ()


def with_jdbc_hosts(url, hosts):
    """A JDBC connection URL with its hosts replaced by hosts (none: the URL without hosts, as the record holds it when
    each environment renders its own); any other value unchanged."""
    found = _JDBC.match(url) if isinstance(url, str) else None
    return found.group(1) + ",".join(hosts) + found.group(3) if found else url


def _role_of(d, host):
    return host[len(UNBOUND):] if host.startswith(UNBOUND) else published_role(d, host)


def hosts_role(d, hosts):
    """(role, port): the role every host[:port] is published as (a service name, an external host of that role, a
    rendered UNBOUND:<role>) and their common port; (None, None) when they aren't all one role."""
    ends = [endpoint(h) for h in hosts]
    roles = {_role_of(d, h) for h, _ in ends}
    ports = {p for _, p in ends}
    if not ends or len(roles) != 1 or None in roles:
        return None, None
    return roles.pop(), (ports.pop() if len(ports) == 1 else None)


def unnamed(d, hosts):
    """Whether no host[:port] of hosts is named in the record yet (a role's service name or external host, a rendered
    UNBOUND:<role>): what the fix naming them needs, so that one setting's hosts never end up under two roles."""
    return all(_role_of(d, endpoint(h)[0]) is None for h in hosts)


def role_hosts(m, role, port=None):
    """The host[:port] values a product setting naming a role renders for environment m: each binding's host, in host
    order, with port (the setting's own, common to its hosts) when given, else an external host's own port (recorded
    when the setting's hosts don't share one); UNBOUND:<role> when m binds none. One binding renders as
    core.environment.bound does."""
    def at(host, own):
        p = port or own
        return f"{host}:{p}" if p else host
    found = role_bindings(m, role)
    if not found:
        return (at(f"{UNBOUND}{role}", None),)
    return tuple(at(one(b, "ciamFqdn") or f"{UNBOUND}{role}",
                    one(b, "ciamPort") if is_kind(m.d, b, "ciamExternalHost") else None) for b in found)


# ------------------------------------------------------------------ the fix naming them
def _cn(host):
    return "ext-" + re.sub(r"[^a-z0-9-]+", "-", host.lower()).strip("-")


def _role_input(host):
    hint = re.sub(r"[^a-z0-9-]+", "-", host.lower().split(".", 1)[0]).strip("-")
    return Input("role", "the role of the system it reaches", (), (hint,), ROLE_PATTERN)


def _binding(m, host, port, role, order=None):
    cn = _cn(host)
    return new_entry(f"cn={cn},ou=bindings,{m.dn}", ("top", "ciamExternalHost"), {
        "cn": (cn,), "ciamFqdn": (host,), **({"ciamPort": (str(port),)} if port else {}),
        **({"ciamHostOrder": (str(order),)} if order else {}), "ciamBindingRole": (role,)})


def _manual(importer, what):
    return (f"Import the product again ({importer}): {what} then names the role in place of the host.",
            "Bind the role in every other environment with the host it reaches there (the plan's binding fix "
            "offers it once the role is recorded).")


_RISKS = ("A system that is the same from every environment gets the same host in each: the fix only names it, so a "
          "move can't miss it.",)


def external_host_fix(m, host, what, key, importer, port=None):
    """The Fix recording host (and port, when the product's setting names one the role must carry) as environment m's
    host of an external system's role (the role an input: never guessed), so that importing the product again
    (importer) names the role in place of the host."""
    return Fix(key, "Hosts", f"Record `{host}`, which {what} reaches, as {m.label}'s host of a role",
               (*bindings_container(m.d, m.dn), _binding(m, host, port, _role_input(host))),
               _manual(importer, what), _RISKS)


def external_hosts_fix(m, hosts, what, key, importer):
    """The Fix recording each of hosts (host[:port], as the product's setting lists them) as environment m's host of
    one external system's role: one host gives external_host_fix's fix; several give a binding each, in the setting's
    order (ciamHostOrder), with their own port when they don't share one (a shared port stays the setting's). None
    when there are none."""
    listed = tuple(endpoint(h) for h in hosts)
    ends = tuple(e for i, e in enumerate(listed) if e[0].lower() not in {h.lower() for h, _ in listed[:i]})
    if len(ends) < 2:
        return external_host_fix(m, ends[0][0], what, key, importer) if ends else None
    own_ports = len({p for _, p in ends}) > 1
    role = _role_input(ends[0][0])
    names = ", ".join(f"`{h}`" for h, _ in ends)
    return Fix(key, "Hosts", f"Record {names}, which {what} reaches, as {m.label}'s hosts of a role",
               (*bindings_container(m.d, m.dn),
                *(_binding(m, h, p if own_ports else None, role, i) for i, (h, p) in enumerate(ends, 1))),
               _manual(importer, what),
               (*_RISKS, "The hosts keep the setting's order (ciamHostOrder, the first tried first): change it there "
                         "if another environment should prefer another host."))

