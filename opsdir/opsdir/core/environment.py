"""The resolved view of one environment that every renderer and check works from.

Nothing is looked up by hostname or file path. Callers ask for *roles* ("network", "ds-ldaps-service")
and the environment's bindings answer (SPEC R7). Which roles an environment must bind is supplied by
the caller (the adapters that apply), never hardcoded here, plus the roles the environment itself declares.
An overlay environment's bindings, stack, declared roles and overrides include what it inherits (core.overlays).
"""
from typing import NamedTuple, Optional

from .directory import Directory, Entry, children, follow, get, is_a, one, rdn_value, subtree
from .naming import branch
from .overlays import (apply_overrides, declared_roles, effective_bindings, effective_overrides, effective_stack,
                       lineage)

UNBOUND = "UNBOUND:"              # a value from a role the environment doesn't bind: UNBOUND:<role>

# One declared component of an environment's stack: the adapter (by registered name) that fills a role.
StackComponent = NamedTuple("StackComponent", [("role", str), ("adapter", str), ("versions", Optional[str]),
                                               ("source", Optional[str])])
EnvModel = NamedTuple("EnvModel", [("d", Directory), ("dn", str), ("env", Entry), ("cloud", Entry),
                                   ("provider", str), ("label", str), ("servers", tuple),
                                   ("bindings", tuple), ("unbound", tuple),
                                   ("stack", tuple),        # StackComponents, empty when none is declared
                                   ("declared_roles", tuple),   # roles the environment declares it must bind
                                   ("overrides", tuple),        # ciamOverride entries that apply to it
                                   ("lineage", tuple)])         # the environment, then its bases (overlays)


def env_dn(spec):
    """'source/prod' → env=prod,cloud=source,ou=environments,dc=ciam-ops (full DNs pass through)."""
    if "=" in spec:
        return spec
    cloud, env = spec.split("/")
    return f"env={env},cloud={cloud},{branch('environments')}"


def stack_component(e):
    return StackComponent(one(e, "ciamStackRole"), one(e, "ciamAdapter"), one(e, "ciamAdapterVersion"),
                          one(e, "ciamAdapterSource"))


def _with_role(bindings, role):
    return tuple(b for b in bindings if one(b, "ciamBindingRole") == role)


def _unbound(bindings, required_roles, declared):
    return tuple(r for r in dict.fromkeys((*required_roles, *declared)) if not _with_role(bindings, r))


def env_model(d, spec, required_roles=()):
    """Resolve an environment spec against a snapshot: its own servers, and its bindings, stack, declared roles and
    overrides with what it inherits as an overlay. Roles in required_roles, or declared by the environment, that
    nothing binds are unbound."""
    dn = env_dn(spec)
    env = get(d, dn)
    if not env:
        raise SystemExit(f"no such environment: {dn}")
    cloud = get(d, dn.split(",", 1)[1])
    layers = lineage(d, env)
    bindings, declared = effective_bindings(d, layers), declared_roles(d, layers)
    return EnvModel(d=d, dn=dn, env=env, cloud=cloud, provider=one(cloud, "ciamCloudProvider"),
                    label=f"{rdn_value(cloud)}/{rdn_value(env)}", servers=children(d, dn, "ciamServer"),
                    bindings=bindings, unbound=_unbound(bindings, required_roles, declared),
                    stack=tuple(stack_component(c) for c in effective_stack(d, layers)),
                    declared_roles=declared, overrides=effective_overrides(d, layers), lineage=layers)


def as_seen(m):
    """The environment with its snapshot as it sees the record: its overrides in place of the shared values. What
    every renderer of the environment reads."""
    return m._replace(d=apply_overrides(m.d, m.overrides)) if m.overrides else m


def with_required_roles(m, required_roles):
    """The same environment, with unbound roles recomputed for a (new) set of required roles (and its own)."""
    return m._replace(unbound=_unbound(m.bindings, required_roles, m.declared_roles))


def published_role(d, host):
    """The binding role of the service name some environment publishes at this host (case-insensitive), or None:
    how an importer turns a host in a product's configuration into a role each environment binds."""
    names = (b for b in subtree(d, branch("environments"), "ciamServiceName")
             if host and (one(b, "ciamFqdn") or "").lower() == host.lower())
    return next((one(b, "ciamBindingRole") for b in names), None)


def server_location(server):
    """'cloud/env' of a server entry."""
    parts = dict(p.split("=", 1) for p in server.dn.split(",")[1:3])
    return f"{parts.get('cloud')}/{parts.get('env')}"


def server_named(d, name, roles, what):
    """(server entry, None), or (None, why not): the one server of these roles whose hostname is name, else whose
    record name is (case-insensitive): how an importer of servers' own files places a folder named by its server.
    what: the servers in words ('directory server')."""
    servers = tuple(e for e in d.entries.values() if "ciamServer" in e.classes and one(e, "ciamServerRole") in roles)
    wanted = name.lower()
    found = tuple(s for s in servers if (one(s, "ciamHostname") or "").lower() == wanted) or \
        tuple(s for s in servers if rdn_value(s).lower() == wanted)
    if len(found) == 1:
        return found[0], None
    if not found:
        return None, f"{name}: no {what} in the record has this hostname or name; not imported"
    return None, (f"{name}: names {what}s in several environments ({', '.join(server_location(s) for s in found)}); "
                  f"name the folder by the server's hostname; not imported")


def by_role(m, role):
    return _with_role(m.bindings, role)


def one_role(m, role):
    found = by_role(m, role)
    return found[0] if found else None


def of_class(m, oc):
    return tuple(b for b in m.bindings if is_a(b, oc))


def servers_with_role(m, role):
    return tuple(s for s in m.servers if one(s, "ciamServerRole") == role)


def subnet_of(m, server):
    return follow(m.d, server, "ciamSubnet")


def secret(m, role):
    b = one_role(m, role)
    return one(b, "ciamRefUri") if b else None


def bound(m, role, attr):
    """The attribute of the role's binding in environment m (a service name's ciamFqdn, a secret's ciamRefUri), or
    UNBOUND:<role> when the environment binds none: what a product renderer writes where a value differs per
    environment (the planner blocks on the unbound ones)."""
    b = one_role(m, role)
    return one(b, attr) if b is not None and one(b, attr) else f"{UNBOUND}{role}"


def secret_placeholder(m, role):
    """How a withheld credential is written for environment m: the reference of the role's binding, resolved at
    deployment (${secret:<ref-uri>}), or UNBOUND:<role>."""
    ref = bound(m, role, "ciamRefUri")
    return ref if ref.startswith(UNBOUND) else "${secret:" + ref + "}"


def joins(m):
    """The environment whose replication deployment this one joins (migration), if any."""
    return follow(m.d, m.env, "ciamJoinsDeploymentOf")
