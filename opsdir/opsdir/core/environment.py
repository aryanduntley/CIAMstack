"""The resolved view of one environment that every renderer and check works from.

Nothing is looked up by hostname or file path. Callers ask for *roles* ("network", "ds-ldaps-service")
and the environment's bindings answer (SPEC R7). Which roles an environment must bind is supplied by
the caller (the adapters that apply), never hardcoded here.
"""
from typing import NamedTuple

from .directory import Directory, Entry, children, follow, get, is_a, one, rdn_value
from .naming import branch

EnvModel = NamedTuple("EnvModel", [("d", Directory), ("dn", str), ("env", Entry), ("cloud", Entry),
                                   ("provider", str), ("label", str), ("servers", tuple),
                                   ("bindings", tuple), ("unbound", tuple)])


def env_dn(spec):
    """'aws-current/prod' → env=prod,cloud=aws-current,ou=environments,dc=ciam-ops (full DNs pass through)."""
    if "=" in spec:
        return spec
    cloud, env = spec.split("/")
    return f"env={env},cloud={cloud},{branch('environments')}"


def _with_role(bindings, role):
    return tuple(b for b in bindings if one(b, "ciamBindingRole") == role)


def env_model(d, spec, required_roles=()):
    """Resolve an environment spec against a snapshot; roles in required_roles that nothing binds are unbound."""
    dn = env_dn(spec)
    env = get(d, dn)
    if not env:
        raise SystemExit(f"no such environment: {dn}")
    cloud = get(d, dn.split(",", 1)[1])
    bindings = children(d, f"ou=bindings,{dn}")
    return EnvModel(d=d, dn=dn, env=env, cloud=cloud, provider=one(cloud, "ciamCloudProvider"),
                    label=f"{rdn_value(cloud)}/{rdn_value(env)}", servers=children(d, dn, "ciamServer"),
                    bindings=bindings, unbound=tuple(r for r in required_roles if not _with_role(bindings, r)))


def with_required_roles(m, required_roles):
    """The same environment, with unbound roles recomputed for a (new) set of required roles."""
    return m._replace(unbound=tuple(r for r in required_roles if not _with_role(m.bindings, r)))


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


def joins(m):
    """The environment whose replication deployment this one joins (migration), if any."""
    return follow(m.d, m.env, "ciamJoinsDeploymentOf")
