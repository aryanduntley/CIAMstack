"""Environment overlays and overrides: pure functions of a snapshot.

An environment may be an overlay of another (ciamOverlayOf): a stage environment sharing most of production's
bindings, say. It inherits its base's bindings, stack components, declared required roles and overrides, except what
it has itself (the same role, stack role or overridden attribute) and the roles it drops (ciamDropsRole); a base may
itself be an overlay. Servers are never inherited.

An override (ciamOverride, under ou=overrides of an environment) is the environment's own value for one attribute of
a shared entry. The store accepts it only for attributes whose definition allows it (X-OVERRIDABLE); rendering
applies an environment's overrides to the snapshot before any renderer reads it.
"""
from functools import reduce
from types import MappingProxyType

from .directory import children, get, is_a, make_entry, norm_dn, one, rdn_value, values
from .naming import env_label


def _label(e):
    return env_label(e.dn)


def _provider(d, env):
    cloud = get(d, env.dn.split(",", 1)[1])
    return one(cloud, "ciamCloudProvider") if cloud else None


def lineage(d, env, seen=()):
    """The environment, then the environment it is an overlay of, then that one's base, ...: refused when the chain
    loops, names something that is not an environment, or crosses to another provider (their bindings can't be
    shared)."""
    if env.norm in seen:
        raise SystemExit(f"overlay cycle: {' -> '.join((*seen, env.norm))}")
    base_dn = one(env, "ciamOverlayOf")
    if not base_dn:
        return (env,)
    base = get(d, base_dn)
    if base is None or not is_a(base, "ciamEnvironment"):
        raise SystemExit(f"{_label(env)} is an overlay of {base_dn}, which is not an environment")
    if _provider(d, base) != _provider(d, env):
        raise SystemExit(f"{_label(env)} ({_provider(d, env)}) is an overlay of {_label(base)} "
                         f"({_provider(d, base)}): bindings can't be shared across providers")
    return (env, *lineage(d, base, (*seen, env.norm)))


def inherited(layers, key, drops=frozenset()):
    """The items of the nearest layer, then each farther layer's items whose key no nearer layer has and that are not
    dropped."""
    def add(acc, layer):
        taken = {key(x) for x in acc}
        return (*acc, *(x for x in layer if key(x) not in taken and key(x) not in drops))
    return reduce(add, layers[1:], tuple(layers[0])) if layers else ()


def drops(layers):
    """Roles the overlays in a lineage do not inherit."""
    return frozenset(r for e in layers for r in values(e, "ciamDropsRole"))


def _role(e):
    return one(e, "ciamBindingRole")


def effective_bindings(d, layers):
    return inherited([children(d, f"ou=bindings,{e.dn}") for e in layers], _role, drops(layers))


def effective_stack(d, layers):
    return inherited([children(d, f"ou=stack,{e.dn}", "ciamStackComponent") for e in layers],
                     lambda c: one(c, "ciamStackRole"))


def declared_roles(d, layers):
    """Roles the environment's lineage declares it must bind (ciamRequiredRole), each once, dropped ones excluded."""
    found = inherited([children(d, f"ou=stack,{e.dn}", "ciamRequiredRole") for e in layers], _role, drops(layers))
    return tuple(dict.fromkeys(_role(r) for r in found))


def override_key(o):
    return (norm_dn(one(o, "ciamOverrides")), one(o, "ciamOverrideAttribute").lower())


def effective_overrides(d, layers):
    """The overrides that apply to the environment: its own, then each base's for attributes it doesn't override."""
    return inherited([children(d, f"ou=overrides,{e.dn}", "ciamOverride") for e in layers], override_key)


def overridden_in(o):
    """The environment an override entry belongs to, as cloud/env."""
    return env_label(o.dn.split(",ou=overrides,", 1)[1])


def _overridden(d, entries, o):
    target = entries.get(norm_dn(one(o, "ciamOverrides")))
    if target is None:
        raise SystemExit(f"override {rdn_value(o)} names {one(o, 'ciamOverrides')}, which is not in the record")
    attr = d.lower_types.get(one(o, "ciamOverrideAttribute").lower(), one(o, "ciamOverrideAttribute"))
    return {**entries, target.norm: make_entry(target.dn, target.classes,
                                               {**target.attrs, attr: values(o, "ciamOverrideValue")})}


def apply_overrides(d, overrides):
    """The snapshot as an environment sees it: each override's value in place of the shared one."""
    if not overrides:
        return d
    return d._replace(entries=MappingProxyType(reduce(lambda acc, o: _overridden(d, acc, o), overrides,
                                                      dict(d.entries))))


def _values_seen(d, o, dn, attr):
    """What an environment sees for an attribute: its override's values, else the shared entry's."""
    if o is not None:
        return tuple(values(o, "ciamOverrideValue"))
    shared = get(d, dn)
    return tuple(values(shared, d.lower_types.get(attr.lower(), attr))) if shared else ()


def override_differences(d, src_overrides, dst_overrides):
    """(entry DN, attribute, source values, target values, source override, target override) for every attribute
    the two environments' overrides make them see differently (an environment without an override sees the shared
    value), in order of first mention."""
    src, dst = ({override_key(o): o for o in os} for os in (src_overrides, dst_overrides))
    rows = ((one((src.get(k) or dst.get(k)), "ciamOverrides"), one((src.get(k) or dst.get(k)), "ciamOverrideAttribute"),
             src.get(k), dst.get(k)) for k in dict.fromkeys((*src, *dst)))
    seen = ((dn, attr, _values_seen(d, s, dn, attr), _values_seen(d, t, dn, attr), s, t) for dn, attr, s, t in rows)
    return tuple(r for r in seen if r[2] != r[3])
