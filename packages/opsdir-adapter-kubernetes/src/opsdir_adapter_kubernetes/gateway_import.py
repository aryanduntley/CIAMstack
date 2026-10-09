"""Reading a cluster's in-cluster gateways back from its manifests (the `kubernetes/workloads` importer's part). Pure.

A Gateway API Gateway in manifests under <cloud>/<env>/ (an environment the record holds) is that environment's cluster
gateway binding (ciamClusterGateway, the core edge domain), named like the Gateway: its implementation (the row of
gateway.IMPLEMENTATIONS whose GatewayClass it names; another class is named in a notice, not recorded), its namespace,
the cluster it runs in (annotation opsdir.io/cluster-role, else `cluster`, as for workloads) and, when its
infrastructure annotations give one, the private address its Service takes (Azure's internal load balancer). What the
record adds (its CA, Secret keys, owners) is kept. HTTPRoutes aren't read: a deployment kit declares its routes.
"""
from opsdir.core.directory import get, make_entry, merged_attrs
from .gateway import IMPLEMENTATIONS

GATEWAY_OWNED = ("cn", "ciamBindingRole", "ciamClusterRole", "ciamNamespace", "ciamGatewayImplementation",
                 "ciamFrontendIp")
ADDRESS_ANNOTATIONS = ("service.beta.kubernetes.io/azure-load-balancer-ipv4",)
_BY_CLASS = {x.gateway_class: x.name for x in IMPLEMENTATIONS.values()}


def _meta(o):
    return o.get("metadata") or {}


def implementation_named(o):
    """The implementation (vocabulary value) a Gateway's GatewayClass is rendered by, or None."""
    return _BY_CLASS.get((o.get("spec") or {}).get("gatewayClassName"))


def gateway_entry(d, env, o):
    """Environment env's ciamClusterGateway for one Gateway object."""
    meta, spec = _meta(o), o.get("spec") or {}
    name = meta.get("name")
    dn = f"cn={name},ou=bindings,{env}"
    annotations = {**(meta.get("annotations") or {}), **((spec.get("infrastructure") or {}).get("annotations") or {})}
    owned = {"cn": (name,), "ciamBindingRole": (annotations.get("opsdir.io/gateway-role") or f"{name}-gateway",),
             "ciamClusterRole": (annotations.get("opsdir.io/cluster-role") or "cluster",),
             "ciamNamespace": (meta.get("namespace") or "default",),
             "ciamGatewayImplementation": (implementation_named(o),),
             "ciamFrontendIp": (next((annotations[a] for a in ADDRESS_ANNOTATIONS if annotations.get(a)), None),)}
    return make_entry(dn, ("top", "ciamClusterGateway"), merged_attrs(get(d, dn), owned, GATEWAY_OWNED))


def read_gateways(d, found, environment_at, rdn_safe):
    """(entries, notices) of the Gateways in the manifests: ((path, object), ...) as the importer found them;
    environment_at(d, path) the environment a path's <cloud>/<env>/ names, rdn_safe(name) whether a name can be a
    record name."""
    gateways = [(p, o) for p, o in found if o and o.get("kind") == "Gateway"
                and str(o.get("apiVersion", "")).startswith("gateway.networking.k8s.io/")]
    placed = [(p, o, environment_at(d, p)) for p, o in gateways if rdn_safe(_meta(o).get("name") or "")]
    entries = tuple(gateway_entry(d, env, o) for p, o, env in placed if env)
    routes = sum(1 for _, o in found if o and o.get("kind") == "HTTPRoute")
    return entries, (
        *(f"{p}: Gateway {_meta(o).get('name')}: not under <cloud>/<env>/ of an environment the record holds; not "
          "imported" for p, o, env in placed if not env),
        *(f"{p}: Gateway {_meta(o).get('name')}: GatewayClass {(o.get('spec') or {}).get('gatewayClassName')!r} "
          f"isn't one opsdir renders ({', '.join(sorted(_BY_CLASS))}); its implementation isn't recorded"
          for p, o, env in placed if env and implementation_named(o) is None),
        *((f"{routes} HTTPRoute(s): not read (a deployment kit declares its routes)",) if routes else ()))
