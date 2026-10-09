"""The in-cluster gateway a cluster routes the service names of the roles it alone runs through (a ciamClusterGateway
binding; the core edge domain says which service names it fronts). Each cloud renders the front before it (load
balancer, WAF, TLS certificate, DNS record) from the service names' policies; this renders, per gateway, the Kubernetes
Gateway API objects behind that front. Pure.

  gateway.yaml  (the gateway's namespace) the Gateway: an HTTP listener for service names whose TLS the front
                terminates, an HTTPS one presenting the gateway's internal certificate for those it re-encrypts; the
                implementation's own objects; and the cloud's plug (Services.gateway_plug: the Service's annotations
                and type, objects such as a target group binding)
  routes.yaml   (each fronted role's namespace) an HTTPRoute per service name, from the routes its deployment kit
                declares (Services.routes); a BackendTLSPolicy for a Service that speaks TLS; cookie stickiness when
                the service name's traffic policy asks for it

Which implementation runs a gateway is data: the binding's ciamGatewayImplementation, else the estate setting
kubernetes-gateway-implementation. IMPLEMENTATIONS holds one row per implementation rendered, pinned to the release its
objects were checked against: how the Gateway names and annotates its Service, trusts the front's X-Forwarded-For, and
keeps a client on one backend pod. Only standard-channel Gateway API objects are shared; the rest is the row's.

The gateway's Secrets (its internal TLS key pair) are read like a workload's (ciamWorkloadSecret on the binding,
delivered by render.py); the CAs its backends' certificates are checked against are a ConfigMap beside each
BackendTLSPolicy (<gateway>-backend-ca, key ca.crt: the PEMs recorded for the CAs the gateway trusts, core
edge.gateways.backend_ca; public material). Values the record can't give are UNBOUND:<what>.
"""
from collections import namedtuple
from types import MappingProxyType

from opsdir.core.contract import GatewayPlug, Setting
from opsdir.core.directory import one, rdn_of, rdn_value
from opsdir.core.environment import UNBOUND, of_class
from opsdir.core.settings import setting_value
from opsdir.domains.compute.workloads import namespace_of, runs_on_kubernetes, workload_secrets, workloads
from opsdir.domains.edge.gateways import GATEWAY_HTTP as HTTP_PORT, GATEWAY_HTTPS as HTTPS_PORT, backend_ca, \
    fronted_services, gateway_port
from opsdir.domains.edge.resolve import front_edge
from .names import k8s_name

GATEWAY_API = "gateway.networking.k8s.io/v1"         # standard channel, Gateway API v1.6.1
TRUSTED_HOPS = 1                                     # the cloud's front, before the gateway
COOKIE = "route"                                     # the affinity cookie (ForgeOps' name for AM's)
TLS_KEYS = ("tls.crt", "tls.key")                    # the gateway's internal key pair, one Secret's keys

# One implementation: name (the vocabulary value), gateway_class and controller (its GatewayClass, and whether we
# render it: own_class), release (pinned, what its objects were checked against), gateway(ns, name, plug) -> (Gateway
# metadata annotations, spec.infrastructure, further objects), stickiness(ns, route, services, seconds) -> objects.
Implementation = namedtuple("Implementation", ("name", "gateway_class", "controller", "own_class", "release",
                                               "gateway", "stickiness"))


def _ttl(seconds):
    return f"{seconds}s" if seconds else "0s"


# ------------------------------------------------------------------ Istio (gateway only, no mesh)
def _istio_gateway(ns, name, plug):
    """Istio names the generated Deployment and Service from gateway.istio.io/name-override, takes the Service type
    from networking.istio.io/service-type, and copies spec.infrastructure.annotations to the Service and the pods
    (where proxy.istio.io/config sets the trusted hops)."""
    hops = f"gatewayTopology:\n  numTrustedProxies: {TRUSTED_HOPS}\n"
    return ({"gateway.istio.io/name-override": name, "networking.istio.io/service-type": plug.service_type},
            {"annotations": {**dict(plug.annotations), "proxy.istio.io/config": hops}}, ())


def _istio_stickiness(ns, route, services, seconds):
    return tuple({"apiVersion": "networking.istio.io/v1", "kind": "DestinationRule",
                  "metadata": {"name": k8s_name(f"{service}-affinity"), "namespace": ns},
                  "spec": {"host": f"{service}.{ns}.svc.cluster.local",
                           "trafficPolicy": {"loadBalancer": {"consistentHash": {"httpCookie": {
                               "name": COOKIE, "ttl": _ttl(seconds), "path": "/"}}}}}}
                 for service in services)


# ------------------------------------------------------------------ Envoy Gateway
def _envoy_gateway(ns, name, plug):
    """Envoy Gateway takes the Service's name, type and annotations from an EnvoyProxy the Gateway names, and the
    trusted hops from a ClientTrafficPolicy on the Gateway."""
    proxy = f"{name}-proxy"
    return ({}, {"parametersRef": {"group": "gateway.envoyproxy.io", "kind": "EnvoyProxy", "name": proxy}},
            ({"apiVersion": "gateway.envoyproxy.io/v1alpha1", "kind": "EnvoyProxy",
              "metadata": {"name": proxy, "namespace": ns},
              "spec": {"provider": {"type": "Kubernetes", "kubernetes": {"envoyService": {
                  "name": name, "type": plug.service_type,
                  **({"annotations": dict(plug.annotations)} if plug.annotations else {})}}}}},
             {"apiVersion": "gateway.envoyproxy.io/v1alpha1", "kind": "ClientTrafficPolicy",
              "metadata": {"name": f"{name}-client-ip", "namespace": ns},
              "spec": {"targetRefs": [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": name}],
                       "clientIPDetection": {"xForwardedFor": {"numTrustedHops": TRUSTED_HOPS}}}}))


def _envoy_stickiness(ns, route, services, seconds):
    return ({"apiVersion": "gateway.envoyproxy.io/v1alpha1", "kind": "BackendTrafficPolicy",
             "metadata": {"name": k8s_name(f"{route}-affinity"), "namespace": ns},
             "spec": {"targetRefs": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "name": route}],
                      "loadBalancer": {"type": "ConsistentHash", "consistentHash": {
                          "type": "Cookie", "cookie": {"name": COOKIE, "ttl": _ttl(seconds),
                                                       "attributes": {"Path": "/"}}}}}},)


IMPLEMENTATIONS = MappingProxyType({x.name: x for x in (
    Implementation("istio", "istio", "istio.io/gateway-controller", False, "1.31.1", _istio_gateway,
                   _istio_stickiness),
    Implementation("envoy-gateway", "envoy", "gateway.envoyproxy.io/gatewayclass-controller", True, "v1.9.2",
                   _envoy_gateway, _envoy_stickiness),
)})
CHOICES = tuple(IMPLEMENTATIONS)
SETTING = Setting("kubernetes-gateway-implementation", "string", "istio",
                  "Which Gateway API implementation runs a cluster's in-cluster gateway when its binding names none "
                  "(ciamGatewayImplementation)", choices=CHOICES)
VOCABULARY = MappingProxyType({"ciamGatewayImplementation": CHOICES})


# ------------------------------------------------------------------ what the record says
def implementation_of(m, gw):
    """The Implementation running a cluster gateway: its binding's, else the estate setting's; None for a value no
    row renders."""
    return IMPLEMENTATIONS.get(one(gw, "ciamGatewayImplementation") or setting_value(m.d, SETTING))


def gateway_name(gw):
    """The Kubernetes name of a cluster gateway's Gateway and of its data-plane Service."""
    return k8s_name(rdn_value(gw))


def gateway_namespace(m, gw):
    """The namespace a cluster gateway runs in: its binding's, else the first fronted role's workloads'."""
    fronted = [one(svc, "ciamTargetRole") for svc, g in fronted_services(m) if g.dn == gw.dn]
    return one(gw, "ciamNamespace") or next((ns for role in fronted for ns in role_namespaces(m, role)), "default")


def role_namespaces(m, role):
    """The namespaces environment m runs a server role's workloads in on Kubernetes, in the record's order."""
    return tuple(dict.fromkeys(namespace_of(w) for w in workloads(m.d)
                               if one(w, "ciamTargetRole") == role and runs_on_kubernetes(m, w)))


def tls_secret(gw):
    """The Secret holding a cluster gateway's internal key pair (the one its ciamWorkloadSecret keys tls.crt and
    tls.key name), else UNBOUND."""
    keys = {}
    for s, k, _ in workload_secrets(gw):
        keys.setdefault(s, set()).add(k)
    return next((s for s, ks in keys.items() if set(TLS_KEYS) <= ks), f"{UNBOUND}gateway-tls-secret")


def _fronted(m, services, gw):
    """((service name, EdgeSpec or None, routes, namespace), ...) of the service names a gateway fronts that have
    routes declared."""
    declared = services.routes(m)
    return tuple((svc, front_edge(m, svc, services.endpoints), routes, ns)
                 for svc, g in fronted_services(m) if g.dn == gw.dn
                 for routes in (tuple(r for r in declared if r.server_role == one(svc, "ciamTargetRole")),) if routes
                 for ns in role_namespaces(m, one(svc, "ciamTargetRole"))[:1])


def gateway_ports(m, services, gw):
    """The ports a cluster gateway's Service serves on: HTTP and/or HTTPS, as the fronts need."""
    return tuple(sorted({gateway_port(spec) for _, spec, _, _ in _fronted(m, services, gw)}))


# ------------------------------------------------------------------ objects
def _allowed(namespaces):
    return {"namespaces": {"from": "Selector", "selector": {"matchExpressions": [
        {"key": "kubernetes.io/metadata.name", "operator": "In", "values": list(namespaces)}]}}}


def gateway_docs(m, services, gw):
    """The objects in a cluster gateway's namespace: its implementation's GatewayClass when we render it, the Gateway,
    the implementation's objects, the cloud plug's objects; () when no row renders its implementation or it fronts
    nothing with routes."""
    impl = implementation_of(m, gw)
    if impl is None:
        return ()
    ns, name, fronted = gateway_namespace(m, gw), gateway_name(gw), _fronted(m, services, gw)
    ports = gateway_ports(m, services, gw)
    plug = services.gateway_plug(m, gw, (name, ports)) or GatewayPlug((), ())
    meta, infrastructure, extra = impl.gateway(ns, name, plug)
    allowed = _allowed(dict.fromkeys(rns for _, _, _, rns in fronted))
    listeners = [*([{"name": "http", "protocol": "HTTP", "port": HTTP_PORT, "allowedRoutes": allowed}]
                   if HTTP_PORT in ports else []),
                 *([{"name": "https", "protocol": "HTTPS", "port": HTTPS_PORT,
                     "tls": {"mode": "Terminate", "certificateRefs": [{"kind": "Secret", "name": tls_secret(gw)}]},
                     "allowedRoutes": allowed}] if HTTPS_PORT in ports else [])]
    record = {"opsdir.io/cluster-role": one(gw, "ciamClusterRole"),      # read back by gateway_import
              "opsdir.io/gateway-role": one(gw, "ciamBindingRole")}
    gateway = {"apiVersion": GATEWAY_API, "kind": "Gateway",
               "metadata": {"name": name, "namespace": ns, "annotations": {**record, **meta}},
               "spec": {"gatewayClassName": impl.gateway_class, "infrastructure": infrastructure,
                        "listeners": listeners}}
    own = ({"apiVersion": GATEWAY_API, "kind": "GatewayClass", "metadata": {"name": impl.gateway_class},
            "spec": {"controllerName": impl.controller}},) if impl.own_class else ()
    placed = tuple({**o, "metadata": {"namespace": ns, **o.get("metadata", {})}} for o in plug.objects)
    return (*own, gateway, *extra, *placed) if listeners else ()


def route_docs(m, services, gw):
    """{namespace: objects}: per service name a cluster gateway fronts, its HTTPRoute in its role's namespace, the
    BackendTLSPolicies of the Services there that speak TLS with the backend CA bundle they check against, and cookie
    stickiness when its policy asks for it."""
    impl = implementation_of(m, gw)
    if impl is None:
        return {}
    gns, name, out = gateway_namespace(m, gw), gateway_name(gw), {}
    bundle, missing = backend_ca(m.d, gw)
    ca = bundle or f"{UNBOUND}{rdn_of(missing[0]) if missing else 'gateway-ca'}-pem"
    for svc, spec, routes, ns in _fronted(m, services, gw):
        route = k8s_name(rdn_value(svc))
        section = "https" if gateway_port(spec) == HTTPS_PORT else "http"
        rules = [{"matches": [{"path": {"type": "PathPrefix" if r.match == "prefix" else "Exact", "value": r.path}}],
                  **({"filters": [{"type": "URLRewrite", "urlRewrite": {"path": {
                      "type": "ReplacePrefixMatch", "replacePrefixMatch": r.rewrite}}}]} if r.rewrite else {}),
                  "backendRefs": [{"name": r.service, "port": r.port}]} for r in routes]
        tls = tuple(dict.fromkeys(r.service for r in routes if r.tls))
        sticky = impl.stickiness(ns, route, tuple(dict.fromkeys(r.service for r in routes)),
                                 spec.stickiness_seconds) if spec is not None and spec.stickiness == "cookie" else ()
        out.setdefault(ns, []).extend((
            {"apiVersion": GATEWAY_API, "kind": "HTTPRoute", "metadata": {"name": route, "namespace": ns},
             "spec": {"parentRefs": [{"name": name, "namespace": gns, "sectionName": section}],
                      "hostnames": [one(svc, "ciamFqdn")], "rules": rules}},
            *({"apiVersion": GATEWAY_API, "kind": "BackendTLSPolicy",
               "metadata": {"name": k8s_name(f"{service}-tls"), "namespace": ns},
               "spec": {"targetRefs": [{"group": "", "kind": "Service", "name": service}],
                        "validation": {"caCertificateRefs": [{"group": "", "kind": "ConfigMap",
                                                              "name": f"{name}-backend-ca"}],
                                       "hostname": f"{service}.{ns}.svc.cluster.local"}}} for service in tls),
            *(({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{name}-backend-ca", "namespace": ns},
                "data": {"ca.crt": ca}},) if tls else ()),
            *sticky))
    return {ns: tuple({(d["kind"], d["metadata"]["name"]): d for d in docs}.values()) for ns, docs in out.items()}


def cluster_gateways(m):
    """Environment m's cluster gateway bindings."""
    return of_class(m, "ciamClusterGateway")
