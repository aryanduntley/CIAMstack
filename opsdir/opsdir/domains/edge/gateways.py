"""Cluster gateways: the in-cluster gateway (a ciamClusterGateway binding) a cluster routes the service names of the
roles it alone runs through. A cloud's front (load balancer, WAF, TLS certificate, DNS record, rendered from the
service name's policies as for servers) reaches the gateway, which routes to the roles' pods. Which service names a
gateway fronts follows from the record: a service name's role runs only on Kubernetes, in a cluster with a gateway.
Every cloud and the planner read this one answer. Pure.
"""
from ...core.directory import one
from ...core.environment import of_class
from ..compute.workloads import only_on_kubernetes, role_clusters

GATEWAY_HTTP, GATEWAY_HTTPS = 80, 443          # the gateway's listeners: HTTP behind a terminating front, else HTTPS


def cluster_gateway(m, cluster):
    """Environment m's gateway binding for a cluster (binding), or None."""
    role = one(cluster, "ciamBindingRole")
    return next((g for g in of_class(m, "ciamClusterGateway") if one(g, "ciamClusterRole") == role), None)


def role_gateway(m, role):
    """The gateway of the first cluster environment m runs a server role in that has one, or None."""
    return next((g for c in role_clusters(m, role) for g in (cluster_gateway(m, c),) if g is not None), None)


def fronted_services(m):
    """((service name, gateway), ...): environment m's service names whose role it runs only on Kubernetes, in a cluster
    with a gateway, in the record's order: what a cloud's front sends to the gateway."""
    return tuple((svc, g) for svc in of_class(m, "ciamServiceName") if only_on_kubernetes(m, one(svc, "ciamTargetRole"))
                 for g in (role_gateway(m, one(svc, "ciamTargetRole")),) if g is not None)


def gateway_port(spec):
    """The gateway port a service name's front sends to: HTTPS (the gateway's internal certificate) when its policy
    re-encrypts, else HTTP."""
    return GATEWAY_HTTPS if spec is not None and spec.mode == "reencrypt" else GATEWAY_HTTP


def gateway_ca(m, gw):
    """The reference (ciamRefUri) of the CA certificate a cluster gateway's internal certificate chains to (its
    ciamTrustsCertificate, as environment m's certificate store holds it), or None: what a front re-encrypting to the
    gateway trusts."""
    ca = one(gw, "ciamTrustsCertificate")
    held = (r for r in of_class(m, "ciamCertificateRef") if ca and one(r, "ciamHoldsCertificate") == ca)
    return next((one(r, "ciamRefUri") for r in held), None)
