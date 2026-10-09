"""AWS: the front before a cluster's in-cluster gateway, and how the gateway's Service is plugged into it. Pure.

A service name whose role an environment runs only on EKS, in a cluster with a gateway (the core edge domain's
edge.gateways), is fronted as a service on servers is: an ALB with its TLS policy and ACM certificate, the WAFv2 web ACL
and Shield protection its protection policy asks for, a CloudFront distribution when a CDN fronts it, its DNS alias. Its
target groups take IP targets in the cluster's node subnets, on the gateway's port (HTTP, or HTTPS when the policy
re-encrypts: an ALB doesn't check the gateway's certificate), and the AWS Load Balancer Controller registers the
gateway's pods in them: one TargetGroupBinding per target group (the plug), naming the group and the gateway's Service.
An ALB's health checks carry no service host, so any answer from the gateway counts as healthy (the gateway routes by
host; the pods behind it are Kubernetes' to check).
"""
from functools import partial

from opsdir.core.contract import GatewayPlug
from opsdir.core.directory import one, rdn_value, values
from opsdir.domains.compute.workloads import cluster_subnets
from opsdir.domains.edge.gateways import fronted_services, gateway_port
from opsdir.domains.edge.resolve import front_edge
from opsdir_format_terraform.hcl import block, ref, tf_name
from .cdn import alias, distribution
from .dns import service_record
from .edge import Backend, alb_service, target_group_name

ANY_ANSWER = "200-499"        # the gateway answered: healthy (its 404 for a host-less health check included)


def _no_attachments(n, port):
    return ()


def _cluster_peering(fqdn, cidrs, port, n, ports):
    """The ALB's egress to the cluster's node subnets on the gateway's port (pods take addresses there)."""
    return tuple(block("resource", ["aws_vpc_security_group_egress_rule", f"{n}_alb_to_gateway_{i}"], [
        ("security_group_id", ref(f"aws_security_group.{n}_alb.id")), ("cidr_ipv4", cidr),
        ("from_port", port), ("to_port", port), ("ip_protocol", "tcp"),
        ("description", f"to the cluster gateway serving {fqdn}")]) for i, cidr in enumerate(cidrs))


def gateway_backend(m, svc, spec):
    """The Backend of a service name a cluster gateway fronts: IP targets on the gateway's port, registered by a
    TargetGroupBinding (no attachments), the ALB allowed out to the cluster's node subnets, any answer healthy."""
    port = gateway_port(spec)
    cidrs = tuple(one(s, "ciamCidr") for s in cluster_subnets(m, one(svc, "ciamTargetRole")) if one(s, "ciamCidr"))
    return Backend("ip", port, _no_attachments, partial(_cluster_peering, one(svc, "ciamFqdn"), cidrs, port),
                   ANY_ANSWER)


def gateway_front(m, svc, gw, endpoints):
    """The Terraform for a service name a cluster gateway fronts: its ALB (in the cluster's node subnets) sending to
    the gateway, its CloudFront distribution when a CDN fronts it, and its DNS alias."""
    n, spec = tf_name(rdn_value(svc)), front_edge(m, svc, endpoints)
    subnets = cluster_subnets(m, one(svc, "ciamTargetRole"))
    return (*alb_service(m, svc, spec, gateway_backend(m, svc, spec), subnets),
            "# the ALB doesn't check the cluster gateway's certificate; the AWS Load Balancer Controller registers "
            "the gateway's pods (TargetGroupBinding); the EKS nodes' security group must admit this ALB's",
            *(distribution(m, svc, spec, n) if spec.cdn else ()),
            *service_record(m.d, m, svc, n, alias(n) if spec.cdn else None))


def gateway_plug(m, gw, service):
    """Adapter gateway_plug: a TargetGroupBinding per target group of each service name the gateway fronts (the
    group by name, IP targets, the gateway's Service on the port its front sends to); the Service stays ClusterIP."""
    name, _ = service
    return GatewayPlug((), tuple(
        {"apiVersion": "elbv2.k8s.aws/v1beta1", "kind": "TargetGroupBinding",
         "metadata": {"name": f"{name}-{rdn_value(svc)}-{port}"},
         "spec": {"targetGroupName": target_group_name(m, svc, port), "targetType": "ip",
                  "serviceRef": {"name": name, "port": gateway_port(front_edge(m, svc, ()))}}}
        for svc, g in fronted_services(m) if g.dn == gw.dn for port in values(svc, "ciamPort")))
