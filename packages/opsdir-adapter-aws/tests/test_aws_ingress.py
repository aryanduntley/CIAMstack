"""The front before a cluster's in-cluster gateway on AWS: the ALB a service on servers would get, in the cluster's node
subnets, with IP target groups on the gateway's port that the AWS Load Balancer Controller fills (a TargetGroupBinding
per group, the plug), out to the cluster's subnets, any answer from the gateway healthy."""
import re

from opsdir.core.environment import env_model, of_class
from opsdir.core.interchange.ldif import parse
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.edge.naming import EDGE_POLICIES
from opsdir_adapter_aws.ingress import gateway_front, gateway_plug
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"


def _binding(cn, oc, role, extra=""):
    return (f"dn: cn={cn},ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\n"
            f"ciamBindingRole: {role}\n{extra}")


RECORDS = (
    f"dn: {WORKLOADS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: workloads\n",
    f"dn: {workload_dn('am')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: am\nciamWorkloadKind: deployment\n"
    "ciamTargetRole: am\nciamClusterRole: eks\nciamNamespace: ciam\nciamWorkloadRole: am-workload\n",
    _binding("eks", "ciamCluster", "eks", "ciamProviderRef: eks-1\nciamSubnetRole: subnet-eks-a\n"
                                          "ciamSubnetRole: subnet-eks-b\n"),
    _binding("subnet-eks-a", "ciamSubnetBinding", "subnet-eks-a", "ciamCidr: 10.20.8.0/22\n"),
    _binding("subnet-eks-b", "ciamSubnetBinding", "subnet-eks-b", "ciamCidr: 10.20.12.0/22\n"),
    _binding("am", "ciamWorkloadBinding", "am-workload"),
    _binding("svc-login", "ciamServiceName", "login-service",
             "ciamFqdn: login.example.test\nciamPort: 443\nciamTargetRole: am\nciamFrontendIp: 198.51.100.20\n"
             "ciamDnsZoneRef: Z123\n"),
    _binding("gw", "ciamClusterGateway", "eks-gateway", "ciamClusterRole: eks\nciamNamespace: edge\n"),
    f"dn: {EDGE_POLICIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
    f"dn: cn=sign-on,{EDGE_POLICIES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamTrafficPolicy\n"
    "cn: sign-on\nciamServiceRole: login-service\nciamTlsMode: reencrypt\n")


def _model(*records):
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *records)))))
    return env_model(d, "alpha/prod")


def _parts(m):
    return next(b for b in of_class(m, "ciamServiceName") if b.dn.startswith("cn=svc-login,")), \
        of_class(m, "ciamClusterGateway")[0]


def test_an_alb_with_ip_targets_on_the_gateways_port():
    m = _model(*RECORDS)
    svc, gw = _parts(m)
    out = "\n".join(gateway_front(m, svc, gw, ()))
    assert re.search(r'name\s+= "ciam-prod-svc-login-443"\s+port\s+= 443\s+protocol\s+= "HTTPS"', out)
    assert 'target_type = "ip"' in out and "aws_lb_target_group_attachment" not in out
    assert re.search(r'matcher\s+= "200-499"', out)
    assert re.search(r'cidr_ipv4\s+= "10.20.8.0/22"', out) and re.search(r'cidr_ipv4\s+= "10.20.12.0/22"', out)
    assert "data.aws_subnet.subnet_eks_a.id" in out and "data.aws_subnet.subnet_eks_b.id" in out
    assert "TargetGroupBinding" in out                                  # the comment naming what fills it


def test_a_terminating_front_sends_http_on_80():
    records = tuple(r.replace("ciamTlsMode: reencrypt", "ciamTlsMode: terminate") for r in RECORDS)
    m = _model(*records)
    svc, gw = _parts(m)
    out = "\n".join(gateway_front(m, svc, gw, ()))
    assert re.search(r'name\s+= "ciam-prod-svc-login-443"\s+port\s+= 80\s+protocol\s+= "HTTP"', out)


def test_the_plug_binds_each_target_group_to_the_gateway_service():
    m = _model(*RECORDS)
    _, gw = _parts(m)
    plug = gateway_plug(m, gw, ("gw", (443,)))
    assert plug.annotations == () and plug.service_type == "ClusterIP"
    assert plug.objects == ({"apiVersion": "elbv2.k8s.aws/v1beta1", "kind": "TargetGroupBinding",
                             "metadata": {"name": "gw-svc-login-443"},
                             "spec": {"targetGroupName": "ciam-prod-svc-login-443", "targetType": "ip",
                                      "serviceRef": {"name": "gw", "port": 443}}},)
