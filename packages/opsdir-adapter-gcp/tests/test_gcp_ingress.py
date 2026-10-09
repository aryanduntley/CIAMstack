"""The front before a cluster's in-cluster gateway on Google Cloud: the Application Load Balancer a service on servers
would get, its backends the gateway Service's standalone NEGs (read once per zone the cluster spans, rate balanced),
health checks sending the service's host, the proxy and probe rules on the cluster's node subnets; and the plug naming
those NEGs on the gateway's Service."""
import json
import re

from opsdir.core.environment import env_model, of_class
from opsdir.core.interchange.ldif import parse
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.edge.naming import EDGE_POLICIES
from opsdir_adapter_gcp.ingress import gateway_front, gateway_negs, gateway_plug
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"


def _binding(cn, oc, role, extra=""):
    return (f"dn: cn={cn},ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\n"
            f"ciamBindingRole: {role}\n{extra}")


RECORDS = (
    f"dn: {WORKLOADS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: workloads\n",
    f"dn: {workload_dn('am')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: am\nciamWorkloadKind: deployment\n"
    "ciamTargetRole: am\nciamClusterRole: gke\nciamNamespace: ciam\nciamWorkloadRole: am-workload\n",
    _binding("gke", "ciamCluster", "gke", "ciamProviderRef: gke-1\nciamSubnetRole: subnet-gke\n"
                                          "ciamSpansZone: us-central1-a\nciamSpansZone: us-central1-b\n"),
    _binding("subnet-gke", "ciamSubnetBinding", "subnet-gke", "ciamCidr: 10.30.8.0/22\n"),
    _binding("subnet-edge", "ciamSubnetBinding", "subnet-edge", "ciamCidr: 10.30.250.0/24\n"),
    _binding("am", "ciamWorkloadBinding", "am-workload"),
    _binding("svc-login", "ciamServiceName", "login-service",
             "ciamFqdn: login.example.test\nciamPort: 443\nciamTargetRole: am\nciamFrontendIp: 198.51.100.20\n"),
    _binding("gw", "ciamClusterGateway", "gke-gateway", "ciamClusterRole: gke\nciamNamespace: edge\n"),
    f"dn: {EDGE_POLICIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
    f"dn: cn=sign-on,{EDGE_POLICIES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamTrafficPolicy\n"
    "cn: sign-on\nciamServiceRole: login-service\nciamTlsMode: reencrypt\nciamHealthProtocol: https\n"
    "ciamHealthPath: /am/json/health/ready\n")


def _model(*records):
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *records)))))
    return env_model(d, "alpha/prod")


def _parts(m):
    return next(b for b in of_class(m, "ciamServiceName") if b.dn.startswith("cn=svc-login,")), \
        of_class(m, "ciamClusterGateway")[0]


def test_the_gateways_negs_are_read_once_per_zone():
    out = "\n".join(gateway_negs(_model(*RECORDS)))
    assert out.count('data "google_compute_network_endpoint_group"') == 2
    assert re.search(r'name\s+= "ciam-prod-gw-443"\s+zone\s+= "us-central1-a"', out)
    unzoned = tuple(r.replace("ciamSpansZone: us-central1-a\nciamSpansZone: us-central1-b\n", "") for r in RECORDS)
    assert gateway_negs(_model(*unzoned))[0].startswith("# UNBOUND: the zones cluster `gke` spans")


def test_an_application_load_balancer_over_the_gateways_negs():
    m = _model(*RECORDS)
    svc, gw = _parts(m)
    out = "\n".join(gateway_front(m, svc, gw, (), ((), "198.51.100.20"), ()))
    assert 'group                 = data.google_compute_network_endpoint_group.neg_gw_443_us_central1_a.self_link' \
        in out
    assert re.search(r'balancing_mode\s+= "RATE"\s+max_rate_per_endpoint = 100', out)
    assert "port_name" not in out and 'protocol              = "HTTPS"' in out
    assert re.search(r'https_health_check \{\s+port\s+= 443\s+host\s+= "login.example.test"', out)
    assert 'destination_ranges = ["10.30.8.0/22"]' in out and "target_tags" not in out


def test_the_plug_names_the_negs_on_the_gateways_service():
    m = _model(*RECORDS)
    _, gw = _parts(m)
    plug = gateway_plug(m, gw, ("gw", (80, 443)))
    assert plug.service_type == "ClusterIP" and plug.objects == ()
    (name, value), = plug.annotations
    assert name == "cloud.google.com/neg" and json.loads(value) == {"exposed_ports": {
        "80": {"name": "ciam-prod-gw-80"}, "443": {"name": "ciam-prod-gw-443"}}}
