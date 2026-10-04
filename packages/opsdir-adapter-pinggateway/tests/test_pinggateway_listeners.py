"""PingGateway's listeners for the ports matrix: its HTTPS listener, and the ports its routes reach on the
applications behind service names."""
from opsdir.core.contract import Listener
from opsdir_adapter_pinggateway.listeners import HTTPS, listeners
from network_fixtures import ALPHA, entry, model

TREE = ("dn: ou=pinggateway,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: pinggateway\n",
        "dn: ou=routes,ou=pinggateway,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: routes\n",
        entry("ou=routes,ou=pinggateway,dc=ciam-ops", "portal", "ciamObject", objectClass="pinggwRoute",
              pinggwBackendRole="portal-service"),
        entry("ou=routes,ou=pinggateway,dc=ciam-ops", "fixed", "ciamObject", objectClass="pinggwRoute"))


def test_https_and_what_the_routes_reach():
    svc = entry(ALPHA, "svc-portal", "ciamServiceName", ciamBindingRole="portal-service",
                ciamFqdn="portal.example.test", ciamPort="8443", ciamTargetRole="web")
    _, m, _ = model(alpha=(svc,), tree=TREE)
    assert listeners(m) == (HTTPS, Listener("web", 8443, "tcp", "PingGateway route portal", ("ig",)))
