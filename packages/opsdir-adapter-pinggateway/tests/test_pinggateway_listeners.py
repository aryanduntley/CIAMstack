"""PingGateway's listeners for the ports matrix: its HTTPS listener, its admin connector from 2025.3 (none recorded:
the newest release), and the ports its routes reach on the applications behind service names; its health endpoint by
version, on the admin port from 2025.3."""
from opsdir.core.contract import Listener
from opsdir.domains.edge.resolve import declared_endpoints, health_port
from opsdir_adapter_pinggateway.listeners import ADMIN, HTTPS, listeners
from opsdir_adapter_pinggateway.naming import ENDPOINTS
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
    assert listeners(m) == (HTTPS, ADMIN, Listener("web", 8443, "tcp", "PingGateway route portal", ("ig",)))
    gw = entry(ALPHA, "ig-1", "ciamServer", ciamServerRole="ig", ciamHostname="ig-1.example.test",
               ciamProductVersion="PingGateway 2024.11.0")
    _, old, _ = model(alpha=(svc, gw), tree=TREE)
    assert ADMIN not in listeners(old)


def test_the_health_endpoint_moves_to_the_admin_port_in_2025_3():
    assert declared_endpoints(ENDPOINTS, "ig", recorded=("PingGateway 2024.11.0",)) == {"health": ("/openig/ping",)}
    assert health_port(ENDPOINTS, "ig", ("PingGateway 2024.11.0",)) is None
    assert declared_endpoints(ENDPOINTS, "ig", recorded=("PingGateway 2025.3.1",)) == {"health": ("/ping",)}
    assert declared_endpoints(ENDPOINTS, "ig") == {"health": ("/health/startup",)}
    assert health_port(ENDPOINTS, "ig") == 8085
