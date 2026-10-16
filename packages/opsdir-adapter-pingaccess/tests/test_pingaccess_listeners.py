"""PingAccess's listeners for the ports matrix: the engines' runtime port, the admin node's console and cluster
configuration ports, the certificate rotation port from 9.1 (none recorded: the newest release), and the ports its
sites reach on the applications behind service names; the heartbeat on the engine and admin ports."""
from opsdir.core.contract import Listener
from opsdir.domains.edge.resolve import declared_endpoints, health_port
from opsdir_adapter_pingaccess.listeners import ADMIN_API, CLUSTER, ENGINE_HTTPS, ROTATION, listeners
from opsdir_adapter_pingaccess.naming import ENDPOINTS
from network_fixtures import ALPHA, entry, model

TREE = ("dn: ou=pingaccess,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: pingaccess\n",
        "dn: ou=sites,ou=pingaccess,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: sites\n",
        entry("ou=sites,ou=pingaccess,dc=ciam-ops", "portal-backend", "ciamObject", objectClass="paSite",
              paBackendRole="portal-backend"),
        entry("ou=sites,ou=pingaccess,dc=ciam-ops", "fixed", "ciamObject", objectClass="paSite"))
BACKEND = entry(ALPHA, "svc-portal-backend", "ciamServiceName", ciamBindingRole="portal-backend",
                ciamFqdn="portal-backend.example.test", ciamPort="8443", ciamTargetRole="app")


def test_engine_admin_cluster_and_what_the_sites_reach():
    _, m, _ = model(alpha=(BACKEND,), tree=TREE)
    assert listeners(m) == (ENGINE_HTTPS, ADMIN_API, CLUSTER, ROTATION,
                            Listener("app", 8443, "tcp", "PingAccess site portal-backend", ("pa-engine",)))
    admin = entry(ALPHA, "pa-admin-1", "ciamServer", ciamServerRole="pa-admin", ciamHostname="pa-admin-1.example.test",
                  ciamProductVersion="PingAccess 8.3.6")
    _, old, _ = model(alpha=(BACKEND, admin), tree=TREE)
    assert ROTATION not in listeners(old)


def test_the_heartbeat_on_the_engine_and_admin_ports():
    assert declared_endpoints(ENDPOINTS, "pa-engine", recorded=("PingAccess 9.1.1",)) == {
        "health": ("/pa/heartbeat.ping",)}
    assert health_port(ENDPOINTS, "pa-engine", ("PingAccess 9.1.1",)) == 3000
    assert health_port(ENDPOINTS, "pa-admin", ("PingAccess 9.1.1",)) == 9000
