"""PingIDM's listeners for the ports matrix: its REST interface, and the ports its connectors reach through service
names (the connector's own port, else the service's)."""
from opsdir.core.contract import Listener
from opsdir_adapter_pingidm.listeners import REST, listeners
from network_fixtures import ALPHA, entry, model

SVC = entry(ALPHA, "svc-ldaps", "ciamServiceName", ciamBindingRole="ds-ldaps-service", ciamFqdn="ldap.example.test",
            ciamPort="1636", ciamTargetRole="ds")
TREE = ("dn: ou=pingidm,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: pingidm\n",
        "dn: ou=connectors,ou=pingidm,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: connectors\n",
        entry("ou=connectors,ou=pingidm,dc=ciam-ops", "ldap", "ciamObject", objectClass="pingidmConnector",
              pingidmTargetRole="ds-ldaps-service", pingidmConfig='{"configurationProperties":{"port":636}}'),
        entry("ou=connectors,ou=pingidm,dc=ciam-ops", "dir", "ciamObject", objectClass="pingidmConnector",
              pingidmTargetRole="ds-ldaps-service"),
        entry("ou=connectors,ou=pingidm,dc=ciam-ops", "hr", "ciamObject", objectClass="pingidmConnector"))


def test_rest_and_what_the_connectors_reach():
    _, m, _ = model(alpha=(SVC,), tree=TREE)
    assert listeners(m) == (REST, Listener("ds", 1636, "tcp", "PingIDM connector dir", ("idm",)),
                            Listener("ds", 636, "tcp", "PingIDM connector ldap", ("idm",)))
