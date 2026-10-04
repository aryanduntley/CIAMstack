"""PingFederate's listeners for the ports matrix: what its nodes' run.properties say (runtime for clients, admin for
the operators, the cluster ports for the other nodes), the defaults where the record holds none, and the ports its
engines reach through the data stores' service names."""
from opsdir.core.contract import Listener
from opsdir_adapter_pingfederate.listeners import listeners, node_listeners, store_listeners
from network_fixtures import ALPHA, entry, model

STORES = ("dn: ou=pingfederate,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: pingfederate\n",
          "dn: ou=data-stores,ou=pingfederate,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\n"
          "ou: data-stores\n",
          entry("ou=data-stores,ou=pingfederate,dc=ciam-ops", "users", "ciamObject", objectClass="pingfedDataStore",
                pingfedStoreType="LDAP", pingfedTargetRole="ds-ldaps-service", pingfedPort="636"),
          entry("ou=data-stores,ou=pingfederate,dc=ciam-ops", "fixed", "ciamObject", objectClass="pingfedDataStore",
                pingfedStoreType="JDBC"))


def _node(cn, role, *listening, mode=None):
    return entry(ALPHA, cn, "ciamServer", objectClass="pingfedNode", ciamServerRole=role,
                 ciamHostname=f"{cn}.example.test", ciamSubnet=f"cn=subnet-web,ou=bindings,{ALPHA}",
                 ciamProductVersion="PingFederate 12.1.4", **({"pingfedListener": listening} if listening else {}),
                 **({"pingfedOperationalMode": mode} if mode else {}))


def test_nodes_listen_on_what_run_properties_says():
    _, m, _ = model(alpha=(_node("pf-admin-1", "pf-admin", "admin=9999", "cluster=7600", mode="CLUSTERED_CONSOLE"),
                           _node("pf-engine-1", "pf-engine", "runtime=9031", "cluster=7700"),
                           _node("pf-engine-2", "pf-engine", "runtime=9031", "cluster=7700",
                                 "cluster-failure-detection=7700")))
    assert node_listeners(m) == (
        Listener("pf-engine", 9031, "tcp", "runtime", ("clients",)),
        Listener("pf-engine", 7700, "tcp", "cluster", ("peers", "pf-admin")),
        Listener("pf-engine", 7700, "tcp", "cluster-failure-detection", ("peers", "pf-admin")),
        Listener("pf-admin", 9999, "tcp", "admin", ("admin",)),
        Listener("pf-admin", 7600, "tcp", "cluster", ("peers", "pf-engine")),
        Listener("pf-admin", 7700, "tcp", "cluster-failure-detection", ("peers", "pf-engine")))


def test_defaults_where_the_record_holds_no_run_properties():
    _, m, _ = model(alpha=(_node("pf-engine-1", "pf-engine", mode="CLUSTERED_ENGINE"), _node("pf-admin-1", "pf-admin")))
    assert node_listeners(m) == (Listener("pf-engine", 9031, "tcp", "runtime", ("clients",)),
                                 Listener("pf-engine", 7600, "tcp", "cluster", ("peers", "pf-admin")),
                                 Listener("pf-engine", 7700, "tcp", "cluster-failure-detection", ("peers", "pf-admin")),
                                 Listener("pf-admin", 9999, "tcp", "admin", ("admin",)))


def test_data_stores_reach_the_role_behind_their_service_name():
    svc = entry(ALPHA, "svc-ldaps", "ciamServiceName", ciamBindingRole="ds-ldaps-service", ciamFqdn="ldap.example.test",
                ciamPort="1636", ciamTargetRole="ds")
    _, m, _ = model(alpha=(svc, _node("pf-engine-1", "pf-engine")), tree=STORES)
    assert store_listeners(m) == (Listener("ds", 636, "tcp", "PingFederate data store users", ("pf-engine",)),)
    assert listeners(m)[-1] == store_listeners(m)[0]
