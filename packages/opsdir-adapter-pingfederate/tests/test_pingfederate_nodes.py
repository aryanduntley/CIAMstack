"""PingFederate nodes: each node's run.properties, jgroups.properties (or an upgraded install's tcp.xml) and
hivemodule.xml imported (operational mode, tags, listeners and settings on the server, secrets withheld; the discovery
protocol checked against the environment's pf-cluster-discovery binding; which store backs clients and grants), the
cluster's discovery rendered per environment from the protocol its binding chooses, and the planner's findings when
the target chooses a different protocol, one PingFederate doesn't support, or none."""
import datetime as dt
import json

import pytest

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.checks import check_cluster
from opsdir_adapter_pingfederate.naming import STORAGE
from opsdir_adapter_pingfederate.render import render_env
from opsdir_adapter_pingfederate.schema import FRAGMENT
import mini_estate
from support import build_directory

REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
ALPHA, BETA = ("env=prod,cloud=alpha,ou=environments,dc=ciam-ops", "env=prod,cloud=beta,ou=environments,dc=ciam-ops")
ADMIN, ENGINE = f"cn=pf-admin,{ALPHA}", f"cn=pf-engine-1,{ALPHA}"


def _server(cn, role, host):
    return (f"dn: cn={cn},{ALPHA}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: {role}\n"
            f"ciamHostname: {host}\nciamSubnet: cn=subnet-pf,ou=bindings,{ALPHA}\n")


def _discovery(env, ref):
    return (f"dn: cn=pf-discovery,ou=bindings,{env}\nobjectClass: top\nobjectClass: ciamBackupTarget\n"
            f"cn: pf-discovery\nciamBindingRole: pf-cluster-discovery\nciamStorageRef: {ref}\n")


EXTRA = "\n".join((
    f"dn: cn=subnet-pf,ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: ciamSubnetBinding\ncn: subnet-pf\n"
    "ciamBindingRole: subnet-pf\nciamCidr: 10.1.4.0/24\n",
    _server("pf-admin", "pf-admin", "pf-admin.alpha.example.test"),
    _server("pf-engine-1", "pf-engine", "pf-1.alpha.example.test"),
    _discovery(ALPHA, "s3://alpha-pf-cluster/pf")))
BETA_BLOB = _discovery(BETA, "azblob://betapf/cluster")


def _chosen(env, protocol, fqdn=None):
    """A pingfedClusterDiscovery binding stating its protocol."""
    return (f"dn: cn=pf-discovery,ou=bindings,{env}\nobjectClass: top\nobjectClass: pingfedClusterDiscovery\n"
            f"cn: pf-discovery\nciamBindingRole: pf-cluster-discovery\npingfedDiscoveryProtocol: {protocol}\n"
            + (f"ciamFqdn: {fqdn}\n" if fqdn else ""))


BETA_DNS = _chosen(BETA, "DNS_PING", "pf-cluster.beta.example.test")


def _tcp(protocol):
    return (f'<config xmlns="urn:org:jgroups"><TCP bind_port="${{pf.cluster.bind.port}}"/>'
            f'<{protocol} bucket_name="alpha-pf-cluster"/><MERGE3/></config>')


HIVEMODULE = """<module id="pf" version="1.0.0">
  <service-point id="ClientManager" interface="org.sourceid.oauth20.domain.ClientManager">
    <invoke-factory><construct class="org.sourceid.oauth20.domain.ClientManagerJdbcImpl"/></invoke-factory>
  </service-point>
  <service-point id="AccessGrantManager" interface="org.sourceid.oauth20.token.AccessGrantManager">
    <invoke-factory><construct class="org.sourceid.oauth20.token.AccessGrantManagerJdbcImpl"/></invoke-factory>
  </service-point>
  <service-point id="SomethingElse"><invoke-factory><construct class="x.Y"/></invoke-factory></service-point>
</module>"""


def jgroups(protocol):
    """A PingFederate 11+ node: jgroups.properties names the protocol, tcp.xml holds ${DISCOVERY_TAG}."""
    return {"pf-1.alpha.example.test/bin/jgroups.properties":
            f"pf.cluster.discovery.protocol={protocol}\npf.cluster.{protocol}.bucket_name=alpha-pf-cluster\n",
            "pf-1.alpha.example.test/server/default/conf/tcp.xml":
            '<config xmlns="urn:org:jgroups"><TCP bind_port="${pf.cluster.bind.port}"/>${DISCOVERY_TAG}</config>'}


def files(protocol="org.jgroups.aws.s3.NATIVE_S3_PING"):
    return {"pf-admin.alpha.example.test/bin/run.properties":
            "# console\npf.operational.mode=CLUSTERED_CONSOLE\npf.admin.https.port=9999\npf.cluster.bind.port=7600\n"
            "pf.cluster.bind.address=10.1.4.10\npf.cluster.auth.pwd=not-a-real-secret-123\n",
            "pf-admin.alpha.example.test/server/default/conf/tcp.xml": _tcp(protocol),
            "pf-1.alpha.example.test/bin/run.properties":
            "pf.operational.mode=CLUSTERED_ENGINE\npf.https.port=9031\npf.cluster.bind.port=7600\nnode.tags=east, a\n",
            "pf-1.alpha.example.test/server/default/conf/tcp.xml": _tcp(protocol),
            "pf-1.alpha.example.test/server/default/conf/META-INF/hivemodule.xml": HIVEMODULE,
            "pf-9.example.test/bin/run.properties": "pf.operational.mode=CLUSTERED_ENGINE\n"}


def records(extra="", discovery=True):
    alpha = EXTRA if discovery else EXTRA[:EXTRA.index("dn: cn=pf-discovery")]
    return tuple(parse(mini_estate.LDIF + "\n" + alpha + "\n" + extra))


def imported(node_files=None, extra="", discovery=True):
    """(the record (alpha binding S3 discovery unless not) after importing the node files, the import's change
    records, notices)."""
    base = build_directory(REGISTRY, records(extra, discovery))
    changes, notices = preview_import(base, "pingfederate/node-files", node_files or files(), (ADAPTER,))
    return build_directory(REGISTRY, records(extra, discovery), changes), changes, notices


@pytest.fixture(scope="module")
def after():
    d, _, notices = imported()
    return d, notices


def test_a_nodes_run_properties_are_recorded_on_its_server(after):
    d, _ = after
    admin, engine = get(d, ADMIN), get(d, ENGINE)
    assert "pingfedNode" in admin.classes and one(admin, "pingfedOperationalMode") == "CLUSTERED_CONSOLE"
    assert (values(admin, "pingfedListener"), values(engine, "pingfedListener"), values(engine, "pingfedNodeTags")) == \
        (("admin=9999", "cluster=7600"), ("runtime=9031", "cluster=7600"), ("east", "a"))
    assert json.loads(one(admin, "pingfedConfig")) == {"pf.cluster.bind.address": "10.1.4.10",
                                                       "pf.cluster.auth.pwd": None}
    assert values(admin, "pingfedWithheld") == ("/pf.cluster.auth.pwd",)
    assert (one(admin, "pingfedDiscovery"), one(admin, "ciamHostname")) == ("NATIVE_S3_PING",
                                                                             "pf-admin.alpha.example.test")


def test_which_store_backs_clients_and_grants(after):
    d, _ = after
    assert json.loads(one(get(d, STORAGE), "pingfedConfig")) == {
        "clients": {"implementation": "org.sourceid.oauth20.domain.ClientManagerJdbcImpl", "storage": "JDBC"},
        "grants": {"implementation": "org.sourceid.oauth20.token.AccessGrantManagerJdbcImpl", "storage": "JDBC"}}


def test_notices(after):
    _, notices = after
    assert {"pf-9.example.test: no PingFederate server in the record has this hostname or name; not imported",
            "node pf-admin.alpha.example.test: its secrets are withheld; set pingfedCredentialRole to the secret role "
            "that holds them"} <= set(notices)
    assert not any("discovers its cluster" in n for n in notices)        # S3, as alpha binds
    _, _, other = imported(files("azure.AZURE_PING"))
    assert {"node pf-1.alpha.example.test: discovers its cluster with AZURE_PING, a community JGroups extension "
            "(jgroups-azure) PingFederate doesn't document; choose one of TCPPING, NATIVE_S3_PING, DNS_PING for its "
            "environment",
            "node pf-1.alpha.example.test: discovers its cluster with AZURE_PING, but its environment's "
            "pf-cluster-discovery binding uses NATIVE_S3_PING (s3://alpha-pf-cluster/pf)"} <= set(other)
    _, _, unbound = imported(files("TCPPING"), discovery=False)
    assert "node pf-1.alpha.example.test: discovers its cluster with TCPPING, but its environment binds no " \
           "pf-cluster-discovery role: bind it, with pingfedDiscoveryProtocol TCPPING" in unbound


def test_jgroups_properties_names_the_protocol_on_pingfederate_11_and_later():
    d, _, notices = imported({**files(), **jgroups("DNS_PING")})
    assert (one(get(d, ENGINE), "pingfedDiscovery"), one(get(d, ADMIN), "pingfedDiscovery")) == \
        ("DNS_PING", "NATIVE_S3_PING")                                    # the admin node still has the tcp.xml element
    assert any(n.startswith("node pf-1.alpha.example.test: discovers its cluster with DNS_PING, but") for n in notices)


def test_importing_the_same_files_again_changes_nothing():
    d, _, _ = imported()
    assert preview_import(d, "pingfederate/node-files", files(), (ADAPTER,))[0] == ()


def _jgroups(d, env):
    return render_env(env_model(d, env), None)["pingfederate/cluster/jgroups.properties"].splitlines()[1:]


def test_discovery_renders_the_protocol_each_environment_chooses():
    d, _, _ = imported(extra=BETA_DNS)
    assert _jgroups(d, "alpha/prod") == [          # implied by its s3:// reference
        "pf.cluster.discovery.protocol=NATIVE_S3_PING", "pf.cluster.NATIVE_S3_PING.region_name=region-1",
        "pf.cluster.NATIVE_S3_PING.bucket_name=alpha-pf-cluster",
        "pf.cluster.NATIVE_S3_PING.remove_all_data_on_view_change=true",
        "pf.cluster.NATIVE_S3_PING.write_data_on_find=true"]
    assert _jgroups(d, "beta/prod") == ["pf.cluster.discovery.protocol=DNS_PING",
                                        "pf.cluster.DNS_PING.dns_query=pf-cluster.beta.example.test"]


def test_tcpping_lists_the_environments_clustered_nodes():
    d, _, _ = imported(extra=_chosen(ALPHA, "TCPPING"), discovery=False)
    assert _jgroups(d, "alpha/prod") == [
        "pf.cluster.discovery.protocol=TCPPING",
        "pf.cluster.TCPPING.initial_hosts=pf-1.alpha.example.test[7600],pf-admin.alpha.example.test[7600]",
        "pf.cluster.TCPPING.port_range=0"]


def test_a_protocol_pingfederate_does_not_support_is_not_rendered():
    d, _, _ = imported(extra=BETA_BLOB)
    assert _jgroups(d, "beta/prod") == [
        "# UNSUPPORTED:pf-cluster-discovery: AZURE_PING is a community JGroups extension (jgroups-azure) PingFederate "
        "doesn't document; choose pingfedDiscoveryProtocol (TCPPING, NATIVE_S3_PING, DNS_PING)"]


def plan(d, dst="beta/prod"):
    return check_cluster(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, dst), None, dt.date(2026, 10, 1),
                                     {}, {}, ()))


def test_the_planner_flags_a_change_of_protocol_an_unsupported_one_and_discovery_nobody_recorded():
    bare, _, _ = imported()
    assert [t for _, t, _ in plan(bare).blockers] == [         # alpha binds S3, beta nothing: the core check says so
        "PingFederate node `pf-admin` has withheld credentials but no credential role: nothing says which secret "
        "beta/prod gives it. Set pingfedCredentialRole."]
    dns, _, _ = imported(extra=BETA_DNS)
    assert [t for _, t, _, _ in plan(dns).actions] == [
        "PingFederate's cluster discovery changes from NATIVE_S3_PING (s3://alpha-pf-cluster/pf) to DNS_PING "
        "(pf-cluster.beta.example.test): put the lines of pingfederate/cluster/jgroups.properties in each node's "
        "bin/jgroups.properties."]
    assert plan(bare, "alpha/prod").ok == (
        "PingFederate's cluster discovery (NATIVE_S3_PING: s3://alpha-pf-cluster/pf) is bound in alpha/prod.",)
    blob, _, _ = imported(extra=BETA_BLOB)
    assert ("beta/prod's `pf-cluster-discovery` binding uses AZURE_PING, a community JGroups extension "
            "(jgroups-azure) PingFederate doesn't document: choose pingfedDiscoveryProtocol (TCPPING, NATIVE_S3_PING, "
            "DNS_PING).") in [t for _, t, _ in plan(blob).blockers]
    no_name, _, _ = imported(extra=_chosen(BETA, "DNS_PING"))
    assert "beta/prod's `pf-cluster-discovery` binding uses DNS_PING, which needs a DNS name (ciamFqdn)." in \
           [t for _, t, _ in plan(no_name).blockers]
    unrecorded, _, _ = imported(discovery=False)
    assert plan(unrecorded).blockers[0][1] == (
        "PingFederate's cluster (2 clustered node(s) in alpha/prod) has no recorded discovery, so nothing says how "
        "its members find each other in beta/prod: bind role `pf-cluster-discovery` in both and choose "
        "pingfedDiscoveryProtocol (TCPPING, NATIVE_S3_PING, DNS_PING).")
