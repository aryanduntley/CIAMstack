"""The compute domain: host baselines per server role (truststore additions, pinned names), compute groups and
clusters as bindings a cloud reads, workloads (server roles run as containers), their reports, and the planner's
findings about what a target can't reproduce or runs less safely."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.directory import one
from opsdir.core.environment import env_model
from opsdir.core.findings import findings
from opsdir.core.interchange.ldif import parse
from opsdir.core.inventory import environment_groups, resource
from opsdir.domains.compute.hosts import baseline_rows, check_hosts, compute_rows
from opsdir.domains.compute.naming import BASELINES, WORKLOADS, baseline_dn, workload_dn
from opsdir.domains.compute.workloads import check_workloads, workload_rows
import mini_estate
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
CA = "cn=partner-root-ca,ou=certificates,dc=ciam-ops"
UNKNOWN = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"


def _server(env, cn, role):
    return (f"dn: cn={cn},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: {role}\n"
            f"ciamHostname: {cn}.example.test\nciamSubnet: cn=net,ou=bindings,{env}\n")


def _group(env, cn, role, extra):
    return (f"dn: cn={cn},ou=bindings,{env}\nobjectClass: top\nobjectClass: ciamComputeGroup\ncn: {cn}\n"
            f"ciamBindingRole: {cn}\nciamTargetRole: {role}\nciamProviderRef: ref-{cn}\n{extra}")


RECORDS = "\n".join((
    "dn: ou=certificates,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: certificates\n",
    f"dn: {CA}\nobjectClass: top\nobjectClass: ciamCertificate\ncn: partner-root-ca\n"
    "ciamFingerprint: 11:22:33\nciamNotAfter: 20260920000000Z\nciamCertPurpose: ca\n",
    _server(ALPHA, "web-1", "web"), _server(ALPHA, "app-1", "app"), _server(BETA, "web-b1", "web"),
    _server(BETA, "app-b1", "app"),
    f"dn: {BASELINES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: baselines\n",
    f"dn: {baseline_dn('web')}\nobjectClass: top\nobjectClass: ciamHostBaseline\ncn: web\nciamTargetRole: web\n"
    f"ciamOs: rhel 9.4\nciamJdk: temurin 17.0.11\nciamTrustsCertificate: {CA}\nciamTrustedFingerprint: {UNKNOWN}\n"
    "ciamOsLimit: ds soft nofile 65536\nciamKernelSetting: net.core.somaxconn=4096\nciamHugePages: never\n"
    "ciamFipsMode: FALSE\nciamHostAgent: falcon-sensor 7.10\nciamPinnedHost: 10.1.9.9 legacy-db.internal\n"
    f"ciamFoundOn: cn=web-1,{ALPHA}\n",
    _group(ALPHA, "web-group", "web", "ciamImageRef: img-1\nciamInstanceSize: m6i.large\nciamMinSize: 2\n"
           "ciamDesiredSize: 3\nciamMaxSize: 6\nciamSpansZone: a\nciamSpansZone: b\nciamSpansZone: c\n"
           "ciamMetadataTokens: TRUE\n"),
    _group(BETA, "web-group", "web", "ciamMaxSize: 2\nciamSpansZone: a\nciamMetadataTokens: FALSE\n"),
    f"dn: cn=k8s,ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: ciamCluster\ncn: k8s\nciamBindingRole: k8s\n"
    "ciamProviderRef: cluster-1\nciamClusterVersion: 1.30\nciamClusterAddon: vpc-cni v1.18\n"
    "ciamNodePool: system: m6i.large, 2-4\n",
    f"dn: {WORKLOADS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: workloads\n",
    f"dn: {workload_dn('ds')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: ds\nciamWorkloadKind: statefulset\n"
    "ciamTargetRole: ds\nciamClusterRole: k8s\nciamNamespace: identity\nciamReplicaCount: 3\n"
    "ciamContainerImage: registry.example.test/ds:7.5\nciamStorageSize: 100Gi\nciamStorageClass: fast\n"
    "ciamServiceAccount: ds\nciamIdentityRole: ds-identity\nciamPodSecurity: runAsNonRoot\n"
    "ciamPodSecurity: privileged\nciamSecretName: ds-passwords\n"))


def directory(extra=""):
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + RECORDS + "\n" + extra)))


def context(d, src="alpha/prod", dst="beta/prod"):
    return PlanContext(d, env_model(d, src), env_model(d, dst), None, dt.date(2026, 10, 1), {}, {}, ())


def test_the_baselines_report():
    (row,) = baseline_rows(directory())
    assert row == ("web", "rhel 9.4", "temurin 17.0.11", "partner-root-ca, 1 not recorded", "ds soft nofile 65536",
                   "net.core.somaxconn=4096", "never", "no", "", "falcon-sensor 7.10", "",
                   "10.1.9.9 legacy-db.internal", "web-1")


def test_the_compute_report_lists_groups_and_clusters_in_every_environment():
    rows = compute_rows(directory())
    assert rows == [
        ("alpha/prod", "k8s", "k8s", "kubernetes 1.30", "vpc-cni v1.18", "system: m6i.large, 2-4", "", "", ""),
        ("alpha/prod", "web-group", "web-group", "servers: web", "img-1", "m6i.large", "2/3/6", "a, b, c", "yes"),
        ("beta/prod", "web-group", "web-group", "servers: web", "", "", "?/?/2", "a", "no")]


def test_the_planner_names_what_a_rebuild_loses_and_weaker_target_compute():
    f = check_hosts(context(directory()))
    assert not f.blockers
    assert [t for _, t, _, _ in f.actions] == [
        "Servers of role `web` trust 1 certificate(s) in their Java truststore that the record doesn't hold "
        "(AB:CD:EF:01:23:45:67:89…): record them, or a server rebuilt from a stock image loses them silently.",
        "Servers of role `web` pin 1 name(s) in /etc/hosts (10.1.9.9 legacy-db.internal): pinned addresses don't "
        "move with the platform. Replace them with names beta/prod resolves.",
        "Server role `app` has no host baseline: what its servers run beyond the product (Java truststore "
        "additions, limits, agents) isn't recorded, so servers built for beta/prod can't be checked against the "
        "source's.",
        "Compute group `web-group` (role `web`) in beta/prod lets the instance metadata service answer without "
        "session tokens: a request forged through a server reads its credentials. Require session tokens.",
        "Compute group `web-group` (role `web`) in beta/prod spans 1 zone(s); alpha/prod spreads the role over 3.",
        "Compute group `web-group` (role `web`) in beta/prod scales to at most 2 instance(s); alpha/prod runs 3."]


def test_nothing_is_asked_of_a_record_without_baselines_or_compute():
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    assert check_hosts(context(d)) == check_workloads(context(d)) == findings()


def test_the_workloads_report_and_what_the_target_cant_run():
    (row,) = workload_rows(directory())
    assert row == ("ds", "statefulset", "ds", "k8s", "identity", "3", "registry.example.test/ds:7.5",
                   "100Gi (fast)", "ds-identity (as ds)", "runAsNonRoot, privileged", "", "ds-passwords", "")
    f = check_workloads(context(directory()))
    assert [t for _, t, _ in f.blockers] == [
        "Workload `ds` runs role `ds` in alpha/prod's cluster (`k8s`); beta/prod binds no cluster for it and has no "
        "servers of the role.",
        "Workload `ds` assumes the identity of role `ds-identity`, which neither alpha/prod nor beta/prod binds: "
        "record the identity each environment gives it."]
    assert [t for _, t, _, _ in f.actions] == [
        "Workload `ds` runs privileged containers: what they can reach on their nodes isn't in the record. Drop the "
        "privilege or record why it is needed."]


def test_a_target_running_the_role_on_servers_has_somewhere_to_run_it():
    f = check_workloads(context(directory(_server(BETA, "ds-b1", "ds"))))
    assert not any("binds no cluster" in t for _, t, _ in f.blockers)


def test_compute_groups_and_clusters_are_bindings_a_cloud_reads():
    d = directory()
    groups, notices = environment_groups(d, "beta/prod", (
        resource("compute", "asg-web", {"ciamTargetRole": "web", "ciamMaxSize": "4", "ciamSpansZone": ("a", "b")},
                 name="web-asg", role="web-asg"),
        resource("cluster", "aks-1", {"ciamClusterVersion": "1.30"}, name="aks", role="k8s"),
        resource("compute", "asg-untagged", {"ciamTargetRole": "web"}, name="untagged")))
    placed = {dn: e for dn, (e,) in groups}
    asg, aks = placed[f"cn=web-asg,ou=bindings,{BETA}"], placed[f"cn=aks,ou=bindings,{BETA}"]
    assert (asg.classes, one(asg, "ciamProviderRef"), asg.attrs["ciamSpansZone"]) == \
        (("top", "ciamComputeGroup"), "asg-web", ("a", "b"))
    assert (aks.classes, one(aks, "ciamBindingRole"), one(aks, "ciamClusterVersion")) == \
        (("top", "ciamCluster"), "k8s", "1.30")
    assert any("untagged" in n for n in notices)
