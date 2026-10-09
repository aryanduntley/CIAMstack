"""The compute domain: host baselines per server role (truststore additions, pinned names), compute groups and
clusters as bindings a cloud reads, workloads (server roles run as containers) and the workload bindings that say how
an environment runs them on Kubernetes, their reports, and the planner's findings about what a target can't
reproduce, runs less safely, or leaves behind when a role moves between servers and Kubernetes."""
import datetime as dt
import re

from opsdir.connectors.stack import unsupported_products
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, one
from opsdir.core.environment import env_model
from opsdir.core.findings import findings
from opsdir.core.interchange.ldif import parse
from opsdir.core.inventory import environment_groups, resource
from opsdir.core.secrets import CORE_PATTERNS, scan
from opsdir.domains.compute.hosts import baseline_rows, check_hosts, compute_rows
from opsdir.domains.compute.naming import BASELINES, WORKLOAD_SECRET, WORKLOADS, baseline_dn, workload_dn
from opsdir.domains.compute.workloads import (all_compute_rows, check_workloads, product_versions, runs_on_kubernetes,
                                              runs_product, version_holders, workload_rows, workload_secrets)
from opsdir.domains.infrastructure.checks import check_versions
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


def _workload_binding(env, role="ds-workload"):
    return (f"dn: cn=ds,ou=bindings,{env}\nobjectClass: top\nobjectClass: ciamWorkloadBinding\ncn: ds\n"
            f"ciamBindingRole: {role}\nciamContainerImage: ds=registry.example.test/ds:7.5\nciamWorkloadReplicas: 3\n"
            "ciamCpuRequest: 500m\nciamMemoryRequest: 2Gi\nciamMemoryLimit: 4Gi\nciamStorageSize: 100Gi\n"
            "ciamStorageClass: fast\n")


def _cluster(env):
    return (f"dn: cn=k8s,ou=bindings,{env}\nobjectClass: top\nobjectClass: ciamCluster\ncn: k8s\n"
            "ciamBindingRole: k8s\nciamProviderRef: cluster-2\n")


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
    "ciamTargetRole: ds\nciamClusterRole: k8s\nciamNamespace: identity\nciamWorkloadRole: ds-workload\n"
    "ciamServiceAccount: ds\nciamIdentityRole: ds-identity\nciamPodSecurity: runAsNonRoot\n"
    "ciamPodSecurity: privileged\nciamWorkloadSecret: ds-passwords/admin <- ds-admin-password\n"
    "ciamSecretName: ds-env\n",
    _workload_binding(ALPHA)))


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


def test_weaker_target_compute_offers_fixes_that_clear_it():
    f = check_hosts(context(directory()))
    assert [(x.key, [r.mods for r in x.records]) for x in f.fixes] == [
        ("metadata-tokens:web-group", [(("replace", "ciamMetadataTokens", ("TRUE",)),)]),
        ("max-size:web-group", [(("replace", "ciamMaxSize", ("3",)),)])]
    fixed = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + RECORDS)),
                            tuple(r for x in f.fixes for r in x.records))
    after = check_hosts(context(fixed))
    assert after.fixes == () and not any("session tokens" in t or "scales to" in t for _, t, _, _ in after.actions)


def test_nothing_is_asked_of_a_record_without_baselines_or_compute():
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    assert check_hosts(context(d)) == check_workloads(context(d)) == findings()


def test_the_workloads_report_and_what_the_target_cant_run():
    (row,) = workload_rows(directory())
    assert row == ("ds", "statefulset", "ds", "k8s", "identity", "ds-workload", "ds-identity (as ds)",
                   "runAsNonRoot, privileged", "", "ds-passwords/admin <- ds-admin-password, ds-env", "")
    assert workload_secrets(get(directory(), workload_dn("ds"))) == (("ds-passwords", "admin", "ds-admin-password"),)
    f = check_workloads(context(directory()))
    assert [t for _, t, _ in f.blockers] == [
        "Workload `ds` runs role `ds` on Kubernetes in alpha/prod; beta/prod neither runs it there (workload role "
        "`ds-workload`, cluster `k8s`) nor has servers of the role.",
        "Workload `ds` assumes the identity of role `ds-identity`, which neither alpha/prod nor beta/prod binds: "
        "record the identity each environment gives it.",
        "Workload `ds` reads Secret keys filled from role(s) 'ds-admin-password', which neither alpha/prod nor "
        "beta/prod binds: record where each secret is kept."]
    assert [t for _, t, _, _ in f.actions] == [
        "Workload `ds` runs privileged containers: what they can reach on their nodes isn't in the record. Drop the "
        "privilege or record why it is needed."]


def test_the_compute_report_lists_each_environments_workload_bindings():
    rows = all_compute_rows(directory())
    assert ("alpha/prod", "ds", "ds-workload", "workload ds (ds)", "ds=registry.example.test/ds:7.5",
            "cpu 500m/-, memory 2Gi/4Gi 100Gi (fast)", "3", "", "") in rows
    assert [r for r in rows if r[1] != "ds"] == compute_rows(directory())    # groups and clusters in their order
    assert [r[0] for r in rows] == ["alpha/prod"] * 3 + ["beta/prod"]            # each environment's rows together


def test_a_target_running_the_role_on_servers_has_somewhere_to_run_it():
    f = check_workloads(context(directory(_server(BETA, "ds-b1", "ds"))))
    assert not any("neither runs it there" in t for _, t, _ in f.blockers)
    assert "Role `ds` moves from Kubernetes in alpha/prod to servers in beta/prod (workload `ds`): its image, " \
           "resources and secrets must be rebuilt as a host baseline and service units." in \
           [t for _, t, _, _ in f.actions]


def test_a_target_running_the_workload_needs_its_cluster():
    d = directory(_workload_binding(BETA))
    assert runs_on_kubernetes(env_model(d, "beta/prod"), get(d, workload_dn("ds")))
    f = check_workloads(context(d))
    assert "beta/prod runs workload `ds` on Kubernetes but binds no cluster for it (cluster role `k8s`)." in \
        [t for _, t, _ in f.blockers]
    f = check_workloads(context(directory(_workload_binding(BETA) + "\n" + _cluster(BETA))))
    assert not any("ds` on Kubernetes" in t or "neither runs it there" in t for _, t, _ in f.blockers)


def test_a_role_moving_from_servers_to_kubernetes_must_carry_its_baseline():
    web = (f"dn: {workload_dn('web')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: web\n"
           "ciamWorkloadKind: deployment\nciamTargetRole: web\nciamClusterRole: k8s\nciamWorkloadRole: web-workload\n")
    d = directory("\n".join((web, _workload_binding(BETA, "web-workload").replace("cn=ds,", "cn=web,")
                             .replace("cn: ds\n", "cn: web\n"), _cluster(BETA))))
    assert "Role `web` moves from servers in alpha/prod to Kubernetes in beta/prod (workload `web`): what its host " \
           "baseline adds (truststore, limits, kernel settings, agents) must be built into the image or the pod " \
           "spec." in [t for _, t, _, _ in check_workloads(context(d)).actions]


def test_a_product_run_on_kubernetes_has_its_version_on_the_workload_binding():
    binding = _workload_binding(BETA).replace("ciamStorageClass: fast\n", "ciamStorageClass: fast\n"
                                                                           "ciamProductVersion: PingDS 8.0.1\n")
    d = directory(binding + "\n" + _cluster(BETA))
    beta, alpha = env_model(d, "beta/prod"), env_model(d, "alpha/prod")
    assert product_versions(beta) == ("PingDS 8.0.1",) and runs_product(beta, ("PingDS",))     # no servers of it
    assert not runs_product(alpha, ("PingDS",))
    assert version_holders(beta) == (("workload ds on Kubernetes", "PingDS 8.0.1"),)
    ds7 = mini_estate.FAKE._replace(name="ds7", products=(("PingDS", ">=7,<8"),))
    assert unsupported_products(beta, (ds7,)) == (("workload ds on Kubernetes", ds7, "PingDS 8.0.1", ">=7,<8"),)
    assert unsupported_products(beta, (ds7._replace(products=(("PingDS", ">=7,<9"),)),)) == ()
    unversioned = directory(_workload_binding(BETA) + "\n" + _cluster(BETA))
    (action,) = [t for _, t, _, _ in check_versions(context(unversioned)).actions]
    assert action.startswith("No product version recorded for") and "beta/prod workload ds" in action


def test_a_workload_without_a_workload_role_runs_where_its_cluster_is_bound():
    legacy = (f"dn: {workload_dn('old')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: old\n"
              "ciamWorkloadKind: deployment\nciamTargetRole: old\nciamClusterRole: k8s\n")
    d = directory(legacy)
    w = get(d, workload_dn("old"))
    assert runs_on_kubernetes(env_model(d, "alpha/prod"), w) and not runs_on_kubernetes(env_model(d, "beta/prod"), w)


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


def test_a_workload_secret_named_like_a_password_is_not_taken_for_one():
    value = "pf-admin/PING_IDENTITY_PASSWORD <- pf-admin-password"      # the store refuses what the scan finds
    assert scan(value, CORE_PATTERNS) == () and re.match(WORKLOAD_SECRET, value)
    assert scan(value.replace(" <- ", "="), CORE_PATTERNS) == ("secret-assignment",)   # why the form isn't key=role
