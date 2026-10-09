"""Google Cloud for Kubernetes workloads: the GKE workload identity annotation (the service account's email from the
binding or the project) and how External Secrets and the Google CSI provider read gcp-sm:// references."""
from types import SimpleNamespace

import yaml

from opsdir.core.directory import make_entry
from opsdir_adapter_gcp.kubernetes import SECRET_DELIVERY, service_account_email
from opsdir.core.directory import get
from opsdir.domains.compute.naming import WORKLOADS
from opsdir_adapter_gcp.terraform import _firewall_rule, _service
from network_fixtures import ALPHA, entry, model, rule

M = SimpleNamespace(cloud=make_entry("cloud=standby,ou=environments,dc=ciam-ops", ("top", "ciamCloud"),
                                     {"ciamCloudProvider": ("gcp",), "ciamAccountRef": ("ciam-standby",)}))
CLUSTER = make_entry("cn=gke,ou=bindings,env=prod,cloud=standby,ou=environments,dc=ciam-ops", ("top", "ciamCluster"),
                     {"ciamBindingRole": ("cluster",),
                      "ciamProviderRef": ("projects/ciam-standby/locations/us-east4/clusters/gke-ciam",)})


def _binding(ref):
    return make_entry("cn=identity-am,ou=bindings,env=prod,cloud=standby,ou=environments,dc=ciam-ops",
                      ("top", "ciamIdentityBinding"), {"ciamBindingRole": ("identity-am",), "ciamProviderRef": (ref,)})


def test_the_service_account_email():
    assert service_account_email(M, _binding("am@ciam-standby.iam.gserviceaccount.com")) == \
        "am@ciam-standby.iam.gserviceaccount.com"
    assert service_account_email(M, _binding("ciam-prod-am")) == "ciam-prod-am@ciam-standby.iam.gserviceaccount.com"


def test_secret_manager_through_external_secrets_and_csi():
    d = SECRET_DELIVERY["gcp-sm"]
    regional = "projects/ciam-standby/locations/us-east4/secrets/am-admin"
    assert (d.store_key("projects/ciam-standby/secrets/am-admin"), d.store_key(regional)) == \
        ("ciam-standby", "ciam-standby/us-east4")
    gcpsm = d.eso_provider(M, None, "ciam-standby/us-east4", "am", CLUSTER)["gcpsm"]
    assert (gcpsm["projectID"], gcpsm["location"], gcpsm["auth"]["workloadIdentity"]) == (
        "ciam-standby", "us-east4", {"clusterLocation": "us-east4", "clusterName": "gke-ciam",
                                     "serviceAccountRef": {"name": "am"}})
    assert d.eso_provider(M, None, "ciam-standby", "am", None)["gcpsm"]["auth"]["workloadIdentity"]["clusterName"] \
        == "UNBOUND:gke-cluster-name"
    assert d.eso_ref(regional) == {"key": "am-admin", "version": "latest"}
    params = d.csi_parameters(M, None, "ciam-standby", (("admin", regional),), None)
    assert d.csi_provider == "gcp" and yaml.safe_load(params["secrets"]) == \
        [{"resourceName": regional + "/versions/latest", "path": "admin"}]


def test_a_role_run_only_on_kubernetes_gets_notes_not_a_load_balancer_or_rules():
    tree = (f"dn: {WORKLOADS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: workloads\n",
            entry(WORKLOADS, "am", "ciamWorkload", ciamWorkloadKind="deployment", ciamTargetRole="am",
                  ciamClusterRole="k8s", ciamWorkloadRole="am-workload"))
    alpha = (entry(ALPHA, "k8s", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef="cluster-1"),
             entry(ALPHA, "am", "ciamWorkloadBinding", ciamBindingRole="am-workload"),
             entry(ALPHA, "svc-login", "ciamServiceName", ciamBindingRole="am-service", ciamFqdn="login.example.test",
                   ciamTargetRole="am", ciamPort="443", ciamFrontendIp="198.51.100.9"),
             rule(ALPHA, "fw-login", "0.0.0.0/0", "443", "am"))
    _, m, _ = model(alpha=alpha, tree=tree)
    svc, fw = (get(m.d, f"cn={cn},ou=bindings,{ALPHA}") for cn in ("svc-login", "fw-login"))
    out = "\n".join((*_service(m, svc), *_firewall_rule(m, fw, 100, True)))
    assert "# NOTE: service name `svc-login` (login.example.test) reaches role `am`, which runs only on " \
           "Kubernetes" in out
    assert "# NOTE: firewall rule `fw-login` reaches role `am`, which runs only on Kubernetes" in out
    assert "resource" not in out
