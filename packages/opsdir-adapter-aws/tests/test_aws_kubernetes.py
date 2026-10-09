"""AWS for Kubernetes workloads: the IAM role a service account assumes (IRSA annotation) from the identity binding and
the recorded account, and how External Secrets and the Secrets Store CSI driver read aws-sm:// references."""
from types import SimpleNamespace

import yaml

from opsdir.core.directory import make_entry
from opsdir_adapter_aws.kubernetes import SECRET_DELIVERY, role_arn, workload_identity
from opsdir.core.directory import get
from opsdir.domains.compute.naming import WORKLOADS
from opsdir_adapter_aws.terraform import _ingress_rules, _service
from network_fixtures import ALPHA, entry, model, rule

CLOUD = make_entry("cloud=aws,ou=environments,dc=ciam-ops", ("top", "ciamCloud"),
                   {"ciamCloudProvider": ("aws",), "ciamRegion": ("us-east-1",), "ciamAccountRef": ("111122223333",)})
M = SimpleNamespace(cloud=CLOUD)


def _binding(ref):
    return make_entry("cn=identity-am,ou=bindings,env=prod,cloud=aws,ou=environments,dc=ciam-ops",
                      ("top", "ciamIdentityBinding"), {"ciamBindingRole": ("identity-am",), "ciamProviderRef": (ref,)})


def test_the_role_arn_from_the_ref_or_the_account():
    assert role_arn(M, _binding("arn:aws:iam::999:role/am")) == "arn:aws:iam::999:role/am"
    assert workload_identity(M, _binding("ciam-prod-am")).annotations == \
        (("eks.amazonaws.com/role-arn", "arn:aws:iam::111122223333:role/ciam-prod-am"),)
    no_account = SimpleNamespace(cloud=make_entry(CLOUD.dn, CLOUD.classes, {"ciamRegion": ("us-east-1",)}))
    assert role_arn(no_account, _binding("ciam-prod-am")) == "UNBOUND:identity-am-role-arn"


def test_secrets_manager_through_external_secrets_and_csi():
    d = SECRET_DELIVERY["aws-sm"]
    arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:ciam/am-admin-AbCdEf"
    assert (d.store_key("ciam/am/admin"), d.store_key(arn)) == ("", "us-west-2")
    assert d.eso_provider(M, None, "", "am", None) == {"aws": {
        "service": "SecretsManager", "region": "us-east-1", "auth": {"jwt": {"serviceAccountRef": {"name": "am"}}}}}
    assert d.eso_ref("ciam/am/admin") == {"key": "ciam/am/admin"}
    params = d.csi_parameters(M, None, "us-west-2", (("admin", arn),), None)
    assert (d.csi_provider, params["region"], params["usePodIdentity"]) == ("aws", "us-west-2", "false")
    assert yaml.safe_load(params["objects"]) == [{"objectName": arn, "objectType": "secretsmanager",
                                                  "objectAlias": "admin"}]


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
    out = "\n".join((*_service(m, svc), *_ingress_rules(m, fw)))
    assert "# NOTE: service name `svc-login` (login.example.test) reaches role `am`, which runs only on " \
           "Kubernetes" in out
    assert "# NOTE: firewall rule `fw-login` reaches role `am`, which runs only on Kubernetes" in out
    assert "resource" not in out
