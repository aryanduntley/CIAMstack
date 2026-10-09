"""Azure for Kubernetes workloads: AKS workload identity (client id from the identity binding, tenant from the cloud,
the use label on pods) and how External Secrets and the Key Vault CSI provider read azkv:// references, in Azure and
in Azure Government."""
from types import SimpleNamespace

import yaml

from opsdir.core.directory import make_entry
from opsdir_adapter_azure.kubernetes import SECRET_DELIVERY, workload_identity
from opsdir.core.directory import get
from opsdir.domains.compute.naming import WORKLOADS
from opsdir_adapter_azure.terraform import _security_rule, _service
from network_fixtures import ALPHA, entry, model, rule

TENANT = "7e1d0000-0000-4000-8000-000000000001"


def _m(environment="public", tenant=TENANT):
    return SimpleNamespace(cloud=make_entry("cloud=target,ou=environments,dc=ciam-ops", ("top", "ciamCloud"), {
        "ciamCloudProvider": ("azure",), "ciamCloudEnvironment": (environment,),
        **({"ciamOrganizationRef": (tenant,)} if tenant else {})}))


def _binding(client=None):
    return make_entry("cn=identity-am,ou=bindings,env=prod,cloud=target,ou=environments,dc=ciam-ops",
                      ("top", "ciamIdentityBinding"),
                      {"ciamBindingRole": ("identity-am",), "ciamProviderRef": ("/subscriptions/s/x/id-am",),
                       **({"ciamIdentityClientId": (client,)} if client else {})})


def test_workload_identity_names_the_client_and_tenant():
    i = workload_identity(_m(), _binding("c1d2"))
    assert i.annotations == (("azure.workload.identity/client-id", "c1d2"),
                             ("azure.workload.identity/tenant-id", TENANT))
    assert i.pod_labels == (("azure.workload.identity/use", "true"),)
    assert workload_identity(_m(tenant=None), _binding()).annotations == \
        (("azure.workload.identity/client-id", "UNBOUND:identity-am-client-id"),)


def test_key_vault_through_external_secrets_and_csi_in_each_cloud():
    d = SECRET_DELIVERY["azkv"]
    assert (d.store_key("kv-ciam-prod/am-admin") == "kv-ciam-prod"
            and d.eso_ref("kv-ciam-prod/am-admin") == {"key": "am-admin"})
    public = d.eso_provider(_m(), None, "kv-ciam-prod", "am", None)["azurekv"]
    gov = d.eso_provider(_m("usgovernment"), None, "kv-ciam-prod", "am", None)["azurekv"]
    assert (public["vaultUrl"], public["environmentType"], public["tenantId"]) == \
        ("https://kv-ciam-prod.vault.azure.net", "PublicCloud", TENANT)
    assert (gov["vaultUrl"], gov["environmentType"], gov["authType"]) == \
        ("https://kv-ciam-prod.vault.usgovcloudapi.net", "USGovernmentCloud", "WorkloadIdentity")
    params = d.csi_parameters(_m("usgovernment"), None, "kv-ciam-prod", (("admin", "kv-ciam-prod/am-admin"),),
                              _binding("c1d2"))
    assert (d.csi_provider, params["keyvaultName"], params["clientID"], params["cloudName"]) == \
        ("azure", "kv-ciam-prod", "c1d2", "AzureUSGovernmentCloud")
    (obj,) = yaml.safe_load(params["objects"])["array"]
    assert yaml.safe_load(obj) == {"objectName": "am-admin", "objectType": "secret", "objectAlias": "admin"}


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
    out = "\n".join((*_service(m, svc), *_security_rule(m, fw, 100, True)))
    assert "# NOTE: service name `svc-login` (login.example.test) reaches role `am`, which runs only on " \
           "Kubernetes" in out
    assert "# NOTE: firewall rule `fw-login` reaches role `am`, which runs only on Kubernetes" in out
    assert "resource" not in out
