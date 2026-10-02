"""Azure compute: virtual machine scale sets read as compute groups (the server role they run, SKU, instances, zones,
image, min/max from the autoscale setting that targets them) and AKS clusters as clusters (version, enabled add-ons,
node pools), from Terraform state."""
import json

from opsdir_adapter_azure.inventory import state_resources

RG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers"
VMSS = f"{RG}/Microsoft.Compute/virtualMachineScaleSets/vmss-pf"
AKS = f"{RG}/Microsoft.ContainerService/managedClusters/aks-ciam"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("azurerm_linux_virtual_machine_scale_set", "pf", {
        "id": VMSS, "name": "vmss-pf", "sku": "Standard_D4s_v5", "instances": 2, "zones": ["1", "2", "3"],
        "source_image_id": f"{RG}/Microsoft.Compute/images/pf-2026-09", "tags": {"Role": "pf"}}),
    ("azurerm_monitor_autoscale_setting", "pf", {"target_resource_id": VMSS.lower(),
                                                 "profile": [{"capacity": [{"minimum": 2, "maximum": 6,
                                                                            "default": 2}]}]}),
    ("azurerm_kubernetes_cluster", "aks", {
        "id": AKS, "name": "aks-ciam", "kubernetes_version": "1.30.3", "azure_policy_enabled": True,
        "workload_identity_enabled": True, "oidc_issuer_enabled": True, "oms_agent": [],
        "key_vault_secrets_provider": [{"secret_rotation_enabled": True}],
        "default_node_pool": [{"name": "system", "vm_size": "Standard_D2s_v5", "min_count": 2, "max_count": 3,
                               "zones": ["1", "2"]}], "tags": {"BindingRole": "k8s"}}),
    ("azurerm_kubernetes_cluster_node_pool", "ds", {"kubernetes_cluster_id": AKS, "name": "ds",
                                                   "vm_size": "Standard_E4s_v5", "node_count": 3, "zones": ["3"]}))


def _by_kind(kind):
    resources, _ = state_resources(STATE)
    return {r.ref: r for r in resources if r.kind == kind}


def test_a_scale_set_is_a_compute_group_with_its_autoscale_capacity():
    pf = _by_kind("compute")[VMSS]
    assert (pf.name, pf.role) == ("vmss-pf", "compute-pf")
    assert pf.attrs == {"ciamTargetRole": ("pf",), "ciamImageRef": (f"{RG}/Microsoft.Compute/images/pf-2026-09",),
                        "ciamInstanceSize": ("Standard_D4s_v5",), "ciamMinSize": ("2",), "ciamMaxSize": ("6",),
                        "ciamDesiredSize": ("2",), "ciamSpansZone": ("1", "2", "3")}


def test_an_aks_cluster_with_its_pools_and_enabled_addons():
    aks = _by_kind("cluster")[AKS]
    assert (aks.name, aks.role) == ("aks-ciam", "k8s")
    assert aks.attrs == {"ciamClusterVersion": ("1.30.3",),
                         "ciamClusterAddon": ("azure-policy", "key-vault-secrets-provider", "oidc-issuer",
                                              "workload-identity"),
                         "ciamNodePool": ("ds: Standard_E4s_v5, 3-3", "system: Standard_D2s_v5, 2-3"),
                         "ciamSpansZone": ("1", "2", "3")}
