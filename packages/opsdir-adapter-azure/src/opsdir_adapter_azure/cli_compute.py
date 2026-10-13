"""The Azure CLI's virtual machine scale sets and autoscale settings (and an ARM template's, read the same way:
properties flattened), normalized to the attribute names of the matching hashicorp/azurerm resources (inventory reads
compute groups from them, volumes a scale set's disks). Pure.

  az vmss list                    Microsoft.Compute/virtualMachineScaleSets -> azurerm_linux_virtual_machine_scale_set
                                  (azurerm_windows_virtual_machine_scale_set when its OS profile is Windows's,
                                  azurerm_orchestrated_virtual_machine_scale_set when its orchestration is Flexible):
                                  size and instance count (its sku), zones, image, OS and data disks, tags
  az monitor autoscale list       Microsoft.Insights/autoscalesettings -> azurerm_monitor_autoscale_setting (its target
                                  and each profile's capacity)
  az aks list                     Microsoft.ContainerService/managedClusters -> azurerm_kubernetes_cluster: version,
                                  enabled add-ons (addonProfiles by azurerm's keys, OIDC issuer, workload identity,
                                  Defender), its first System pool as the default node pool, every other pool in its
                                  agentPoolProfiles as azurerm_kubernetes_cluster_node_pool
  az aks nodepool list            Microsoft.ContainerService/managedClusters/agentPools -> its node pools (an ARM
                                  template's separate pools); a pool listed both ways is read once
"""

import re

SCALE_SETS = "microsoft.compute/virtualmachinescalesets"
AUTOSCALE = "microsoft.insights/autoscalesettings"
CLUSTERS = "microsoft.containerservice/managedclusters"
POOLS = "microsoft.containerservice/managedclusters/agentpools"
READ = (SCALE_SETS, AUTOSCALE, CLUSTERS, POOLS)       # what an ARM template's reader reads of these
# addonProfiles keys as azurerm names them (internal/services/containers/kubernetes_addons.go), by its arguments
ADDON_PROFILES = (("azurepolicy", "azure_policy_enabled", True), ("omsagent", "oms_agent", False),
                  ("azurekeyvaultsecretsprovider", "key_vault_secrets_provider", False),
                  ("ingressapplicationgateway", "ingress_application_gateway", False),
                  ("httpapplicationrouting", "http_application_routing_enabled", True),
                  ("openservicemesh", "open_service_mesh_enabled", True))
_AGENT_POOLS = re.compile(r"/agentPools/(?=[^/]+$)", re.IGNORECASE)


def _id(o):
    return (o or {}).get("id") if isinstance(o, dict) else o


def _size(d):
    return d.get("diskSizeGB") or d.get("diskSizeGb")


def _kind(s):
    profile = (s.get("virtualMachineProfile") or {}).get("osProfile") or {}
    return ("azurerm_orchestrated_virtual_machine_scale_set" if s.get("orchestrationMode") == "Flexible" else
            "azurerm_windows_virtual_machine_scale_set" if profile.get("windowsConfiguration") else
            "azurerm_linux_virtual_machine_scale_set")


def _number(v):
    return int(v) if isinstance(v, str) and v.isdigit() else v


def _scale_set(s):
    storage = (s.get("virtualMachineProfile") or {}).get("storageProfile") or {}
    image, osd = storage.get("imageReference") or {}, storage.get("osDisk") or {}
    managed = osd.get("managedDisk") or {}
    return (_kind(s), {
        "id": s.get("id"), "name": s.get("name"), "location": s.get("location"),
        "sku": (s.get("sku") or {}).get("name"), "instances": _number((s.get("sku") or {}).get("capacity")),
        "zones": s.get("zones") or [], "tags": s.get("tags") or {},
        "source_image_id": image.get("id"),
        "source_image_reference": [] if image.get("id") or not image.get("offer") else [
            {k: image.get(k) for k in ("publisher", "offer", "sku", "version")}],
        "os_disk": [{"disk_size_gb": _size(osd), "storage_account_type": managed.get("storageAccountType"),
                     "disk_encryption_set_id": _id(managed.get("diskEncryptionSet"))}] if osd else [],
        "data_disk": [{"lun": d.get("lun"), "disk_size_gb": _size(d),
                       "storage_account_type": (d.get("managedDisk") or {}).get("storageAccountType"),
                       "disk_iops_read_write": d.get("diskIOPSReadWrite") or d.get("diskIopsReadWrite"),
                       "disk_mbps_read_write": d.get("diskMBpsReadWrite") or d.get("diskMbpsReadWrite"),
                       "disk_encryption_set_id": _id((d.get("managedDisk") or {}).get("diskEncryptionSet"))}
                      for d in storage.get("dataDisks") or ()]})


def _autoscale(a):
    return ("azurerm_monitor_autoscale_setting", {
        "id": a.get("id"), "name": a.get("name"), "target_resource_id": a.get("targetResourceUri"),
        "profile": [{"name": p.get("name"), "capacity": [{k: _number((p.get("capacity") or {}).get(k))
                                                          for k in ("default", "minimum", "maximum")}]}
                    for p in a.get("profiles") or ()]})


def _pool(p, cluster_id=None):
    """A node pool's azurerm attributes (min and max only when it autoscales, as azurerm keeps them)."""
    scaling = p.get("enableAutoScaling") is True
    return {**({"kubernetes_cluster_id": cluster_id} if cluster_id else {}), "name": p.get("name"),
            "vm_size": p.get("vmSize"), "node_count": _number(p.get("count")),
            "min_count": _number(p.get("minCount")) if scaling else None,
            "max_count": _number(p.get("maxCount")) if scaling else None,
            "zones": [str(z) for z in p.get("availabilityZones") or ()], "vnet_subnet_id": p.get("vnetSubnetId"),
            "mode": p.get("mode")}


def _on(o):
    return isinstance(o, dict) and o.get("enabled") is True


def _cluster(c, separate):
    """azurerm_kubernetes_cluster with its default node pool, and the other pools as their own resources; separate:
    the names of the pools listed on their own (read from there)."""
    inline = [p for p in c.get("agentPoolProfiles") or () if isinstance(p, dict) and p.get("name") not in separate]
    default = next((p for p in inline if p.get("mode") == "System"), inline[0] if inline else None)
    addons = {str(k).lower(): v for k, v in (c.get("addonProfiles") or {}).items()}
    security = c.get("securityProfile") or {}
    return [("azurerm_kubernetes_cluster", {
                "id": c.get("id"), "name": c.get("name"),
                "kubernetes_version": c.get("kubernetesVersion") or c.get("currentKubernetesVersion"),
                "default_node_pool": [_pool(default)] if default else [], "tags": c.get("tags") or {},
                **{arg: (_on(addons.get(key)) if flag else [{}] if _on(addons.get(key)) else [])
                   for key, arg, flag in ADDON_PROFILES},
                "oidc_issuer_enabled": _on(c.get("oidcIssuerProfile")),
                "workload_identity_enabled": _on(security.get("workloadIdentity")),
                "microsoft_defender": [{}] if _on((security.get("defender") or {}).get("securityMonitoring")) else []}),
            *(("azurerm_kubernetes_cluster_node_pool", _pool(p, c.get("id"))) for p in inline if p is not default)]


def _cluster_id(pool_id):
    """The cluster a pool's ID is under, else None."""
    parts = _AGENT_POOLS.split(pool_id or "")
    return parts[0] if len(parts) == 2 else None


def _clusters(items):
    pools = [(p, _cluster_id(p.get("id"))) for k, p in items if k == POOLS]

    def separate(cluster_id):
        return {p.get("name") for p, owner in pools if owner and owner.lower() == (cluster_id or "").lower()}
    return [*(x for k, c in items if k == CLUSTERS for x in _cluster(c, separate(c.get("id")))),
            *(("azurerm_kubernetes_cluster_node_pool", _pool(p, owner)) for p, owner in pools)]


def compute_items(items):
    """(azurerm type, attributes) pairs of the scale sets, autoscale settings, AKS clusters and their node pools among
    (kind, item) pairs."""
    return [*(_scale_set(i) for k, i in items if k == SCALE_SETS),
            *(_autoscale(i) for k, i in items if k == AUTOSCALE), *_clusters(items)]
