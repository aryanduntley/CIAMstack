"""Compute fixture data: the server roles the target runs as containers (48-workloads: ciamWorkload, intent shared by
every environment) and, in the target environment, the AKS cluster they run in and how it runs each (its workload
bindings: images, the product version they run, replicas, resources, storage), and the in-cluster gateway behind the
Application Gateways that front the sign-on names (ciamClusterGateway: Istio by the estate setting's default, an
internal load balancer address in the AKS subnet, its internal certificate's key pair from Key Vault, the CA it chains
to). The source and the standby run these
roles on servers, so the planner sees AM, IDM, PingGateway and PingFederate move from virtual machines to Kubernetes
while the directory stays on servers.

ForgeOps deploys AM, IDM and PingGateway, Ping's ping-devops chart PingFederate. Each workload names the Secret keys
its pods read and the secret role that fills each; what it leaves out (ForgeOps' AM secrets, the DS servers' CA,
PingFederate's license) is planted: the deployment kits' checks name it.
"""
from types import MappingProxyType

from .common import R, spec

WORKLOADS = f"ou=workloads,{R}"
FILE = "48-workloads"
REGISTRY = "crciamprod.azurecr.io/ciam"
AKS = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
       "Microsoft.ContainerService/managedClusters/aks-ciam-prod")
NAMESPACE = "ciam"

# (name, kind, role, service account, identity role, ingress host, ("secret/key <- role", ...))
WORKLOAD_ROWS = (
    ("am", "deployment", "am", "ciam-platform", None, "login.example-aero.test",
     ("am-env-secrets/AM_PASSWORDS_AMADMIN_CLEAR <- am-admin-password",
      "ds-env-secrets/AM_STORES_USER_PASSWORD <- am-ds-bind-password")),
    ("idm", "deployment", "idm", "ciam-platform", None, None,
     ("idm-env-secrets/OPENIDM_ADMIN_PASSWORD <- idm-admin-password",
      "ds-passwords/dirmanager.pw <- ds-root-password")),
    ("ig", "deployment", "ig", "ciam-gateway", None, "apps.example-aero.test", ()),
    ("pf-admin", "statefulset", "pf-admin", "pingfederate", "identity-pf", None,
     ("pf-admin/PING_IDENTITY_PASSWORD <- pf-admin-password",)),
    ("pf-engine", "deployment", "pf-engine", "pingfederate", "identity-pf", "sso.example-aero.test", ()),
)


def workloads():
    """The workloads (intent): each role the target runs on Kubernetes, in namespace ciam of the cluster role
    k8s-cluster."""
    return (spec(FILE, WORKLOADS, ["top", "organizationalUnit"], ou="workloads"),
            *(spec(FILE, f"cn={name},{WORKLOADS}", ["top", "ciamWorkload"], cn=name, ciamWorkloadKind=kind,
                   ciamTargetRole=role, ciamNamespace=NAMESPACE, ciamClusterRole="k8s-cluster",
                   ciamWorkloadRole=f"{name}-workload", ciamServiceAccount=account, ciamIdentityRole=identity,
                   ciamIngressHost=host, ciamWorkloadSecret=list(secrets) or None,
                   ciamPodSecurity="level=restricted")
              for name, kind, role, account, identity, host, secrets in WORKLOAD_ROWS))


def _binding(name, images, version, replicas, cpu, memory, storage=None):
    return ("ciamWorkloadBinding", name, f"{name}-workload", {
        "ciamContainerImage": [f"{c}={REGISTRY}/{i}" for c, i in images], "ciamProductVersion": version,
        "ciamWorkloadReplicas": replicas, "ciamCpuRequest": cpu, "ciamMemoryRequest": memory,
        "ciamMemoryLimit": memory, **({"ciamStorageSize": storage[0], "ciamStorageClass": storage[1]}
                                      if storage else {})})


# Each environment's Kubernetes bindings: (class, name, binding role, attributes), as infrastructure lays them out
KUBERNETES = MappingProxyType({
    "target": (
        ("ciamCluster", "aks", "k8s-cluster", {
            "ciamProviderRef": AKS, "ciamClusterVersion": "1.33.3",
            "ciamClusterAddon": ["azure-policy", "oidc-issuer", "workload-identity"],
            "ciamNodePool": ["system: Standard_D4s_v5, 3-6"], "ciamSpansZone": ["1", "2", "3"],
            "ciamSubnetRole": "subnet-aks"}),
        _binding("am", (("openam", "am:7.5.1"), ("amster", "amster:7.5.1"), ("admin-ui", "admin-ui:7.5.1"),
                        ("end-user-ui", "end-user-ui:7.5.1"), ("login-ui", "login-ui:7.5.1")),
                 "PingAM 7.5.1", 2, "2", "4Gi"),
        _binding("idm", (("openidm", "idm:7.5.0"),), "PingIDM 7.5.0", 2, "1", "2Gi"),
        _binding("ig", (("ig", "ig:2024.11.0"),), "PingGateway 2024.11.0", 2, "1", "2Gi"),
        _binding("pf-admin", (("pingfederate", "pingfederate:12.1.4"),), "PingFederate 12.1.4", 1, "1", "4Gi",
                 ("8Gi", "managed-csi-premium")),
        _binding("pf-engine", (("pingfederate", "pingfederate:12.1.4"),), "PingFederate 12.1.4", 2, "1", "4Gi"),
        ("ciamClusterGateway", "ciam-edge", "ciam-edge", {
            "ciamClusterRole": "k8s-cluster", "ciamNamespace": NAMESPACE, "ciamFrontendIp": "10.60.15.250",
            "ciamSubnetRole": "subnet-aks", "ciamServiceAccount": "ciam-edge",
            "ciamTrustsCertificate": f"cn=ciam-internal-ca,ou=certificates,{R}",
            "ciamWorkloadSecret": ["ciam-edge-tls/tls.crt <- ciam-edge-tls-cert",
                                   "ciam-edge-tls/tls.key <- ciam-edge-tls-key"],
            "description": "The in-cluster gateway the Application Gateways send the sign-on names to"}),
        ("ciamCertificateRef", "cert-internal-ca", "internal-ca-certificate", {
            "ciamRefUri": "azkv-cert://kv-ciam-prod/ciam-internal-ca",
            "ciamHoldsCertificate": f"cn=ciam-internal-ca,ou=certificates,{R}"}),
        *(("ciamSecretRef", f"secret-{role}", role, {"ciamRefUri": f"azkv://kv-ciam-prod/{role}"})
          for role in ("ciam-edge-tls-cert", "ciam-edge-tls-key")),
    ),
})
