"""A service name whose role runs only on Kubernetes, behind its cluster's in-cluster gateway, rendered by each cloud's
Terraform (the front before the gateway: Application Gateway, ALB with IP target groups, Application Load Balancer over
NEGs): what `terraform validate` checks beyond the showcase, whose target is Azure only. The policy re-encrypts to the
gateway and asks for a web application firewall, so every part of the front is there."""
import pathlib

from opsdir_adapter_aws.terraform import render as aws
from opsdir_adapter_azure.terraform import render as azure
from opsdir_adapter_gcp.terraform import render as gcp
from opsdir.connectors.registry import services
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.edge.naming import EDGE_POLICIES
import mini_estate
from network_fixtures import ALPHA, entry
from support import REGISTRY, build_directory

CA = "cn=internal-ca,ou=certificates,dc=ciam-ops"
# cloud: (renderer, {placeholder: its provider ref there})
CLOUDS = {"aws": (aws, {"NET": "vpc-0a1b2c3d4e5f67890", "SUBNET": "subnet-0{}",
                        "CERT": "aws-acm://arn:aws:acm:us-east-1:111122223333:certificate/1",
                        "CA": "aws-acm://arn:aws:acm:us-east-1:111122223333:certificate/2"}),
          "azure": (azure, {"NET": "vnet-ciam-prod", "RG": "rg-ciam-prod", "SUBNET": "vnet-ciam-prod/snet-{}",
                            "CERT": "azkv-cert://kv-ciam/sso-tls",
                            "CA": "azkv-cert://kv-ciam/internal-ca"}),
          "gcp": (gcp, {"NET": "projects/example-net/global/networks/ciam-a",
                        "SUBNET": "projects/example-net/regions/us-central1/subnetworks/ciam-{}",
                        "CERT": "gcp-cert://projects/example-ciam/locations/us-central1/certificates/sso-tls",
                        "CA": "gcp-cert://projects/example-ciam/locations/us-central1/certificates/internal-ca"})}


def _records(refs):
    return (
        f"dn: {WORKLOADS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: workloads\n",
        f"dn: {workload_dn('am')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: am\nciamWorkloadKind: deployment\n"
        "ciamTargetRole: am\nciamClusterRole: k8s\nciamNamespace: ciam\nciamWorkloadRole: am-workload\n",
        entry(ALPHA, "k8s", "ciamCluster", ciamBindingRole="k8s", ciamProviderRef="k8s-1", ciamSubnetRole="subnet-k8s",
              ciamSpansZone=("us-central1-a", "us-central1-b")),
        entry(ALPHA, "subnet-k8s", "ciamSubnetBinding", ciamBindingRole="subnet-k8s", ciamCidr="10.1.8.0/22",
              ciamProviderRef=refs["SUBNET"].format("k8s")),
        entry(ALPHA, "subnet-edge", "ciamSubnetBinding", ciamBindingRole="subnet-edge", ciamCidr="10.1.250.0/24",
              ciamProviderRef=refs["SUBNET"].format("edge")),
        entry(ALPHA, "am", "ciamWorkloadBinding", ciamBindingRole="am-workload"),
        entry(ALPHA, "svc-login", "ciamServiceName", ciamBindingRole="login-service", ciamFqdn="login.example.test",
              ciamPort="443", ciamTargetRole="am", ciamFrontendIp="198.51.100.20", ciamDnsZoneRef="Z123",
              ciamDnsZone="example.test",
              ciamProviderRef="pip-login", ciamTlsCertificate="cn=sso-tls,ou=certificates,dc=ciam-ops"),
        entry(ALPHA, "gw", "ciamClusterGateway", ciamBindingRole="gw", ciamClusterRole="k8s", ciamNamespace="edge",
              ciamFrontendIp="10.1.11.250", ciamSubnetRole="subnet-k8s", ciamTrustsCertificate=CA),
        entry(ALPHA, "cert-tls", "ciamCertificateRef", ciamBindingRole="sso-tls", ciamRefUri=refs["CERT"],
              ciamHoldsCertificate="cn=sso-tls,ou=certificates,dc=ciam-ops"),
        entry(ALPHA, "cert-ca", "ciamCertificateRef", ciamBindingRole="internal-ca", ciamRefUri=refs["CA"],
              ciamHoldsCertificate=CA),
        f"dn: {EDGE_POLICIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
        f"dn: cn=sign-on,{EDGE_POLICIES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamTrafficPolicy\n"
        "cn: sign-on\nciamServiceRole: login-service\nciamTlsMode: reencrypt\nciamStickiness: cookie\n",
        f"dn: cn=protect,{EDGE_POLICIES}\nobjectClass: top\nobjectClass: ciamObject\n"
        "objectClass: ciamProtectionPolicy\ncn: protect\nciamServiceRole: login-service\nciamWafMode: block\n"
        "ciamWafCategory: core-rules\n")


# the mini estate's own service name fronts a role nothing runs here: left out, so the sample is the gateway's front;
# its network gets the cloud's provider ref (and, on Azure, its resource group)
def _changes(refs):
    group = f"add: ciamResourceGroup\nciamResourceGroup: {refs['RG']}\n-\n" if "RG" in refs else ""
    return (*parse(f"dn: cn=svc-sso,ou=bindings,{ALPHA}\nchangetype: delete\n"),
            *parse(f"dn: cn=net,ou=bindings,{ALPHA}\nchangetype: modify\nadd: ciamProviderRef\n"
                   f"ciamProviderRef: {refs['NET']}\n-\n{group}"))


def write_samples(root):
    """Each cloud's main Terraform root for the sample environment under root/<cloud>/; returns root."""
    for cloud, (render, refs) in CLOUDS.items():
        d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *_records(refs))))), _changes(refs))
        for path, text in render(env_model(d, "alpha/prod"), services()).items():
            if path.startswith("terraform/") and path.count("/") == 1:
                target = pathlib.Path(root) / cloud / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
    return root
