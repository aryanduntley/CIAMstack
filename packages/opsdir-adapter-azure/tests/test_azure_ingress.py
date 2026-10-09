"""The front before a cluster's in-cluster gateway on Azure: the Application Gateway a service on servers would get,
sending to the gateway's internal load balancer address instead (HTTP behind a terminating front, HTTPS to the
gateway's internal certificate when the policy re-encrypts, trusting its CA from Key Vault), and the plug that makes the
gateway's Service that internal load balancer."""
import re

from opsdir.core.directory import make_entry
from opsdir_adapter_azure.edge import gateway_service
from opsdir_adapter_azure.ingress import gateway_backend, gateway_plug
from edge_fixtures import ENV, environment, service, spec, subnet

EDGE = subnet("subnet-edge", "subnet-edge", "10.60.250.0/24")
CA = "cn=ciam-internal-ca,ou=certificates,dc=ciam-ops"


def _binding(cn, oc, role, **attrs):
    return make_entry(f"cn={cn},ou=bindings,{ENV}", ("top", oc), {"ciamBindingRole": [role],
                                                                  **{k: [v] for k, v in attrs.items()}})


GATEWAY = _binding("edge-gw", "ciamClusterGateway", "k8s-gateway", ciamClusterRole="k8s",
                   ciamFrontendIp="10.60.9.10", ciamSubnetRole="subnet-aks", ciamTrustsCertificate=CA)
CA_REF = _binding("ca-ref", "ciamCertificateRef", "internal-ca", ciamHoldsCertificate=CA,
                  ciamRefUri="azkv-cert://kv-ciam-prod/ciam-internal-ca")
AKS = _binding("subnet-aks", "ciamSubnetBinding", "subnet-aks", ciamProviderRef="vnet-ciam-prod/snet-aks")
CERT = "azkv-cert://kv-ciam-prod/sso-tls-2026"


def _front(s, *bindings):
    svc = service("198.51.100.77", ciamProviderRef="pip-ciam-sso-prod")
    m = environment(svc, EDGE, *bindings)
    return "\n".join(gateway_service(m, svc, s, gateway_backend(m, bindings[0], s)))


def test_a_reencrypting_front_sends_https_to_the_gateway_and_trusts_its_ca():
    out = _front(spec(certificate=CERT), GATEWAY, CA_REF, AKS)
    assert re.search(r'backend_address_pool \{\s+name\s+= "gateway"\s+ip_addresses = \["10.60.9.10"\]', out)
    assert re.search(r'name\s+= "gateway-443"\s+port\s+= 443\s+protocol\s+= "Https"', out)
    assert re.search(r'trusted_root_certificate_names = \["backend-ca"\]', out)
    assert 'key_vault_secret_id = "${data.azurerm_key_vault.sso_ca.vault_uri}secrets/ciam-internal-ca"' in out
    assert 'resource "azurerm_role_assignment" "sso_gateway_ca"' in out
    assert 'name = "WAF_v2"' in out                                   # the protection policy, as for servers


def test_a_terminating_front_sends_http_and_trusts_nothing():
    out = _front(spec(mode="terminate", certificate=CERT), GATEWAY, CA_REF, AKS)
    assert re.search(r'name\s+= "gateway-443"\s+port\s+= 80\s+protocol\s+= "Http"', out)
    assert "trusted_root_certificate" not in out


def test_without_the_gateways_ca_the_front_says_what_is_missing():
    out = _front(spec(certificate=CERT), GATEWAY._replace(attrs={**GATEWAY.attrs, "ciamTrustsCertificate": ()}), AKS)
    assert "# UNBOUND: the CA the backend's certificate chains to, in Key Vault (UNBOUND:gateway-ca)" in out


def test_the_plug_makes_the_gateway_service_an_internal_load_balancer():
    plug = gateway_plug(environment(GATEWAY, AKS), GATEWAY, ("edge-gw", (80, 443)))
    assert plug.service_type == "LoadBalancer" and plug.objects == ()
    assert dict(plug.annotations) == {"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
                                      "service.beta.kubernetes.io/azure-load-balancer-internal-subnet": "snet-aks",
                                      "service.beta.kubernetes.io/azure-load-balancer-ipv4": "10.60.9.10"}
    bare = gateway_plug(environment(), _binding("gw", "ciamClusterGateway", "gw", ciamClusterRole="k8s"), ("gw", ()))
    assert dict(bare.annotations)["service.beta.kubernetes.io/azure-load-balancer-internal-subnet"] == \
        "UNBOUND:gateway-subnet"
