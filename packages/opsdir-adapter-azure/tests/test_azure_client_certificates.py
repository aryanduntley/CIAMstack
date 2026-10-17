"""Client certificates checked at an Application Gateway (milestone 122, task 577): an edge trust policy's chains as
the gateway's trusted client certificates, an SSL profile with them on the service's listeners, the verified
certificate forwarded to the backends, its ARM form, what the gateway can't do as notes, and a blocker when TLS passes
through a load balancer or no anchor records a certificate."""
import base64
import re
from types import SimpleNamespace

from opsdir.core.interchange.ldif import parse
from opsdir_format_terraform.hcl import TfFile, as_text, tf_block
from opsdir_adapter_azure import client_certificates
from opsdir_adapter_azure.arm_types import arm_translation
from opsdir_adapter_azure.client_certificates import client_certificate_notes
from opsdir_adapter_azure.edge import gateway_service, servers_backend
from opsdir_adapter_azure.terraform import cert_forwarding
from edge_fixtures import server, spec
from network_fixtures import ALPHA, entry, model
from pki_samples import edge_trust_records

PEM = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n"
EDGE = entry(ALPHA, "subnet-edge", "ciamSubnetBinding", ciamBindingRole="subnet-edge", ciamCidr="10.60.250.0/24")


def _gateway(changes=(), **kw):
    _, alpha, _ = model(alpha=(EDGE,), tree=edge_trust_records(PEM, store=None, **kw), changes=changes)
    svc = next(b for b in alpha.bindings if b.dn.startswith("cn=svc-sso,"))
    return alpha, svc, gateway_service(alpha, svc, spec(certificate="azkv-cert://kv-ciam-prod/sso-tls"),
                                       servers_backend((server("web-1", "10.60.2.10"),)))


def test_an_edge_policy_is_the_gateways_ssl_profile_on_its_listeners_with_the_certificate_forwarded():
    _, _, blocks = _gateway(extra="ciamRevocationMode: ocsp\n")
    text = re.sub(r" +", " ", "\n".join(as_text(blocks)))
    for line in ('name = "cac_users-dod_root_ca_6-1"', f'data = "{base64.b64encode(PEM.encode()).decode()}"',
                 'name = "mtls-cac_users"', 'trusted_client_certificate_names = ["cac_users-dod_root_ca_6-1"]',
                 'client_authentication_mode = "Strict"', 'verify_client_certificate_revocation = "OCSP"',
                 'ssl_profile_name = "mtls-cac_users"', 'rewrite_rule_set_name = "client-certificate"',
                 'header_name = "X-Client-Cert"', 'header_value = "{var_client_certificate}"'):
        assert line in text, line
    t = arm_translation(SimpleNamespace(dn=ALPHA, label="alpha/prod"), {"terraform/main.tf": TfFile("", (
        tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-a")]),
        tf_block("data", ["azurerm_subnet", "subnet_edge"], [
            ("name", "subnet-edge"), ("virtual_network_name", "vnet"), ("resource_group_name", "rg-a")]),
        *blocks))}, "Azure edge")
    (agw,) = [r for (_, k), tpl in t.templates.items() for r in tpl.resources
              if r.type == "Microsoft.Network/applicationGateways"]
    (profile,) = agw.properties["sslProfiles"]
    assert profile["properties"]["clientAuthConfiguration"] == {
        "verifyClientAuthMode": "Strict", "verifyClientCertIssuerDN": False, "verifyClientRevocation": "OCSP"}
    assert agw.properties["trustedClientCertificates"][0]["properties"] == {
        "data": base64.b64encode(PEM.encode()).decode()}
    (rules,) = agw.properties["rewriteRuleSets"]
    assert rules["properties"]["rewriteRules"][0]["actionSet"] == {"requestHeaderConfigurations": [
        {"headerName": "X-Client-Cert", "headerValue": "{var_client_certificate}"}]}
    assert "sslProfile" in agw.properties["httpListeners"][0]["properties"]
    assert "rewriteRuleSet" in agw.properties["requestRoutingRules"][0]["properties"]


def test_what_the_gateway_cant_check_is_named_and_a_passthrough_is_a_blocker():
    m, svc, _ = _gateway(extra="ciamRevocationMode: crl\n")
    action, chain_only = client_certificate_notes(m, (svc,))
    assert action.severity == "action" and "only by OCSP" in action.text
    assert chain_only.severity == "note" and "X-Client-Cert" in chain_only.text
    (blocker,) = client_certificate_notes(m, ())
    assert blocker.severity == "blocker" and "an application gateway in front of sso.example.test" in blocker.text


def test_in_azure_government_confirming_gateway_mtls_is_an_action():
    gov = ("dn: cloud=alpha,ou=environments,dc=ciam-ops\nchangetype: modify\nreplace: ciamRegion\n"
           "ciamRegion: usgovvirginia\n-\n")
    m, svc, _ = _gateway(changes=parse(gov), extra="ciamRevocationMode: ocsp\n")
    *_, confirm = client_certificate_notes(m, (svc,))
    assert confirm.severity == "action" and "Application Gateway mutual TLS" in confirm.text


def test_without_an_anchor_certificate_the_listeners_stay_plain():
    m, svc, blocks = _gateway(anchors=False)
    assert "ssl_profile" not in "\n".join(as_text(blocks))
    (blocker,) = client_certificate_notes(m, (svc,))
    assert "an anchor recording its certificate" in blocker.text


def test_a_chain_over_the_file_limit_is_split_each_part_starting_with_its_root(monkeypatch):
    monkeypatch.setattr(client_certificates, "FILE_LIMIT", 12)
    assert client_certificates._packed("ROOT\n", ("aaaa\n", "bbbb\n", "cccc\n")) == (
        "ROOT\naaaa\n", "ROOT\nbbbb\n", "ROOT\ncccc\n")


def test_a_gateway_verifying_a_service_forwards_the_leaf_from_the_gateway_subnet():
    tree = ("dn: ou=edge-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
            entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                  ciamTlsMode="terminate"))
    _, alpha, _ = model(alpha=(EDGE,), tree=(*edge_trust_records(PEM, store=None), *tree))
    svc = next(b for b in alpha.bindings if b.dn.startswith("cn=svc-sso,"))
    f = cert_forwarding(alpha, svc)
    assert (f.header, f.encoding, f.holds, f.sources) == ("X-Client-Cert", "pem", "leaf", ("10.60.250.0/24",))
    _, plain, _ = model(alpha=(EDGE,), tree=edge_trust_records(PEM, store=None))
    assert cert_forwarding(plain, svc) is None             # TLS passes through a load balancer: nothing verifies
