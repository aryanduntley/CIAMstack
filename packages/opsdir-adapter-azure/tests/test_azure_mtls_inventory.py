"""Client certificates checked at an Application Gateway, read back (milestone 122, task 585): the render of an edge
trust policy reads back through Terraform state and its ARM form with no change and nothing said; a listener without
the policy's SSL profile, a profile passing certificates through, a rewrite no longer forwarding the certificate, or
trusted client certificates that differ from the policy's bundle (by SHA-256) is an import notice; the Azure CLI's
gateway list (sub-resources flattened or under properties) reads the same."""
import base64
import json
import re

from opsdir.connectors.registry import ADAPTERS
from opsdir.connectors.roundtrip import read_back
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import TfFile, tf_block, written
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.arm_types import arm_files
from opsdir_adapter_azure.cli import read_cli_inventory
from opsdir_adapter_azure.edge import gateway_service, servers_backend
from opsdir_adapter_azure.inventory import read_terraform_state
from opsdir_adapter_azure.mtls_inventory import bundle_fingerprints, file_fingerprints
from opsdir_adapter_azure.rendered_state import rendered_states
from opsdir_adapter_azure.terraform import render_files
from edge_fixtures import server, spec
from network_fixtures import ALPHA, entry, model
from pki_samples import CA_FINGERPRINT, CA_PEM, edge_trust_records

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
SUB = "00000000-0000-0000-0000-0000000000aa"
GW = f"/subscriptions/{SUB}/resourceGroups/rg-ciam-prod/providers/Microsoft.Network/applicationGateways/" \
     "agw-ciam-prod-svc-sso"
OTHER_PEM = CA_PEM.replace("MIIBtDCC", "MIIBtDCD")
EDGE = entry(ALPHA, "subnet-edge", "ciamSubnetBinding", ciamBindingRole="subnet-edge", ciamCidr="10.1.250.0/24")
TERMINATE = ("dn: ou=edge-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
             entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                   ciamTlsMode="terminate"))


def _alpha(trust=True):
    azure = LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                             ("replace", "ciamRegion", ("eastus2",)),
                                             ("replace", "ciamCloudProvider", ("azure",)),
                                             ("replace", "ciamAccountRef", (SUB,))))
    group = LdifRecord(ALPHA, "modify", {}, (("replace", "ciamResourceGroup", ("rg-ciam-prod",)),))
    web = LdifRecord(f"cn=web-1,{ALPHA}", "modify", {}, (("replace", "ciamPrivateIp", ("10.1.2.10",)),))
    _, alpha, _ = model(alpha=(EDGE,), tree=(*(edge_trust_records(CA_PEM, store=None) if trust else ()), *TERMINATE),
                        changes=(azure, group, web))
    return alpha


def _states(m):
    files = {f"alpha/prod/{p[len('terraform/'):]}": t for p, t in written(render_files(m, None)).items()}
    return rendered_states(files, m.d, "alpha/prod")


def _changed(states, change):
    doc = json.loads(states["alpha/prod/terraform.tfstate"])
    for r in doc["resources"]:
        if r["type"] == "azurerm_application_gateway":
            r["instances"][0]["attributes"] = change(r["instances"][0]["attributes"])
    return {**states, "alpha/prod/terraform.tfstate": json.dumps(doc)}


def _mtls(notices):
    return [n for n in notices if "SSL profile" in n or "client certificate" in n or "X-Client-Cert" in n]


# ------------------------------------------------------------------ Terraform state
def test_the_render_of_an_edge_policy_reads_back_with_no_change_and_nothing_said():
    m = _alpha()
    files = written(render_files(m, None))
    assert 'ssl_profile_name               = "mtls-cac_users"' in files["terraform/main.tf"]
    (trip,) = read_back(m.d, ADAPTER, files, ADAPTERS, None, "alpha/prod")
    assert trip.drift == () and _mtls(trip.notices) == []
    assert _mtls(read_terraform_state(_states(m), m.d, ()).notices) == []


def test_a_listener_without_the_policys_profile_or_passing_certificates_through_is_named():
    m = _alpha()
    plain = _changed(_states(m), lambda a: {**a, "http_listener": [{**ls, "ssl_profile_name": None}
                                                                     for ls in a["http_listener"]]})
    (n,) = _mtls(read_terraform_state(plain, m.d, ()).notices)
    assert n.startswith("alpha/prod: agw-ciam-prod-svc-sso listener listener-443 (sso.example.test, trust policy "
                        "cac-users) checks no client certificate")
    through = _changed(_states(m), lambda a: {**a, "ssl_profile": [{**p, "client_authentication_mode": "Passthrough"}
                                                                   for p in a["ssl_profile"]]})
    (n,) = _mtls(read_terraform_state(through, m.d, ()).notices)
    assert "passes client certificates on unchecked (client authentication Passthrough)" in n


def test_a_rewrite_that_stops_forwarding_the_certificate_is_named():
    m = _alpha()
    dropped = _changed(_states(m), lambda a: {**a, "request_routing_rule": [
        {**r, "rewrite_rule_set_name": None} for r in a["request_routing_rule"]]})
    (n,) = _mtls(read_terraform_state(dropped, m.d, ()).notices)
    assert "doesn't pass the verified certificate on in X-Client-Cert" in n


def test_trusted_certificates_that_differ_from_the_policy_bundle_are_named_by_fingerprint():
    m = _alpha()
    other = base64.b64encode(OTHER_PEM.encode()).decode()
    swapped = _changed(_states(m), lambda a: {**a, "trusted_client_certificate": [
        {**c, "data": other} for c in a["trusted_client_certificate"]]})
    (n,) = _mtls(read_terraform_state(swapped, m.d, ()).notices)
    (extra,) = bundle_fingerprints(OTHER_PEM)
    assert n == (f"alpha/prod: agw-ciam-prod-svc-sso SSL profile mtls-cac_users (trust policy cac-users) trusts 1 CA "
                 f"certificate(s) the policy doesn't: SHA-256 {extra}; lacks 1 the policy trusts: CN=DoD Root CA 6 "
                 f"(SHA-256 {CA_FINGERPRINT}): render and apply the edge again, or find what changed it")


def test_a_certificate_file_is_pem_or_one_der_certificate():
    der = base64.b64decode("".join(CA_PEM.splitlines()[1:-1]))
    assert file_fingerprints(base64.b64encode(der).decode()) == (CA_FINGERPRINT,)
    assert file_fingerprints(base64.b64encode(CA_PEM.encode()).decode()) == (CA_FINGERPRINT,)
    assert file_fingerprints("not base64!") == ()


def test_nothing_is_checked_without_an_edge_policy():
    m = _alpha(trust=False)
    assert _mtls(read_terraform_state(_states(m), m.d, ()).notices) == []


# ------------------------------------------------------------------ ARM
def test_the_arm_form_reads_back_with_no_change_and_nothing_said():
    m = _alpha()
    svc = next(b for b in m.bindings if b.dn.startswith("cn=svc-sso,"))
    blocks = gateway_service(m, svc, spec(certificate="azkv-cert://kv-ciam-prod/sso-tls"),
                             servers_backend((server("web-1", "10.1.2.10"),)))
    root = TfFile("", (tf_block("data", ["azurerm_resource_group", "main"], [("name", "rg-ciam-prod")]),
                       tf_block("data", ["azurerm_subnet", "subnet_edge"], [
                           ("name", "subnet-edge"), ("virtual_network_name", "vnet"),
                           ("resource_group_name", "rg-ciam-prod")]),
                       *blocks))
    files = written(arm_files(m, {"terraform/main.tf": root}, "Azure edge", ("arm",)))
    template = next(t for p, t in files.items() if p.endswith(".json") and "applicationGateways" in t)
    assert "sslProfiles" in template and "trustedClientCertificates" in template
    def arm(rendered):
        return next(rt for rt in read_back(m.d, ADAPTER, rendered, ADAPTERS, None, "alpha/prod")
                    if rt.importer == "azure/arm")
    trip = arm(files)
    assert trip.files and trip.drift == () and _mtls(trip.notices) == []
    pems = (base64.b64encode(CA_PEM.encode()).decode(), base64.b64encode(OTHER_PEM.encode()).decode())
    (n,) = _mtls(arm({p: t.replace(*pems) if t == template else t for p, t in files.items()}).notices)
    assert "trusts 1 CA certificate(s) the policy doesn't" in n


# ------------------------------------------------------------------ the Azure CLI
def _part(kind, name, wrapped, **props):
    """A gateway part as the CLI prints it (flattened), or under properties as REST and templates give it."""
    base = {"id": f"{GW}/{kind}/{name}", "name": name}
    return {**base, "properties": props} if wrapped else {**base, **props}


def _cli(wrapped=False, mode="Strict", data=CA_PEM):
    gateway = {
        "id": GW, "name": "agw-ciam-prod-svc-sso", "type": "Microsoft.Network/applicationGateways",
        "tags": {"Service": "sso.example.test"}, "frontendPorts": [{"name": "port-443", "port": 443}],
        "trustedClientCertificates": [_part("trustedClientCertificates", "cac_users-dod_root_ca_6-1", wrapped,
                                            data=base64.b64encode(data.encode()).decode())],
        "sslProfiles": [_part("sslProfiles", "mtls-cac_users", wrapped, trustedClientCertificates=[
            {"id": f"{GW}/trustedClientCertificates/cac_users-dod_root_ca_6-1"}],
            clientAuthConfiguration={"verifyClientCertIssuerDN": False, "verifyClientRevocation": "None",
                                     "verifyClientAuthMode": mode})],
        "httpListeners": [_part("httpListeners", "listener-443", wrapped, protocol="Https",
                                sslProfile={"id": f"{GW}/sslProfiles/mtls-cac_users"})],
        "requestRoutingRules": [_part("requestRoutingRules", "route-443", wrapped,
                                      httpListener={"id": f"{GW}/httpListeners/listener-443"},
                                      rewriteRuleSet={"id": f"{GW}/rewriteRuleSets/client-certificate"})],
        "rewriteRuleSets": [_part("rewriteRuleSets", "client-certificate", wrapped, rewriteRules=[
            {"name": "forward-client-certificate", "ruleSequence": 100, "actionSet": {"requestHeaderConfigurations": [
                {"headerName": "X-Client-Cert", "headerValue": "{var_client_certificate}"}]}}])]}
    return {"alpha/prod/gateways.json": json.dumps([gateway])}


def test_the_cli_gateway_list_reads_the_same_flattened_or_under_properties():
    m = _alpha()
    for wrapped in (False, True):
        found = read_cli_inventory(_cli(wrapped=wrapped), m.d, ())
        assert _mtls(found.notices) == [], wrapped
    (n,) = _mtls(read_cli_inventory(_cli(mode="Passthrough"), m.d, ()).notices)
    assert "(client authentication Passthrough)" in n
    (n,) = _mtls(read_cli_inventory(_cli(data=OTHER_PEM, wrapped=True), m.d, ()).notices)
    assert re.search(r"trusts 1 CA certificate\(s\) the policy doesn't: SHA-256 [0-9A-F:]+; lacks 1", n)
