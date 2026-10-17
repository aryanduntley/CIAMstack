"""PingFederate's part of the client-certificate trust policies (milestone 122, task 579): the CAs a policy accepted by
a PingFederate role trusts imported (admin-api and terraform, not the bulk document), revocation checking from its mode
and failure policy (with the environment's proxy; none where PingFederate can't say it or policies disagree), the
incoming proxy's certificate header for a policy checked at the edge (from the load balancer's forwarding, in an
encoding PingFederate decodes, the properties the version's spec lacks left out), held settings kept beside them, a
render's trust settings not read back, and what is left to people as render notes."""
import json
from types import SimpleNamespace

from opsdir.core.contract import CertForwarding
from opsdir.core.directory import get, make_entry
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.admin_api import OUTPUT, admin_api_files, requests
from opsdir_adapter_pingfederate.bulk import bulk_document
from opsdir_adapter_pingfederate.client_certificates import (CA_IMPORT, INCOMING_PROXY, REVOCATION, ca_id,
                                                             revocation_settings, trust_notes)
from opsdir_adapter_pingfederate.importer import resources
from opsdir_adapter_pingfederate.naming import RESOURCES
from opsdir_adapter_pingfederate.terraform_target import terraform_files
from network_fixtures import ALPHA, entry, model
from pki_samples import edge_trust_records

PEM = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n"
POLICY = "cn=cac-users,ou=trust-policies,dc=ciam-ops"
ALB = CertForwarding("X-Amzn-Mtls-Clientcert-Leaf", "url-pem", "leaf", ("10.1.2.0/24",))
SQUID = entry(ALPHA, "squid", "ciamProxy", ciamBindingRole="squid", ciamProxyKind="forward-proxy",
              ciamProxyAddress="proxy.corp.example:3128")


def _pf(version="PingFederate 13.1.3"):
    return (entry(ALPHA, "pf-1", "ciamServer", ciamServerRole="pf-engine", ciamHostname="pf-1.example.test",
                  ciamSubnet=f"cn=subnet-web,ou=bindings,{ALPHA}", ciamZone="zone-a", ciamProductVersion=version),
            entry(ALPHA, "svc-pf", "ciamServiceName", ciamBindingRole="pf-sso-service", ciamFqdn="pf.example.test",
                  ciamPort="443", ciamTargetRole="pf-engine", ciamExposure="internet"))


def _alpha(at="edge", revocation="", version="PingFederate 13.1.3", role="pf-engine", alpha=(), tree=()):
    records = tuple(r.replace("ciamTrustEnforcedAt: edge", f"ciamTrustEnforcedAt: {at}")
                    for r in edge_trust_records(PEM, store=None, role=role, extra=revocation))
    return model(alpha=(*_pf(version), *alpha), tree=(*records, *tree))[1]


def _services(forwarding=ALB):
    return SimpleNamespace(cert_forwarding=lambda m, svc: forwarding)


def _by_path(reqs):
    return {r.path: r for r in reqs}


def test_a_product_checked_policy_imports_its_cas_and_sets_revocation_checking():
    m = _alpha(at="product", revocation="ciamRevocationMode: ocsp-then-crl\nciamRevocationFailure: reject\n")
    found = _by_path(requests(m, _services()))
    ca = found[CA_IMPORT]
    assert (ca.method, ca.create_with) == ("POST", None)
    assert ca.body == {"id": "dod-root-ca-6-abababab", "fileData": "MIIBroot"}      # the DER, base64
    assert found[REVOCATION].body == {
        "crlSettings": {"treatNonRetrievableCrlAsRevoked": True, "verifyCrlSignature": True},
        "ocspSettings": {"actionOnResponderUnavailable": "FAILOVER", "actionOnStatusUnknown": "FAILOVER",
                         "actionOnUnsuccessfulResponse": "FAILOVER"}}
    assert INCOMING_PROXY not in found                                  # TLS reaches PingFederate itself
    doc = json.loads(admin_api_files(m, _services())[OUTPUT])
    assert doc["adminApi"] and not [p for p in doc["problems"] if "certificates" in p]
    notes = trust_notes(m, _services())
    adapter = next(n for n in notes if "X.509 Certificate IdP Adapter" in n.text)
    assert adapter.severity == "action" and adapter.entry == POLICY
    assert "Constrain Acceptable Root Issuers, Issuer DN: CN=DoD Root CA 6" in adapter.how
    assert any(n.subject == "trusted CA certificates" and n.severity == "action" for n in notes)


def test_what_pingfederate_isnt_given_is_an_action():
    m = _alpha(at="product", revocation="ciamAllowedPolicyOid: 2.16.840.1.101.2.1.11.19\nciamRequiredEku: "
               "1.3.6.1.5.5.7.3.2\nciamIdentityMapping: san-upn\n")
    texts = {n.text: n for n in trust_notes(m, _services())}
    given = next(n for t, n in texts.items() if "is not given the policy's" in t)
    assert given.severity == "action" and "2.16.840.1.101.2.1.11.19" in given.text and "1.3.6.1.5.5.7.3.2" in given.text
    mapping = next(n for t, n in texts.items() if "identity mapping (san-upn)" in t)
    assert "userPrincipalName" in mapping.how[0]
    assert not any("PEM" in t for t in texts)                          # its anchor records one
    bare = _alpha(at="product").d
    stripped = make_entry(get(bare, "cn=DoD Root CA 6,ou=certificates,dc=ciam-ops").dn, ("top", "ciamCertificate"),
                          {"cn": ("DoD Root CA 6",), "ciamCertPurpose": ("ca",)})
    m = _alpha(at="product")._replace(d=bare._replace(entries={**bare.entries, stripped.norm: stripped}))
    assert any(n.severity == "blocker" and "no CA certificate to trust" in n.text for n in trust_notes(m, None))
    assert CA_IMPORT not in _by_path(requests(m))


def test_the_ca_id_is_its_name_in_pingfederates_characters_with_a_fingerprint_prefix():
    cert = make_entry("cn=DoD ID CA-72 (2025),ou=certificates,dc=ciam-ops", ("ciamCertificate",),
                      {"ciamFingerprint": ("0a:1B:" + ":".join(["CC"] * 30),)})
    assert ca_id(cert) == "dod-id-ca-72-2025-0a1bcccc"
    assert ca_id(make_entry("cn=Root,ou=certificates,dc=ciam-ops", ("ciamCertificate",), {})) == "root"


def test_revocation_follows_the_mode_and_failure_policy():
    def said(**attrs):
        return revocation_settings(make_entry(POLICY, ("ciamTrustPolicy",), {k: (v,) for k, v in attrs.items()}))
    assert said(ciamRevocationMode="ocsp", ciamRevocationFailure="allow") == {"ocspSettings": {
        "actionOnResponderUnavailable": "CONTINUE", "actionOnStatusUnknown": "CONTINUE",
        "actionOnUnsuccessfulResponse": "CONTINUE"}}
    assert said(ciamRevocationMode="ocsp", ciamRevocationFailure="cached", ciamRevocationCacheHours="24")[
        "ocspSettings"]["responseCachePeriod"] == 24
    assert said(ciamRevocationMode="crl", ciamRevocationFailure="allow") == {"crlSettings": {
        "treatNonRetrievableCrlAsRevoked": False, "verifyCrlSignature": True}}
    assert said(ciamRevocationMode="ocsp")["ocspSettings"]["actionOnResponderUnavailable"] == "FAIL"   # unset: reject
    assert said(ciamRevocationMode="crl-then-ocsp") is None and said(ciamRevocationMode="none") is None


def test_crl_before_ocsp_is_an_action_and_the_proxy_goes_with_revocation_checking():
    m = _alpha(at="product", revocation="ciamRevocationMode: crl-then-ocsp\n")
    assert REVOCATION not in _by_path(requests(m))
    assert any("can't check CRLs before OCSP" in n.text for n in trust_notes(m, _services()))
    proxied = _alpha(at="product", revocation="ciamRevocationMode: crl\n", alpha=(SQUID,))
    assert _by_path(requests(proxied))[REVOCATION].body["proxySettings"] == {"host": "proxy.corp.example",
                                                                             "port": 3128}
    cached = _alpha(at="product", revocation="ciamRevocationMode: ocsp\nciamRevocationFailure: cached\n"
                                             "ciamRevocationCacheHours: 12\n")
    assert _by_path(requests(cached))[REVOCATION].body["ocspSettings"]["responseCachePeriod"] == 12
    assert any(n.severity == "note" and "cached revocation answers" in n.text for n in trust_notes(cached, None))


def test_an_edge_checked_policy_reads_the_forwarded_certificate_header():
    m = _alpha()
    body = _by_path(requests(m, _services()))[INCOMING_PROXY].body
    assert body == {"enableClientCertHeaderAuth": True, "clientCertSSLHeaderName": "X-Amzn-Mtls-Clientcert-Leaf",
                    "clientCertHeaderEncodingFormat": "NGINX"}
    assert INCOMING_PROXY not in _by_path(requests(m))                  # without the Services: not known
    notes = trust_notes(m, _services())
    restrict = next(n for n in notes if "no allowlist" in n.text)
    assert restrict.severity == "action" and "10.1.2.0/24" in restrict.text and "`pf-engine`" in restrict.text
    confirm = next(n for n in notes if "is not confirmed" in n.text)
    assert "as NGINX" in confirm.text and "'+' unescaped" in confirm.text
    pem = _by_path(requests(m, _services(ALB._replace(header="X-Client-Cert", encoding="pem"))))
    assert pem[INCOMING_PROXY].body["clientCertHeaderEncodingFormat"] == "APACHE_MOD_SSL"


def test_nothing_verifying_at_the_edge_or_an_undecoded_encoding_is_a_blocker():
    m = _alpha()
    for services, words in ((_services(None), "verifies client certificates"),
                            (_services(ALB._replace(encoding="der-base64")), "doesn't document decoding")):
        assert INCOMING_PROXY not in _by_path(requests(m, services))
        assert any(n.severity == "blocker" and words in n.text for n in trust_notes(m, services))


def test_an_older_version_leaves_out_what_its_spec_lacks():
    m = _alpha(version="PingFederate 12.1.4")
    assert _by_path(requests(m, _services()))[INCOMING_PROXY].body == {
        "clientCertSSLHeaderName": "X-Amzn-Mtls-Clientcert-Leaf"}
    notes = trust_notes(m, _services())
    (lacks,) = [n for n in notes if "Admin API of PingFederate 12.1.4 has no" in n.text]
    assert "enableClientCertHeaderAuth, clientCertHeaderEncodingFormat" in lacks.text
    assert any("reads the certificate in X-Amzn-Mtls-Clientcert-Leaf;" in n.text for n in notes)   # no encoding said


def test_held_settings_are_kept_beside_the_policys():
    m = _alpha()
    base = f"ou=incomingProxySettings,{RESOURCES}"
    held = (make_entry(RESOURCES, ("top", "organizationalUnit"), {"ou": ("resources",)}),
            make_entry(base, ("top", "organizationalUnit"), {"ou": ("incomingProxySettings",)}),
            make_entry(f"cn=settings,{base}", ("top", "ciamObject", "pingfedResource"), {
                "cn": ("settings",), "pingfedResourceType": (INCOMING_PROXY,),
                "pingfedConfig": (json.dumps({"forwardedIpAddressHeaderName": "X-Forwarded-For",
                                              "enableClientCertHeaderAuth": False}),)}))
    d = m.d._replace(entries={**m.d.entries, **{e.norm: e for e in held}})
    reqs = [r for r in requests(m._replace(d=d), _services()) if r.path == INCOMING_PROXY]
    assert len(reqs) == 1 and reqs[0].body == {"forwardedIpAddressHeaderName": "X-Forwarded-For",
                                               "enableClientCertHeaderAuth": True,
                                               "clientCertSSLHeaderName": "X-Amzn-Mtls-Clientcert-Leaf",
                                               "clientCertHeaderEncodingFormat": "NGINX"}


def test_terraform_carries_them_and_the_bulk_document_leaves_the_cas_out():
    m = _alpha(revocation="ciamRevocationMode: ocsp\nciamRevocationFailure: reject\n")
    main = terraform_files(m, _services())["pingfederate/terraform/main.tf"]
    for line in ('resource "pingfederate_certificate_ca" "dod_root_ca_6_abababab"', 'ca_id', 'file_data',
                 'resource "pingfederate_certificates_revocation_settings"', 'action_on_responder_unavailable',
                 'resource "pingfederate_incoming_proxy_settings"', 'client_cert_header_encoding_format',
                 'enable_client_cert_header_auth'):
        assert line in main, line
    assert "not taken by the provider" not in main and "Not managed here" not in main
    kinds = [op["resourceType"] for op in bulk_document(m, _services())["operations"]]
    assert CA_IMPORT not in kinds and REVOCATION in kinds and INCOMING_PROXY in kinds


def test_a_renders_trust_settings_are_not_read_back():
    m = _alpha(revocation="ciamRevocationMode: ocsp\n")
    _, unread, *_ = resources(admin_api_files(m, _services()))
    assert REVOCATION not in unread and INCOMING_PROXY not in unread


def test_nothing_without_a_policy_a_pingfederate_role_accepts():
    m = _alpha(role="web")
    assert not any(r.path in (CA_IMPORT, REVOCATION, INCOMING_PROXY) for r in requests(m, _services()))
    assert ADAPTER.notes(m, _services()) == () and get(m.d, POLICY) is not None
