"""Certificate sign-in at PingAM (milestone 122, task 580): a client-auth trust policy an AM role accepts as a disabled
certificate journey in the realms on its service names (the edge's header and single-address sources on the collector,
revocation on the validation node), what AM's reference doesn't establish as actions, a blocker and no journey when the
edge forwards no certificate, and the read-back leaving the journeys out."""
import json
from types import SimpleNamespace

from opsdir.core.contract import CertForwarding
from opsdir_adapter_pingam.certificates import (COLLECTOR, EXTRACTOR, VALIDATION, amster_read_back,
                                                certificate_notes, node_id, render_certificate_journeys,
                                                trusted_hosts)
from network_fixtures import ALPHA, entry, model
from pki_samples import edge_trust_records

PEM = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n"
REALM = ("dn: cn=customers,ou=identity-services,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamIdentityService\n"
         "cn: customers\nciamBaseUrl: https://am.example.test\nciamEntityId: urn:example:am\n"
         "ciamOidcIssuer: https://am.example.test/am/oauth2\nciamTargetRole: am\n")
SVC = entry(ALPHA, "svc-am", "ciamServiceName", ciamBindingRole="am-service", ciamFqdn="am.example.test",
            ciamPort="443", ciamTargetRole="am")
ALB = CertForwarding("X-Amzn-Mtls-Clientcert-Leaf", "url-pem", "leaf", ("10.1.2.0/24", "10.1.3.7/32"))
TREE = "am/realms/root/AuthTree/certificate-cac-users.json"


def _alpha(edge=True, svc=True, **kw):
    records = edge_trust_records(PEM, store=None, role="am", **kw)
    if not edge:
        records = (*records[:-1], records[-1].replace("ciamTrustEnforcedAt: edge", "ciamTrustEnforcedAt: product"))
    _, alpha, _ = model(alpha=(SVC,) if svc else (), tree=(*records, REALM))
    return alpha


def _services(forwarding=ALB):
    return SimpleNamespace(cert_forwarding=lambda m, svc: forwarding)


def _data(files, kind):
    return json.loads(files[f"am/realms/root/{kind}/{node_id('/', _policy(), kind)}.json"])["data"]


def _policy():
    return SimpleNamespace(attrs={"cn": ("cac-users",)}, dn="cn=cac-users,ou=trust-policies,dc=ciam-ops")


def test_an_edge_policy_is_a_disabled_journey_reading_the_edges_header_from_its_single_addresses():
    m = _alpha(extra="ciamRevocationMode: ocsp-then-crl\nciamIdentityMapping: san-upn\n")
    files = render_certificate_journeys(m, _services())
    tree = json.loads(files[TREE])["data"]
    assert tree["enabled"] is False and tree["entryNodeId"] == node_id("/", _policy(), COLLECTOR)
    assert sorted(n["nodeType"] for n in tree["nodes"].values()) == [COLLECTOR, EXTRACTOR, VALIDATION]
    collector = _data(files, COLLECTOR)
    assert collector["clientCertificateHttpHeaderName"] == "X-Amzn-Mtls-Clientcert-Leaf"
    assert collector["trustedRemoteHosts"] == ["10.1.3.7"] and "certificateCollectionMethod" not in collector
    assert _data(files, VALIDATION) == {"_id": node_id("/", _policy(), VALIDATION), "checkCertificateExpiry": True,
                                        "matchCertificateToCRL": True, "ocspValidationEnabled": True,
                                        "_type": {"_id": VALIDATION}}
    notes = certificate_notes(m, _services())
    assert "blocker" not in {n.severity for n in notes}
    text = " ".join(n.text + " ".join(n.how) for n in notes)
    for part in ("`Header`", "`UPN`", "Not Collected -> failure", "10.1.2.0/24", "unconfigured Validation node",
                 "Online Certificate Status Protocol", "crlMatchingCertificateAttribute", "url-pem", "DoD Root CA 6"):
        assert part in text, part


def test_the_render_is_stable_and_its_read_back_leaves_the_journey_out():
    m = _alpha()
    files = render_certificate_journeys(m, _services())
    assert files == render_certificate_journeys(m, _services()) and len(files) == 4
    stripped = {p[len("am/"):]: t for p, t in files.items()}
    assert amster_read_back({**stripped, "realms/root/AuthTree/Login.json": "{}"}, m.d) == \
        {"realms/root/AuthTree/Login.json": "{}"}


def test_an_edge_that_forwards_no_certificate_is_a_blocker_and_no_journey():
    m = _alpha()
    assert render_certificate_journeys(m, _services(None)) == {}
    (blocker,) = certificate_notes(m, _services(None))
    assert blocker.severity == "blocker" and "am.example.test" in blocker.text


def test_a_product_policy_collects_from_the_request_and_names_the_container():
    m = _alpha(edge=False, svc=False)
    files = render_certificate_journeys(m, _services(None))
    assert _data(files, COLLECTOR) == {"_id": node_id("/", _policy(), COLLECTOR), "_type": {"_id": COLLECTOR}}
    text = " ".join(n.text + " ".join(n.how) for n in certificate_notes(m, _services(None)))
    assert "`Request`" in text and "web container" in text and "records no identity mapping" in text


def test_only_single_addresses_are_trusted_hosts():
    assert trusted_hosts(("10.0.0.5/32", "10.0.0.0/24", "2001:db8::1/128")) == (("10.0.0.5", "2001:db8::1"),
                                                                                ("10.0.0.0/24",))
