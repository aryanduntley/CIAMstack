"""Certificates recorded as PEM (core pki.pem) and a cluster gateway's backend CA bundle (core edge.gateways): a usable
PEM is nothing but certificates, its fingerprint is checked against the entry's, and a gateway trusting a CA with no
PEM recorded is the planner's action."""
import datetime as dt

from opsdir.connectors.plan import plan
from opsdir.core.directory import get
from opsdir.core.environment import env_model, of_class
from opsdir.core.interchange.ldif import parse
from opsdir.domains.edge.gateways import backend_ca
from opsdir.domains.pki.pem import certificate_pem, pem_fingerprint
import mini_estate
from mini_estate import FAKE
from pki_samples import CA_FINGERPRINT, CA_PEM, CERTIFICATES, ca_records
from support import REGISTRY, build_directory

AS_OF = dt.date(2026, 1, 1)
CA = f"cn=internal-ca,{CERTIFICATES}"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
GATEWAY = (f"dn: cn=gw,ou=bindings,{BETA}\nobjectClass: top\nobjectClass: ciamClusterGateway\ncn: gw\n"
           f"ciamBindingRole: gw\nciamClusterRole: k8s\nciamTrustsCertificate: {CA}\n")


def _directory(*records):
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *records)))))


def _pem_actions(p):
    return [a[1] for a in p.actions if "PEM" in a[1]]


def test_a_recorded_pem_is_used_and_its_fingerprint_is_the_certificates():
    c = get(_directory(*ca_records()), CA)
    assert certificate_pem(c) == CA_PEM and pem_fingerprint(CA_PEM) == CA_FINGERPRINT
    assert certificate_pem(None) is None


def test_a_pem_that_isnt_only_certificates_or_isnt_this_certificate_is_an_action():
    junk = "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"
    d = _directory(*ca_records(pem=junk))
    assert certificate_pem(get(d, CA)) is None
    (text,) = _pem_actions(plan(d, "alpha/prod", "beta/prod", AS_OF, (FAKE,)))
    assert text.startswith("Certificate `internal-ca` records a PEM (ciamCertificatePem) that isn't only PEM")
    d = _directory(*ca_records(fingerprint="AA:BB"))
    (text,) = _pem_actions(plan(d, "alpha/prod", "beta/prod", AS_OF, (FAKE,)))
    assert f"(SHA-256 {CA_FINGERPRINT}) isn't the one its fingerprint names (AA:BB)" in text


def test_a_gateways_backend_ca_bundle_is_its_trusted_cas_pems():
    d = _directory(*ca_records(), GATEWAY)
    (gw,) = of_class(env_model(d, "beta/prod"), "ciamClusterGateway")
    assert backend_ca(d, gw) == (CA_PEM, ())
    assert not _pem_actions(plan(d, "alpha/prod", "beta/prod", AS_OF, (FAKE,)))


def test_a_gateway_trusting_a_ca_with_no_pem_is_an_action():
    d = _directory(*ca_records(pem=None), GATEWAY)
    (gw,) = of_class(env_model(d, "beta/prod"), "ciamClusterGateway")
    assert backend_ca(d, gw) == (None, (CA,))
    (text,) = _pem_actions(plan(d, "alpha/prod", "beta/prod", AS_OF, (FAKE,)))
    assert text.startswith("Cluster gateway `gw` in beta/prod trusts CA `internal-ca`, whose certificate (PEM, ")
