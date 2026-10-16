"""What the revocation observation asks each recorded CA's endpoints (pure; the collector runs it, the importer reads
the same plan back to say why an endpoint wasn't observed): a CRL or delta CRL endpoint is fetched as it is; an OCSP
responder is asked about one certificate the CA issued (core domains.pki.revocation.probe_serial) with an RFC 6960
request sent by GET (Appendix A.1: the URL, '/', the request's DER as base64, URL-encoded), its CertID hashed with
SHA-1 (RFC 5019: what responders answer from cache) over the CA certificate the record holds, without a nonce.

Paths in the export: <CA name>/<endpoint name>.json, each an observation (core.observation)."""
import base64
import urllib.parse
from typing import NamedTuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from opsdir.domains.pki.issued import authorities, endpoints
from opsdir.domains.pki.pem import certificate_pem
from opsdir.domains.pki.revocation import OBSERVED_KINDS, authority_certificates, observable_url, probe_serial
from opsdir.core.directory import one, rdn_value
from .verify import key_hash, load_certificate, name_hash

# One endpoint of a CA as the observation plans it: the CA and the endpoint (entries), the export path its answer is
# written to, the URL to GET (None: not observed) and why not (None: observed), and for an OCSP responder the serial
# asked about.
Planned = NamedTuple("Planned", [("authority", object), ("endpoint", object), ("path", str), ("url", object),
                                 ("why_not", object), ("serial", object)])


def signing_certificates(d, authority):
    """((record entry, x509.Certificate), ...) of the CA's own certificates the record holds with a readable PEM."""
    return tuple((e, c) for e in authority_certificates(d, authority)
                 for c in (load_certificate(certificate_pem(e) or ""),) if c is not None)


def ocsp_request(issuer, serial):
    """The DER of an RFC 6960 OCSPRequest about the certificate with that serial (hex) the CA certificate issuer
    (x509.Certificate) issued: one SHA-1 CertID, no nonce, unsigned."""
    builder = ocsp.OCSPRequestBuilder().add_certificate_by_hash(name_hash(issuer), key_hash(issuer),
                                                                int(serial.replace(":", ""), 16), hashes.SHA1())
    return builder.build().public_bytes(serialization.Encoding.DER)


def ocsp_get_url(url, request):
    """The GET form of an OCSP request (RFC 6960 A.1): the responder's URL, '/', the request's base64 URL-encoded."""
    return f"{url.rstrip('/')}/{urllib.parse.quote(base64.b64encode(request).decode('ascii'), safe='')}"


def export_path(authority, endpoint):
    """Where an endpoint's answer is in the export: <CA name>/<endpoint name>.json."""
    return f"{rdn_value(authority)}/{rdn_value(endpoint)}.json"


def _ocsp(d, authority, url):
    cas = signing_certificates(d, authority)
    if not cas:
        return None, "the record holds no certificate of the CA (PEM) to build the request with", None
    serial, which = probe_serial(d, authority)
    if serial is None:
        return None, which, None
    try:
        return ocsp_get_url(url, ocsp_request(cas[0][1], serial)), None, serial
    except ValueError:
        return None, f"serial {serial} ({which}) isn't hex", None


def planned(d, authority, endpoint):
    """How the observation treats one endpoint of a CA (Planned)."""
    url, why = observable_url(endpoint)
    serial = None
    if url is not None and one(endpoint, "ciamRevocationKind") == "ocsp":
        url, why, serial = _ocsp(d, authority, url)
    return Planned(authority, endpoint, export_path(authority, endpoint), url, why, serial)


def plan(d):
    """The Planned endpoints of every CA the record holds (CRL, delta CRL and OCSP; CA issuers aren't observed)."""
    return tuple(planned(d, a, e) for a in authorities(d) for e in endpoints(d, a)
                 if one(e, "ciamRevocationKind") in OBSERVED_KINDS)
