"""A certificate's public facts as the record writes them, read with the cryptography library: CA-neutral, for every
CA product whose inventory gives its issued certificates as PEM (Vault PKI, EJBCA) rather than as facts, including the
revocation endpoints the CA wrote into it (what a CA whose own settings can't be read, EJBCA's over REST, is known to
publish). Pure; public material only (a PEM holding anything but certificates is refused before it gets here, core
secrets)."""
import base64
import textwrap

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from opsdir.core.directory import gtime
from opsdir.domains.pki.pem import pem_fingerprint
from .verify import load_certificate, serial_hex


def _usages(cert):
    try:
        return tuple(u.dotted_string for u in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        return None


# (the record's revocation endpoint kind, an access method of the Authority Information Access extension)
AIA_KINDS = (("ocsp", AuthorityInformationAccessOID.OCSP), ("ca-issuers", AuthorityInformationAccessOID.CA_ISSUERS))


def _extension(cert, kind):
    try:
        return cert.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return ()


def _uris(names):
    return tuple(n.value for n in names or () if isinstance(n, x509.UniformResourceIdentifier))


def _endpoints(cert):
    """((kind, url), ...) of the revocation endpoints a certificate names, in the record's order: its CRL distribution
    points (crl), freshest CRL (delta-crl), OCSP responders (ocsp) and CA issuers (ca-issuers), URIs only."""
    points = lambda kind: tuple(u for p in _extension(cert, kind) for u in _uris(p.full_name))     # noqa: E731
    access = _extension(cert, x509.AuthorityInformationAccess)
    return (*(("crl", u) for u in points(x509.CRLDistributionPoints)),
            *(("delta-crl", u) for u in points(x509.FreshestCRL)),
            *((kind, u) for kind, oid in AIA_KINDS for a in access if a.access_method == oid
              for u in _uris((a.access_location,))))


def _names(cert):
    """The DNS names and IP addresses a certificate names: its subject's common names, then its alternative names'
    DNS names and IP addresses, first mention kept."""
    common = tuple(a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                   if isinstance(a.value, str))
    alt = _extension(cert, x509.SubjectAlternativeName)
    listed = (*alt.get_values_for_type(x509.DNSName), *map(str, alt.get_values_for_type(x509.IPAddress))) if alt else ()
    return tuple(dict.fromkeys(n for n in (*common, *listed) if n))


def der_pem(text):
    """The PEM of a certificate given as base64 of its DER (what a store's API returns as the certificate: Key Vault's
    cer), or None when the text isn't base64 of DER."""
    try:
        raw = base64.b64decode(text or "", validate=True)
    except ValueError:
        return None
    body = base64.b64encode(raw).decode()
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(body, 64)) + "\n-----END CERTIFICATE-----\n"
            if raw[:1] == b"\x30" else None)


def certificate_facts(pem):
    """{serial, sha256, subject, issuer, not_before, not_after, usages, endpoints, names} of a PEM's first
    certificate: the serial as lowercase hex of even length, the SHA-256 as ciamFingerprint writes it, subject and
    issuer as RFC 4514 strings, validity as GeneralizedTime, its extended key usages as OIDs (None when it has no such
    extension), the revocation endpoints it names ((kind, url), ...: crl, delta-crl, ocsp, ca-issuers) and the DNS
    names and IP addresses it names (subject common names, then alternative names: ciamCertificateName's); None when
    the text holds no certificate."""
    cert = load_certificate(pem) if isinstance(pem, str) else None
    if cert is None:
        return None
    return {"serial": serial_hex(cert.serial_number), "sha256": pem_fingerprint(pem),
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": gtime(cert.not_valid_before_utc), "not_after": gtime(cert.not_valid_after_utc),
            "usages": _usages(cert), "endpoints": _endpoints(cert), "names": _names(cert)}
