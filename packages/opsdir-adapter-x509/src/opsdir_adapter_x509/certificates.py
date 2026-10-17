"""A certificate's public facts as the record writes them, read with the cryptography library: CA-neutral, for every
CA product whose inventory gives its issued certificates as PEM (Vault PKI) rather than as facts. Pure; public
material only (a PEM holding anything but certificates is refused before it gets here, core secrets)."""
from cryptography import x509

from opsdir.core.directory import gtime
from opsdir.domains.pki.pem import pem_fingerprint
from .verify import load_certificate, serial_hex


def _usages(cert):
    try:
        return tuple(u.dotted_string for u in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        return None


def certificate_facts(pem):
    """{serial, sha256, subject, issuer, not_before, not_after, usages} of a PEM's first certificate: the serial as
    lowercase hex of even length, the SHA-256 as ciamFingerprint writes it, subject and issuer as RFC 4514 strings,
    validity as GeneralizedTime, and its extended key usages as OIDs (None when it has no such extension); None when
    the text holds no certificate."""
    cert = load_certificate(pem) if isinstance(pem, str) else None
    if cert is None:
        return None
    return {"serial": serial_hex(cert.serial_number), "sha256": pem_fingerprint(pem),
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": gtime(cert.not_valid_before_utc), "not_after": gtime(cert.not_valid_after_utc),
            "usages": _usages(cert)}
