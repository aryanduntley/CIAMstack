"""Certificates recorded as PEM (ciamCertificatePem): public material, recorded for a CA something must be given to
trust (a cluster gateway checking its backends' certificates). Never a key: the store's secret guard refuses private
keys, and a value that isn't nothing but certificates isn't used. The planner's check names a PEM that isn't usable,
or whose first certificate isn't the one the entry's facts describe (its SHA-256 differs from ciamFingerprint). Pure.
"""
import base64
import hashlib
import re

from ...core.directory import children, one, rdn_value
from ...core.findings import findings, owner_label
from ...core.secrets import certificates_only
from .naming import CERTIFICATES

_FIRST = re.compile(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----")


def certificate_pem(c):
    """Certificate entry c's recorded PEM when it is nothing but PEM certificates, else None."""
    pem = one(c, "ciamCertificatePem") if c is not None else None
    return pem if certificates_only(pem) else None


def pem_fingerprint(pem):
    """The SHA-256 fingerprint of a PEM's first certificate, as colon-separated upper-case hex (ciamFingerprint's
    form)."""
    der = base64.b64decode("".join(_FIRST.search(pem).group(1).split()))
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _same(a, b):
    return (a or "").replace(":", "").upper() == (b or "").replace(":", "").upper()


def _problem(c):
    if not one(c, "ciamCertificatePem"):
        return None
    pem = certificate_pem(c)
    if pem is None:
        return (f"Certificate `{rdn_value(c)}` records a PEM (ciamCertificatePem) that isn't only PEM certificates: it "
                "isn't used. Record the certificate itself (public material, never a key).")
    if not _same(pem_fingerprint(pem), one(c, "ciamFingerprint")):
        return (f"Certificate `{rdn_value(c)}` records a PEM whose first certificate (SHA-256 {pem_fingerprint(pem)}) "
                f"isn't the one its fingerprint names ({one(c, 'ciamFingerprint')}): record the right certificate, or "
                "correct the fingerprint.")
    return None


def check_certificate_pems(ctx):
    """Actions for recorded PEMs that aren't usable, or don't match the certificate's fingerprint."""
    return findings(actions=[("Certificate", text, owner_label(ctx.d, c), None)
                             for c in children(ctx.d, CERTIFICATES, "ciamCertificate")
                             for text in (_problem(c),) if text])
