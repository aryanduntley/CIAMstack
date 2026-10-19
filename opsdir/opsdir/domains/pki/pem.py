"""Certificates recorded as PEM (ciamCertificatePem): public material, recorded for a CA something must be given to
trust (a cluster gateway checking its backends' certificates). Never a key: the store's secret guard refuses private
keys, and a value that isn't nothing but certificates isn't used. The planner's check names a PEM that isn't usable,
or whose first certificate isn't the one the entry's facts describe (its SHA-256 differs from ciamFingerprint). Pure.
"""
import base64
import hashlib
import re

from ...core.directory import children, make_entry, merged_attrs, one, rdn_value, values
from ...core.findings import findings, owner_label
from ...core.secrets import certificates_only
from .naming import CERTIFICATES

_FIRST = re.compile(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----")
# What a certificate says of itself, as a reader of its PEM (opsdir-adapter-x509) writes it on its record entry: its
# policies, key usages, typed alternative names (and identifiers derived from them), key identifiers and basic
# constraints. Facts it doesn't carry are removed: the certificate is the source.
PEM_FACTS = ("ciamCertPolicyOid", "ciamExtendedKeyUsage", "ciamSanUpn", "ciamSanEmail", "ciamSanUri",
             "ciamSubjectIdentifier", "ciamSubjectKeyId", "ciamAuthorityKeyId", "ciamIsCa", "ciamPathLength")
# facts a reader fills in only where the record holds none (an operator's value is kept)
PEM_BASICS = ("ciamSubject", "ciamIssuer", "ciamNotBefore", "ciamSerialNumber")


def certificate_pem(c):
    """Certificate entry c's recorded PEM when it is nothing but PEM certificates, else None."""
    pem = one(c, "ciamCertificatePem") if c is not None else None
    return pem if certificates_only(pem) else None


def _digest(pem, algorithm):
    der = base64.b64decode("".join(_FIRST.search(pem).group(1).split()))
    digest = hashlib.new(algorithm, der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def pem_fingerprint(pem):
    """The SHA-256 fingerprint of a PEM's first certificate, as colon-separated upper-case hex (ciamFingerprint's
    form)."""
    return _digest(pem, "sha256")


def pem_thumbprint(pem):
    """The SHA-1 thumbprint of a PEM's first certificate, as colon-separated upper-case hex (ciamThumbprint's form):
    what a certificate manager that gives no SHA-256 is matched by."""
    return _digest(pem, "sha1")


def with_pem_facts(c, facts):
    """Certificate entry c with what its PEM says of itself: facts {attribute: tuple of values} replace its PEM_FACTS
    (one the certificate doesn't carry removed) and fill the PEM_BASICS it holds none of; everything else kept."""
    owned = {**{k: tuple(facts.get(k) or ()) for k in PEM_FACTS},
             **{k: tuple(facts[k]) for k in PEM_BASICS if facts.get(k) and not values(c, k)}}
    return make_entry(c.dn, c.classes, merged_attrs(c, owned, tuple(owned)))


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
