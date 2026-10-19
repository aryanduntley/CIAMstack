"""A certificate's public facts as the record writes them, read with the cryptography library: CA-neutral, for every
CA product whose inventory gives its issued certificates as PEM (Vault PKI, EJBCA) rather than as facts, including the
revocation endpoints the CA wrote into it (what a CA whose own settings can't be read, EJBCA's over REST, is known to
publish). Pure; public material only (a PEM holding anything but certificates is refused before it gets here, core
secrets).

What a certificate says of itself beyond its DNS names is read too, for what a relying party checks (a CAC/PIV or ECA
certificate): its typed alternative names (UPN otherNames, email addresses, URIs) and identifiers recognised in them by
a known convention only (UPN_CONVENTIONS: a DoD EDIPI; never assumed: an ECA subscriber has none), its key identifiers,
basic constraints, policies and key usages, and a cross-certificate's policy mappings, which the library doesn't parse
(read here from the extension's DER). record_facts gives them as the record's attributes."""
import base64
import re
import textwrap

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

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


def _policies(cert):
    """The certificate policy OIDs a certificate asserts (its certificatePolicies extension), in its order."""
    return tuple(p.policy_identifier.dotted_string for p in _extension(cert, x509.CertificatePolicies))


# the UPN otherName (a Microsoft OID every CAC/PIV and smart card logon certificate uses)
UPN_OID = "1.3.6.1.4.1.311.20.2.3"
# identifiers a UPN carries by convention: (form, the UPN's domain, the digit counts its local part may have, how many
# leading digits are the identifier). DoD PKE documents a CAC's UPN as the EDIPI (10 digits) followed by 6 more, @mil;
# a bare 10-digit EDIPI@mil is accepted too (README Known limits)
UPN_CONVENTIONS = (("edipi", "mil", (10, 16), 10),)
# ASN.1 string types an otherName's value may be written in: UTF8String, PrintableString, IA5String
STRING_TAGS = (0x0C, 0x13, 0x16)
OID_TAG, SEQUENCE_TAG = 0x06, 0x30


def _tlv(der, at=0):
    """(tag, content, where the next element starts) of the DER element at `at`, or None when it is malformed."""
    if len(der) < at + 2:
        return None
    tag, size, start = der[at], der[at + 1], at + 2
    if size & 0x80:
        count = size & 0x7F
        if not 0 < count <= 4 or len(der) < start + count:
            return None
        size, start = int.from_bytes(der[start:start + count], "big"), start + count
    end = start + size
    return (tag, der[start:end], end) if len(der) >= end else None


def _elements(content):
    """The DER elements one after another in content ((tag, content), ...), or None when one is malformed."""
    if not content:
        return ()
    element = _tlv(content)
    if element is None:
        return None
    rest = _elements(content[element[2]:])
    return None if rest is None else (element[:2], *rest)


def _oid(content):
    """The dotted form of an OBJECT IDENTIFIER's content octets."""
    arcs, value = [], 0
    for byte in content:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if not arcs:
        return ""
    first = min(arcs[0] // 40, 2)
    return ".".join(map(str, (first, arcs[0] - 40 * first, *arcs[1:])))


def _der_text(der):
    """The text of a DER string (STRING_TAGS) that is the whole of der, or None."""
    element = _tlv(der)
    if element is None or element[0] not in STRING_TAGS or element[2] != len(der):
        return None
    try:
        return element[1].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _alt(cert, kind):
    alt = _extension(cert, x509.SubjectAlternativeName)
    return tuple(alt.get_values_for_type(kind)) if alt else ()


def _upns(cert):
    """The UPNs a certificate's alternative names carry (UPN otherNames whose value is a string), in its order."""
    return tuple(t for o in _alt(cert, x509.OtherName) if o.type_id.dotted_string == UPN_OID
                 for t in (_der_text(o.value),) if t is not None)


def upn_identifiers(upns):
    """The identifiers UPNs carry by a known convention (UPN_CONVENTIONS), as '<form>:<value>', each once: only a UPN
    whose domain and local part (all digits, of a listed length) match one; none otherwise."""
    return tuple(dict.fromkeys(f"{form}:{local[:keep]}" for upn in upns for local, _, domain in (upn.rpartition("@"),)
                               for form, at, lengths, keep in UPN_CONVENTIONS
                               if domain.lower() == at and re.fullmatch(r"[0-9]+", local) and len(local) in lengths))


def _key_ids(cert):
    """(subject key identifier, authority key identifier) as lowercase hex, None where absent."""
    ski = _extension(cert, x509.SubjectKeyIdentifier)
    aki = _extension(cert, x509.AuthorityKeyIdentifier)
    return (ski.digest.hex() if ski else None,
            aki.key_identifier.hex() if aki and aki.key_identifier is not None else None)


def _constraints(cert):
    """(cA, pathLenConstraint) of a certificate's basic constraints; (None, None) without the extension."""
    bc = _extension(cert, x509.BasicConstraints)
    return (bc.ca, bc.path_length) if bc else (None, None)


def _policy_mappings(cert):
    """((issuerDomainPolicy, subjectDomainPolicy), ...) of a certificate's policy mappings extension (RFC 5280
    4.2.1.5), read from its DER; () without it or when it is malformed."""
    try:
        der = cert.extensions.get_extension_for_oid(ExtensionOID.POLICY_MAPPINGS).value
    except x509.ExtensionNotFound:
        return ()
    outer = _tlv(getattr(der, "value", b"") or b"")
    pairs = _elements(outer[1]) if outer is not None and outer[0] == SEQUENCE_TAG else None
    mapped = tuple(_elements(c) if t == SEQUENCE_TAG else None for t, c in pairs or ())
    if not pairs or any(m is None or len(m) != 2 or any(t != OID_TAG for t, _ in m) for m in mapped):
        return ()
    return tuple((_oid(a), _oid(b)) for (_, a), (_, b) in mapped)


def certificate_facts(pem):
    """{serial, sha256, subject, issuer, not_before, not_after, usages, endpoints, names, policies, upns, emails, uris,
    identifiers, ski, aki, ca, path_length, policy_mappings} of a PEM's first certificate: the serial as lowercase hex
    of even length, the SHA-256 as ciamFingerprint writes it, subject and issuer as RFC 4514 strings, validity as
    GeneralizedTime, its extended key usages as OIDs (None when it has no such extension), the revocation endpoints it
    names ((kind, url), ...: crl, delta-crl, ocsp, ca-issuers) and the DNS names and IP addresses it names (subject
    common names, then alternative names: ciamCertificateName's) and the certificate policy OIDs it asserts; its
    alternative names' UPNs, email addresses and URIs, the identifiers recognised in its UPNs (upn_identifiers), its
    subject and authority key identifiers (lowercase hex, None when absent), its basic constraints (ca, path_length:
    None without the extension; path_length None: no limit) and its policy mappings ((issuer's OID, subject's OID),
    ...); None when the text holds no certificate."""
    cert = load_certificate(pem) if isinstance(pem, str) else None
    if cert is None:
        return None
    upns = _upns(cert)
    (ski, aki), (ca, path_length) = _key_ids(cert), _constraints(cert)
    return {"serial": serial_hex(cert.serial_number), "sha256": pem_fingerprint(pem),
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": gtime(cert.not_valid_before_utc), "not_after": gtime(cert.not_valid_after_utc),
            "usages": _usages(cert), "endpoints": _endpoints(cert), "names": _names(cert), "policies": _policies(cert),
            "upns": upns, "emails": _alt(cert, x509.RFC822Name), "uris": _alt(cert, x509.UniformResourceIdentifier),
            "identifiers": upn_identifiers(upns), "ski": ski, "aki": aki, "ca": ca, "path_length": path_length,
            "policy_mappings": _policy_mappings(cert)}


def _maybe(v):
    return (v,) if v is not None else ()


def record_facts(facts):
    """The record's attributes of a certificate's facts (certificate_facts'), {attribute: tuple of values}: subject,
    issuer, validity, serial and fingerprint, policies, extended key usages, typed alternative names and the identifiers
    recognised in them, key identifiers, basic constraints (TRUE/FALSE, a path length) and policy mappings
    (issuer=subject); () where the certificate carries none."""
    return {"ciamSubject": (facts["subject"],), "ciamIssuer": (facts["issuer"],),
            "ciamNotBefore": (facts["not_before"],), "ciamNotAfter": (facts["not_after"],),
            "ciamSerialNumber": (facts["serial"],), "ciamFingerprint": (facts["sha256"],),
            "ciamCertPolicyOid": tuple(facts["policies"]), "ciamExtendedKeyUsage": tuple(facts["usages"] or ()),
            "ciamSanUpn": tuple(facts["upns"]), "ciamSanEmail": tuple(facts["emails"]),
            "ciamSanUri": tuple(facts["uris"]), "ciamSubjectIdentifier": tuple(facts["identifiers"]),
            "ciamSubjectKeyId": _maybe(facts["ski"]), "ciamAuthorityKeyId": _maybe(facts["aki"]),
            "ciamIsCa": _maybe(None if facts["ca"] is None else "TRUE" if facts["ca"] else "FALSE"),
            "ciamPathLength": _maybe(None if facts["path_length"] is None else str(facts["path_length"])),
            "ciamPolicyMapping": tuple(f"{a}={b}" for a, b in facts["policy_mappings"])}
