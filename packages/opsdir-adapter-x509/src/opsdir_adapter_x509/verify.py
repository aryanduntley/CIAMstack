"""What a revocation endpoint served, read and checked against the CA certificates the record holds (RFC 5280 CRLs,
RFC 6960 OCSP responses), with the cryptography library: pure functions of bytes and certificates, never a network
call. Each gives the facts the core records of an endpoint's answer (domains.pki.revocation FACTS).

A CRL is the CA's when its issuer is one of the CA's certificates' subject and that certificate's key verifies its
signature (and, when the certificate says how its key may be used, it may sign CRLs): else invalid, or other-issuer
when no CA certificate has its issuer's name (an indirect CRL counts as another issuer). An OCSP response is the CA's
when the CA's own key signed it, or a responder certificate in the response that the CA issued directly for OCSP
signing (id-kp-OCSPSigning), valid when the response was produced, signed it: else unauthorized-responder, or invalid.
RSA-PSS-signed OCSP responses aren't verified (the library doesn't give their parameters): unsupported, as is any key
type it can't verify with. Signatures are checked as evidence of what the endpoint serves, never as a trust decision
for the platform."""
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, SignatureAlgorithmOID

from opsdir.core.directory import gtime

PEM_CRL = b"-----BEGIN X509 CRL-----"
OCSP_STATUSES = {ocsp.OCSPResponseStatus.MALFORMED_REQUEST: "malformedRequest",
                 ocsp.OCSPResponseStatus.INTERNAL_ERROR: "internalError",
                 ocsp.OCSPResponseStatus.TRY_LATER: "tryLater",
                 ocsp.OCSPResponseStatus.SIG_REQUIRED: "sigRequired",
                 ocsp.OCSPResponseStatus.UNAUTHORIZED: "unauthorized"}
CERT_STATUSES = {ocsp.OCSPCertStatus.GOOD: "good", ocsp.OCSPCertStatus.REVOKED: "revoked",
                 ocsp.OCSPCertStatus.UNKNOWN: "unknown"}


def load_certificate(pem):
    """The first certificate of a PEM text as an x509.Certificate, or None when it isn't one."""
    try:
        return x509.load_pem_x509_certificate(pem.encode())
    except (ValueError, TypeError, AttributeError):
        return None


def serial_hex(n):
    """A serial number (int) as the record writes it: lowercase hex, even length."""
    text = f"{n:x}"
    return text if len(text) % 2 == 0 else "0" + text


def key_hash(cert):
    """SHA-1 of a certificate's subjectPublicKey bits (RFC 6960 CertID issuerKeyHash, RFC 5280 key identifier method
    1)."""
    return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest


def name_hash(cert):
    """SHA-1 of a certificate's DER subject name (RFC 6960 CertID issuerNameHash, as its issuer)."""
    return hashlib.sha1(cert.subject.public_bytes(), usedforsecurity=False).digest()


def _may_sign_crls(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign
    except x509.ExtensionNotFound:
        return True


def _crl_signature(crl, cas):
    """(check, the signing CA certificate (entry, cert) or None, detail)."""
    if not cas:
        return "no-ca-certificate", None, None
    named = tuple((e, c) for e, c in cas if c.subject == crl.issuer)
    if not named:
        return "other-issuer", None, f"issued by {crl.issuer.rfc4514_string()}"
    try:
        signer = next(((e, c) for e, c in named if crl.is_signature_valid(c.public_key())), None)
    except (UnsupportedAlgorithm, TypeError, ValueError) as err:
        return "unsupported", None, f"signature not verifiable here ({type(err).__name__})"
    if signer is None:
        return "invalid", None, None
    if not _may_sign_crls(signer[1]):
        return "invalid", signer, "the CA certificate's key usage doesn't include CRL signing"
    return "valid", signer, None


def _number(crl, kind):
    try:
        return str(crl.extensions.get_extension_for_class(kind).value.crl_number)
    except x509.ExtensionNotFound:
        return None


def crl_facts(body, cas):
    """The facts of a CRL an endpoint served (DER, or PEM), checked against cas ((record entry, x509.Certificate),
    ...: the CA's own certificates): answered with its update times, numbers and signature check, else unreadable."""
    try:
        crl = (x509.load_pem_x509_crl(body) if body.lstrip().startswith(PEM_CRL) else x509.load_der_x509_crl(body))
        this, nxt = crl.last_update_utc, crl.next_update_utc
    except ValueError as err:
        return {"ciamEndpointAnswer": "unreadable", "ciamInventoryProblem": (f"not a CRL ({err})",)}
    check, signer, detail = _crl_signature(crl, cas)
    return {"ciamEndpointAnswer": "answered", "ciamThisUpdate": gtime(this),
            "ciamNextUpdate": gtime(nxt) if nxt else None, "ciamCrlNumber": _number(crl, x509.CRLNumber),
            "ciamBaseCrlNumber": _number(crl, x509.DeltaCRLIndicator), "ciamSignatureCheck": check,
            "ciamSignedBy": signer[0].dn if signer else None, "ciamInventoryProblem": (detail,) if detail else ()}


def _verified(response, key):
    """'valid', 'invalid' or 'unsupported': whether key signed the response."""
    data, signature, hashed = response.tbs_response_bytes, response.signature, response.signature_hash_algorithm
    try:
        if isinstance(key, rsa.RSAPublicKey):
            if response.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
                return "unsupported"
            key.verify(signature, data, padding.PKCS1v15(), hashed)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(hashed))
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(signature, data)
        else:
            return "unsupported"
    except InvalidSignature:
        return "invalid"
    except (UnsupportedAlgorithm, TypeError, ValueError):
        return "unsupported"
    return "valid"


def _names_responder(response, cert):
    if response.responder_key_hash is not None:
        return key_hash(cert) == response.responder_key_hash
    return cert.subject == response.responder_name


def _delegated_by(cert, ca, at):
    """Whether cert is an OCSP responder certificate ca issued directly, valid at `at`."""
    try:
        cert.verify_directly_issued_by(ca)
        usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound):
        return False
    return (ExtendedKeyUsageOID.OCSP_SIGNING in usages
            and cert.not_valid_before_utc <= at <= cert.not_valid_after_utc)


def _ocsp_signature(response, cas):
    """(check, the CA certificate entry whose key verified it, directly or through its responder, or None, detail)."""
    if not cas:
        return "no-ca-certificate", None, None
    direct = next(((e, c) for e, c in cas if _names_responder(response, c)), None)
    if direct is not None:
        check = _verified(response, direct[1].public_key())
        return check, direct[0] if check == "valid" else None, None
    responders = tuple(r for r in response.certificates if _names_responder(response, r))
    delegated = next(((e, r) for r in responders for e, c in cas if _delegated_by(r, c, response.produced_at_utc)),
                     None)
    if delegated is None:
        named = responders[0].subject.rfc4514_string() if responders else "a responder not in the response"
        return "unauthorized-responder", None, f"signed by {named}"
    check = _verified(response, delegated[1].public_key())
    return check, delegated[0] if check == "valid" else None, \
        f"through responder certificate {delegated[1].subject.rfc4514_string()}"


def ocsp_facts(body, cas, serial=None):
    """The facts of an OCSP responder's answer (DER) to a request about one certificate, checked against cas: its
    status (a response that isn't successful: its status, about serial, the certificate asked about), the certificate's
    status, update times and serial, and the signature check; unreadable when it isn't an OCSP response."""
    try:
        response = ocsp.load_der_ocsp_response(body)
    except ValueError as err:
        return {"ciamEndpointAnswer": "unreadable", "ciamInventoryProblem": (f"not an OCSP response ({err})",)}
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return {"ciamEndpointAnswer": "answered", "ciamOcspStatus": OCSP_STATUSES[response.response_status],
                "ciamSerialNumber": serial}
    try:
        this, nxt, status, asked = (response.this_update_utc, response.next_update_utc, response.certificate_status,
                                    response.serial_number)
    except ValueError as err:                       # more than one certificate answered: not what was asked
        return {"ciamEndpointAnswer": "unreadable", "ciamInventoryProblem": (f"not one answer ({err})",),
                "ciamSerialNumber": serial}
    check, signer, detail = _ocsp_signature(response, cas)
    return {"ciamEndpointAnswer": "answered", "ciamThisUpdate": gtime(this),
            "ciamNextUpdate": gtime(nxt) if nxt else None, "ciamOcspStatus": CERT_STATUSES[status],
            "ciamSerialNumber": serial_hex(asked), "ciamSignatureCheck": check,
            "ciamSignedBy": signer.dn if signer is not None else None,
            "ciamInventoryProblem": (detail,) if detail else ()}
