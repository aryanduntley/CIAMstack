"""Certificate chains as the record holds them: the CA certificates a certificate is issued under, and what a client
that doesn't already trust them must be given (a synthetic check of a service whose certificate a private CA issued).
Pure.

A certificate's issuer is the certificate it names (ciamIssuedBy), else the CA certificate (purpose ca) the record holds
whose subject is its issuer (ciamIssuer); the chain runs issuer by issuer up to a self-issued certificate (its issuer
is its subject, or 'self-signed') or the last one the record holds. A CA's certificate is public material: the record
holds it (ciamCertificatePem; never a key: SPEC R4 covers keys and secrets), and its PEM is what a client is given,
added to the client's own trust store, never replacing it (a public root recorded here is harmless to add). When no
self-issued certificate is among the PEMs given, the client trusts the intermediate CA it is given as its anchor
(partial chain). A CA rotation is a record change: its new certificate recorded, what trusts it re-rendered.
"""
from typing import NamedTuple

from ...core.directory import children, follow, norm_dn, one
from .issued import AUTHORITY_CLASS, authority_of
from .naming import AUTHORITIES, CERTIFICATES
from .pem import certificate_pem

SELF_SIGNED = "self-signed"

# What a client is given to trust a certificate chaining to CA certificates the record holds: the recorded PEMs along
# the chain joined (None when none is recorded), whether an intermediate CA is the anchor (no self-issued certificate
# among them), the chain (CA certificate entries, nearest first) and the CA the certificate was issued by
# (ciamCertAuthority, or None).
Trust = NamedTuple("Trust", [("pem", object), ("partial", bool), ("chain", tuple), ("authority", object)])


def ca_certificates(d):
    """The CA certificates the record holds (purpose ca), in record order."""
    return tuple(c for c in children(d, CERTIFICATES, "ciamCertificate") if one(c, "ciamCertPurpose") == "ca")


def self_issued(cert):
    """Whether a certificate is self-issued (a root): its issuer is its subject, or 'self-signed'."""
    issuer = one(cert, "ciamIssuer") or ""
    subject = one(cert, "ciamSubject") or ""
    return issuer.lower() == SELF_SIGNED or (bool(issuer) and norm_dn(issuer) == norm_dn(subject))


def issuer_certificate(d, cert, cas=None):
    """The certificate cert was issued by, as the record holds it (its ciamIssuedBy, else the CA certificate whose
    subject is its ciamIssuer), or None (self-issued, or an issuer the record doesn't hold)."""
    if self_issued(cert):
        return None
    named = follow(d, cert, "ciamIssuedBy")
    if named is not None:
        return named
    issuer = norm_dn(one(cert, "ciamIssuer") or "")
    return next((c for c in (ca_certificates(d) if cas is None else cas)
                 if issuer and c.norm != cert.norm and norm_dn(one(c, "ciamSubject") or "") == issuer), None)


def issuer_chain(d, cert):
    """The CA certificates cert is issued under, nearest first, as far as the record holds them; () when it holds
    none. A loop in the record's links ends the chain."""
    cas = ca_certificates(d)

    def up(c, chain):
        nxt = issuer_certificate(d, c, cas)
        seen = {cert.norm, *(x.norm for x in chain)}
        return chain if nxt is None or nxt.norm in seen else up(nxt, (*chain, nxt))
    return up(cert, ())


def trust_for(d, cert):
    """The Trust a client needs for a certificate whose chain reaches CA certificates the record holds, else None (no
    certificate, or an issuer the record doesn't hold: the client's own trust store decides)."""
    chain = issuer_chain(d, cert) if cert is not None else ()
    if not chain:
        return None
    given = tuple((c, certificate_pem(c)) for c in chain)
    pems = tuple(pem.strip() + "\n" for _, pem in given if pem)
    authority = authority_of(d, cert, children(d, AUTHORITIES, AUTHORITY_CLASS))
    return Trust("".join(pems) or None, bool(pems) and not any(self_issued(c) for c, pem in given if pem), chain,
                 authority)
