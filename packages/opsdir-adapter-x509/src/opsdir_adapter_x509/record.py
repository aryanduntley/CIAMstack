"""The certificates importer (x509/certificates): what certificates say of themselves, read with the cryptography
library (certificates.py) into the record, and the cross-certificates among them recognised (core domains.pki.pem,
domains.pki.cross).

It reads every record certificate (ou=certificates) whose PEM the record holds (ciamCertificatePem, its first
certificate the one its fingerprint names), and any PEM files given (certificates only: a file holding a private key
isn't read): a given certificate with a record certificate's fingerprint stands in for the PEM the record lacks. Each
record certificate read gets what it says of itself (pem.PEM_FACTS: typed alternative names and the identifiers
recognised in them, key identifiers, basic constraints, policies, key usages; subject, issuer, validity start and serial
where the record holds none), entry by entry: nothing else the record holds on it changes.

A cross-certificate is a CA certificate whose issuer is another CA and whose subject is a root the record holds (a
self-issued CA certificate under ou=certificates, or a root a trust bundle holds: cross.certified_root), or one already
recorded under ou=cross-certificates with its fingerprint: it is recorded there with its facts and PEM (its role and
owners, the record's, kept). One the record also holds under ou=certificates is named in the notices (the planner asks
for its removal). A given certificate that is neither is left out, with a notice. Pure: reading the files and the
record."""
import re

from opsdir.core.contract import Importer, Imported
from opsdir.core.directory import children, fingerprint, one, ou_entry, rdn_value
from opsdir.domains.pki.cross import CROSS_FACTS, certified_root, cross_certificates, cross_entry, cross_name, cross_of
from opsdir.domains.pki.naming import CERTIFICATES, CROSS_CERTIFICATES
from opsdir.domains.pki.pem import certificate_pem, pem_fingerprint, with_pem_facts

from .certificates import certificate_facts, record_facts

PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
KEY_MARK = "PRIVATE KEY-----"


def pem_blocks(text):
    """The PEM certificates a text holds, each as its own PEM text, in order."""
    return tuple(m.group(0) + "\n" for m in PEM_BLOCK.finditer(text or ""))


def _given(files):
    """(((path, PEM), ...) of the certificates the files hold, notices for the files not read)."""
    keyed = tuple(p for p, t in sorted(files.items()) if KEY_MARK in (t or ""))
    read = tuple((p, b) for p, t in sorted(files.items()) if p not in keyed for b in pem_blocks(t))
    empty = tuple(p for p, t in sorted(files.items()) if p not in keyed and not pem_blocks(t))
    return read, (*(f"{p}: holds a private key: not read (give certificates only)" for p in keyed),
                  *(f"{p}: holds no PEM certificate: not read" for p in empty))


def _sha(pem):
    return fingerprint(pem_fingerprint(pem))


def own_pem(c):
    """An entry's recorded PEM when its first certificate is the one its fingerprint names, else None."""
    pem = certificate_pem(c)
    return pem if pem and _sha(pem) == fingerprint(one(c, "ciamFingerprint") or "") else None


def _cross(d, pem, facts):
    """The cross-certificate entry a certificate is (facts: certificate_facts'), or None when it is none."""
    known = cross_of(d, facts["sha256"])
    if known is None and certified_root(d, facts["subject"], facts["issuer"], facts["ca"]) is None:
        return None
    owned = {k: v for k, v in record_facts(facts).items() if k in CROSS_FACTS}
    return cross_entry(d, cross_name(d, facts["subject"], facts["issuer"], facts["sha256"]),
                       {**owned, "ciamCertificatePem": (pem.strip() + "\n",)})


def read_certificates(files, d, patterns, at=None):
    """Imported: each record certificate read from its PEM (its own, else a given file's) given what it says of itself,
    and the cross-certificates among the record's certificates, the recorded cross-certificates' PEMs and the files
    recorded under ou=cross-certificates, entry by entry; given certificates that are neither left out with a
    notice."""
    given, notices = _given(files)
    by_sha = {_sha(b): (p, b) for p, b in given}
    certs = children(d, CERTIFICATES, "ciamCertificate")
    pems = {c.norm: own_pem(c) or by_sha.get(fingerprint(one(c, "ciamFingerprint") or ""), (None, None))[1]
            for c in certs}
    facts = {pem: certificate_facts(pem) for pem in (*pems.values(), *(b for _, b in given),
                                                    *(own_pem(x) for x in cross_certificates(d))) if pem}
    read = tuple((c, pems[c.norm]) for c in certs if pems[c.norm] and facts[pems[c.norm]])
    updated = tuple(with_pem_facts(c, record_facts(facts[pem])) for c, pem in read)
    candidates = {_sha(pem): pem for pem in facts if facts[pem]}
    crosses = {sha: x for sha, pem in candidates.items() for x in (_cross(d, pem, facts[pem]),) if x is not None}
    held = tuple((c, crosses[_sha(pem)]) for c, pem in read if _sha(pem) in crosses)
    record = {fingerprint(one(c, "ciamFingerprint") or "") for c in certs}
    strays = tuple((p, b) for p, b in given if _sha(b) not in record and _sha(b) not in crosses)
    return Imported(
        containers=(ou_entry(CROSS_CERTIFICATES),) if crosses else (),
        groups=tuple((e.dn, (e,)) for e in (*updated, *crosses.values())),
        notices=(f"certificates: {len(read)} record certificate(s) read from their PEM "
                 f"({sum(1 for c, pem in read if pem != own_pem(c))} from the files given), {len(crosses)} "
                 "cross-certificate(s)",
                 *notices,
                 *(f"{rdn_value(c)}: a cross-certificate ({one(x, 'ciamIssuer')} -> {one(x, 'ciamSubject')}), recorded "
                   f"as `{rdn_value(x)}` under ou=cross-certificates: remove it from ou=certificates" for c, x in held),
                 *(f"{p}: {facts[b]['subject'] if facts[b] else 'a certificate'} (SHA-256 {_sha(b)}) is neither a "
                   "record certificate nor a cross-certificate of a root the record holds: left out"
                   for p, b in strays)))


CERTIFICATES_IMPORTER = Importer("certificates", "What the record's certificates say of themselves (typed alternative "
                                                 "names, key identifiers, basic constraints, policies, key usages), "
                                                 "read from their recorded PEMs and any PEM files given, and the "
                                                 "cross-certificates among them", read_certificates, reference=True)
