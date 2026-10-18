"""DISA PKE trust bundles (the importer `dod-pki/bundle`): each bundle the exporter wrote (dod-pki/<bundle>.json, from
the archive DISA distributes: export.py) read into the core pki domain's trust bundles (domains.pki.trust), its CA
certificates as the bundle's children, public facts only. Pure.

Its verification is judged here, from what the exporter found:
- failed: the manifest's signature didn't verify, the signer chain isn't a root alone or with one CA it issued
  (the archive's README says what it must hold), the combined bundle isn't in the manifest, a listed file is missing
  or its digest differs, or the signature couldn't be checked at all (openssl missing: nothing then covers the
  files);
- signed-unanchored: all of that holds, but the chain's root isn't a CA certificate the record holds (compare its
  SHA-1 with the one crl.disa.mil publishes, as the README says, then approve the root as an anchor: the next import is
  verified);
- verified: the chain's root is one the record holds (purpose ca, matched by SHA-256).
A per-root bundle file the manifest doesn't list is a problem but doesn't fail the bundle (its certificates come from
the combined file, which must be listed). The import time is --at, else when the exporter ran.

A CA certificate is named after its subject's common name (DOD ID CA-81), with the start of its fingerprint added when
two in the bundle share one; a root is a certificate whose subject is its issuer. Its root group is the per-root file
it came in (DoD Root CA 6). A certificate the cryptography library refuses (DoD Root CA 4, whose signature algorithm
isn't strict DER) is read from the facts the exporter took with openssl, without its certificate policies."""
import datetime as dt
from collections import Counter

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import children, fingerprint, gtime, norm_dn, one, ou_entry
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.pki.issued import common_name
from opsdir.domains.pki.naming import CERTIFICATES, TRUST_BUNDLES
from opsdir.domains.pki.trust import (DIGESTS_ONLY, FAILED, UNANCHORED, VERIFIED, bundle_entry, bundle_group,
                                      member_entry)
from opsdir_adapter_x509.certificates import certificate_facts

ROOT = "dod-pki/"


def _documents(files):
    return tuple((p, json_document(files[p], dict)) for p in sorted(files)
                 if p.startswith(ROOT) and p.endswith(".json") and "/" not in p[len(ROOT):])


def chain_shape_ok(chain):
    """Whether the archive's signer chain is what its README requires: a self-issued root first, then at most one CA
    that root issued (the DoD archive ships the root and the signer's CA; the ECA archive the root alone, the CA
    travelling in the signature)."""
    subject = lambda c: norm_dn(c.get("subject") or "")         # noqa: E731
    issuer = lambda c: norm_dn(c.get("issuer") or "")           # noqa: E731
    return (1 <= len(chain) <= 2 and subject(chain[0]) == issuer(chain[0])
            and all(issuer(c) == subject(chain[0]) and subject(c) != subject(chain[0]) for c in chain[1:]))


def integrity_problems(doc):
    """What fails a bundle's integrity: the signature, the signer chain, the manifest's coverage and digests."""
    m, chain = doc.get("manifest") or {}, doc.get("chain") or []
    files = m.get("files") or []
    listed = {f.get("name") for f in files}
    status = m.get("signature")
    return (*((f"the manifest's signature doesn't verify: {m.get('error') or 'openssl refused it'}",)
              if status == "invalid" else ()),
            *((f"the manifest's signature wasn't checked ({m.get('error') or 'no reason given'}), so nothing covers "
               "the files",) if status not in ("valid", "invalid") else ()),
            *(("the signer chain isn't a DoD root alone or with one CA it issued (what the archive's README requires)",)
              if status == "valid" and not chain_shape_ok(chain) else ()),
            *((f"the combined bundle {doc.get('combined')} isn't in the manifest",)
              if status == "valid" and doc.get("combined") not in listed else ()),
            *(f"{f.get('name')} is listed in the manifest but not in the archive" for f in files
              if f.get("actual") is None),
            *(f"{f.get('name')}'s SHA-256 differs from the manifest's" for f in files
              if f.get("actual") is not None and f.get("actual") != f.get("listed")))


def verification(d, doc, problems):
    """The bundle's verification: failed on any integrity problem, else verified when the signer chain's root is a CA
    certificate the record holds, else signed-unanchored (digests-only when a manifest was matched unsigned: not a
    form DISA publishes)."""
    if problems:
        return FAILED
    if (doc.get("manifest") or {}).get("signature") != "valid":
        return DIGESTS_ONLY
    root = fingerprint((doc.get("chain") or [{}])[0].get("sha256") or "")
    held = {fingerprint(one(c, "ciamFingerprint") or "") for c in children(d, CERTIFICATES, "ciamCertificate")
            if one(c, "ciamCertPurpose") == "ca"}
    return VERIFIED if root and root in held else UNANCHORED


def _facts(cert):
    """A certificate's facts: the cryptography library's reading, else the exporter's openssl reading (no policies)."""
    f = certificate_facts(cert.get("pem"))
    given = cert.get("facts")
    if f is not None or not isinstance(given, dict) or not all(
            isinstance(given.get(k), str) for k in ("subject", "issuer", "not_before", "not_after", "serial",
                                                     "sha256")):
        return f
    return {**given, "sha256": fingerprint(given["sha256"]), "policies": ()}


def _member_facts(cert):
    f = _facts(cert)
    if f is None:
        return None
    return {"ciamFingerprint": f["sha256"], "ciamNotAfter": f["not_after"], "ciamNotBefore": f["not_before"],
            "ciamSubject": f["subject"], "ciamIssuer": f["issuer"], "ciamSerialNumber": f["serial"],
            "ciamCaType": "root" if norm_dn(f["subject"]) == norm_dn(f["issuer"]) else "subordinate",
            "ciamCertificatePem": cert.get("pem").strip() + "\n", "ciamCertPolicyOid": tuple(f["policies"]),
            "ciamBundleGroup": cert.get("group")}


def member_names(facts):
    """Each certificate's entry name: its subject's common name, with the first eight hex digits of its fingerprint
    added when another certificate of the bundle shares it (or it has none usable)."""
    base = [common_name(f["ciamSubject"]) for f in facts]
    counts = Counter(base)
    tag = lambda f: fingerprint(f["ciamFingerprint"]).replace(":", "")[:8]      # noqa: E731
    return tuple(b if b and rdn_safe(b) and counts[b] == 1 else f"{b if b and rdn_safe(b) else 'CA'} {tag(f)}"
                 for b, f in zip(base, facts))


def _when(doc, at):
    if at is not None:
        return gtime(at)
    try:
        return gtime(dt.datetime.fromisoformat(doc.get("exported_at") or ""))
    except ValueError:
        return None


def _read(d, path, doc, at):
    """(groups, notices) of one exported bundle."""
    if doc is None or not doc.get("bundle") or not rdn_safe(doc.get("bundle")):
        return (), (f"{path}: not a bundle export (python -m opsdir_adapter_dod_pki.export writes them)",)
    when = _when(doc, at)
    if when is None:
        return (), (f"{path}: no time to date it by: give --at (when the archive was downloaded)",)
    problems = integrity_problems(doc)
    state = verification(d, doc, problems)
    unreadable = sum(1 for c in doc.get("certificates") or [] if _facts(c) is None)
    facts = tuple(f for f in (_member_facts(c) for c in doc.get("certificates") or []) if f is not None)
    chain = doc.get("chain") or []
    bundle = bundle_entry(d, doc["bundle"], when, state, {
        "ciamTrustBundleRelease": doc.get("version"), "ciamBundleSource": doc.get("source"),
        "ciamBundleDigest": doc.get("archive_sha256"),
        "ciamBundleSigner": (doc.get("manifest") or {}).get("signer_sha256"),
        "ciamSignerAnchor": chain[0].get("sha256") if chain else None,
        "ciamInventoryProblem": tuple((*problems,
                                       *(f"{n} isn't covered by the manifest" for n in doc.get("unlisted") or []),
                                       *((f"{unreadable} certificates in the bundle couldn't be read",)
                                         if unreadable else ()))) or None,
        "ciamProviderRef": doc.get("combined")})
    members = tuple(member_entry(d, bundle, n, f) for n, f in zip(member_names(facts), facts))
    notice = {FAILED: f"{doc['bundle']} {doc.get('version')}: integrity check failed ({'; '.join(problems)}); "
                      "its CA certificates are recorded but nothing is proposed from it",
              UNANCHORED: f"{doc['bundle']} {doc.get('version')}: signed under a root the record doesn't hold yet "
                          f"({chain[0].get('subject') if chain else '?'}, SHA-1 {doc.get('chain_root_sha1')}): "
                          "compare that SHA-1 with crl.disa.mil before approving it as an anchor"}.get(state)
    return (bundle_group(bundle, members),), ((notice,) if notice else ())


def read_bundles(files, d, patterns, at=None):
    """Imported: each exported bundle with its CA certificates, each replacing the record's bundle of that name."""
    read = tuple(_read(d, p, doc, at) for p, doc in _documents(files))
    groups = tuple(g for gs, _ in read for g in gs)
    notices = tuple(n for _, ns in read for n in ns)
    return Imported(containers=(ou_entry(TRUST_BUNDLES),), groups=groups,
                    notices=notices if read else ("no bundle exports (dod-pki/<bundle>.json, as python -m "
                                                  "opsdir_adapter_dod_pki.export writes them)",))


BUNDLE_IMPORTER = Importer("bundle", "DISA's DoD PKE trust bundles (DoD, ECA, JITC, WCF): CA certificates and how the "
                                     "bundle's signed manifest verified (python -m opsdir_adapter_dod_pki.export "
                                     "turns a downloaded archive into the export)", read_bundles, reference=True)
