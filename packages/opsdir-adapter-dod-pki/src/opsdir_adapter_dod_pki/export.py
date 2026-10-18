"""DISA PKE bundle exporter: a bundle archive as DISA distributes it (unclass-certificates_pkcs7_DoD.zip, _ECA, _JITC,
_WCF from cyber.mil's PKI/PKE tools page) turned into what the importer dod-pki/bundle reads:
<out>/dod-pki/<bundle>.json. Public material only (CA certificates and digests); nothing secret is involved.

    python -m opsdir_adapter_dod_pki.export ARCHIVE.zip [ARCHIVE.zip ...] --out DIR

What it does is what the archive's README tells an administrator to do, and nothing is judged here (the importer
judges): it checks the S/MIME (CMS) signature on the archive's manifest (certificates_pkcs7_<version>_<group>.sha256,
signed by the DoD PKE code-signing credential) with `openssl cms -verify` against the chain the archive ships
(DoD_PKE_CA_chain.pem: the DoD root, then the signer's issuing CA), takes the manifest's SHA-256 lines and computes
every file's own digest, and lists the certificates of the combined DER bundle with the root group each one's per-root
file puts it in (and, for one the cryptography library refuses, openssl's reading of its facts). It keeps the
SHA-256 of the signer's certificate and of the chain's root (and the root's SHA-1, the form crl.disa.mil publishes),
never the signer's name. openssl must be on the PATH; without it the signature is
recorded as unchecked and no certificate is read (openssl splits the PKCS#7 files).

Effects (the archive, openssl, the output files) are in main and _verify; export_document is pure."""
import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from opsdir.domains.pki.pem import pem_fingerprint, pem_thumbprint
from opsdir_adapter_x509.certificates import certificate_facts

ROOT = "dod-pki/"
# certificates_pkcs7_v5_14_dod: version 5.14 (Major_Minor[_Release]) of group dod
BASE = re.compile(r"^certificates_pkcs7_v(\d+(?:_\d+){1,2})_([a-z]+)", re.IGNORECASE)
COMBINED = re.compile(r"^certificates_pkcs7_v\d+(?:_\d+){1,2}_[a-z]+[._]der\.p7b$", re.IGNORECASE)
PER_ROOT = re.compile(r"^certificates_pkcs7_v\d+(?:_\d+){1,2}_[a-z]+_(.+?)[._]der\.p7b$", re.IGNORECASE)
MANIFEST, CHAIN = re.compile(r"\.sha256$", re.IGNORECASE), re.compile(r"_chain\.pem$", re.IGNORECASE)
LINE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$")


def _named(files, pattern):
    return sorted(n for n in files if pattern.search(PurePosixPath(n).name))


def manifest_lines(text):
    """{file name: SHA-256 hex (lower case)} of a sha256sum-style manifest (CRLF tolerated)."""
    return {m.group(2): m.group(1).lower() for m in (LINE.match(x) for x in (text or "").splitlines()) if m}


def split_pems(text):
    """The PEM certificates in a text, in order (what `openssl pkcs7 -print_certs` or a chain file holds)."""
    return tuple(m.group(0) + "\n" for m in re.finditer(
        r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text or "", re.DOTALL))


def root_groups(files, pems):
    """{SHA-256 fingerprint: root group} from the per-root DER bundles (..._DoD_Root_CA_6.der.p7b: DoD Root CA 6);
    pems {archive path: its certificates as PEM}."""
    return {pem_fingerprint(pem): PER_ROOT.match(PurePosixPath(n).name).group(1).replace("_", " ")
            for n in _named(files, PER_ROOT) for pem in pems.get(n, ())}


def export_document(source, archive_sha256, files, pems, signature, exported_at, fallback=None):
    """The importer's document for one archive: source (its file name), its SHA-256, files {path in the archive:
    bytes}, pems {path of each .p7b: its certificates as PEM, as openssl splits them}, signature {status: valid |
    invalid | unchecked, error, content (the manifest text the signature covers), signer_pem} as _verify found it,
    exported_at (ISO time), fallback {PEM: facts} for certificates the cryptography library refuses (openssl's
    reading: _openssl_facts). None when the archive isn't a DISA PKE bundle (no combined DER bundle)."""
    combined = next(iter(_named(files, COMBINED)), None)
    base = BASE.match(PurePosixPath(combined).name) if combined else None
    if base is None:
        return None
    chain_file = next(iter(_named(files, CHAIN)), None)
    chain_pems = split_pems(files[chain_file].decode("ascii", "replace")) if chain_file else ()
    chain = tuple(certificate_facts(p) for p in chain_pems)
    root_pem = chain_pems[0] if chain_pems else None
    listed = manifest_lines(signature.get("content"))
    by_name = {PurePosixPath(n).name: n for n in files}
    groups = root_groups(files, pems)
    return {"bundle": base.group(2).lower(), "version": base.group(1).replace("_", "."), "source": source,
            "archive_sha256": archive_sha256, "exported_at": exported_at,
            "manifest": {"file": next((PurePosixPath(n).name for n in _named(files, MANIFEST)), None),
                         "signature": signature.get("status"), "error": signature.get("error"),
                         "signer_sha256": pem_fingerprint(signature["signer_pem"]) if signature.get("signer_pem")
                         else None,
                         "files": [{"name": name, "listed": digest,
                                    "actual": hashlib.sha256(files[by_name[name]]).hexdigest()
                                    if name in by_name else None} for name, digest in sorted(listed.items())]},
            "chain": [{"subject": f["subject"], "issuer": f["issuer"], "sha256": f["sha256"]} for f in chain if f],
            "chain_root_sha1": pem_thumbprint(root_pem) if root_pem else None,
            "unlisted": sorted(PurePosixPath(n).name for n in files if n.lower().endswith(".p7b")
                               and PurePosixPath(n).name not in listed),
            "combined": PurePosixPath(combined).name,
            "certificates": [{"pem": pem, "group": groups.get(pem_fingerprint(pem)),
                              **({"facts": (fallback or {})[pem]} if pem in (fallback or {}) else {})}
                             for pem in pems.get(combined, ())]}


def unreadable(pems):
    """The certificates the cryptography library refuses (DoD Root CA 4's signature algorithm carries parameters
    strict DER parsing rejects, since cryptography 50), each once."""
    return tuple(dict.fromkeys(p for ps in pems.values() for p in ps if certificate_facts(p) is None))


OPENSSL_DATE = "%b %d %H:%M:%S %Y %Z"


def openssl_facts(text):
    """Facts {subject, issuer, not_before, not_after, serial, sha256} from `openssl x509 -noout -nameopt RFC2253
    -subject -issuer -startdate -enddate -serial -fingerprint -sha256` output, else None."""
    got = dict(line.split("=", 1) for line in (text or "").splitlines() if "=" in line)
    keys = {k.lower().strip(): v.strip() for k, v in got.items()}
    try:
        when = lambda k: dt.datetime.strptime(" ".join(keys[k].split()), OPENSSL_DATE).strftime(  # noqa: E731
            "%Y%m%d%H%M%SZ")
        serial = keys["serial"].lower()
        return {"subject": keys["subject"], "issuer": keys["issuer"], "not_before": when("notbefore"),
                "not_after": when("notafter"), "serial": serial if len(serial) % 2 == 0 else "0" + serial,
                "sha256": keys["sha256 fingerprint"]}
    except (KeyError, ValueError):
        return None


def _openssl_facts(pem):
    """openssl's reading of a certificate (effects: openssl), or None."""
    try:
        run = subprocess.run(["openssl", "x509", "-noout", "-nameopt", "RFC2253", "-subject", "-issuer",
                              "-startdate", "-enddate", "-serial", "-fingerprint", "-sha256"],
                             input=pem, capture_output=True, encoding="utf-8", check=False)
    except FileNotFoundError:
        return None
    return openssl_facts(run.stdout) if run.returncode == 0 else None


def _openssl_pems(raw):
    """A PKCS#7 bundle's certificates as PEM, split by `openssl pkcs7 -print_certs` (effects: openssl): DER, else
    PEM. openssl, unlike the cryptography library, takes DISA's bundles whole (DoD Root CA 4 included)."""
    for form in ("DER", "PEM"):
        try:
            run = subprocess.run(["openssl", "pkcs7", "-inform", form, "-print_certs"], input=raw,
                                 capture_output=True, check=False)
        except FileNotFoundError:
            return ()
        if run.returncode == 0:
            return split_pems(run.stdout.decode("ascii", "replace"))
    return ()


def _verify(files):
    """The manifest's signature checked with `openssl cms -verify` against the archive's chain (effects: a temporary
    folder, openssl)."""
    manifest, chain = next(iter(_named(files, MANIFEST)), None), next(iter(_named(files, CHAIN)), None)
    if manifest is None or chain is None:
        return {"status": "unchecked", "error": "the archive has no signed manifest or no signer chain"}
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        (t / "m.sha256").write_bytes(files[manifest])
        (t / "chain.pem").write_bytes(files[chain])
        try:
            run = subprocess.run(["openssl", "cms", "-verify", "-inform", "DER", "-in", str(t / "m.sha256"),
                                  "-CAfile", str(t / "chain.pem"), "-purpose", "any", "-signer",
                                  str(t / "signer.pem"), "-out", str(t / "content.txt")],
                                 capture_output=True, encoding="utf-8", check=False)
        except FileNotFoundError:
            return {"status": "unchecked", "error": "openssl isn't on the PATH"}
        content = ((t / "content.txt").read_text(encoding="utf-8", errors="replace")
                   if (t / "content.txt").exists() else None)
        signer = (t / "signer.pem").read_text(encoding="utf-8") if (t / "signer.pem").exists() else None
    if run.returncode != 0:
        return {"status": "invalid", "error": (run.stderr.strip().splitlines() or ["openssl failed"])[-1]}
    return {"status": "valid", "error": None, "content": content, "signer_pem": signer}


def main(argv=None):
    args = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    args.add_argument("archives", nargs="+", type=Path)
    args.add_argument("--out", required=True, type=Path)
    a = args.parse_args(argv)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    for archive in a.archives:
        raw = archive.read_bytes()
        with zipfile.ZipFile(archive) as z:
            files = {n: z.read(n) for n in z.namelist() if not n.endswith("/")}
        pems = {n: _openssl_pems(files[n]) for n in files if n.lower().endswith(".p7b")}
        fallback = {p: f for p in unreadable(pems) for f in (_openssl_facts(p),) if f is not None}
        doc = export_document(archive.name, hashlib.sha256(raw).hexdigest(), files, pems, _verify(files), now,
                              fallback)
        if doc is None:
            print(f"{archive}: not a DISA PKE bundle archive (no certificates_pkcs7_..._der.p7b)", file=sys.stderr)
            return 1
        out = a.out / ROOT / f"{doc['bundle']}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(f"{out}: {doc['bundle']} {doc['version']}, {len(doc['certificates'])} CA certificates, signature "
              f"{doc['manifest']['signature']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
