"""Bundles and verification against the repo: pure.

A bundle is code, scripts, templates or a package deployed as a unit. The record holds where it lives in version
control, what it is, its version and its SHA-256, never its content. Its digest is the SHA-256 of the file, or, for a
directory, of its files' "sha256  path" lines sorted by path (as sha256sum prints them), so the same content always
gives the same digest.

Verification compares the record with a checkout of the repo: a bundle's recorded digest with the repo's, and a
captured file's text rebuilt from the record with the repo's copy (the record is the source; a difference means the
repo drifted or the record changed since).
"""
import hashlib

from ...core.directory import children, make_entry, one
from ...core.secrets import text_concerns
from .naming import BUNDLES, bundle_dn

VERIFY_HEADERS = ("kind", "name", "repo path", "status", "detail")
BUNDLE_HEADERS = ("bundle", "kind", "version", "format", "repo path", "deploy role", "sha256")


def content_digest(files):
    """SHA-256 of a bundle's content: {relative path: bytes}; a single file is {"": bytes} and digests as itself."""
    if set(files) == {""}:
        return hashlib.sha256(files[""]).hexdigest()
    lines = "".join(f"{hashlib.sha256(data).hexdigest()}  {path}\n" for path, data in sorted(files.items()))
    return hashlib.sha256(lines.encode()).hexdigest()


def _text(data):
    try:
        return data.decode()
    except UnicodeDecodeError:
        return None                                  # binary content: nothing to read


def content_concerns(files, patterns):
    """What in a bundle's text files may be secret material, as "path line n: concern" (binary files are skipped)."""
    texts = ((path, _text(data)) for path, data in sorted(files.items()))
    return tuple(f"{path + ' ' if path else ''}line {n}: {what}" for path, text in texts if text is not None
                 for n, what in text_concerns(text, patterns))


def bundle_entries(name, repo_path, kind, digest, format_name=None, version=None, role=None, deploy_path=None):
    """The bundle's entry (and its branch, which the caller adds only when missing)."""
    optional = {"ciamFormat": format_name, "ciamBundleVersion": version, "ciamTargetRole": role,
                "ciamDeployPath": deploy_path}
    return make_entry(bundle_dn(name), ("top", "ciamBundle"),
                      {"cn": (name,), "ciamRepoPath": (repo_path,), "ciamBundleKind": (kind,), "ciamSha256": (digest,),
                       **{k: (v,) for k, v in optional.items() if v}})


def bundles(d):
    return children(d, BUNDLES, "ciamBundle")


def bundle_rows(d, dn=None):
    """Report `bundles`: every recorded bundle."""
    return [(one(b, "cn"), one(b, "ciamBundleKind"), one(b, "ciamBundleVersion") or "", one(b, "ciamFormat") or "",
             one(b, "ciamRepoPath"), one(b, "ciamTargetRole") or "", one(b, "ciamSha256")) for b in bundles(d)]


def _status(recorded, found):
    if found is None:
        return "missing"
    return "unchanged" if found == recorded else "changed"


def bundle_verification(d, digests, concerns):
    """Verify rows for bundles: digests {repo path: digest or None when missing}, concerns {repo path: (concern, ...)}
    (what in the bundle's text may be secret material: reported, since a bundle is deployed as it is)."""
    return [("bundle", one(b, "cn"), one(b, "ciamRepoPath"),
             _status(one(b, "ciamSha256"), digests.get(one(b, "ciamRepoPath"))),
             "; ".join(concerns.get(one(b, "ciamRepoPath"), ()))) for b in bundles(d)]
