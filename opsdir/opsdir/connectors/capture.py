"""Capturing config files into the record and rebuilding them from it: joins the configuration domain with the
registered formats, the secret patterns and the environments. Pure; the CLI reads and writes the files and applies
the change records under an approved change."""
from typing import NamedTuple

from ..core.changeset import diff
from ..core.contract import SecretPattern
from ..core.directory import get, make_entry, one, subtree
from ..core.formats import format_by_extension
import hashlib

from ..domains.configuration.bundles import (VERIFY_HEADERS, bundle_entries, bundle_verification, bundles,
                                             content_concerns, content_digest)
from ..domains.configuration.naming import BUNDLES, CONFIG_FILES, bundle_dn, file_dn
from ..domains.configuration.record import (captured_files, deployed_files, file_entries, linked, rebuild,
                                            render_problems)
from .registry import ADAPTERS, FORMATS, environment, format_named, secret_patterns

# The captured files an environment receives, rendered: {path: text}, {path: format}, {path: scope}, and
# ((file name, reason), ...) for those that can't be rendered there
RenderedConfig = NamedTuple("RenderedConfig", [("files", dict), ("formats", dict), ("scopes", dict),
                                               ("not_rendered", tuple)])
CAPTURED_DIR = "files"


def capture_format(path, name=None, formats=FORMATS):
    """The format to capture a file in: the one named, else the one its extension says."""
    fmt = format_named(name, formats) if name else format_by_extension(path, formats)
    if fmt is None:
        raise SystemExit(f"no registered format {'named ' + name if name else 'for ' + str(path)} (use --format)")
    return fmt


def _patterns(installed):
    return tuple(SecretPattern(name, pattern, description)
                 for name, pattern, _, description in secret_patterns(installed))


def capture_changes(d, fmt, text, name, repo_path, role=None, deploy_path=None, accept_concerns=False,
                    installed=ADAPTERS):
    """(LDIF change records, notices): what turns the record's copy of the file (none yet, or an earlier capture)
    into this one. Settings whose locators are unchanged keep their entries (and history)."""
    entries, notices = file_entries(fmt, text, name, repo_path, _patterns(installed), role, deploy_path,
                                    accept_concerns)
    return _changes(d, CONFIG_FILES, file_dn(name), entries), notices


def _changes(d, branch_dn, dn, entries):
    """Change records turning the record's subtree at dn into entries (adding the branch when it is missing)."""
    ou = branch_dn.split(",", 1)[0].split("=", 1)[1]
    branch = () if get(d, branch_dn) else (make_entry(branch_dn, ("top", "organizationalUnit"), {"ou": (ou,)}),)
    before = {e.norm: e for e in subtree(d, dn)} if get(d, dn) else {}
    after = {e.norm: e for e in (*branch, *entries)}
    return diff(d._replace(entries=before), d._replace(entries=after))


def bundle_changes(d, name, repo_path, kind, content, format_name=None, version=None, role=None, deploy_path=None,
                   installed=ADAPTERS):
    """(change records, notices) recording a bundle (or updating its record) from its content ({relative path:
    bytes}; one file is {"": bytes}). The content is digested, never stored; what in it may be secret material is
    noticed (the bundle is deployed as it is)."""
    digest = content_digest(content)
    entry = bundle_entries(name, repo_path, kind, digest, format_name, version, role, deploy_path)
    concerns = content_concerns(content, _patterns(installed))
    return _changes(d, BUNDLES, bundle_dn(name), (entry,)), (
        f"{name}: {kind} bundle at {repo_path} ({len(content)} file(s), sha256 {digest[:12]})",
        *(f"{name}: may hold secret material: {c}" for c in concerns))


def rebuilt_file(d, name, spec=None, installed=ADAPTERS, formats=FORMATS):
    """(the file's text rebuilt from the record, where it lives in version control); settings linked to bindings
    take environment spec's values."""
    entry = get(d, file_dn(name))
    if entry is None:
        raise SystemExit(f"no captured file named {name} (see `opsdir report capture`)")
    fmt = format_named(one(entry, "ciamFormat"), formats)
    m = environment(d, spec, installed)[0] if spec else None
    try:
        return rebuild(d, fmt, entry, m), one(entry, "ciamRepoPath")
    except ValueError as e:
        raise SystemExit(str(e))


def _rendered(d, f, m, formats):
    """(text, None) or (None, why) for one captured file rendered for environment m."""
    why = render_problems(d, f, m)
    if why:
        return None, "; ".join(why)
    try:
        return rebuild(d, format_named(one(f, "ciamFormat"), formats), f, m), None
    except ValueError as e:
        return None, str(e)


def _scope(d, f):
    return "environment-specific" if linked(d, f) else "environment-neutral"


def rendered_config(d, m, formats=FORMATS):
    """The captured files environment m receives, rebuilt with its bindings, under files/<repo path>: byte for byte
    (no generated header; the MANIFEST records them). Files that can't be rendered there are listed with why."""
    results = tuple((f, *_rendered(d, f, m, formats)) for f in deployed_files(d, m))
    ok = tuple((f"{CAPTURED_DIR}/{one(f, 'ciamRepoPath').lstrip('/')}", f, text) for f, text, why in results if not why)
    return RenderedConfig({path: text for path, _, text in ok},
                          {path: one(f, "ciamFormat") for path, f, _ in ok},
                          {path: _scope(d, f) for path, f, _ in ok},
                          tuple((one(f, "cn"), why) for f, _, why in results if why))


def verify_paths(d):
    """The repo paths verification reads: every bundle's and every captured file's."""
    return tuple(dict.fromkeys(one(e, "ciamRepoPath") for e in (*bundles(d), *captured_files(d))))


def _config_row(d, f, digests, formats):
    path, level = one(f, "ciamRepoPath"), one(f, "ciamCaptureLevel")
    found = digests.get(path)
    if found is None:
        return ("config file", one(f, "cn"), path, "missing", "")
    if level == "reference":
        same = found == one(f, "ciamSha256")
        return ("config file", one(f, "cn"), path, "unchanged" if same else "changed", "held only as a reference")
    try:
        text = rebuild(d, format_named(one(f, "ciamFormat"), formats), f)
    except ValueError as e:
        return ("config file", one(f, "cn"), path, "not comparable", str(e))
    same = hashlib.sha256(text.encode()).hexdigest() == found
    return ("config file", one(f, "cn"), path, "same as the record" if same else "differs from the record", "")


def verification(d, contents, formats=FORMATS, installed=ADAPTERS):
    """(headers, rows): every bundle and captured file against a checkout of the repo. contents: {repo path:
    {relative path: bytes} (one file: {"": bytes}), or None when the repo has nothing there}."""
    digests = {path: content_digest(c) if c is not None else None for path, c in contents.items()}
    patterns = _patterns(installed)
    concerns = {path: content_concerns(c, patterns) for path, c in contents.items() if c is not None}
    return VERIFY_HEADERS, (*bundle_verification(d, digests, concerns),
                            *(_config_row(d, f, digests, formats) for f in captured_files(d)))
