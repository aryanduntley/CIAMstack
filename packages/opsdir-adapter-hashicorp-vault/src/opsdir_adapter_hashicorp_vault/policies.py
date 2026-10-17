"""Who may request certificates from a Vault PKI role, read from Vault's ACL policies: the policies that grant a
role's issue or sign endpoint (create or update), each judged on its own the way Vault picks the rule that applies
to a path (its priority matching: the most specific matching path; deny there wins). Pure.

A token holds the union of its policies, so a role's enrollees are the policies that grant it by themselves.
`default` is attached to every token not created without it: a role it grants is open to every authenticated client
(broad). The root policy (root tokens, break-glass) isn't counted. Who holds the other policies (auth methods' roles,
entities, groups) isn't read: a role only named policies grant is restricted, as a template only named groups may
enroll from is. Templated path segments ({{identity...}}) are taken as matching any one segment. Sentinel (RGP/EGP)
policies and control groups (Enterprise) aren't read."""
import itertools
import json
import re

from opsdir.core.sources import json_document

REQUEST = ("create", "update")           # the capabilities issuing or signing needs (a write)
BROAD = "default"                        # attached to every token unless created without it
SKIPPED = ("root",)                      # root tokens hold everything; not an enrollment grant
BROAD_POLICY, RESTRICTED, UNKNOWN = "broad", "restricted", "unknown"
# Vault's pre-capabilities policy values, as the capabilities they stand for
LEGACY = {"deny": ("deny",), "read": ("read", "list"), "write": ("create", "read", "update", "delete", "list"),
          "sudo": ("create", "read", "update", "delete", "list", "sudo")}
_TOKEN = re.compile(r'(?P<path>path\s+"(?:[^"\\]|\\.)*"\s*\{)|"(?:[^"\\]|\\.)*"|#[^\n]*|//[^\n]*|/\*.*?\*/|[{}]',
                    re.DOTALL)
_PATH_NAME = re.compile(r'"((?:[^"\\]|\\.)*)"')
_CAPABILITIES = re.compile(r'capabilities\s*=\s*\[([^\]]*)\]')
_LEGACY = re.compile(r'policy\s*=\s*"([a-z]+)"')


def _capabilities(body):
    found = _CAPABILITIES.search(body)
    legacy = _LEGACY.search(body)
    return (tuple(re.findall(r'"([^"]*)"', found.group(1))) if found else
            LEGACY.get(legacy.group(1), ()) if legacy else ())


def _hcl_rules(text):
    marks = tuple(m for m in _TOKEN.finditer(text) if m.group("path") or m.group() in "{}")
    depth = tuple(itertools.accumulate(-1 if m.group() == "}" else 1 for m in marks))
    def close(i):
        return next((j for j in range(i + 1, len(marks)) if depth[j] == depth[i] - 1), None)
    found = tuple((json.loads(f'"{_PATH_NAME.search(m.group()).group(1)}"'), i, close(i))
                  for i, m in enumerate(marks) if m.group("path"))
    if any(j is None for _, _, j in found):
        return None
    return tuple((p, _capabilities(text[marks[i].end():marks[j].start()])) for p, i, j in found)


def _json_rules(doc):
    paths = doc.get("path")
    blocks = (paths,) if isinstance(paths, dict) else tuple(b for b in paths if isinstance(b, dict)) \
        if isinstance(paths, list) else ()
    return tuple((p, tuple(rule.get("capabilities") or LEGACY.get(rule.get("policy"), ())))
                 for b in blocks for p, rule in b.items() if isinstance(rule, dict))


def policy_rules(text):
    """((path, capabilities), ...) of an ACL policy's text, HCL or JSON (legacy policy = "write" values as their
    capabilities); None when it can't be read (an unclosed block)."""
    doc = json_document(text or "", dict)
    return _json_rules(doc) if doc is not None else _hcl_rules(text or "")


def path_matches(pattern, path):
    """Whether a policy path pattern covers a request path: + is one whole segment, a trailing * any rest, a
    templated segment ({{...}}) any one segment."""
    glob = pattern.endswith("*")
    body = pattern[:-1] if glob else pattern
    segment = lambda s: "[^/]+" if s == "+" else "[^/]+".join(map(re.escape, re.split(r"\{\{.*?\}\}", s)))  # noqa
    return re.fullmatch("/".join(map(segment, body.split("/"))) + (".*" if glob else ""), path) is not None


def path_priority(pattern):
    """The sort key of a policy path among those matching one request (highest applies), Vault's rules in order: the
    first + or * later; not ending in *; fewer + segments; longer; lexically larger."""
    first = min((i for i, c in enumerate(pattern) if c in "+*"), default=len(pattern))
    return (first, not pattern.endswith("*"), -pattern.split("/").count("+"), len(pattern), pattern)


def grants(rules, path, wanted=REQUEST):
    """Whether one policy's rules give a request path any of the wanted capabilities: the capabilities of its
    highest-priority matching paths (merged), unless they deny."""
    matching = tuple((p, caps) for p, caps in rules if path_matches(p, path))
    if not matching:
        return False
    top = max(path_priority(p) for p, _ in matching)
    caps = {c for p, cs in matching if path_priority(p) == top for c in cs}
    return "deny" not in caps and bool(caps & set(wanted))


def role_paths(mount, role, issuers=()):
    """The request paths that issue or sign from a role of a mount: <mount>/issue|sign/<role>, and through each
    issuer reference given (its id, its name, default): <mount>/issuer/<ref>/issue|sign/<role>."""
    return (*(f"{mount}/{op}/{role}" for op in ("issue", "sign")),
            *(f"{mount}/issuer/{ref}/{op}/{role}" for ref in dict.fromkeys(issuers) if ref for op in ("issue", "sign")))


def verbatim_paths(mount, issuers=()):
    """The request paths signing any request whatever the roles allow (sign-verbatim, with or without a role and
    through each issuer reference given)."""
    return (f"{mount}/sign-verbatim", f"{mount}/sign-verbatim/+",
            *(f"{mount}/issuer/{ref}/sign-verbatim{tail}" for ref in dict.fromkeys(issuers) if ref
              for tail in ("", "/+")))


def granting(policies, paths):
    """The names of the policies (of {name: rules}) granting any of the request paths, root left out, in name order."""
    return tuple(n for n in sorted(policies) if n not in SKIPPED and policies[n] is not None
                 and any(grants(policies[n], p) for p in paths))


def enrollment(policies, paths):
    """(enrollees, scope, why) of a role reached at these request paths: the policies granting it ('policy <name>'),
    broad when the default policy does, restricted otherwise; unknown with why when the policies weren't read
    (policies None) or one couldn't be read ({name: None})."""
    if policies is None:
        return (), UNKNOWN, "the ACL policies weren't read"
    unread = tuple(n for n in sorted(policies) if policies[n] is None and n not in SKIPPED)
    if unread:
        return (), UNKNOWN, f"policies {', '.join(unread)} couldn't be read"
    names = granting(policies, paths)
    return tuple(f"policy {n}" for n in names), BROAD_POLICY if BROAD in names else RESTRICTED, None
