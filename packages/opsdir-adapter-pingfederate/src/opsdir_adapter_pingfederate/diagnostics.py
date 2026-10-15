"""What every PingFederate render of an environment says about its requests (admin-api's requests.json, the Terraform
root's main.tf, the bulk document's problems.json). Pure, but for the spec it loads.

  - the servers running other versions than the one rendered for;
  - key pairs whose material the environment doesn't supply (opsdir_adapter_pingfederate.keypairs);
  - each request body the Admin API spec of the target's version refuses, or that no spec is vendored for it;
  - held settings exported from another PingFederate version (pingfedSourceVersion, recorded at import): one line per
    source version naming its objects, and one per change between the two versions (versions.VERSION_CHANGES) that
    touches some of them, with what to do. Nothing is migrated: Ping documents no bulk import across versions and no
    migration of an export; its way to settings of the new version is to upgrade a copy and export it again. Settings
    exported from a newer version than the target are named too: what the target lacks is refused by its spec,
    never dropped.
"""
from opsdir.core.directory import children, get, one, rdn_value
from opsdir.core.versions import crossed, parsed, product_version
from .admin_api_spec import load_spec, request_problems, spec_version
from .connections import served_integrations
from .generic import held_resources
from .keypairs import key_pair_imports
from .naming import AUTH_SERVER, CONTRACTS, DATA_STORES, DEFAULT_POLICY, FRAGMENTS, OIDC_POLICIES, SERVER_ROLES
from .plugins import KINDS
from .versions import VERSION_CHANGES, pingfederate_version

SOURCE = "pingfedSourceVersion"


def checked(spec, reqs):
    """The problems of the requests against a spec: '<method> <path>: <JSON path>: <what>'."""
    return tuple(f"{r.method} {r.path}: {p}" for r in reqs for p in request_problems(spec, r.method, r.path, r.body))


def held_objects(m):
    """The entries holding Admin API settings that environment m's renders carry."""
    d = m.d
    return (*children(d, DATA_STORES, "pingfedDataStore"),
            *(e for k in KINDS.values() for e in children(d, k.base, "pingfedPlugin")),
            *children(d, CONTRACTS, "pingfedPolicyContract"), *children(d, FRAGMENTS, "pingfedAuthPolicy"),
            *(e for e in (get(d, DEFAULT_POLICY), get(d, AUTH_SERVER)) if e is not None),
            *children(d, DEFAULT_POLICY, "pingfedAuthPolicy"), *children(d, OIDC_POLICIES, "pingfedOidcPolicy"),
            *(i for i in served_integrations(d) if "pingfedHeldSettings" in i.classes), *held_resources(d))


def _names(entries):
    return tuple(sorted(dict.fromkeys(rdn_value(e) for e in entries)))


def _ranges(has):
    return " or ".join((has,) if isinstance(has, str) else has)


def _changes(m, names, lacks, has):
    """A line per VersionChange that version `has` has and `lacks` lacks, touching some of these names."""
    def touched(c):
        found = c.touches(m.d, m, SERVER_ROLES[0]) if c.touches is not None else ()
        return tuple(n for n in names if n in (found or ()))
    return tuple(f"PingFederate {_ranges(c.has)}: {c.change}: {', '.join(hit)}: {c.fix}"
                 for c in VERSION_CHANGES if crossed(c.has, lacks, has) for hit in (touched(c),) if hit)


def _from(m, objects, src, to, spec):
    """The lines of the held settings exported from version src, rendered for version to (spec: whether its spec
    checks the requests)."""
    names = _names(e for e in objects if one(e, SOURCE) == src)
    held = (f"held settings exported from PingFederate {src}, rendered for {to}: {len(names)} objects "
            f"({', '.join(names)})")
    if parsed(src) < parsed(to):
        return (f"{held}: nothing is migrated between the versions; review them against the changes named, or "
                f"upgrade a copy of PingFederate {src} and export it again", *_changes(m, names, src, to))
    return (f"{held}, an older version: nothing is dropped; "
            f"{'its spec refuses what it lacks' if spec else 'no spec checks what it lacks'}",
            *(f"{to} lacks: {line}" for line in _changes(m, names, to, src)))


def version_problems(m, objects, target, spec=True):
    """What the render says about held settings exported from other PingFederate versions than the target (spec:
    whether the target's spec checks the requests)."""
    to = product_version(target)[1] if target else None
    if parsed(to or "") is None:
        return ()
    sources = tuple(dict.fromkeys(one(e, SOURCE) for e in objects if one(e, SOURCE)))
    unknown = _names(e for e in objects if not one(e, SOURCE))
    return (*(line for src in sources if parsed(src) is not None and parsed(src) != parsed(to)
              for line in _from(m, objects, src, to, spec)),
            *((f"{len(unknown)} objects hold settings with no recorded source version ({', '.join(unknown)}): not "
               f"compared with {to}",) if unknown and sources else ()))


def problems(m, reqs):
    """(PingFederate version, vendored spec version or None, problems) of environment m's requests."""
    version, others = pingfederate_version(m)
    vendored = spec_version(version)
    spec = load_spec(vendored) if vendored else None
    return version, spec["version"] if spec else None, (
        *((f"servers run other versions too ({', '.join(others)}): checked against {version}",) if others else ()),
        *key_pair_imports(m)[1],
        *(checked(spec, reqs) if spec else
          (f"no Admin API spec for {version or 'an unknown version'}: the requests are not checked",)),
        *version_problems(m, held_objects(m), version, spec is not None))
