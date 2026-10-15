"""PingFederate's server profile (render target server-profile, on request; decision 2817): the record's PingFederate
configuration as a Ping server profile, per namespace ping-devops/server-profile/<namespace>/pingfederate/: its
instance/ tree (instance/bulk-config/data.json, the bulk import the admin console runs at start and replicates to the
engines; captured files such as instance/bin/run.properties). Pure.

No profile holds a secret: every ${secret:<ref>} the PingFederate adapter renders becomes ${OPSDIR_<ROLE>}
(core.profiles.slot_env) and its file a .subst file, which the image fills from the environment at start. The pods read
the variable from the Secret key the record maps on the workload (ciamWorkloadSecret <secret>/OPSDIR_<ROLE> <- <role>),
as every other key it records. Where a product's binding names a profile repository (ciamProfileRepo: Git URL, path,
branch) its containers fetch the profile from there (SERVER_PROFILE_URL / _PATH / _BRANCH, helm.py; commit the
pingfederate/ folder at that path); otherwise the Dockerfile beside it rebuilds the record's image with the profile in
/opt/in. A README lists each product's way, and each variable, its role and whether the record maps it."""
from opsdir.core.formats import DOCKERFILE, MARKDOWN
from opsdir.core.manifest import header
from opsdir.core.profiles import slot_env, slotted
from opsdir.domains.compute.workloads import profile_repo, workload_binding
from opsdir_adapter_kubernetes.kits import workload_of
from .products import image_of, placements, secret_keys
from .release import CHART, PRODUCTS, PROFILE_DIR, SERVER_PROFILE

PRODUCT = "PingFederate"
SUBST = ".subst"
_DOCKERFILE = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n\nCOPY --chown=ping:identity " + PROFILE_DIR + "/ /opt/in/\n"


def _variable(role):
    return "${" + slot_env(role) + "}"


def profile_files(m, tree):
    """({path in the profile: text}, (role, ...)): a PingFederate profile tree, each file with a secret reference
    holding ${OPSDIR_<ROLE>} and named <file>.subst (the image substitutes it at start); the roles it uses."""
    done = {path: slotted(m, text, _variable) for path, text in sorted(tree.items())}
    return ({path + (SUBST if roles else ""): text for path, (text, roles, _) in done.items()},
            tuple(dict.fromkeys(r for _, roles, _ in done.values() for r in roles)))


def delivered(p):
    """The OPSDIR_* variables the record delivers to a placement's PingFederate products (their workloads' keys)."""
    return {k for x in PRODUCTS for w in (workload_of(p, x.name),) if w is not None
            for _, k, path in secret_keys(w) if path is None and k.startswith("OPSDIR_")}


def _ways(m, p):
    """((product, repository (url, path, branch) or None, its image), ...) of the PingFederate products run here."""
    return tuple((x.name, profile_repo(workload_binding(m, w)), image_of(m, p, x.name))
                 for x in PRODUCTS for w in (workload_of(p, x.name),) if w is not None)


def _readme(m, p, ways, roles):
    mapped = delivered(p)
    how = "".join(f"- `{name}`: " + (f"fetched from `{repo[0]}`" + (f" path `{repo[1]}`" if repo[1] else "")
                                       + (f" branch `{repo[2]}`" if repo[2] else "")
                                       + f": commit the `{PROFILE_DIR}/` folder there\n"
                                       if repo else f"built into its image: build this folder with `--build-arg "
                                       f"BASE_IMAGE=<the PingFederate image to start from>` and push it as `{image}`\n")
                  for name, repo, image in ways)
    rows = "".join(f"| `{slot_env(r)}` | {r} | {'yes' if slot_env(r) in mapped else '**no**'} |\n" for r in roles)
    return header(m, f"PingFederate server profile for namespace {p.namespace}", MARKDOWN) + (
        f"# PingFederate server profile, namespace {p.namespace}\n\n{how}\n"
        + ("## Secrets\n\nEach variable comes from the Secret key the record maps on the workloads "
           "(`ciamWorkloadSecret <secret>/<variable> <- <role>`).\n\n| variable | role | mapped |\n|---|---|---|\n"
           + rows
           if roles else "No file holds a secret.\n"))


def namespace_profile(m, p, tree):
    """{path: text}: a placement's server profile, its README and (when a product builds it into its image) the
    Dockerfile; {} when the record holds nothing for PingFederate."""
    if not tree:
        return {}
    root = f"{CHART}/{SERVER_PROFILE}/{p.namespace}"
    files, roles = profile_files(m, tree)
    ways = _ways(m, p)
    built = [image for _, repo, image in ways if repo is None]
    what = (f"PingFederate server profile for namespace {p.namespace}: build with --build-arg BASE_IMAGE=<the "
            f"PingFederate image to start from>; push as {', '.join(dict.fromkeys(built))}")
    return {**{f"{root}/{PROFILE_DIR}/{path}": text for path, text in files.items()},
            **({f"{root}/Dockerfile": header(m, what, DOCKERFILE) + _DOCKERFILE} if built else {}),
            f"{root}/README.md": _readme(m, p, ways, roles)}


def render_profiles(m, profiles, targets):
    """Adapter.render_profiles: per namespace running PingFederate with the chart, its server profile when the target
    server-profile is chosen."""
    if SERVER_PROFILE not in targets:
        return {}
    return {path: text for p in placements(m) for path, text in namespace_profile(m, p, profiles.get(PRODUCT)).items()}
