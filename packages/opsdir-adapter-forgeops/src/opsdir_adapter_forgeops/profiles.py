"""ForgeOps config profiles (render target config-profiles, decision 2817): the record's product configuration as the
release builds it into images, per namespace forgeops/config-profiles/<namespace>/<component>/ in its
docker/<component>/ layout: config-profiles/opsdir/ (the product's own instance files, core.profiles) and the
Dockerfile that builds them, for the operator's CI to build and push as the image the record names (the Helm values
and the overlay point the release at it):

  idm     a busybox configuration image with the profile under /config/ (conf/, resolver/): the chart's idm_custom
          init container copies it over IDM's configuration on its first start; built and pushed as the image the
          record names for the container idm-custom
  amster  the record's amster image rebuilt with the profile under /opt/amster (config/global/, config/realms/: what
          the amster job imports, import-config --path /opt/amster/config)
  ig      the record's PingGateway image rebuilt with the profile under its instance directory ${IG_INSTANCE_DIR}, as
          ForgeOps' base images define it (config/config.json, admin.json, config/routes/)

AM's own file-based configuration stays its image's: the record's AM configuration is Amster's. No profile carries a
secret: every ${secret:<ref>} a product renders becomes &{opsdir.<role>} (core.profiles.slot_token), which IDM,
PingGateway and Amster fill from the environment variable OPSDIR_<ROLE> (slot_env). The pods read it from the Secret
key the record maps on the workload (ciamWorkloadSecret <secret>/OPSDIR_<ROLE> <- <role>; amster reads
amster-env-secrets whole, so its keys go there): the values and the overlay add the variable to IDM's, AM's and
PingGateway's containers. A README per namespace lists each token, its variable, its role and whether the record
maps it (the planner names the unmapped ones). Pure."""
from opsdir.core.formats import DOCKERFILE, MARKDOWN
from opsdir.core.manifest import header
from opsdir.core.profiles import slot_env, slot_token, slotted
from .components import image_of, placements, slot_envs
from .release import CONFIG_PROFILES, PROFILE_BUILDS, PROFILE_NAME, VERSION

_DOCKERFILE = {
    "config": ("ARG REPO=busybox\nARG TAG=musl\nFROM ${{REPO}}:${{TAG}}\n\nARG CONFIG_PROFILE={profile}\n"
               "RUN mkdir /config\nCOPY --chown=11111:0 config-profiles/${{CONFIG_PROFILE}}/ {dest}\n"),
    "derived": ("ARG BASE_IMAGE\nFROM ${{BASE_IMAGE}}\n\nARG CONFIG_PROFILE={profile}\n"
                "COPY --chown=forgerock:root config-profiles/${{CONFIG_PROFILE}}/ {dest}\n")}


def _token(role):
    return "&{" + slot_token(role) + "}"


def _built(component, how):
    return "the image the record names for " + (f"the container {component}-custom" if how == "config" else component)


def component_profile(m, p, component, product, how, dest, tree):
    """({path: text}, ((token, variable, role, mapped), ...)): one component's build context in a placement (its
    Dockerfile and config-profiles/opsdir/ with the product's files, secrets as tokens) and the slots it uses."""
    root = f"forgeops/{CONFIG_PROFILES}/{p.namespace}/{component}"
    done = {path: slotted(m, text, _token) for path, text in sorted(tree.items())}
    roles = tuple(dict.fromkeys(r for _, roles, _ in done.values() for r in roles))
    mapped = slot_envs(m, p, component)
    base = "" if how == "config" else (f"; build with --build-arg BASE_IMAGE=<the {product} image to start from: "
                                       f"{image_of(m, p, component)} is what the release runs>")
    what = (f"ForgeOps {VERSION} {component} config profile '{PROFILE_NAME}' for namespace {p.namespace}: build this "
            f"folder and push it as {_built(component, how)}{base}")
    return ({f"{root}/Dockerfile": header(m, what, DOCKERFILE) + _DOCKERFILE[how].format(profile=PROFILE_NAME,
                                                                                        dest=dest),
             **{f"{root}/config-profiles/{PROFILE_NAME}/{path}": text for path, (text, _, _) in done.items()}},
            tuple((slot_token(r), slot_env(r), r, slot_env(r) in mapped) for r in roles))


def _readme(m, p, slots):
    rows = "".join(f"| {c} | `&{{{t}}}` | `{v}` | {r} | {'yes' if ok else '**no**'} |\n" for c, (t, v, r, ok) in slots)
    where = (f"Each variable comes from the Secret key the record maps on the component's workload "
             f"(`ciamWorkloadSecret <secret>/<variable> <- <role>`; amster's in `amster-env-secrets`).")
    return header(m, f"ForgeOps {VERSION} config profiles for namespace {p.namespace}", MARKDOWN) + (
        f"# Config profiles, namespace {p.namespace}\n\nOne folder per component: build it and push the image the "
        "Dockerfile names; the Helm values and the overlay run it.\n\n"
        + (f"## Secrets\n\n{where}\n\n| component | token | variable | role | mapped |\n|---|---|---|---|---|\n{rows}"
           if slots else "No profile holds a secret.\n"))


def namespace_profiles(m, p, profiles):
    """{path: text}: the build contexts of the components on in a placement whose product has files, and the
    namespace's README."""
    built = [(component, component_profile(m, p, component, product, how, dest, profiles[product]))
             for component, product, how, dest in PROFILE_BUILDS
             if component in p.on and profiles.get(product)]
    if not built:
        return {}
    files = {path: text for _, (fs, _) in built for path, text in fs.items()}
    slots = [(component, s) for component, (_, ss) in built for s in ss]
    return {**files, f"forgeops/{CONFIG_PROFILES}/{p.namespace}/README.md": _readme(m, p, slots)}


def render_profiles(m, profiles, targets):
    """{path: text}: per namespace of the workloads run with ForgeOps, the config profiles, when the target
    config-profiles is chosen."""
    return {path: text for p in placements(m) for path, text in namespace_profiles(m, p, profiles).items()} \
        if CONFIG_PROFILES in targets else {}
