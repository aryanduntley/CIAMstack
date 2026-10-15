"""ForgeOps' planner check on the target environment. Pure.

What the rendered values and overlay can't settle on their own, as actions: Secrets the release's pods read that the
record doesn't deliver (no workload in the namespace records the key, and ForgeOps doesn't make it), the one service
account the identity-platform chart runs every pod as, a ds workload ForgeOps can't place (it runs DS as ds-idrepo or
ds-cts), one DS store in the cluster and the other on servers (unsupported: one truststore CA), ForgeOps' public images
(for development and testing only), and a config profile's secret variable (OPSDIR_<ROLE>) the record doesn't deliver
to its component (when the target renders config profiles).
"""
import re

from opsdir.core.directory import rdn_value
from opsdir.core.environment import one_role, roles_for
from opsdir.core.findings import findings, responsible
from opsdir.domains.compute.workloads import workload_secrets
from opsdir_adapter_kubernetes.render import namespace_of, on_kubernetes, service_account_of
from .components import image_of, keystore_from_record, placements, slot_envs, split_ds, unplaced
from .release import (AMSTER_ENV_SECRET, CONFIG_PROFILES, HELM, IDENTITY_PLATFORM, KEYSTORE_KEY, KEYSTORE_PRODUCTS,
                      KEYSTORE_SECRET, KUSTOMIZE, SERVERS_CA, component, kit_secrets, public_image)

AREA = "ForgeOps"
_TOKEN = re.compile(r"&\{(opsdir\.[a-z0-9.]+)\}")


def _recorded(m, ns):
    return {(s, k) for w in on_kubernetes(m) if namespace_of(w) == ns for s, k, _ in workload_secrets(w)}


def unrecorded_secrets(m):
    """((namespace, KitSecret, missing keys, ((target, what makes it), ...)), ...): per placement, the Secret keys the
    release's pods read that no workload in the namespace records and ForgeOps doesn't make under every target."""
    found = []
    for p in placements(m):
        recorded = _recorded(m, p.namespace)
        made = {s.name: s.made for s, _ in kit_secrets(p.on, HELM)}
        for s, _ in kit_secrets(p.on, HELM):
            missing = tuple(k for k in s.keys if (s.name, k) not in recorded)
            if missing and {t for t, _ in made[s.name]} != {HELM, KUSTOMIZE}:
                found.append((p.namespace, s, missing, made[s.name]))
    return tuple(found)


def _secret_text(m, ns, s, missing, made):
    by = "".join(f"; under {t} {what} makes it" for t, what in made)
    what = " (the CA that signed the DS servers' certificates, which AM and IDM trust)" if s == SERVERS_CA else ""
    return (f"ForgeOps in {m.label} (namespace `{ns}`) reads Secret `{s.name}` key(s) {', '.join(missing)}{what}, "
            f"which no workload there records: record the role that fills each (ciamWorkloadSecret "
            f"{s.name}/<key> <- <role>) so it is delivered, or create it{by}.")


def _accounts(m, p):
    names = dict.fromkeys(service_account_of(w) for c, w in p.placed if component(c).chart == IDENTITY_PLATFORM)
    return (f"The identity-platform chart runs every pod in namespace `{p.namespace}` of {m.label} as one service "
            f"account; the ForgeOps workloads there name {len(names)} ({', '.join(names)}). The Helm values use "
            f"`{next(iter(names))}` (the Kustomize overlay sets each).",) if len(names) > 1 else ()


def _split(m, p):
    split = split_ds(p)
    return (f"ForgeOps in {m.label} (namespace `{p.namespace}`) runs `{split[0]}` in the cluster and `{split[1]}` on "
            f"servers: ForgeOps then makes the DS certificates, so AM's and IDM's truststore holds only its own CA and "
            f"their TLS connections to the DS servers fail. Run both stores in the cluster or both on servers.",) \
        if split else ()


def unmapped_slots(m, p, files):
    """((component, variable), ...): the secret variables a namespace's rendered config profiles read (their
    &{opsdir.<role>} tokens) that the record doesn't deliver to the component (components.slot_envs)."""
    root = f"forgeops/{CONFIG_PROFILES}/{p.namespace}/"
    found = {(path[len(root):].split("/", 1)[0], token.upper().replace(".", "_"))
             for path, text in files.items() if path.startswith(root) and "/" in path[len(root):]
             for token in _TOKEN.findall(text)}
    return tuple(sorted((c, v) for c, v in found if v not in slot_envs(m, p, c)))


def _slot_text(m, p, c, v):
    where = (f"`{AMSTER_ENV_SECRET}/{v} <- <role>` on a workload in the namespace (the amster job reads that Secret "
             "whole)" if c == "amster" else f"`<secret>/{v} <- <role>` on the {c} workload")
    return (f"ForgeOps config profile `{c}` in {m.label} (namespace `{p.namespace}`) reads `{v}`, which the record "
            f"doesn't deliver: record ciamWorkloadSecret {where} (the namespace's config-profiles README names the "
            "role).")


def _keystore(m, p):
    """The action naming the keystore the release generates while the environment binds the record's (AM's and
    IDM's keystore roles, am-keystore and idm-keystore: release.KEYSTORE_PRODUCTS), or ()."""
    bound = [r for product in KEYSTORE_PRODUCTS for r in roles_for(m, product, "keystore")
             if one_role(m, r) is not None]
    if not bound or not {"am", "idm"} & set(p.on) or keystore_from_record(m, p):
        return ()
    return (f"ForgeOps in {m.label} (namespace `{p.namespace}`) generates AM's and IDM's keystore (the keystore-create "
            f"job) while the record holds {', '.join(bound)}: map it on a workload (ciamWorkloadSecret "
            f"{KEYSTORE_SECRET}/{KEYSTORE_KEY} <- <role>) so the release runs the record's keys and generates none. "
            "The keystore must hold the aliases the job makes (the chart's keystore_create.config.keytoolAliases).",)


def check_forgeops(ctx):
    """Actions on the target: ForgeOps Secrets the record doesn't deliver, one service account per Helm release, ds
    workloads ForgeOps can't place, a DS layout split between the cluster and servers, ForgeOps' public images, config
    profiles' secret variables the record doesn't deliver."""
    m = ctx.dst
    spaces = placements(m)
    if not spaces and not unplaced(m):
        return findings()
    owner = responsible(ctx.d, m.env)
    texts = (*(_secret_text(m, *row) for row in unrecorded_secrets(m)),
             *(t for p in spaces for t in _accounts(m, p)),
             *(t for p in spaces for t in _split(m, p)),
             *(f"Workload `{rdn_value(w)}` runs DS on Kubernetes in {m.label}, but ForgeOps runs DS as `ds-idrepo` "
               f"or `ds-cts`: name the workload after the one it is, or it isn't deployed." for w in unplaced(m)),
             *(f"ForgeOps component `{c}` in {m.label} (namespace `{p.namespace}`) runs ForgeOps' public image "
               f"`{ref}`: those images are for development and testing only; production deployments run images "
               f"they build." for p in spaces for c in p.on for ref in (image_of(m, p, c),) if public_image(ref)),
             *(_slot_text(m, p, c, v) for p in spaces for c, v in unmapped_slots(m, p, ctx.dst_files)),
             *(t for p in spaces for t in _keystore(m, p)))
    actions = tuple((AREA, t, owner, None) for t in texts)
    ok = () if actions else (f"ForgeOps in {m.label} has every Secret its pods read recorded or made, and its own "
                             "images.",)
    return findings(actions=actions, ok=ok)
