"""ForgeOps' planner check on the target environment. Pure.

What the rendered values and overlay can't settle on their own, as actions: Secrets the release's pods read that the
record doesn't deliver (no workload in the namespace records the key, and ForgeOps doesn't make it), the one service
account the identity-platform chart runs every pod as, a ds workload ForgeOps can't place (it runs DS as ds-idrepo or
ds-cts), and ForgeOps' public images (for development and testing only).
"""
from opsdir.core.directory import rdn_value
from opsdir.core.findings import findings, responsible
from opsdir.domains.compute.workloads import workload_secrets
from opsdir_adapter_kubernetes.render import namespace_of, on_kubernetes, service_account_of
from .components import image_of, placements, unplaced
from .release import HELM, IDENTITY_PLATFORM, KUSTOMIZE, SERVERS_CA, component, kit_secrets, public_image

AREA = "ForgeOps"


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


def check_forgeops(ctx):
    """Actions on the target: ForgeOps Secrets the record doesn't deliver, one service account per Helm release, ds
    workloads ForgeOps can't place, ForgeOps' public images."""
    m = ctx.dst
    spaces = placements(m)
    if not spaces and not unplaced(m):
        return findings()
    owner = responsible(ctx.d, m.env)
    texts = (*(_secret_text(m, *row) for row in unrecorded_secrets(m)),
             *(t for p in spaces for t in _accounts(m, p)),
             *(f"Workload `{rdn_value(w)}` runs DS on Kubernetes in {m.label}, but ForgeOps runs DS as `ds-idrepo` "
               f"or `ds-cts`: name the workload after the one it is, or it isn't deployed." for w in unplaced(m)),
             *(f"ForgeOps component `{c}` in {m.label} (namespace `{p.namespace}`) runs ForgeOps' public image "
               f"`{ref}`: those images are for development and testing only; production deployments run images "
               f"they build." for p in spaces for c in p.on for ref in (image_of(m, p, c),) if public_image(ref)))
    actions = tuple((AREA, t, owner, None) for t in texts)
    ok = () if actions else (f"ForgeOps in {m.label} has every Secret its pods read recorded or made, and its own "
                             "images.",)
    return findings(actions=actions, ok=ok)
