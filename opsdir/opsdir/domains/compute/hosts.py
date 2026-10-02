"""Host baselines and compute: the reports and the planner's check. Pure.

A host baseline is what a server role's servers run beyond its product (OS, Java runtime, truststore additions,
limits, kernel settings, agents, service units), the same in every environment. A compute group is where an
environment runs a role's instances as a group (an autoscaling group, a scale set); a cluster is a managed Kubernetes
cluster. Both are bindings, so the core's role check asks the target to bind what the source binds; this check asks
what the record alone can tell: truststore additions it can't reproduce, names pinned to addresses, roles a target
runs servers of without a recorded baseline, and a target's compute that is less safe or less spread than the source's.
"""
from ...core.directory import children, get, is_a, one, rdn_value, values
from ...core.environment import servers_with_role
from ...core.findings import findings, merge_findings, responsible
from ...core.naming import env_label
from .naming import BASELINES

BASELINE_HEADERS = ("role", "os", "java", "trusts", "limits", "kernel", "huge pages", "fips", "selinux", "agents",
                    "units", "pinned hosts", "found on")
COMPUTE_HEADERS = ("environment", "binding", "role", "runs", "image", "size", "scale", "zones", "metadata tokens")


def baselines(d):
    return children(d, BASELINES, "ciamHostBaseline")


def baseline_for(d, role):
    """The host baseline of a server role, or None."""
    return next((b for b in baselines(d) if one(b, "ciamTargetRole") == role), None)


def _yes_no(v):
    return {"TRUE": "yes", "FALSE": "no"}.get(v or "", "")


def trusted(d, b):
    """What a baseline's truststore adds, in words: the certificates the record holds, then how many it doesn't."""
    held = [rdn_value(c) for c in (get(d, dn) for dn in values(b, "ciamTrustsCertificate")) if c]
    unknown = values(b, "ciamTrustedFingerprint")
    return ", ".join((*held, *((f"{len(unknown)} not recorded",) if unknown else ())))


def baseline_rows(d, dn=None):
    """One row per server role's host baseline."""
    return [(one(b, "ciamTargetRole"), one(b, "ciamOs") or "", one(b, "ciamJdk") or "", trusted(d, b),
             "; ".join(values(b, "ciamOsLimit")), "; ".join(values(b, "ciamKernelSetting")),
             one(b, "ciamHugePages") or "", _yes_no(one(b, "ciamFipsMode")), one(b, "ciamSelinuxMode") or "",
             ", ".join(values(b, "ciamHostAgent")), "; ".join(values(b, "ciamServiceUnit")),
             "; ".join(values(b, "ciamPinnedHost")),
             ", ".join(rdn_value(s) for s in (get(d, x) for x in values(b, "ciamFoundOn")) if s))
            for b in baselines(d)]


def environment_of(e):
    """The DN of the environment a binding belongs to."""
    return e.dn.split(",ou=bindings,", 1)[1]


def compute_groups(m):
    return tuple(b for b in m.bindings if is_a(b, "ciamComputeGroup"))


def _scale(e):
    sizes = [one(e, a) for a in ("ciamMinSize", "ciamDesiredSize", "ciamMaxSize")]
    return "/".join(s or "?" for s in sizes) if any(sizes) else ""


def _compute_row(e):
    group = is_a(e, "ciamComputeGroup")
    return (env_label(environment_of(e)), rdn_value(e), one(e, "ciamBindingRole"),
            f"servers: {one(e, 'ciamTargetRole')}" if group else f"kubernetes {one(e, 'ciamClusterVersion') or '?'}",
            one(e, "ciamImageRef") or "" if group else ", ".join(values(e, "ciamClusterAddon")),
            one(e, "ciamInstanceSize") or "" if group else "; ".join(values(e, "ciamNodePool")),
            _scale(e) if group else "", ", ".join(values(e, "ciamSpansZone")),
            _yes_no(one(e, "ciamMetadataTokens")) if group else "")


def compute_rows(d, dn=None):
    """One row per compute group and cluster, in every environment."""
    held = sorted((e for e in d.entries.values() if is_a(e, "ciamComputeGroup") or is_a(e, "ciamCluster")),
                  key=lambda e: (environment_of(e), rdn_value(e)))
    return [_compute_row(e) for e in held]


# ------------------------------------------------------------------ the planner's check
def _baseline(ctx, b):
    role, owner = one(b, "ciamTargetRole"), responsible(ctx.d, b, ctx.dst.env)
    unknown, pinned = values(b, "ciamTrustedFingerprint"), values(b, "ciamPinnedHost")
    return findings(actions=(
        *((("Host", f"Servers of role `{role}` trust {len(unknown)} certificate(s) in their Java truststore that the "
            f"record doesn't hold ({', '.join(f[:23] + '…' for f in unknown)}): record them, or a server rebuilt "
            "from a stock image loses them silently.", owner, None),) if unknown else ()),
        *((("Host", f"Servers of role `{role}` pin {len(pinned)} name(s) in /etc/hosts ({'; '.join(pinned)}): pinned "
            f"addresses don't move with the platform. Replace them with names {ctx.dst.label} resolves.", owner,
            None),) if pinned else ())))


def _missing_baselines(ctx):
    """Roles the target runs servers of, that the source runs too, with no baseline: once the record holds any."""
    if not baselines(ctx.d):
        return findings()
    roles = dict.fromkeys(one(s, "ciamServerRole") for s in ctx.dst.servers)
    missing = [r for r in roles if servers_with_role(ctx.src, r) and baseline_for(ctx.d, r) is None]
    return findings(actions=[("Host", f"Server role `{r}` has no host baseline: what its servers run beyond the "
                              f"product (Java truststore additions, limits, agents) isn't recorded, so servers built "
                              f"for {ctx.dst.label} can't be checked against the source's.",
                              responsible(ctx.d, ctx.dst.env), None) for r in missing])


def _zones(e):
    return set(values(e, "ciamSpansZone"))


def _group(ctx, t):
    role, owner = one(t, "ciamTargetRole"), responsible(ctx.d, t, ctx.dst.env)
    name = f"Compute group `{rdn_value(t)}` (role `{role}`) in {ctx.dst.label}"
    source = [s for s in compute_groups(ctx.src) if one(s, "ciamTargetRole") == role]
    spread = max((len(_zones(s)) for s in source), default=0)
    runs = max((int(one(s, "ciamDesiredSize")) for s in source if (one(s, "ciamDesiredSize") or "").isdigit()),
               default=0)
    most = one(t, "ciamMaxSize")
    return findings(actions=(
        *(((("Compute", f"{name} lets the instance metadata service answer without session tokens: a request "
             "forged through a server reads its credentials. Require session tokens.", owner, None),)
           if one(t, "ciamMetadataTokens") == "FALSE" else ())),
        *(((("Compute", f"{name} spans {len(_zones(t))} zone(s); {ctx.src.label} spreads the role over {spread}.",
             owner, None),) if _zones(t) and len(_zones(t)) < spread else ())),
        *(((("Compute", f"{name} scales to at most {most} instance(s); {ctx.src.label} runs {runs}.", owner, None),)
           if most and most.isdigit() and int(most) < runs else ()))))


def check_hosts(ctx):
    """Truststore additions the record lacks, pinned names, missing baselines and weaker target compute are
    actions."""
    held = baselines(ctx.d)
    groups = compute_groups(ctx.dst)
    if not held and not groups:
        return findings()
    parts = merge_findings([*(_baseline(ctx, b) for b in held), _missing_baselines(ctx),
                            *(_group(ctx, t) for t in groups)])
    if parts.blockers or parts.actions:
        return parts
    return parts._replace(ok=(*parts.ok, f"Host baselines ({len(held)}) and {ctx.dst.label}'s compute groups "
                                         f"({len(groups)}) raise nothing."))
