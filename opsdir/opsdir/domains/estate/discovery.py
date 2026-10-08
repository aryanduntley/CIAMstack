"""Data discovery: the services that examine an environment's stores for sensitive data (ciamDataDiscovery, a binding:
Amazon Macie, Defender for Cloud's sensitive data discovery, Sensitive Data Protection), knowing where it lies (NIST SP
800-53 CM-12, information location). Each names the stores it examines by their binding roles, the organization's own
data types it looks for (`name: regular expression`: the clouds' built-in detectors are theirs and differ), how often it
examines them again, where its findings go and where it keeps its detailed results. The report, and the planner's
check. Pure.

A target that runs none while the source does, that leaves a store unexamined which the source examines and the target
binds, that doesn't look for one of the source's own data types, or that keeps its findings or results in the service
where the source sends them on, gives actions, which block the move where the target holds controlled data
(restricted, or a required authorization level); one examining less often gives an action; a target service sending
findings or results to a role the target doesn't bind is a blocker. The clouds' detectors and sampling differ (Macie
examines S3 only; Defender's sensitive data discovery samples): the record says what is examined, not that it is
catalogued completely."""
from ...core.directory import get, one, rdn_value, subtree, values
from ...core.environment import env_model, of_class, one_role
from ...core.findings import findings, responsible
from ...core.naming import branch
from .authorizations import held_to, required_levels

AREA = "Data discovery"
DISCOVERY = "ciamDataDiscovery"
DISCOVERY_HEADERS = ("environment", "data discovery", "examines", "own data types", "every (days)", "findings to",
                     "results to", "kept by")


def discovery_services(m):
    """Environment m's data discovery services."""
    return of_class(m, DISCOVERY)


def discovery_role(resource, roles):
    """The binding role of a data discovery service a cloud reports without one (ImportKind role)."""
    return "data-discovery"


def custom_identifiers(s):
    """((name, regular expression), ...) a data discovery service looks for."""
    return tuple(tuple(v.split(": ", 1)) for v in values(s, "ciamCustomIdentifier") if ": " in v)


def scanned_roles(services):
    """The store roles these services examine, in order, once each."""
    return tuple(dict.fromkeys(r for s in services for r in values(s, "ciamScansRole")))


def rescan_days(services):
    """The most often any of these services examines its stores again (days), or None when none records it."""
    days = [int(v) for s in services for v in (one(s, "ciamRescanDays"),) if v is not None]
    return min(days) if days else None


def destination(m, s, attr):
    """The binding of environment m a data discovery service's findings (ciamFindingsRole) or results
    (ciamResultsRole) go to, or None."""
    role = one(s, attr)
    return one_role(m, role) if role else None


def _sends(m, services, attr):
    return any(destination(m, s, attr) is not None for s in services)


def _gaps(ctx, src, dst):
    """What the target misses that the source has: no service, a store unexamined, an own data type not looked for,
    findings or results kept in the service."""
    a, b = ctx.src.label, ctx.dst.label
    if not dst:
        stores = scanned_roles(src)
        return [f"{a} runs data discovery ({', '.join(rdn_value(s) for s in src)}"
                + (f", over {', '.join(stores)}" if stores else "") + f") and {b} runs none: where the target's "
                "sensitive data lies would go unknown (NIST SP 800-53 CM-12). Record the target's."]
    bound = {one(x, "ciamBindingRole") for x in ctx.dst.bindings}
    theirs, ours = scanned_roles(dst), {n for s in dst for n, _ in custom_identifiers(s)}
    return [*(f"{a} examines `{r}` for sensitive data and {b}'s data discovery doesn't: add it to the target's."
              for r in scanned_roles(src) if r in bound and r not in theirs),
            *(f"{a} looks for its own data type `{n}` ({rx}) and {b} doesn't: add the identifier to the target's data "
              "discovery, or that data won't be found." for n, rx in dict(
                  (n, rx) for s in src for n, rx in custom_identifiers(s)).items() if n not in ours),
            *((f"{a}'s data discovery sends its findings on and {b}'s keeps them in the service: send them where "
               "someone acts on them.",)
              if _sends(ctx.src, src, "ciamFindingsRole") and not _sends(ctx.dst, dst, "ciamFindingsRole") else ()),
            *((f"{a}'s data discovery keeps its detailed results (where sensitive data was found) and {b}'s doesn't: "
               "keep the target's.",)
              if _sends(ctx.src, src, "ciamResultsRole") and not _sends(ctx.dst, dst, "ciamResultsRole") else ())]


def _softer(ctx, src, dst):
    """What the target does less often: examining its stores."""
    s_days, t_days = rescan_days(src), rescan_days(dst)
    return [f"{ctx.src.label} examines its stores every {s_days} days and {ctx.dst.label} every {t_days}: sensitive "
            "data written in between goes unknown longer; examine the target's as often."
            for _ in (1,) if s_days is not None and t_days is not None and t_days > s_days]


def _unbound(ctx, dst):
    """Blockers for the target's services sending findings or results to a role it doesn't bind."""
    return [(AREA, f"Data discovery `{rdn_value(s)}` in {ctx.dst.label} sends its {what} to role `{one(s, attr)}`, "
                   f"which {ctx.dst.label} doesn't bind: they reach no one. Record where they go.",
             responsible(ctx.d, s, ctx.dst.env))
            for s in dst for attr, what in (("ciamFindingsRole", "findings"), ("ciamResultsRole", "results"))
            if one(s, attr) and destination(ctx.dst, s, attr) is None]


def check_discovery(ctx):
    """The target's data discovery against the source's (see the module). Nothing when neither records one."""
    src, dst = discovery_services(ctx.src), discovery_services(ctx.dst)
    if not src and not dst:
        return findings()
    owner = responsible(ctx.d, ctx.dst.env)
    gaps = _gaps(ctx, src, dst) if src else []
    held = held_to(ctx.dst)
    levels = required_levels(ctx.dst)
    why = (f" {ctx.dst.label} holds controlled data ("
           + (f"held to {', '.join(levels)}" if levels else "classified restricted") + "): this blocks the move.")
    blockers = [*((AREA, text + why, owner) for text in gaps if held), *_unbound(ctx, dst)]
    actions = [*((AREA, text, owner, ctx.cutover) for text in gaps if not held),
               *((AREA, text, owner, ctx.cutover) for text in (_softer(ctx, src, dst) if src and dst else ()))]
    return findings(blockers=blockers, actions=actions,
                    ok=() if blockers or actions or not dst else
                    (f"Data discovery recorded in {ctx.dst.label}: {', '.join(rdn_value(s) for s in dst)}.",))


def _keeper(m, s):
    ref = one(s, "ciamManagedBy")
    keeper = get(m.d, ref) if ref else None
    return rdn_value(keeper) if keeper is not None else "platform"


def discovery_rows(d, dn=None):
    """One row per data discovery service of every environment: the stores it examines, its own data types (by name),
    how often (days), where its findings and results go, and who keeps it (the platform team unless ciamManagedBy names
    someone)."""
    models = [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]
    return [(m.label, rdn_value(s), ", ".join(values(s, "ciamScansRole")),
             ", ".join(n for n, _ in custom_identifiers(s)), one(s, "ciamRescanDays", ""),
             one(s, "ciamFindingsRole", ""), one(s, "ciamResultsRole", ""), _keeper(m, s))
            for m in models for s in discovery_services(m)]
