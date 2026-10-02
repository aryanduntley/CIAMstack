"""PingIDM planner checks: the deployment holds together (every mapping reads and writes things the record has, every
reconciliation schedule runs a mapping it has) and every connector can reach its system from the target (a target
role and a credential role the target binds; a connector with a fixed host is an action)."""

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.findings import findings, merge_findings, responsible
from opsdir.core.jsondata import held_json
from .naming import CONNECTORS, MANAGED, MAPPINGS, SCHEDULES


def _names(d, base, oc):
    return {rdn_value(e) for e in children(d, base, oc)}


def endpoint_problem(d, endpoint):
    """Why a mapping's source or target doesn't exist in the record (system/<connector>/..., managed/<object>), or
    None (other resource paths are IDM's own)."""
    kind, _, rest = (endpoint or "").partition("/")
    name = rest.split("/", 1)[0]
    if kind == "system" and name not in _names(d, CONNECTORS, "pingidmConnector"):
        return f"{endpoint} names connector {name!r}, which the record doesn't have"
    if kind == "managed" and name not in _names(d, MANAGED, "pingidmManagedObject"):
        return f"{endpoint} names managed object {name!r}, which the record doesn't have"
    return None


def deployment_problems(d):
    """(entry, why) for every mapping or schedule that refers to something the deployment doesn't have."""
    mappings = children(d, MAPPINGS, "pingidmMapping")
    names = {rdn_value(m) for m in mappings}
    ends = ((m, endpoint_problem(d, one(m, a))) for m in mappings for a in ("pingidmSource", "pingidmTarget"))
    runs = ((s, held_json(s, "pingidmConfig").get("invokeContext") or {})
            for s in children(d, SCHEDULES, "pingidmSchedule"))
    return (*((m, why) for m, why in ends if why),
            *((s, f"it reconciles mapping {c.get('mapping')!r}, which the record doesn't have") for s, c in runs
              if c.get("action") == "reconcile" and c.get("mapping") and c.get("mapping") not in names))


def _connector(ctx, c):
    name, target, credential = rdn_value(c), one(c, "pingidmTargetRole"), one(c, "pingidmCredentialRole")
    owner = responsible(ctx.d, c, ctx.dst.env)
    missing = [r for r in (target, credential) if r and one_role(ctx.dst, r) is None]
    blockers = (*((("IDM", f"Connector `{name}` has withheld credentials but no credential role: nothing says which "
                    f"secret {ctx.dst.label} gives it. Set pingidmCredentialRole.", owner),)
                  if values(c, "pingidmWithheld") and not credential else ()),
                *(("IDM", f"Connector `{name}` needs role `{r}`, which {ctx.dst.label} doesn't bind.", owner)
                  for r in missing))
    actions = () if target else (("IDM", f"Connector `{name}` reaches a fixed host from every environment (no target "
                                  f"role): confirm {ctx.dst.label} can reach it, or record the system's service name.",
                                  owner, None),)
    return findings(blockers=blockers, actions=actions)


def check_idm(ctx):
    """Mappings and schedules that refer to what the deployment doesn't have, and connectors the target can't give
    what they need, are blockers; a connector with a fixed host is an action."""
    held = findings(blockers=[("IDM", f"`{rdn_value(e)}`: {why}.", responsible(ctx.d, e, ctx.dst.env))
                              for e, why in deployment_problems(ctx.d)])
    parts = merge_findings([held, *(_connector(ctx, c) for c in children(ctx.d, CONNECTORS, "pingidmConnector"))])
    count = len(children(ctx.d, MAPPINGS, "pingidmMapping"))
    return parts if parts.blockers else parts._replace(ok=(*parts.ok, f"IDM's {count} mapping(s) and its schedules "
                                                         "refer only to connectors, objects and mappings it has."))
