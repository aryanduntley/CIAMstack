"""The planner's view of protected web applications, whatever product enforces them, and the fixes that move one to
another product. Pure.

For every application the source enforces (its enforcing role, as the source sees it, runs there):
  - the target's enforcing role (its own override, else the shared one) doesn't run there: a blocker, nothing in the
    target protects it (its resources, rules, sign-on and the headers it trusts stop);
  - the same role: kept;
  - another role (a move to another product): what that product needs from the record is a blocker when missing (the
    service names it is published as, bound in the target; the application behind it, when the source enforced it
    inside the application's own web server; the integration it signs users in as, when the source collected
    credentials itself), and a header contract still set by another role is an action whose fix has the new enforcer
    set it in the target. What the new product can't express is that product's check (express.losses).
The fixes write environment overrides (ciamOverride), never the shared entries: the source keeps what it runs."""
from ...core.changeset import new_entry, set_values
from ...core.directory import follow_all, get, one, rdn_value, values
from ...core.environment import bound_nowhere
from ...core.findings import Fix, findings, merge_findings, responsible
from ..compute.workloads import runs_here
from .apps import enforcer, every_rule, path_resources, protected_apps
from .naming import COLLECTED

AREA = "Web access"


def _override_records(m, entry, attr, value, name, why):
    """The records setting environment m's own value of an overridable attribute of a shared entry: its override
    entry (cn=<name>) added, or its value replaced; the overrides container added when missing."""
    container = f"ou=overrides,{m.dn}"
    held = get(m.d, f"cn={name},{container}")
    if held is not None:
        return (set_values(held, "ciamOverrideValue", (value,)),)
    return (*(() if get(m.d, container) else (new_entry(container, ("top", "organizationalUnit"),
                                                        {"ou": ("overrides",)}),)),
            new_entry(f"cn={name},{container}", ("top", "ciamOverride"),
                      {"cn": (name,), "ciamOverrides": (entry.dn,), "ciamOverrideAttribute": (attr,),
                       "ciamOverrideValue": (value,), "description": (why,)}))


def protect_fix(m, app, role, product, adapter):
    """The Fix having product (its server role) protect an application in environment m: m's override of the
    application's enforcing role. adapter names the fix (protect:<adapter>/<application>)."""
    name = rdn_value(app)
    return Fix(f"protect:{adapter}/{name}", AREA,
               f"Have {product} (`{role}`) protect `{name}` in {m.label}",
               _override_records(m, app, "ciamEnforcedByRole", role, f"{name}-enforcer",
                                 f"{product} protects {name} in this environment"),
               (f"Check what {product} can't express of `{name}` (the plan's {product} findings) before applying "
                "its render.",),
               ("The source keeps its own enforcer: until cutover both protect the application, each in its own "
                "environment.",))


def enforcer_header_fix(m, contract, role):
    """The Fix having role set a header contract's header in environment m (m's override of ciamSetByRole)."""
    name = rdn_value(contract)
    return Fix(f"enforcer-header:{name}", AREA,
               f"Have `{role}` set `{one(contract, 'ciamHeaderName')}` (contract `{name}`) in {m.label}",
               _override_records(m, contract, "ciamSetByRole", role, f"{name}-setter",
                                 f"{role} enforces the application trusting this header here"),
               (f"Confirm `{role}` removes the header from incoming requests before setting it, then record "
                "ciamStripsInbound.",),
               ("The application keeps trusting the header: whoever else can reach it directly can still send it.",))


def _what_stops(d, app):
    rules = every_rule(d, app)
    sign_on = one(app, "ciamSignOn")
    headers = tuple(one(h, "ciamHeaderName") for h in follow_all(d, app, "ciamSetsHeader") if h is not None)
    return (f"its {len(path_resources(d, app))} resource(s), its rules ("
            + (", ".join(f"`{rdn_value(r)}`" for r in rules) or "none") + ")"
            + (f", its {sign_on} sign-on" if sign_on and sign_on != "none" else "")
            + (", and the headers the application trusts (" + ", ".join(f"`{h}`" for h in headers) + ")"
               if headers else ""))


def _move_blockers(ctx, app, seen, role):
    name = rdn_value(app)
    published = values(seen, "ciamPublishedAs")
    backend = one(seen, "ciamBackendRole")
    return (
        *((f"Protected application `{name}` moves to `{role}`, but the record names no service name clients reach "
           "it at: record it (ciamPublishedAs) so the new enforcer answers there.",) if not published else
          tuple(f"Protected application `{name}` is published as `{r}`, which {ctx.dst.label} doesn't bind."
                for r in bound_nowhere(published, ctx.dst))),
        *((f"Protected application `{name}` was enforced inside its own web server; `{role}` must send requests on "
           "to it: record the binding role of the application behind it (ciamBackendRole).",) if not backend else
          tuple(f"Protected application `{name}` sends requests to `{r}`, which {ctx.dst.label} doesn't bind."
                for r in bound_nowhere((backend,), ctx.dst))),
        *((f"Protected application `{name}`'s users sign in with {one(seen, 'ciamSignOn')} collected by "
           f"`{enforcer(ctx.src, app)}`; `{role}` signs them in through an identity service: record the "
           "integration it signs in as (ciamSignInAs), served by an identity service that offers that sign-on.",)
          if one(seen, "ciamSignOn") in COLLECTED and not one(seen, "ciamSignInAs") else ()))


def _header_actions(ctx, app, seen, role, owner):
    contracts = tuple(c for c in follow_all(ctx.dst.d, seen, "ciamSetsHeader") if c is not None)
    moved = tuple(c for c in contracts if one(c, "ciamSetByRole") != role)
    return ([(AREA, f"Header `{one(c, 'ciamHeaderName')}` (contract `{rdn_value(c)}`), which `{rdn_value(app)}` "
              f"trusts, is set by `{one(c, 'ciamSetByRole')}` in {ctx.dst.label}, where `{role}` protects the "
              "application: have it set the header there.", owner, ctx.cutover) for c in moved],
            [enforcer_header_fix(ctx.dst, c, role) for c in moved])


def _app(ctx, app):
    src_role = enforcer(ctx.src, app)
    if not src_role or not runs_here(ctx.src, src_role):
        return findings()
    role, name = enforcer(ctx.dst, app), rdn_value(app)
    owner = responsible(ctx.d, app, ctx.dst.env)
    if not role or not runs_here(ctx.dst, role):
        return findings(blockers=[(AREA, f"Protected application `{name}` (`{one(app, 'ciamBasePath')}`) is enforced "
                                         f"by `{role}`, which {ctx.dst.label} doesn't run: "
                                         f"{_what_stops(ctx.src.d, app)} stop being enforced. Have a product "
                                         f"{ctx.dst.label} runs protect it (its enforcing role overridden there), or "
                                         "retire it.", owner)])
    if role == src_role:
        return findings(ok=[f"Protected application `{name}` stays with `{role}` in {ctx.dst.label}."])
    seen = get(ctx.dst.d, app.dn) or app
    actions, fixes = _header_actions(ctx, app, seen, role, owner)
    blockers = [(AREA, text, owner) for text in _move_blockers(ctx, app, seen, role)]
    return findings(blockers=blockers, actions=actions, fixes=fixes,
                    ok=[] if blockers else [f"Protected application `{name}` moves from `{src_role}` to `{role}` in "
                                            f"{ctx.dst.label}."])


def check_protected_apps(ctx):
    """Applications the source protects that nothing in the target would, and what a move to another product needs
    from the record."""
    return merge_findings([_app(ctx, a) for a in protected_apps(ctx.src.d)])
