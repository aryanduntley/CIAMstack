"""Migration plan: compare two environments and list what's ready and what blocks cutover.

The claim being tested: if intent is environment-neutral and every environment binds the same roles,
a migration is "render the target from the same databases". Anything that makes that false shows up
here as a blocker with an owner.

A connector: the checks here span domains (service names vs the consumers and certificates that depend
on them, firewall bindings vs consumers). They run first, then every applicable adapter's checks, then
every domain's, in registration order; every check is a pure function of a PlanContext returning Findings. A check
that fails never passes silently or hides the others: its failure is a blocker naming the check and the error.
"""
import datetime as dt
from typing import NamedTuple, Optional

from ..core.contract import PlanContext
from .access import access_check
from .edge import edge_check
from ..core.directory import children, date_of, follow, get, one, rdn_value, values
from ..core.environment import EnvModel, one_role, of_class
from ..core.findings import findings, merge_findings, owner_label, responsible
from ..core.naming import env_label
from ..core.overlays import override_differences
from ..domains.directory.domain import consumers_of_role
from ..domains.governance.domain import display_name, operator
from ..domains.pki.naming import CERTIFICATES
from .registry import ADAPTERS, DOMAINS
from .render import assemble, render_parts

Plan = NamedTuple("Plan", [("src", EnvModel), ("dst", EnvModel), ("cutover", Optional[dt.date]),
                           ("as_of", dt.date), ("blockers", tuple), ("actions", tuple), ("ok", tuple),
                           ("requests", tuple),          # ((party entry, ((allowlist, new, role, by), …)), …);
                                                         # allowlist None: an item in a system the party keeps, new
                                                         # its text, role its topic (None: the landing zone; dns)
                           ("target_files", dict),
                           ("target_summary", str)])     # what the target renders to, in words (from its adapters)


# ------------------------------------------------------------------ cross-domain checks
def _check_neutral(ctx):
    """Environment-neutral outputs must be byte-identical (R8), except where the environments' own overrides make
    them run different values (the Overrides actions name each)."""
    differ = [p for p in ctx.neutral_paths if ctx.src_files[p] != ctx.dst_files.get(p)]
    if not differ:
        return findings(ok=[f"All {len(ctx.neutral_paths)} environment-neutral outputs render identically for both "
                            f"environments ({', '.join(ctx.neutral_paths)}). Intent moves as-is."])
    if override_differences(ctx.d, ctx.src.overrides, ctx.dst.overrides):
        return findings(ok=[f"Environment-neutral outputs {', '.join(differ)} differ only by the environments' "
                            "overrides (see the Overrides actions); the shared intent is identical."])
    return findings(blockers=[("Intent", "Environment-neutral outputs differ: " + ", ".join(differ),
                               responsible(ctx.d, ctx.dst.env))])


def _contract(ctx, svc):
    role = one(svc, "ciamBindingRole")
    t = one_role(ctx.dst, role)
    if not t:
        return findings()
    a, b = one(svc, "ciamFqdn"), one(t, "ciamFqdn")
    if a == b:
        return findings(ok=[f"Contract kept: `{role}` is `{a}` in both environments."])
    found = consumers_of_role(ctx.d, one(svc, "ciamTargetRole"))
    users = found if found is not None else ["every SSO application and partner"]
    certs = [rdn_value(c) for c in children(ctx.d, CERTIFICATES, "ciamCertificate")
             if a in values(c, "ciamSubjectAltName") and b not in values(c, "ciamSubjectAltName")]
    return findings(blockers=[("Contract", f"`{role}` changes name `{a}` → `{b}`. Every consumer would have to "
                               f"reconfigure ({', '.join(users)}), and certificate(s) {', '.join(certs) or '-'} "
                               f"don't cover the new name. Fix: bind the stable name `{a}` in {ctx.dst.label}.",
                               responsible(ctx.d, t, ctx.dst.env))])


def _check_contracts(ctx):
    """Service names consumers and partners use must not change (R9)."""
    return merge_findings([_contract(ctx, svc) for svc in of_class(ctx.src, "ciamServiceName")])


def _missing_role(ctx, role):
    consumer = follow(ctx.d, one_role(ctx.src, role), "ciamAllowsConsumer")
    if not consumer:
        return ("Binding", f"Role `{role}` is bound in {ctx.src.label} but not in {ctx.dst.label}.",
                responsible(ctx.d, ctx.dst.env))
    unowned = "" if one(consumer, "ciamOwner") else \
        " Nobody owns it: decide whether to migrate or retire it before cutover."
    return ("Binding", f"Consumer `{rdn_value(consumer)}` (status {one(consumer, 'ciamMigrationStatus')}) is "
            f"allowed in {ctx.src.label} but has no firewall rule in {ctx.dst.label}.{unowned}",
            owner_label(ctx.d, consumer))


def _check_roles(ctx):
    """Every role bound in the source must be bound in the target."""
    src_roles = {one(b, "ciamBindingRole") for b in ctx.src.bindings}
    dst_roles = {one(b, "ciamBindingRole") for b in ctx.dst.bindings}
    return findings(blockers=[_missing_role(ctx, r) for r in sorted(src_roles - dst_roles)],
                    ok=[f"New in {ctx.dst.label}: `{r}`." for r in sorted(dst_roles - src_roles)])


def _declared_why(ctx, role):
    """Why the target's lineage declares a role required (the ciamRequiredRole's description), if it does."""
    found = [r for e in ctx.dst.lineage for r in children(ctx.d, f"ou=stack,{e.dn}", "ciamRequiredRole")
             if one(r, "ciamBindingRole") == role]
    return (f"declared by {env_label(found[0].dn.split(',ou=stack,', 1)[1])}"
            + (f": {one(found[0], 'description')}" if one(found[0], "description") else "")) if found else None


def _check_required(ctx):
    """Every role the target must bind (its domains', its adapters', the ones it declares) is bound. Roles the source
    binds are reported by the role check; this names the rest."""
    src_roles = {one(b, "ciamBindingRole") for b in ctx.src.bindings}
    return findings(blockers=[("Binding", f"Role `{r}` is required in {ctx.dst.label} "
                               f"({_declared_why(ctx, r) or 'by its domains and adapters'}) but nothing binds it.",
                               responsible(ctx.d, ctx.dst.env))
                              for r in ctx.dst.unbound if r not in src_roles])


# ------------------------------------------------------------------ composition
CROSS_DOMAIN_CHECKS = (_check_neutral, _check_contracts, _check_roles, _check_required)


def check_name(check):
    return f"{check.__module__}.{check.__qualname__}"


def run_check(check, ctx):
    """A check's findings; when it fails (data it didn't expect, a defect), a blocker that names the check and the
    error instead, so the verdict can't be READY and every other check still reports."""
    try:
        return check(ctx)
    except Exception as e:      # any failure becomes a finding: a plan never passes a check it couldn't run
        return findings(blockers=[("Planner", f"Check `{check_name(check)}` could not run ({type(e).__name__}: {e}). "
                                   "What it verifies is unknown until it does: correct the data it names, or report "
                                   "the defect.", responsible(ctx.d, ctx.dst.env))])


def checks(adapters, domains=DOMAINS):
    """Every planner check, in report order: cross-domain, then each adapter's, then each domain's."""
    return (*CROSS_DOMAIN_CHECKS, *(c for a in adapters for c in a.checks), *(c for d in domains for c in d.checks))


def _group_requests(requests):
    """((party, ((allowlist, new, role, by), …)), …) in order of each party's first request."""
    parties = {mgr.dn: mgr for mgr, *_ in requests}
    return tuple((mgr, tuple((xa, new, role, by) for m, xa, new, role, by in requests if m.dn == dn))
                 for dn, mgr in parties.items())


def render_summary(adapters):
    """'A, B, and the environment-neutral X/Y configuration' from the adapters' descriptions of their outputs."""
    labels = [a.neutral_label for a in adapters if a.neutral_label]
    items = [a.renders for a in adapters if a.renders] + \
        ([f"the environment-neutral {'/'.join(labels)} configuration"] if labels else [])
    return ", ".join(items[:-1]) + ", and " + items[-1] if len(items) > 1 else (items[0] if items else "nothing")


def plan(d, src_spec, dst_spec, as_of, installed=ADAPTERS, domains=DOMAINS):
    """Plan moving src to dst with the installed adapters: render both, run every check, collect the findings."""
    src, src_adapters, src_neutral, src_specific = render_parts(d, src_spec, installed)
    dst, adapters, dst_neutral, dst_specific = render_parts(d, dst_spec, installed)
    cutover = date_of(dst.env, "ciamPlannedCutover")
    dst_files = assemble(dst, adapters, dst_neutral, dst_specific)
    ctx = PlanContext(d, src, dst, cutover, as_of, assemble(src, src_adapters, src_neutral, src_specific), dst_files,
                      tuple(src_neutral))
    f = merge_findings([*(run_check(check, ctx) for check in checks(adapters, domains)),
                        run_check(access_check(src_adapters, adapters), ctx),
                        run_check(edge_check(src_adapters, adapters), ctx)])
    return Plan(src, dst, cutover, as_of, f.blockers, f.actions, f.ok, _group_requests(f.requests), dst_files,
                render_summary(adapters))


# ------------------------------------------------------------------ output
def _action_order(action):
    area, _, _, by = action
    return (by is None, by or dt.date.max, area)


def to_markdown(p):
    verdict = "NOT READY" if p.blockers else "READY"
    unbound = ((f"Target roles still unbound: {', '.join(f'`{r}`' for r in p.dst.unbound)}", "")
               if p.dst.unbound else ())
    lines = (f"# Migration plan: {p.src.label} → {p.dst.label}", "",
             f"Generated by opsdir as of {p.as_of}. Planned cutover: **{p.cutover or 'not set'}**.", "",
             f"## Verdict: {verdict} ({len(p.blockers)} blockers, {len(p.actions)} actions)", "",
             *unbound,
             "## Blockers", "", "| Area | Finding | Owner |", "|---|---|---|",
             *([f"| {a} | {t} | {o} |" for a, t, o in p.blockers] or ["| - | none | - |"]),
             "", "## Actions (dated)", "", "| Area | Action | Owner | Do by |", "|---|---|---|---|",
             *(f"| {a} | {t} | {o} | {b or ''} |" for a, t, o, b in sorted(p.actions, key=_action_order)),
             "", "## Already in place", "", *(f"- {x}" for x in p.ok),
             "", "## What the target renders to", "",
             f"`opsdir render {p.dst.label}` produces {len(p.target_files)} files from the same databases: "
             f"{p.target_summary}.", "")
    return "\n".join(lines)


# What a party keeps that a request asks it to change (the topic of an item with no allowlist): (subject, where)
_TOPICS = {None: ("Landing zone changes", "in the landing zone you keep (the rendered terraform/landing-zone/ files "
                  "hold what we can describe)"),
           "dns": ("DNS changes", "in the DNS zones you run")}


def _asks(asks):
    """((topic, items), ...) of a request's items with no allowlist, by topic in _TOPICS order."""
    return tuple((topic, items) for topic in _TOPICS
                 for items in ([a for a in asks if a[2] == topic],) if items)


def _ask_lines(items):
    return tuple(f"- {text}" + (f" Needed by {by}." if by else "") for _, text, _, by in items)


def _landing_draft(p, mgr, asks, platform, signer):
    """A request to a party keeping systems the target relies on (its landing zone, DNS zones it runs): what to set up
    or change there before cutover."""
    (topic, first), *more = _asks(asks)
    subject, where = _TOPICS[topic]
    return (f"To: {rdn_value(mgr)} <{one(mgr, 'mail', 'n/a')}>",
            f"Subject: {subject} needed for {p.dst.label}" + (f" before {p.cutover}" if p.cutover else ""),
            "",
            "Hello,", "",
            f"We are moving {platform} to {p.dst.label}" + (f"; planned cutover is {p.cutover}." if p.cutover else ".")
            + f" Please set up the following {where}:", "",
            *_ask_lines(first),
            *(line for t, items in more for line in ("", f"Also, {_TOPICS[t][1]}:", "", *_ask_lines(items))),
            "", "Thank you,", signer, "", "_Generated from the operations directory._")


def _request_draft(p, mgr, items):
    names_stable = not any(b[0] == "Contract" for b in p.blockers)
    org = operator(p.dst.d)
    platform = f"the {display_name(org)} external identity platform" if org else "our external identity platform"
    signer = next((display_name(get(p.dst.d, o)) for o in values(p.dst.env, "ciamOwner")), "The platform team")
    asks, items = [i for i in items if i[0] is None], [i for i in items if i[0] is not None]
    if not items:
        return "\n".join(_landing_draft(p, mgr, asks, platform, signer)) + "\n"
    lines = (f"To: {rdn_value(mgr)} <{one(mgr, 'mail', 'n/a')}>",
             f"Subject: Allowlist update needed before {p.cutover} "
             f"({display_name(org) + ' ' if org else ''}identity platform move)", "",
             "Hello,", "",
             f"We are moving {platform} to a new hosting environment. "
             f"Planned cutover is {p.cutover}. "
             + ("Service names stay the same; some addresses change." if names_stable
                else "Some addresses change (service names are still being confirmed)."), "",
             "Please add the following to the systems you operate:", "",
             *(f"- **{one(xa, 'ciamExternalSystem')}**: add `{new}` "
               f"(currently allowlisted: {', '.join(values(xa, 'ciamRecordedCidr'))}). Needed by {by}."
               for xa, new, role, by in items),
             "", "Please keep the existing entries until we confirm cutover; we'll tell you when they can go.",
             *(line for t, group in _asks(asks)
               for line in ("", f"Also, {_TOPICS[t][1].split(' (')[0]}:", "", *_ask_lines(group))),
             "", "Thank you,", signer, "",
             f"_Generated from the operations directory; entries {', '.join(rdn_value(x[0]) for x in items)}._")
    return "\n".join(lines) + "\n"


def request_drafts(p):
    """One change-request draft per external party whose allowlist must change."""
    return {f"requests/{rdn_value(mgr)}.md": _request_draft(p, mgr, items) for mgr, items in p.requests}
