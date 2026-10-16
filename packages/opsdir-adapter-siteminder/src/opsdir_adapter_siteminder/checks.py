"""The planner's checks for a plan whose source runs SiteMinder (Adapter.source_checks): what stops being protected
when the target doesn't run the agents that protect it, and the user directories whose directory consumer the record
doesn't hold. The partnerships its identity service serves (the federation domain's check), its header contracts
(the edge domain's) and its source objects (governance) are checked by the core. Pure."""
from opsdir.core.directory import children, follow, get, one, rdn_value, subtree, values
from opsdir.core.findings import findings, merge_findings, responsible
from opsdir.domains.compute.workloads import runs_here
from .naming import AGENT, DOMAINS, USER_DIRECTORIES

AREA = "SiteMinder"


def realm_role(d, realm):
    """The server role a realm's agent runs on (a web agent when its agent names none)."""
    agent = follow(d, realm, "smAgent")
    return (one(agent, "ciamTargetRole") if agent is not None else None) or AGENT


def _domain(d, realm):
    return get(d, realm.dn.split(",", 2)[2])


def _granting(d, realm):
    """The policies of a realm's domain granting one of its rules."""
    rules = {r.norm for r in children(d, realm.dn, "smRule")}
    return tuple(p for p in subtree(d, _domain(d, realm).dn, "smPolicy")
                 if any(get(d, r) is not None and get(d, r).norm in rules for r in values(p, "smRule")))


def _headers(d, policies):
    return tuple(dict.fromkeys(one(h, "ciamHeaderName") for p in policies for r in values(p, "smResponse")
                               for h in (get(d, r),) if h is not None and "ciamHeaderContract" in h.classes))


def _listed(names):
    return ", ".join(f"`{n}`" for n in names) or "none"


def _realm(ctx, realm):
    d, role = ctx.d, realm_role(ctx.d, realm)
    if not runs_here(ctx.src, role) or runs_here(ctx.dst, role):
        return findings()
    domain = _domain(d, realm)
    rules, policies = children(d, realm.dn, "smRule"), _granting(d, realm)
    scheme = follow(d, realm, "smAuthScheme")
    sign_on = f"; users sign in with `{rdn_value(scheme)}`" if scheme is not None else ""
    headers = _headers(d, policies)
    return findings(blockers=[(
        AREA,
        f"Realm `{rdn_value(domain)}/{rdn_value(realm)}` (resources `{one(realm, 'smResourceFilter')}`) is protected "
        f"by `{role}` servers, which {ctx.dst.label} doesn't run: its {len(rules)} rule(s) and the policies granting "
        f"them ({_listed(rdn_value(p) for p in policies)}{sign_on}) stop being enforced"
        + (f", and the application loses the headers it trusts ({_listed(headers)})" if headers else "")
        + ". Protect these resources with a gateway or access product the target runs (its paths, rules, sign-on and "
        "headers), then retire the realm.", responsible(d, realm, domain))])


def check_realms(ctx):
    """A blocker for every realm protected by agents the source runs and the target doesn't."""
    return merge_findings([_realm(ctx, r) for r in subtree(ctx.d, DOMAINS, "smRealm")])


def check_user_directories(ctx):
    """An action for every user directory SiteMinder binds to as an account no directory consumer records: the
    directory's consumers don't show it, so nobody tracks its retirement."""
    return findings(actions=[(
        AREA, f"SiteMinder's user directory `{rdn_value(u)}` binds as an account no directory consumer records: record "
        "the consumer (its bind DN, owner, migration status) and link it (smConsumer), so the directory's consumers "
        "show SiteMinder until it is retired.", responsible(ctx.d, u), ctx.cutover)
        for u in children(ctx.d, USER_DIRECTORIES, "smUserDirectory") if one(u, "smConsumer") is None])
