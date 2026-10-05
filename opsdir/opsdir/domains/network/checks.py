"""Network planner checks: egress partners allowlist (fixed, public, and where the routes send traffic), private
endpoints that reach nothing or stop answering the usual name, endpoint-service consumers who must reconnect,
interconnects whose networks overlap or whose other side isn't in place, outside sites the egress proxy or firewall
doesn't allow, time sources and flow logs, and the plumbing the target's keepers still have to build (a request to
each). What the target doesn't bind at all is the core role check's blocker; these
look at what each binding says."""
import ipaddress

from ...core.changeset import add_values, delete_values, set_values
from ...core.directory import children, get, is_kind, one, rdn_value, values
from ...core.environment import of_class, one_role
from ...core.findings import Fix, findings, merge_findings, owner_label, responsible
from ...core.naming import env_label
from ...core.network import is_private
from ..infrastructure.naming import EXTERNAL_ALLOWLISTS
from .plumbing import plumbing_requests, plumbing_unasked
from .routing import allows, default_routes, required_sites


def _by_role(m, oc):
    return {one(b, "ciamBindingRole"): b for b in of_class(m, oc)}


# ------------------------------------------------------------------ egress partners allowlist
def egress_problems(m, egress):
    """Why an egress binding of environment m isn't an address a partner can allowlist, or isn't where its traffic
    leaves: automatic addresses, a private range, no default route through it (when m records routes)."""
    role, cidr = one(egress, "ciamBindingRole"), one(egress, "ciamCidr")
    return (*(("the provider picks its addresses (automatic allocation), so there is nothing fixed to allow: give it "
               "static addresses",) if one(egress, "ciamNatAllocation") == "automatic" else ()),
            *((f"its range {cidr} is private address space, so partners see whichever public address the traffic "
               "leaves by",) if cidr and is_private(cidr) else ()),
            *(("no route table sends traffic for the internet through it",)
              if default_routes(m) and not any(r.kind == "nat" and r.target == role for _, r in default_routes(m))
              else ()))


def check_egress(ctx):
    """Partners' allowlists of the target's egress: each must name a fixed public address the routes actually use."""
    actions = []
    for xa in children(ctx.d, EXTERNAL_ALLOWLISTS, "ciamExternalAllowlist"):
        b = one_role(ctx.dst, one(xa, "ciamRefersToRole"))
        if one(xa, "ciamAllowlistDirection") != "partner-ingress" or b is None or not is_kind(ctx.d, b, "ciamEgress"):
            continue
        party = get(ctx.d, one(xa, "ciamManagedBy"))
        actions += [("Egress", f"`{rdn_value(xa)}` ({rdn_value(party) if party else '?'}) allows {ctx.dst.label}'s "
                     f"`{one(b, 'ciamBindingRole')}`, but {p}.", responsible(ctx.d, b, ctx.dst.env), ctx.cutover)
                    for p in egress_problems(ctx.dst, b)]
    return findings(actions=actions)


# ------------------------------------------------------------------ private endpoints
def check_private_endpoints(ctx):
    """Private endpoints that reach a role their environment doesn't bind, and ones the target keeps without private
    DNS where the source had it (clients using the service's usual name would go to its public endpoint)."""
    actions, fixes = [], []
    for m in (ctx.src, ctx.dst):
        bound = {one(b, "ciamBindingRole") for b in m.bindings}
        dangling = [(p, r) for p in of_class(m, "ciamPrivateEndpoint") for r in values(p, "ciamReachesRole")
                    if r not in bound]
        actions += [("Private endpoints", f"{m.label}: private endpoint `{rdn_value(p)}` reaches `{r}`, which "
                     f"{m.label} doesn't bind.", responsible(ctx.d, p, m.env), None) for p, r in dangling]
        fixes += [Fix(f"reaches:{m.label}:{rdn_value(p)}:{r}", "Private endpoints",
                      f"Stop `{rdn_value(p)}` reaching `{r}` in {m.label}",
                      (delete_values(p, "ciamReachesRole", (r,)),), (),
                      (f"If {m.label} should bind `{r}` (a secret or store it really uses), bind it instead.",))
                  for p, r in dangling]
    dst = _by_role(ctx.dst, "ciamPrivateEndpoint")
    lost = [(role, p) for role, p in sorted(_by_role(ctx.src, "ciamPrivateEndpoint").items())
            if role in dst and one(p, "ciamPrivateDns") == "TRUE" and one(dst[role], "ciamPrivateDns") != "TRUE"]
    actions += [("Private endpoints", f"{ctx.src.label}'s private endpoint `{rdn_value(p)}` answers the "
                 f"{one(p, 'ciamPrivateService')} service's usual name inside the network; {ctx.dst.label}'s "
                 f"(`{rdn_value(dst[role])}`) doesn't, so clients using that name reach the public endpoint: turn on "
                 "private DNS, or point them at the endpoint's own name.", responsible(ctx.d, dst[role], ctx.dst.env),
                 ctx.cutover) for role, p in lost]
    dns = [Fix(f"private-dns:{role}", "Private endpoints", f"Turn on private DNS for `{rdn_value(dst[role])}` in "
                 f"{ctx.dst.label}, as {ctx.src.label}'s has it", (set_values(dst[role], "ciamPrivateDns", ("TRUE",)),),
                 (f"Apply the rendered private endpoint in {ctx.dst.label} (its keeper's root when someone else keeps "
                  "it).",),
                 ("Clients that use the endpoint's own name keep working; ones resolving the service's usual name "
                  "start reaching the endpoint instead of the public service.",)) for role, _ in lost]
    return findings(actions=actions, fixes=[*fixes, *dns])


# ------------------------------------------------------------------ endpoint services
def _reconnects(ctx, e, t):
    """Actions for each consumer of a source endpoint service whose target counterpart has another name."""
    new = one(t, "ciamServiceAlias")
    return [("Endpoint services", f"Consumer `{rdn_value(c)}` connects to `{rdn_value(e)}` privately "
             f"({one(e, 'ciamServiceAlias') or 'its name not recorded'}); for {ctx.dst.label} it must create an "
             f"endpoint to {f'`{new}`' if new else 'the target service (its name not recorded yet)'} and be accepted "
             "before cutover.", owner_label(ctx.d, c), ctx.cutover)
            for c in (get(ctx.d, dn) for dn in values(e, "ciamAllowsConsumer")) if c is not None]


def check_endpoint_services(ctx):
    """Endpoint services across the move: consumers reconnect to the target's name, principals the target no longer
    allows, and target services anyone who knows their name may connect to unaccepted."""
    actions, fixes, dst = [], [], _by_role(ctx.dst, "ciamEndpointService")
    for role, e in sorted(_by_role(ctx.src, "ciamEndpointService").items()):
        t = dst.get(role)
        if t is None:
            continue                                                            # the role check's blocker
        if one(t, "ciamServiceAlias") is None or one(t, "ciamServiceAlias") != one(e, "ciamServiceAlias"):
            actions += _reconnects(ctx, e, t)
        lost = sorted(set(values(e, "ciamAllowedPrincipal")) - set(values(t, "ciamAllowedPrincipal")))
        actions += [("Endpoint services", f"{ctx.src.label} allows {', '.join(f'`{p}`' for p in lost)} to connect to "
                     f"`{rdn_value(e)}`; {ctx.dst.label}'s `{rdn_value(t)}` doesn't: allow them, or confirm they no "
                     "longer connect.", responsible(ctx.d, t, ctx.dst.env), ctx.cutover)] if lost else []
        fixes += [Fix(f"endpoint-principals:{role}", "Endpoint services",
                      f"Allow {', '.join(f'`{p}`' for p in lost)} to connect to `{rdn_value(t)}` in {ctx.dst.label}",
                      (add_values(t, "ciamAllowedPrincipal", lost),),
                      (f"Apply the rendered endpoint service in {ctx.dst.label}.",),
                      (f"Allows exactly what {ctx.src.label} allows; a principal that no longer connects stays "
                       "allowed.",))
                  ] if lost and ctx.src.provider == ctx.dst.provider else []    # another cloud's principals can't be
    actions += [("Endpoint services", f"{ctx.dst.label}: anyone who knows `{rdn_value(t)}`'s name may connect without "
                 "being accepted (no visibility restriction recorded, acceptance not required): restrict who sees it, "
                 "or require acceptance.", responsible(ctx.d, t, ctx.dst.env), None)
                for t in of_class(ctx.dst, "ciamEndpointService")
                if not values(t, "ciamVisibleTo") and one(t, "ciamAcceptanceRequired") != "TRUE"]
    fixes += [Fix(f"acceptance:{rdn_value(t)}", "Endpoint services", f"Require acceptance of each new connection to "
                  f"`{rdn_value(t)}` in {ctx.dst.label}", (set_values(t, "ciamAcceptanceRequired", ("TRUE",)),),
                  (f"Apply the rendered endpoint service in {ctx.dst.label}; accept each consumer's connection when it "
                   "asks.",),
                  ("Consumers that connect unaccepted today wait for an operator after cutover; restricting who may "
                   "see the service (ciamVisibleTo) is the other way.",))
              for t in of_class(ctx.dst, "ciamEndpointService")
              if not values(t, "ciamVisibleTo") and one(t, "ciamAcceptanceRequired") != "TRUE"]
    return findings(actions=actions, fixes=fixes)


# ------------------------------------------------------------------ interconnects
def _networks(d, env):
    return tuple(one(n, "ciamCidr") for n in children(d, f"ou=bindings,{env}", "ciamNetwork") if one(n, "ciamCidr"))


def overlaps(ours, theirs):
    """((our range, their range), ...) that overlap."""
    return tuple((a, b) for a in ours for b in theirs
                 if ipaddress.ip_network(a, strict=False).version == ipaddress.ip_network(b, strict=False).version
                 and ipaddress.ip_network(a, strict=False).overlaps(ipaddress.ip_network(b, strict=False)))


def check_interconnects(ctx):
    """Interconnects whose two networks overlap (traffic for the overlap can't be routed: a blocker in the target) or
    whose other side hasn't accepted or configured its half."""
    blockers, actions = [], []
    for m, target in ((ctx.src, False), (ctx.dst, True)):
        for link in of_class(m, "ciamInterconnect"):
            peer, owner = one(link, "ciamPeerEnvironment"), responsible(ctx.d, link, m.env)
            clash = overlaps(_networks(ctx.d, m.dn), _networks(ctx.d, peer)) if peer else ()
            text = (f"{m.label}: `{rdn_value(link)}` links to {env_label(peer)}, but their networks overlap ("
                    + "; ".join(f"{a} and {b}" for a, b in clash) + "): traffic for the overlap can't be routed.")
            blockers += [("Interconnect", text, owner)] if clash and target else []
            actions += [("Interconnect", text, owner, None)] if clash and not target else []
            actions += [("Interconnect", f"{m.label}: the other side of `{rdn_value(link)}` "
                         f"({env_label(peer) if peer else '?'}) hasn't accepted or configured its half.", owner,
                         ctx.cutover if target else None)] if one(link, "ciamPeerAccepted") == "FALSE" else []
    return findings(blockers=blockers, actions=actions)


# ------------------------------------------------------------------ outside sites
def site_request(m, proxy, site):
    """The text asking whoever keeps a proxy or firewall to let environment m's egress out to a site."""
    roles = ", ".join(f"`{r}`" for r in site.needed_by)
    return (f"Allow `{site.host}` ({site.kind}) through `{rdn_value(proxy)}` ({one(proxy, 'ciamProxyKind')}) for "
            f"{m.label}" + (f": {roles} reach it" if roles else "") + ".")


def check_sites(ctx):
    """Outside sites the platform must reach that the target's egress proxy or firewall doesn't allow (a request to
    the party that keeps it, when one is recorded), and firewalls with domain rules no default route sends egress
    through (their rules aren't enforced)."""
    sites, actions, requests = required_sites(ctx.d), [], []
    for p in of_class(ctx.dst, "ciamProxy"):
        missing = [s for s in sites if not allows(p, s)]
        owner = responsible(ctx.d, p, ctx.dst.env)
        actions += [("Egress", f"{ctx.dst.label}'s egress passes `{rdn_value(p)}` ({one(p, 'ciamProxyKind')}), which "
                     "doesn't allow " + ", ".join(f"`{s.host}` ({s.kind})" for s in missing) + ": allow them before "
                     "cutover, or what the platform fetches there fails (metadata, signing keys, certificate status, "
                     "vendors).", owner, ctx.cutover)] if missing else []
        party = get(ctx.d, one(p, "ciamManagedBy")) if one(p, "ciamManagedBy") else None
        requests += [(party, None, site_request(ctx.dst, p, s), "network", ctx.cutover)
                     for s in missing] if party is not None else []
        role = one(p, "ciamBindingRole")
        unrouted = one(p, "ciamProxyKind") == "firewall" and default_routes(ctx.dst) and not any(
            r.kind in ("firewall", "appliance") and r.target == role for _, r in default_routes(ctx.dst))
        actions += [("Egress", f"{ctx.dst.label}: no route sends internet egress through `{rdn_value(p)}`, so its "
                     "domain rules aren't enforced: route the subnets' default route through it.", owner,
                     ctx.cutover)] if unrouted else []
    return findings(actions=actions, requests=requests)


# ------------------------------------------------------------------ time and flow logs
def check_time(ctx):
    """A target with servers and no time source recorded anywhere: clock skew breaks SAML and replication."""
    if not ctx.dst.servers or of_class(ctx.dst, "ciamTimeSource") or of_class(ctx.src, "ciamTimeSource"):
        return findings()
    return findings(actions=[("Time", f"Neither {ctx.src.label} nor {ctx.dst.label} records where its servers get "
                              "their time (the provider's time service, NTP servers): record it, since clock skew "
                              "breaks SAML assertions and replication.", responsible(ctx.d, ctx.dst.env), None)])


def check_flow_logs(ctx):
    """Flow logs the target keeps for less time than the source, and flow logs sent to a role their environment
    doesn't bind."""
    dst = _by_role(ctx.dst, "ciamFlowLog")
    short = [(role, e) for role, e in sorted(_by_role(ctx.src, "ciamFlowLog").items())
             if role in dst and one(e, "ciamRetentionDays") and one(dst[role], "ciamRetentionDays")
             and int(one(dst[role], "ciamRetentionDays")) < int(one(e, "ciamRetentionDays"))]
    shorter = [("Flow logs", f"`{rdn_value(dst[role])}` keeps flow logs {one(dst[role], 'ciamRetentionDays')} days in "
                f"{ctx.dst.label}; {ctx.src.label} keeps them {one(e, 'ciamRetentionDays')}.",
                responsible(ctx.d, dst[role], ctx.dst.env), None) for role, e in short]
    fixes = [Fix(f"flow-log-retention:{role}", "Flow logs", f"Keep `{rdn_value(dst[role])}`'s flow logs "
                 f"{one(e, 'ciamRetentionDays')} days in {ctx.dst.label}, as {ctx.src.label} does",
                 (set_values(dst[role], "ciamRetentionDays", (one(e, "ciamRetentionDays"),)),),
                 (f"Apply the rendered flow log in {ctx.dst.label}'s landing zone (its keeper's root).",),
                 (f"Carries {ctx.src.label}'s retention over; if {ctx.dst.label} keeps them shorter on purpose (cost, "
                  "a policy), keep the action open instead.",)) for role, e in short]
    nowhere = [("Flow logs", f"{m.label}: flow log `{rdn_value(e)}` goes to `{one(e, 'ciamLogDestinationRole')}`, "
                f"which {m.label} doesn't bind.", responsible(ctx.d, e, m.env), None)
               for m in (ctx.src, ctx.dst) for e in of_class(m, "ciamFlowLog")
               if one(e, "ciamLogDestinationRole") and one_role(m, one(e, "ciamLogDestinationRole")) is None]
    return merge_findings([findings(actions=shorter, fixes=fixes), findings(actions=nowhere)])


# ------------------------------------------------------------------ plumbing the keepers build
def check_plumbing(ctx):
    """The target's plumbing not built yet (no provider ref): a request to each keeper, rendered in their root; an
    action when the record names no one to ask."""
    unasked = [("Network", f"{ctx.dst.label}: {len(k.bindings)} plumbing items in `{k.folder}/` are kept by "
                f"{k.name}, but no party is recorded to ask for them: record the landing zone's owner (or "
                "ciamManagedBy).",
                responsible(ctx.d, ctx.dst.env), ctx.cutover) for k in plumbing_unasked(ctx.dst)]
    return findings(actions=unasked, requests=[(party, None, text, "network", by)
                                               for party, text, by in plumbing_requests(ctx.dst, ctx.cutover)])
