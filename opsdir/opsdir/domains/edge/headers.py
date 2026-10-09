"""Header contracts: a header someone sets and applications or products trust. Header-based sign-on (a gateway puts who
the user is in a header the application believes), the client's address behind a proxy (products rate-limit, assess
risk and audit by it), the scheme and host the client used. Intent: the same in every environment, and a contract like
a service name: the header's name must not change. The report and the planner's check. Pure.

A header is only as trustworthy as its setter: one a client can send itself (the setter doesn't strip it from
incoming requests) is spoofable. A setter the target doesn't run leaves whoever trusts the header without it. A load
balancer that passes TLS through can set no header; one that terminates it hides the client's address from the
servers unless they trust its client-address header.
"""
from ...core.directory import children, get, one, rdn_value, values
from ...core.environment import of_class, servers_with_role
from ...core.findings import findings, merge_findings, responsible
from ..compute.workloads import kubernetes_roles
from .naming import HEADER_CONTRACTS, LAYER7
from .policies import inspects, policy_for
from .running import observed_facts

HEADER_HEADERS = ("contract", "header", "kind", "set by", "trusted by", "value from", "strips inbound")


def contracts(d):
    """Every header contract, by name."""
    return sorted(children(d, HEADER_CONTRACTS, "ciamHeaderContract"), key=rdn_value)


def _trusting(d, c):
    """Who trusts a contract's header, in words: its server roles, then its consumers."""
    return [*(f"`{r}`" for r in values(c, "ciamTrustedByRole")),
            *(f"`{rdn_value(get(d, x))}`" for x in values(c, "ciamTrustedByConsumer") if get(d, x) is not None)]


def header_rows(d, dn=None):
    """One row per header contract."""
    return [(rdn_value(c), one(c, "ciamHeaderName"), one(c, "ciamHeaderKind"), one(c, "ciamSetByRole"),
             ", ".join(t.strip("`") for t in _trusting(d, c)), one(c, "ciamHeaderValue") or "",
             {"TRUE": "yes", "FALSE": "no"}.get(one(c, "ciamStripsInbound"), "")) for c in contracts(d)]


def _is_service(m, role):
    return any(one(b, "ciamBindingRole") == role for b in of_class(m, "ciamServiceName"))


def _contract(ctx, c):
    d, setter, header = ctx.d, one(c, "ciamSetByRole"), one(c, "ciamHeaderName")
    owner, trusting = responsible(d, c, ctx.dst.env), _trusting(d, c)
    who = ", ".join(trusting) or "nobody recorded"
    if _is_service(ctx.src, setter) or _is_service(ctx.dst, setter):
        t, p = policy_for(d, "ciamTrafficPolicy", setter), policy_for(d, "ciamProtectionPolicy", setter)
        layer = () if inspects(t, p) else (
            ("Edge", f"Header `{header}` (contract `{rdn_value(c)}`) is set by the load balancer of `{setter}`, whose "
             "TLS passes through: a layer 4 load balancer sets no header. Terminate TLS there (a traffic policy), or "
             "name the setter that does.", owner, None),)
        blockers = ()
    else:
        layer = ()
        blockers = (("Edge", f"Header `{header}` (contract `{rdn_value(c)}`) is set by `{setter}` servers, which "
                     f"{ctx.dst.label} doesn't run: {who} would go without it"
                     + (" (header-based sign-on stops)." if one(c, "ciamHeaderKind") == "identity" else "."),
                     owner),) if servers_with_role(ctx.src, setter) and not servers_with_role(ctx.dst, setter) \
            and setter not in kubernetes_roles(ctx.dst) else ()
    spoofable = (("Edge", f"Clients can send header `{header}` themselves (contract `{rdn_value(c)}`): `{setter}` must "
                  f"remove it from incoming requests, since {who} {'trust' if len(trusting) > 1 else 'trusts'} it.",
                  owner, None),) \
        if one(c, "ciamHeaderKind") == "identity" and one(c, "ciamStripsInbound") != "TRUE" else ()
    return findings(blockers=blockers, actions=[*layer, *spoofable],
                    ok=[f"Header contract `{rdn_value(c)}` kept: `{header}` set by `{setter}` in {ctx.dst.label}."]
                    if not blockers and not layer else [])


def _client_ip(ctx, role):
    """Actions when the move puts a TLS-terminating load balancer where the source passes TLS through: the servers
    behind it see the balancer's address unless they trust its client-address header."""
    d = ctx.d
    t = policy_for(d, "ciamTrafficPolicy", role)
    if t is None or one(t, "ciamTlsMode") not in LAYER7 or "tls-mode passthrough" not in observed_facts(ctx.src, role):
        return findings()
    owner = responsible(d, t, ctx.dst.env)
    found = [c for c in contracts(d) if one(c, "ciamHeaderKind") == "client-ip" and one(c, "ciamSetByRole") == role]
    if not found:
        return findings(actions=[("Edge", f"{ctx.src.label} passes TLS for `{role}` through, so its servers see each "
                                  f"client's address; {ctx.dst.label} terminates it ({one(t, 'ciamTlsMode')}), so "
                                  "they'll see the load balancer's. Record a client-ip header contract (e.g. "
                                  "X-Forwarded-For) and set the products that use the address (risk, rate limits, "
                                  "audit) to trust it from the load balancer only.", owner, ctx.cutover)])
    return findings(actions=[("Edge", f"`{role}` changes from TLS passthrough ({ctx.src.label}) to "
                              f"{one(t, 'ciamTlsMode')} ({ctx.dst.label}): set {who} to trust "
                              f"`{one(c, 'ciamHeaderName')}` from {ctx.dst.label}'s load balancer before cutover, or "
                              "they'll see its address for every client.", owner, ctx.cutover)
                             for c in found for who in (", ".join(_trusting(d, c)) or "its products",)])


def check_headers(ctx):
    """Header setters the target doesn't run, setters that can't set headers, spoofable identity headers, and client
    addresses a move to a TLS-terminating load balancer would hide."""
    roles = sorted({one(b, "ciamBindingRole") for b in of_class(ctx.src, "ciamServiceName")})
    return merge_findings([*(_contract(ctx, c) for c in contracts(ctx.d)), *(_client_ip(ctx, r) for r in roles)])
