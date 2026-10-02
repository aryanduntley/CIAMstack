"""External services and mail senders: the reports and the planner's check. Pure.

An external service is reached from servers of the roles that use it (ciamReachedFrom) and uses binding roles for its
credentials (ciamUsesRole). Where it holds an allowlist of the platform's names (CAPTCHA allowed domains, a vendor's
redirect allowlist), every public name the target gives those roles must be on it, or the service stops working at
cutover. A mail sender sends as a domain from a sending identity each environment binds (ciamSendingRole): the
target's identity must sign with DKIM and be authorized by SPF before cutover, or reset mail lands in spam.
"""
from ...core.directory import children, follow, get, one, rdn_value, values
from ...core.environment import one_role
from ...core.findings import findings, merge_findings, responsible
from .naming import DMARC_STRENGTH, EXTERNAL_SERVICES, MAIL_SENDERS

SERVICE_HEADERS = ("service", "kind", "vendor", "endpoint", "used from", "allowed domains", "uses", "contact")
SENDER_HEADERS = ("sender", "address", "domain", "sent by", "sending role", "purposes", "bounces")


def external_services(d):
    return children(d, EXTERNAL_SERVICES, "ciamExternalService")


def mail_senders(d):
    return children(d, MAIL_SENDERS, "ciamMailSender")


def _endpoint(s):
    host, ports = one(s, "ciamEndpointHost"), values(s, "ciamPort")
    return f"{host}:{','.join(ports)}" if host and ports else host or ""


def service_rows(d, dn=None):
    """One row per external service."""
    return [(rdn_value(s), one(s, "ciamServiceKind"), one(s, "ciamVendor") or "", _endpoint(s),
             ", ".join(values(s, "ciamReachedFrom")), ", ".join(values(s, "ciamAllowedDomain")),
             ", ".join(values(s, "ciamUsesRole")),
             rdn_value(follow(d, s, "ciamPartnerContact")) if one(s, "ciamPartnerContact") else "")
            for s in external_services(d)]


def sender_rows(d, dn=None):
    """One row per mail sender."""
    return [(rdn_value(m), one(m, "ciamSenderAddress"), sender_domain(m) or "",
             rdn_value(follow(d, m, "ciamSentBy")) if one(m, "ciamSentBy") and get(d, one(m, "ciamSentBy")) else "",
             one(m, "ciamSendingRole") or "", ", ".join(values(m, "ciamMessagePurpose")),
             one(m, "ciamBounceHandling") or "")
            for m in mail_senders(d)]


def sender_domain(m):
    """The domain a sender sends as: its ciamSenderDomain, else its address's."""
    address = one(m, "ciamSenderAddress") or ""
    return one(m, "ciamSenderDomain") or (address.rsplit("@", 1)[1].lower() if "@" in address else None)


def covered(name, allowed):
    """Whether a host name is one of the allowed domains or under one (a leading *. allowed)."""
    low = name.lower()
    return any(low == a or low.endswith("." + a) for a in (x.lower().removeprefix("*.") for x in allowed))


def public_names(m, roles):
    """The DNS names an environment gives the servers of these roles (its service names)."""
    return tuple(dict.fromkeys(one(b, "ciamFqdn") for b in m.bindings
                               if "ciamServiceName" in b.classes and one(b, "ciamTargetRole") in roles
                               and one(b, "ciamFqdn")))


def _unbound(ctx, roles):
    return [r for r in roles if one_role(ctx.src, r) is None and one_role(ctx.dst, r) is None]


def _service(ctx, s):
    name, owner = rdn_value(s), responsible(ctx.d, s, ctx.dst.env)
    allowed = values(s, "ciamAllowedDomain")
    missing = [n for n in public_names(ctx.dst, values(s, "ciamReachedFrom")) if allowed and not covered(n, allowed)]
    return findings(
        blockers=(*((("Service", f"External service `{name}` allows {', '.join(allowed)}; {ctx.dst.label}'s names for "
                      f"the roles that use it aren't among them: {', '.join(missing)}. Add them at the vendor before "
                      "cutover.", owner),) if missing else ()),
                  *(("Service", f"External service `{name}` uses role `{r}`, which neither {ctx.src.label} nor "
                     f"{ctx.dst.label} binds: record where each environment keeps it.", owner)
                    for r in _unbound(ctx, values(s, "ciamUsesRole")))),
        actions=((("Service", f"External service `{name}` has no owner: a vendor account nobody owns lapses unnoticed. "
                   "Name who owns it.", owner, None),) if not values(s, "ciamOwner") else ()))


def _strength(policy):
    return DMARC_STRENGTH.index(policy) if policy in DMARC_STRENGTH else -1


def _sender(ctx, m):
    name, owner, role = rdn_value(m), responsible(ctx.d, m, ctx.dst.env), one(m, "ciamSendingRole")
    domain = sender_domain(m)
    src, dst = (one_role(ctx.src, role), one_role(ctx.dst, role)) if role else (None, None)
    weak = [what for attr, what in (("ciamDkimVerified", "isn't DKIM-verified"),
                                    ("ciamSpfAuthorized", "isn't authorized by the domain's SPF record"))
            if dst is not None and one(dst, attr) == "FALSE"]
    wrong_domain = dst is not None and one(dst, "ciamSenderDomain") and domain and \
        one(dst, "ciamSenderDomain").lower() != domain
    blockers = (*((("Mail", f"Sender `{name}` ({one(m, 'ciamSenderAddress')}) sends from role `{role}`, which neither "
                    f"{ctx.src.label} nor {ctx.dst.label} binds: record each environment's sending identity.",
                    owner),) if role and src is None and dst is None else ()),
                *((("Mail", f"Sender `{name}`: {ctx.dst.label}'s sending identity for {domain} "
                    f"{' and '.join(weak)}: mail it sends lands in spam (password resets included). Publish the "
                    "DNS records before cutover.", owner),) if weak else ()),
                *((("Mail", f"Sender `{name}` sends as {domain}, but {ctx.dst.label}'s sending identity is for "
                    f"{one(dst, 'ciamSenderDomain')}.", owner),) if wrong_domain else ()))
    weaker = src is not None and dst is not None and \
        _strength(one(dst, "ciamDmarcPolicy")) < _strength(one(src, "ciamDmarcPolicy"))
    actions = (*((("Mail", f"Sender `{name}`: {ctx.dst.label}'s DMARC policy for {domain} is "
                   f"{one(dst, 'ciamDmarcPolicy') or 'unset'}, weaker than {ctx.src.label}'s "
                   f"{one(src, 'ciamDmarcPolicy')}.", owner, None),) if weaker else ()),
               *((("Mail", f"Sender `{name}` records no bounce or complaint handling: undeliverable reset mail goes "
                   "unnoticed. Record where bounces go.", owner, None),) if not one(m, "ciamBounceHandling") else ()))
    return findings(blockers=blockers, actions=actions)


def check_services(ctx):
    """External services the target's names would break, roles nobody binds, and mail the target can't deliver are
    blockers; services nobody owns, weaker DMARC and senders without bounce handling are actions."""
    held, senders = external_services(ctx.d), mail_senders(ctx.d)
    if not held and not senders:
        return findings()
    parts = merge_findings([*(_service(ctx, s) for s in held), *(_sender(ctx, m) for m in senders)])
    if parts.blockers or parts.actions:
        return parts
    return parts._replace(ok=(*parts.ok, f"External services ({len(held)}) and mail senders ({len(senders)}) work "
                                         f"from {ctx.dst.label}."))
