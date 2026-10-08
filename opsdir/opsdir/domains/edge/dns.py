"""DNS each environment publishes and resolves: its zones (and who runs them when not the platform), the answers of its
service names and other records with their TTLs and routing, and the forwarders sending queries for other domains
elsewhere. The report and the planner's check. Pure.

A name whose answer changes at cutover keeps resolving to the old address for as long as resolvers cache it: its TTL
must be low (at most TTL_CEILING seconds) by the time the cutover begins, which takes the old TTL to propagate, so the
lowering is dated that far ahead. A zone someone else runs gets the change as a request to them. A forwarder, record or
private zone the source has that the target binds differently is an action: what resolved before wouldn't (one whose
role the target doesn't bind at all is the planner's role check's blocker).
"""
import datetime as dt
import math

from ...core.changeset import set_values
from ...core.directory import get, one, rdn_value, subtree, values
from ...core.environment import environment_of, of_class
from ...core.findings import Fix, awaiting_import, findings, pending, responsible
from ...core.naming import branch, env_label

DNS_HEADERS = ("environment", "name", "type", "answers", "ttl", "routing", "zone", "visibility / run by")
TTL_CEILING = 300           # seconds: at most this before a cutover
LOWERED_TTL = 60            # what to lower it to
ANSWERING = ("A", "AAAA", "CNAME")


def answer(b):
    """What a service name or an address record answers with, as text ('' when nothing is recorded)."""
    return (one(b, "ciamFrontendIp") or "") if "ciamServiceName" in b.classes else \
        ", ".join(values(b, "ciamRecordValue"))


def zone_of(m, name):
    """The zone binding of environment m that a DNS name falls in (the longest matching zone), or None."""
    name = (name or "").lower().rstrip(".")
    found = [z for z in of_class(m, "ciamDnsZoneBinding")
             for zone in ((one(z, "ciamDnsZone") or "").lower().rstrip("."),)
             if name == zone or name.endswith("." + zone)]
    return max(found, key=lambda z: len(one(z, "ciamDnsZone")), default=None)


def lower_by(cutover, ttl):
    """The day a TTL of ttl seconds must be lowered by for resolvers to forget the old value before cutover, or None
    without a cutover."""
    return cutover - dt.timedelta(days=math.ceil(ttl / 86400) + 1) if cutover else None


def _row(d, e):
    env = env_label(environment_of(e))
    if "ciamDnsZoneBinding" in e.classes:
        run_by = get(d, one(e, "ciamManagedBy")) if one(e, "ciamManagedBy") else None
        return (env, one(e, "ciamDnsZone"), "zone", one(e, "ciamProviderRef") or "", "", "", "",
                " / ".join(x for x in (one(e, "ciamZoneVisibility"), run_by and rdn_value(run_by)) if x))
    if "ciamDnsForwarder" in e.classes:
        direction = one(e, "ciamForwardDirection") or "outbound"
        return (env, ", ".join(values(e, "ciamForwardDomain")), f"forward {direction}",
                ", ".join(values(e, "ciamForwardTarget")), "", "", "",
                f"on {', '.join(values(e, 'ciamResolverHost'))}" if values(e, "ciamResolverHost") else "")
    name = one(e, "ciamFqdn") or one(e, "ciamRecordName")
    return (env, name, one(e, "ciamRecordType") or "A", answer(e), one(e, "ciamTtlSeconds") or "",
            one(e, "ciamRoutingPolicy") or "", one(e, "ciamDnsZone") or "", "")


def dns_rows(d, dn=None):
    """One row per zone, service name, record and forwarder in every environment."""
    found = [e for oc in ("ciamDnsZoneBinding", "ciamServiceName", "ciamDnsRecord", "ciamDnsForwarder")
             for e in subtree(d, branch("environments"), oc)]
    return sorted((_row(d, e) for e in found), key=lambda r: (r[0], r[2] != "zone", r[1] or "", r[2]))


def _names(m, types=None):
    """{(name, type): binding} for the service names and records environment m publishes (records of these types
    only, when given)."""
    return {**{((one(r, "ciamRecordName") or "").lower(), one(r, "ciamRecordType")): r
               for r in of_class(m, "ciamDnsRecord") if types is None or one(r, "ciamRecordType") in types},
            **{((one(s, "ciamFqdn") or "").lower(), "A"): s for s in of_class(m, "ciamServiceName")}}


def ttl_fix(ctx, name, b, by):
    """The Fix lowering a changing name's TTL in the source to LOWERED_TTL, marked as set ahead of the live record
    until an import by the source's cloud adapter confirms it."""
    return Fix(f"ttl:{name}", "DNS", f"Lower the TTL of `{name}` in {ctx.src.label} to {LOWERED_TTL} s",
               (set_values(b, "ciamTtlSeconds", (str(LOWERED_TTL),)),
                awaiting_import(b, "ciamTtlSeconds", ctx.src.provider)),
               (f"Apply {ctx.src.label}'s rendered DNS (or have the zone's keeper lower it) by "
                f"{by or 'cutover less the old TTL'}; raise it again after cutover.",
                f"Import {ctx.src.label} again: until an import confirms the live TTL, the DNS check reports it "
                "awaiting verification."),
               ("The record says the TTL is low before resolvers see it: only the import that confirms it shows the "
                "live record changed.",))


def _ttl(ctx, name, b, new):
    """(actions, ok, ask, fixes) for one name whose answer changes: lowering its TTL in the source in time; a TTL the
    record lowered that no import confirmed yet is still an action."""
    ttl, owner = one(b, "ciamTtlSeconds"), responsible(ctx.d, b, ctx.src.env)
    if ttl is None:
        by = lower_by(ctx.cutover, TTL_CEILING)
        return ((("DNS", f"`{name}` changes answer at cutover ({answer(b) or '?'} → {new}) and {ctx.src.label} doesn't "
                  f"record its TTL: make sure it is at most {TTL_CEILING} s, or lower it to {LOWERED_TTL} s, by "
                  f"{by or 'two days before cutover'}.", owner, by),), (),
                f"make sure its TTL is at most {TTL_CEILING} s" + (f" by {by}" if by else ""),
                (ttl_fix(ctx, name, b, by),))
    if int(ttl) <= TTL_CEILING and "ciamTtlSeconds" in (attr for attr, _ in pending(b)):
        by = lower_by(ctx.cutover, TTL_CEILING)
        return ((("DNS", f"`{name}`'s TTL is {ttl} s in the record, set ahead of the live record: apply "
                  f"{ctx.src.label}'s rendered DNS and import {ctx.src.label} again to confirm it"
                  + (f" by {by}." if by else "."), owner, by),), (), "", ())
    if int(ttl) <= TTL_CEILING:
        return (), (f"`{name}`'s TTL is {ttl} s: resolvers pick up the new answer within minutes of cutover.",), "", ()
    by = lower_by(ctx.cutover, int(ttl))
    return ((("DNS", f"Lower the TTL of `{name}` in {ctx.src.label} from {ttl} s to {LOWERED_TTL} s by "
              f"{by or 'cutover less the old TTL'}, so resolvers pick up its new answer ({new}) at cutover; restore "
              "it after.", owner, by),), (),
            f"lower its TTL from {ttl} s to {LOWERED_TTL} s" + (f" by {by}" if by else ""),
            (ttl_fix(ctx, name, b, by),))


def _changing(ctx):
    """((name, source binding, target answer), ...) for the names both environments publish whose answer differs."""
    src, dst = _names(ctx.src, ANSWERING), _names(ctx.dst, ANSWERING)
    return tuple((name, b, answer(dst[key]) or f"the address {ctx.dst.label} binds")
                 for key, b in sorted(src.items()) for name in (key[0],)
                 if key in dst and answer(b) != answer(dst[key]))


def _zone_request(ctx, name, b, new, ttl_ask):
    """(action, request) asking whoever runs the zone a changing name is in, when someone outside the platform does."""
    zone = zone_of(ctx.dst, name) or zone_of(ctx.src, name)
    party = get(ctx.d, one(zone, "ciamManagedBy")) if zone is not None and one(zone, "ciamManagedBy") else None
    if party is None:
        return (), ()
    text = (f"In zone `{one(zone, 'ciamDnsZone')}`, point `{name}` to `{new}` at cutover (today `{answer(b) or '?'}`)"
            + (f"; before that, {ttl_ask}." if ttl_ask else "."))
    return ((("DNS", f"{rdn_value(party)} runs zone `{one(zone, 'ciamDnsZone')}`: ask them to point `{name}` to "
              f"`{new}` at cutover (request drafted).", responsible(ctx.d, b, ctx.dst.env), ctx.cutover),),
            ((party, None, text, "dns", ctx.cutover),))


def _forwarded(m, direction):
    """{domain: forwarder binding} environment m forwards in a direction."""
    return {dom.lower(): f for f in of_class(m, "ciamDnsForwarder")
            if (one(f, "ciamForwardDirection") or "outbound") == direction for dom in values(f, "ciamForwardDomain")}


def check_dns(ctx):
    """Changing answers' TTLs and zones run by others; forwarders, records and private zones the target lacks."""
    actions, ok, requests, fixes = [], [], [], []
    for name, b, new in _changing(ctx):
        a, o, ask, f = _ttl(ctx, name, b, new)
        za, zr = _zone_request(ctx, name, b, new, ask)
        actions += [*a, *za]
        ok += o
        requests += zr
        fixes += f
    owner = responsible(ctx.d, ctx.dst.env)
    # what the target doesn't bind at all is the role check's blocker; these name a role it binds differently
    bound = {one(b, "ciamBindingRole") for b in ctx.dst.bindings}
    for direction, what in (("outbound", "forwards queries for `{dom}` to {targets} (`{cn}`)"),
                            ("inbound", "answers other networks' queries for `{dom}` through `{cn}`")):
        dst = _forwarded(ctx.dst, direction)
        actions += [("DNS", f"{ctx.src.label} " + what.format(dom=dom, cn=rdn_value(f),
                                                              targets=", ".join(values(f, "ciamForwardTarget")))
                     + f"; {ctx.dst.label} has no {direction} forwarder for it: add one before cutover, or what "
                     "resolved before won't.", owner, ctx.cutover)
                    for dom, f in sorted(_forwarded(ctx.src, direction).items())
                    if dom not in dst and one(f, "ciamBindingRole") in bound]
    dst_names = _names(ctx.dst)
    actions += [("DNS", f"{ctx.src.label} publishes {one(r, 'ciamRecordType')} `{one(r, 'ciamRecordName')}`; "
                 f"{ctx.dst.label} records none: copy it, or record why it isn't needed.", owner, ctx.cutover)
                for r in of_class(ctx.src, "ciamDnsRecord")
                if ((one(r, "ciamRecordName") or "").lower(), one(r, "ciamRecordType")) not in dst_names
                and one(r, "ciamBindingRole") in bound]
    dst_zones = {(one(z, "ciamDnsZone") or "").lower() for z in of_class(ctx.dst, "ciamDnsZoneBinding")}
    actions += [("DNS", f"{ctx.src.label} has private zone `{one(z, 'ciamDnsZone')}`; {ctx.dst.label} has none: "
                 "create it and link it to the target's networks, or names only it answers won't resolve.", owner,
                 ctx.cutover)
                for z in of_class(ctx.src, "ciamDnsZoneBinding")
                if one(z, "ciamZoneVisibility") == "private" and (one(z, "ciamDnsZone") or "").lower() not in dst_zones
                and one(z, "ciamBindingRole") in bound]
    return findings(actions=actions, ok=ok, requests=requests, fixes=fixes)
