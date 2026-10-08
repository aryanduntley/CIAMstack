"""Quotas: what each environment needs of a provider's limits (ciamQuotaNeed: a quota kind every cloud limits, or the
provider's own quota, and how many) against what the provider grants its account in its region. The limits are fetched
from the provider (the cloud adapters' quota importers, run with the provider's own commands) into the quota catalog:
one ciamQuotaCatalog per provider account and region under ou=quotas, a ciamQuotaLimit per quota some environment
needs. Environments on one account and region share its limits, so they need the sum of their needs.

The planner's check, for the target: limits not fetched, or a quota the provider's list doesn't have, are actions; a
limit below what the environments need is an action due at cutover that the operator decides (its fix: request the
need, request a value of their own, or deny); a request asks the provider and the renderers render it where the cloud
takes requests; a denied increase stops the move (a blocker) until the need or the decision changes. Pure."""
from collections import namedtuple

from ...core.contract import Imported
from ...core.directory import children, get, make_entry, merged_attrs, one, ou_entry, rdn_value, subtree
from ...core.environment import env_model, of_class
from ...core.findings import Fix, Input, Option, findings, responsible
from ...core.interchange.ldif import LdifRecord
from ...core.naming import branch
from .naming import QUOTAS

AREA = "Quotas"
NEED = "ciamQuotaNeed"
CATALOG = "ciamQuotaCatalog"
LIMIT = "ciamQuotaLimit"
QUOTA_HEADERS = ("environment", "quota", "need", "needed on the account", "limit", "usage", "decision", "requested",
                 "verdict")
# One quota as a provider lists it: its id (the provider's: ec2.L-1216C47A, cores, CPUS), the limit granted, its name,
# the usage when fetched and the quota kind it answers (naming.QUOTA_KINDS), None when not given.
QuotaRow = namedtuple("QuotaRow", ("id", "value", "name", "usage", "kind"), defaults=(None, None, None))
OWNED = ("cn", "ciamQuotaValue", "ciamQuotaName", "ciamQuotaUsage", "ciamQuotaKind")


def catalog_dn(provider, account, region):
    """DN of the quota catalog of a provider's account in a region."""
    return f"cn={provider}:{account}:{region},{QUOTAS}"


def quota_needs(m):
    """Environment m's quota needs."""
    return of_class(m, NEED)


def need_key(need):
    """What a need asks for: its quota kind, else the provider's quota id (ciamProviderRef)."""
    return one(need, "ciamQuotaKind") or one(need, "ciamProviderRef")


def _models(d):
    return [env_model(d, e.dn) for e in subtree(d, branch("environments"), "ciamEnvironment")]


def wanted_quotas(d, provider):
    """(kinds, provider quota ids) the environments on a provider's clouds need: what its quota importer fetches."""
    needs = [n for m in _models(d) if m.provider == provider for n in quota_needs(m)]
    return (tuple(sorted({one(n, "ciamQuotaKind") for n in needs if one(n, "ciamQuotaKind")})),
            tuple(sorted({one(n, "ciamProviderRef") for n in needs
                          if one(n, "ciamProviderRef") and not one(n, "ciamQuotaKind")})))


def quota_regions(d, provider):
    """The regions the record's clouds of a provider run in, by name, whose environments need quotas."""
    return tuple(sorted({one(m.cloud, "ciamRegion") for m in _models(d)
                         if m.provider == provider and quota_needs(m) and one(m.cloud, "ciamRegion")}))


def limits_fetched(d, provider):
    """Whether the quota catalog holds the limits of every account and region of a provider whose environments need
    quotas (the provider's quota prerequisite is met; nothing needed is met too)."""
    return all(quota_catalog(m) is not None for m in _models(d) if m.provider == provider and quota_needs(m))


def _place(m):
    return one(m.cloud, "ciamAccountRef"), one(m.cloud, "ciamRegion")


def quota_catalog(m):
    """The quota catalog of environment m's account and region, or None (not fetched). A cloud that names no account
    takes the provider's only catalog in its region."""
    account, region = _place(m)
    if account:
        return get(m.d, catalog_dn(m.provider, account, region))
    found = [c for c in children(m.d, QUOTAS, CATALOG)
             if one(c, "ciamCloudProvider") == m.provider and one(c, "ciamRegion") == region]
    return found[0] if len(found) == 1 else None


def quota_limit(m, key):
    """The limit of environment m's catalog answering a need key (by kind, else by the provider's quota id), or
    None."""
    catalog = quota_catalog(m)
    limits = children(m.d, catalog.dn, LIMIT) if catalog is not None else ()
    return next((q for q in limits if one(q, "ciamQuotaKind") == key), None) or \
        next((q for q in limits if rdn_value(q) == key), None)


def _int(e, attr):
    v = one(e, attr) if e is not None else None
    return int(v) if v is not None else None


def sharing(m):
    """The environments on environment m's provider, account and region (m among them): they share its limits. A cloud
    that names no account shares them only with the environments on it."""
    account = _place(m)[0]
    return [o for o in _models(m.d) if o.provider == m.provider and _place(o) == _place(m)
            and (account or o.cloud.dn == m.cloud.dn)]


def needed(m, key):
    """How many of a key the environments sharing m's limits need together."""
    return sum(_int(n, "ciamQuotaNeeded") or 0 for o in sharing(m) for n in quota_needs(o) if need_key(n) == key)


def _keys(m):
    return list(dict.fromkeys(need_key(n) for n in quota_needs(m) if need_key(n)))


def _need(m, key):
    return next(n for n in quota_needs(m) if need_key(n) == key)


def _decided(need, decision, requested=None):
    """The change record setting a need's decision (and the limit requested)."""
    return LdifRecord(need.dn, "modify", {}, (("replace", "ciamQuotaDecision", (decision,)),
                                              *((("replace", "ciamQuotaRequested", requested),) if requested else ())))


def quota_fix(m, key, total):
    """The decision a limit below need waits for: request the need, request a value given, or deny."""
    need, label = _need(m, key), m.label
    amount = Input("ciamQuotaRequested", f"the limit of `{key}` to request for {label}'s account", (), (str(total),),
                   r"[1-9][0-9]*")
    return Fix(f"quota:{rdn_value(m.env)}:{key}", AREA, f"Decide on raising `{key}` for {label}", (),
               (f"Apply the rendered request in {label}'s root (or ask the provider where the cloud takes none), then "
                "fetch the quotas again once it is granted.",), (),
               (Option("approve", f"request {total}, what the environments need",
                       (_decided(need, "request", (str(total),)),), ()),
                Option("amount", "request a limit of your own", (_decided(need, "request", (amount,)),),
                       ("A limit below the need leaves the target short.",)),
                Option("deny", "deny the increase: the move stops", (_decided(need, "deny"),),
                       ("The move is blocked until the need is lowered or the decision changes.",))))


def _verdict(m, key):
    """(the finding's kind: ok | action | pending (an increase requested) | blocker | decide, its text, the total
    needed) for one key of m."""
    total, limit = needed(m, key), quota_limit(m, key)
    account, region = _place(m)
    where = f"{m.provider} account {account or '(not recorded)'} in {region}"
    if limit is None:
        return ("action", f"The provider's quota list for {where} has no `{key}` quota, which {m.label} needs "
                          f"{total} of: confirm the limit with the provider (some are raised only through a support "
                          "case).", total)
    value = _int(limit, "ciamQuotaValue")
    if value >= total:
        return "ok", "", total
    short = f"`{key}` on {where} is limited to {value} and its environments need {total}"
    need = _need(m, key)
    decision, requested = one(need, "ciamQuotaDecision"), _int(need, "ciamQuotaRequested") or total
    if decision == "deny":
        return ("blocker", f"{short}; raising it was denied (ciamQuotaDecision): the move stops until the need is "
                           "lowered or the decision changes.", total)
    if decision == "request" and requested < total:
        return ("action", f"{short}; {requested} was requested: still {total - requested} short. Request at least "
                          f"{total}.", total)
    if decision == "request":
        return ("pending", f"{short}; {requested} is requested (rendered where the cloud takes requests): fetch the "
                          "quotas again once the provider grants it.", total)
    return "decide", f"{short}: decide whether to raise it (request the need, a value of your own, or deny).", total


def check_quotas(ctx):
    """The target's quota needs against its limits (see the module), and needs the source records that the target
    doesn't. Nothing when neither environment records a need."""
    dst = ctx.dst
    if not quota_needs(ctx.src) and not quota_needs(dst):
        return findings()
    owner = responsible(ctx.d, dst.env)
    missing = [k for k in _keys(ctx.src) if k not in _keys(dst)]
    unrecorded = [(AREA, f"{ctx.src.label} needs {', '.join(f'`{k}`' for k in missing)} of its provider's limits and "
                         f"{dst.label} records no such need: record the target's (ciamQuotaNeed) so its limits are "
                         "checked.", owner, ctx.cutover)] if missing else []
    if quota_needs(dst) and quota_catalog(dst) is None:
        account, region = _place(dst)
        return findings(actions=[(AREA, f"{dst.label}'s quota limits ({dst.provider} account "
                                        f"{account or '(not recorded)'} in {region}) aren't fetched: fetch them "
                                        f"(`opsdir import {dst.provider}/quotas --run`) so its needs "
                                        f"({', '.join(_keys(dst))}) are checked.", owner, ctx.cutover),
                                 *unrecorded])
    verdicts = [(k, *_verdict(dst, k)) for k in _keys(dst)]
    return findings(
        blockers=[(AREA, text, owner) for _, kind, text, _ in verdicts if kind == "blocker"],
        actions=[*((AREA, text, owner, ctx.cutover) for _, kind, text, _ in verdicts
                   if kind in ("action", "pending", "decide")),
                 *unrecorded],
        fixes=[quota_fix(dst, k, total) for k, kind, _, total in verdicts if kind == "decide"],
        ok=(f"{dst.label}'s quota limits cover what its environments need: {', '.join(k for k, *_ in verdicts)}.",)
        if verdicts and all(kind == "ok" for _, kind, _, _ in verdicts) and not missing else ())


_SHOWN = {"ok": "ok", "blocker": "denied", "decide": "decide", "action": "short", "pending": "requested"}


def _state(m, key, limit):
    if quota_catalog(m) is None:
        return "fetch the limits"
    return _SHOWN[_verdict(m, key)[0]] if limit is not None else "confirm with the provider"


def quota_rows(d, dn=None):
    """One row per environment and quota need: what it needs, what the environments on its account and region need
    together, the limit and usage fetched, the decision and the limit requested, and the verdict."""
    return [(m.label, k, one(need, "ciamQuotaNeeded"), str(needed(m, k)),
             one(limit, "ciamQuotaValue", "") if limit is not None else
             "not fetched" if quota_catalog(m) is None else "not listed",
             one(limit, "ciamQuotaUsage", "") if limit is not None else "",
             one(need, "ciamQuotaDecision", ""), one(need, "ciamQuotaRequested", ""), _state(m, k, limit))
            for m in _models(d) for k in _keys(m) for need, limit in ((_need(m, k), quota_limit(m, k)),)]


def _catalog(d, dn, provider, account, region):
    owned = ("cn", "ciamCloudProvider", "ciamAccountRef", "ciamRegion")
    return make_entry(dn, ("top", CATALOG), merged_attrs(get(d, dn), dict(zip(owned, (
        (f"{provider}:{account}:{region}",), (provider,), (account,), (region,)))), owned))


def _limit(d, dn, row):
    given = {name: (str(v),) for name, v in zip(OWNED, (row.id, row.value, row.name, row.usage, row.kind))
             if v is not None}
    return make_entry(f"cn={row.id},{dn}", ("top", LIMIT), merged_attrs(get(d, f"cn={row.id},{dn}"), given, OWNED))


def quota_import(d, provider, catalogs):
    """Imported: the quota catalogs a provider's lists give, {(account, region): (QuotaRow, ...)}, each catalog made
    the rows its list has of what the environments need (a kind they need, or a provider quota id they name). A list
    with none of them leaves its catalog as it is (an empty or wrong export would remove every limit), said in a
    notice."""
    kinds, ids = wanted_quotas(d, provider)
    kept = {place: tuple(r for r in rows if r.kind in kinds or r.id in ids) for place, rows in catalogs.items()}
    return Imported(
        containers=(ou_entry(QUOTAS),),
        groups=tuple((dn, (_catalog(d, dn, provider, account, region), *(_limit(d, dn, r) for r in rows)))
                     for (account, region), rows in sorted(kept.items()) if rows
                     for dn in (catalog_dn(provider, account, region),)),
        notices=tuple(f"{provider} account {account} in {region}: {len(rows)} of the quotas the environments need"
                      if rows else f"{provider} account {account} in {region}: none of the quotas the environments "
                                   "need is listed; its catalog left as it is"
                      for (account, region), rows in sorted(kept.items())))
