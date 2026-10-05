"""Explicit egress proxies across a move: when the target's servers reach outside sites through a proxy clients must be
told about (network.proxies), each installed product says which settings make its outside traffic use it
(contract.ProxySetting), and the planner compares them with the captured config files the target receives. A
connector: the settings come from the target's installed product adapters, which the planner gives it. Pure.

A setting a captured file holds with the right value is in place. One it holds with another value, or one missing
from a captured file of its place, is an action with a fix (core.findings.Fix): the settings added to the file and
linked to the proxy binding's derived values (network.proxies.DERIVATIONS), never literals, since a captured file is
shared by every environment with the role. A place the record holds no captured file of (an admin setting, the JVM
options, a file not captured) is an action naming what to set, since the record can't confirm it.
"""
from ..core.changeset import entry_mods
from ..core.directory import children, one, rdn_value
from ..core.findings import Fix, findings, merge_findings, responsible
from ..core.interchange.ldif import LdifRecord
from ..domains.configuration.record import added_settings, deployed_files, revalued, setting_attrs, setting_value
from ..domains.network.proxies import proxy_settings
from .registry import format_named


def wanted(m, adapters, settings):
    """The ProxySettings environment m's installed products need for its explicit proxy (settings), in order."""
    return tuple(s for a in adapters if a.proxy_settings for s in a.proxy_settings(m, settings))


def _value(s, m):
    try:
        return setting_value(s, m)
    except ValueError:
        return None


def _files(d, m, file, role):
    """The captured files environment m receives for a server role at a path ending with file."""
    return tuple(f for f in deployed_files(d, m) if (one(f, "ciamRepoPath") or "").endswith(file)
                 and one(f, "ciamTargetRole") in (None, role))


def held(d, m, file, role):
    """{locator: value} of the captured files environment m receives for a server role at a path ending with file,
    or None when it receives none."""
    files = _files(d, m, file, role)
    return {one(s, "ciamLocator"): _value(s, m) for f in files for s in children(d, f.dn, "ciamConfigSetting")} \
        if files else None


def _wanted_attrs(proxy, s):
    return setting_attrs(s.value, f"{one(proxy.binding, 'ciamBindingRole')}#{s.link}" if s.link else None)


def proxy_fix(ctx, proxy, role, place, file, missing, other):
    """The Fix adding the missing settings to the captured file and linking those with other values to the proxy
    (derived values, so every environment receiving the file renders its own proxy, empty where it binds none), or
    None when there is no captured file."""
    files = _files(ctx.d, ctx.dst, file, role)
    if not files:
        return None
    f = files[0]
    current = {one(x, "ciamLocator"): x for x in children(ctx.d, f.dn, "ciamConfigSetting")}
    relinked = tuple(LdifRecord(current[s.locator].dn, "modify", {},
                                entry_mods(current[s.locator], revalued(current[s.locator], _wanted_attrs(proxy, s))))
                     for s in other)
    placed = added_settings(format_named(one(f, "ciamFormat")), f,
                            tuple((s.locator, _wanted_attrs(proxy, s)) for s in missing)) if missing else None
    added = ((*(LdifRecord(e.dn, "add", {"objectClass": tuple(e.classes), **dict(e.attrs)}, ()) for e in placed[1]),
              LdifRecord(f.dn, "modify", {}, entry_mods(f, placed[0]))) if placed else ())
    by_hand = tuple(f"Add `{s.locator}={s.value}` to {one(f, 'ciamRepoPath')} by hand and capture it again (its "
                    "format can't place a new setting)." for s in missing) if missing and not placed else ()
    proxy_role = one(proxy.binding, "ciamBindingRole")
    named = ", ".join(f"`{s.locator}`" for s in (*missing, *other))
    return Fix(f"egress-proxy:{role}:{file}", "Egress proxy",
               f"Link {named} in `{role}`'s {place} ({one(f, 'cn')}) to `{proxy_role}`'s proxy", (*added, *relinked),
               (*by_hand, f"Deploy the rebuilt {one(f, 'ciamRepoPath')} to `{role}`'s servers in {ctx.dst.label}."),
               (f"Every environment receiving {one(f, 'ciamRepoPath')} gets these settings; where it binds no "
                f"`{proxy_role}` they render empty (no proxy).",
                "If a product importer also reads this file into its own entries, re-importing from servers that "
                "don't run the new file yet takes the values back."))


def _place(ctx, proxy, role, place, file, settings):
    """(what to set in one place a server role's settings live, or None; the ok note when it says so already, or
    None; the fix when the record can make it, or None)."""
    found = held(ctx.d, ctx.dst, file, role) if file else None
    if found is None:
        why = "its file isn't captured, so the record can't confirm it" if file else "the record can't confirm it"
        return f"in {place}: " + "; ".join(f"`{s.locator}={s.value}`" for s in settings) + f" ({why})", None, None
    missing = [s for s in settings if s.locator not in found]
    other = [s for s in settings if s.locator in found and found[s.locator] != s.value]
    if not (missing or other):
        return None, f"`{role}`'s {place} says so.", None
    said = "; ".join((*(f"add `{s.locator}={s.value}`" for s in missing),
                      *(f"`{s.locator}` is `{found[s.locator]}`, needs `{s.value}`" for s in other)))
    return (f"in {place}: {said} (`opsdir fix` links them to the proxy binding, so each environment's file names "
            "its own)", None, proxy_fix(ctx, proxy, role, place, file, missing, other))


def _role(ctx, proxy, role, settings, owner):
    """Findings for one server role: one action naming every place it must be told in, the ok notes, the fixes."""
    via = f"{ctx.dst.label}'s outside traffic goes through `{rdn_value(proxy.binding)}` ({proxy.host}:{proxy.port})"
    places = tuple(dict.fromkeys((s.place, s.file) for s in settings))
    done = tuple(_place(ctx, proxy, role, place, file, [s for s in settings if (s.place, s.file) == (place, file)])
                 for place, file in places)
    said = [x for x, _, _ in done if x]
    told = f"{via}, so `{role}` must be told: " + " ".join(f"({i}) {x}." for i, x in enumerate(said, 1))
    return findings(actions=[("Egress proxy", told, owner, ctx.cutover)] if said else [],
                    ok=[f"{via}: {ok}" for _, ok, _ in done if ok], fixes=[f for _, _, f in done if f])


def proxy_check(dst_adapters):
    """The planner check for the target's explicit egress proxy, given its installed adapters."""
    def check_proxies(ctx):
        proxy = proxy_settings(ctx.dst)
        settings = wanted(ctx.dst, dst_adapters, proxy) if proxy is not None else ()
        if not settings:
            return findings()                   # no explicit proxy, or no installed product needs telling
        owner = responsible(ctx.d, proxy.binding, ctx.dst.env)
        return merge_findings([_role(ctx, proxy, role, [s for s in settings if s.server_role == role], owner)
                               for role in dict.fromkeys(s.server_role for s in settings)])
    return check_proxies
