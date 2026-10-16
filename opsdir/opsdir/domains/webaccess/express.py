"""What a product can render of a protected application: each enforcing product declares its capabilities as data,
and this is the one place that says what an application uses that the product can't express. Pure.

A product's planner check reports the losses for the applications it takes over from another product (findings for
the application's owner), and its render leaves out what it can't express and says so (render notes)."""
import re
from typing import NamedTuple

from ...core.directory import one, rdn_value, values
from .apps import every_rule, path_resources
from .naming import COLLECTED, who

# What an enforcing product can express: product (as findings name it); match_kinds, access_modes, who_kinds and
# sign_ons it renders (naming.MATCH_KINDS ...); translated: ((match kind, the kind it renders it as), ...), translated
# without loss (pattern_as); deny: whether it renders a denial (a negated rule); session: which of idle and max session
# limits it enforces per application; ipv6: whether its network rules take IPv6 ranges.
Capabilities = NamedTuple("Capabilities", [("product", str), ("match_kinds", tuple), ("translated", tuple),
                                           ("access_modes", tuple), ("who_kinds", tuple), ("sign_ons", tuple),
                                           ("deny", bool), ("session", tuple), ("ipv6", bool)])
# One thing a product can't express as recorded: severity info (translated, nothing lost) or action (lost: someone
# must decide), and what it is in words
Loss = NamedTuple("Loss", [("severity", str), ("text", str)])


def pattern_as(kind, pattern, as_kind):
    """A path pattern of one match kind written as another without changing what it matches: a prefix as a wildcard
    (<prefix>*) or a regular expression, a wildcard as a regular expression (* any run of characters); anchored at the
    start (a regex holds as written)."""
    if kind == as_kind or kind == "regex":
        return pattern
    if as_kind == "wildcard":
        return pattern + "*"
    return "^" + (re.escape(pattern) if kind == "prefix" else ".*".join(map(re.escape, pattern.split("*"))) + "$")


def expressible_who(value, caps):
    """Whether a product can test a ciamWho value."""
    kind, rest = who(value)
    return kind in caps.who_kinds and (kind != "network" or caps.ipv6 or ":" not in rest)


def expressible_rule(rule, caps):
    """Whether a product can render an access rule itself (its includes are judged on their own)."""
    effect = one(rule, "ciamEffect")
    return effect != "custom" and (effect != "deny" or caps.deny) \
        and all(expressible_who(w, caps) for w in values(rule, "ciamWho"))


def _rule_losses(rule, caps):
    name, effect = rdn_value(rule), one(rule, "ciamEffect")
    if effect == "custom":
        return (Loss("action", f"rule `{name}` is a product rule with no neutral form "
                               f"({one(rule, 'ciamProjectedFrom') or 'recorded by hand'}): rebuild it in "
                               f"{caps.product}"),)
    return (*((Loss("action", f"rule `{name}` denies, which {caps.product} can't render: rewrite it as an "
                              "allowance of everyone else"),) if effect == "deny" and not caps.deny else ()),
            *(Loss("action", f"rule `{name}` admits `{w}`, which {caps.product} can't test"
                             + (": release it as a claim of the sign-in integration and test that (attribute "
                                "<claim>=<value>)" if who(w)[0] in ("user", "group", "filter") else ""))
              for w in values(rule, "ciamWho") if not expressible_who(w, caps)))


def _resource_losses(r, caps):
    kind, mode, name = one(r, "ciamMatchKind", "prefix"), one(r, "ciamAccessMode", "standard"), rdn_value(r)
    as_kind = dict(caps.translated).get(kind)
    return (*((Loss("info", f"resource `{name}` matches by {kind}, rendered as {as_kind}"),) if as_kind else
              (Loss("action", f"resource `{name}` matches by {kind}, which {caps.product} can't render"),)
              if kind not in caps.match_kinds else ()),
            *((Loss("action", f"resource `{name}` is {mode}, which {caps.product} can't render"),)
              if mode not in caps.access_modes else ()))


def _sign_on_losses(app, caps):
    kind = one(app, "ciamSignOn")
    if not kind or kind in caps.sign_ons or not one(app, "ciamSignInAs"):
        return ()       # no integration to sign in through: the core check's blocker
    return (Loss("action", f"users sign in with {kind} today; {caps.product} signs them in through the identity "
                           "service, which must offer that sign-on"
                           + (" (the source's own code: rebuilt there)" if kind == "custom" else "")),) \
        if kind in COLLECTED else (Loss("action", f"sign-on {kind} isn't one {caps.product} renders"),)


def _session_losses(app, caps):
    return tuple(Loss("action", f"its {what} session limit ({one(app, attr)}s) isn't enforced by {caps.product}: the "
                                "identity service's session must hold it")
                 for what, attr in (("idle", "ciamIdleTimeout"), ("max", "ciamMaxSessionTime"))
                 if one(app, attr) and what not in caps.session)


def losses(d, app, caps):
    """(Loss, ...) of what a protected application uses that the product can't express, in a stable order: sign-on,
    session, resources, rules."""
    return (*_sign_on_losses(app, caps), *_session_losses(app, caps),
            *(x for r in path_resources(d, app) for x in _resource_losses(r, caps)),
            *(x for rule in every_rule(d, app) for x in _rule_losses(rule, caps)))
