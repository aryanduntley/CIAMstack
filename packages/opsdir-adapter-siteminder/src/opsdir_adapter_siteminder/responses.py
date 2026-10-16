"""SiteMinder's responses: each response attribute an HTTP header the web agent sets for the application (header-based
sign-on) becomes the edge domain's header contract, set by the agents; a cookie or anything else has no standard
equivalent and is a source object (carried.py). Pure.

A header's value is recorded as what it comes from (a user attribute, the user's DN). A fixed value is never kept:
an application trusting a fixed header value is trusting a shared secret, so it is withheld like one."""
import re

from opsdir.core.directory import get, one, rdn_of
from opsdir.domains.edge.naming import HEADER_NAME
from .entries import entry, sm_attrs
from .naming import AGENT
from .xps import HEADER_RESPONSE, value_of

_USER_ATTR = re.compile(r'<%\s*userattr\s*=\s*"([^"]+)"\s*%>', re.IGNORECASE)
_USER_DN = re.compile(r"<%\s*userdn\s*%>", re.IGNORECASE)
_HEADER = re.compile(HEADER_NAME)


def parts(a):
    """(response type, name, expression) of a response attribute ("<name>=<expression>")."""
    raw = value_of(a, "value") or ""
    head, _, expr = raw.partition("=")
    return value_of(a, "type") or "", head.strip(), expr.strip()


def is_header(a):
    """Whether a response attribute is an HTTP header the agent sets, under a name a header contract can hold."""
    kind, head, _ = parts(a)
    return kind == HEADER_RESPONSE and bool(_HEADER.match(head))


def header_value(expr):
    """(ciamHeaderKind, ciamHeaderValue, withheld) of a header's expression."""
    attr = _USER_ATTR.search(expr)
    if attr:
        return "identity", f"attribute {attr.group(1)}", ()
    if _USER_DN.search(expr):
        return "identity", "the user's DN", ()
    return "other", "a fixed value", ("Value: a fixed header value the application may trust like a shared secret; "
                                      "re-provision in the target",)


def header_entry(d, x, a, dn):
    """The header contract a header response attribute becomes: set by the web agents, trusted by whoever the record
    says (what SiteMinder's export can't), the client's own copy stripped or not as the record says."""
    _, head, expr = parts(a)
    kind, value, held = header_value(expr)
    old = get(d, dn)
    sm = sm_attrs(x, a)
    return entry(d, dn, ("top", "ciamHeaderContract", "smObject"),
                 {"cn": (rdn_of(dn),), "ciamHeaderName": (head,), "ciamHeaderKind": (kind,),
                  **({} if old is not None and one(old, "ciamSetByRole") else {"ciamSetByRole": (AGENT,)}),
                  "ciamHeaderValue": (value,), **sm, "smWithheld": (*sm["smWithheld"], *held)})
