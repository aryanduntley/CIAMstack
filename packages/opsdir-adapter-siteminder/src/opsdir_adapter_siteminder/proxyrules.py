"""An Access Gateway's proxy rules (proxyrules.xml) as ordered routes, and every name read of them, as data. Pure.

UNVERIFIED FOR 12.8 / 12.9: the grammar is the archived Secure Proxy Server 12.52 guide's, with knowledge-base articles
for all supported Access Gateway releases (KB 216168, 276675; README, Known limits):

  <!DOCTYPE nete:proxyrules SYSTEM "file:.../proxy-engine/conf/dtd/proxyrules.dtd">     Broadcom's files carry it
  <nete:proxyrules xmlns:nete="http://www.example.com/" debug="no">
    <nete:cond type="host" criteria="equals">             type host|uri|query|header (headername)|cookie; criteria
      <nete:case value="parts.example.test">              equals (the default)|beginswith|endswith|contains|exists
        <nete:cond type="uri" criteria="beginswith">
          <nete:case value="/parts"><nete:forward>http://parts-app:8080$0</nete:forward></nete:case>
          <nete:default><nete:redirect>https://www.example.test/</nete:redirect></nete:default>
        </nete:cond>
      </nete:case>
      <nete:default>
        <nete:xprcond type="uri">                          a regular expression's capture groups as $1, $2, ...
          <nete:xpr><nete:rule>^/docs/(.*)</nete:rule><nete:result>http://docs:8080/$1</nete:result></nete:xpr>
          <nete:xpr-default>http://www-app:8080$0</nete:xpr-default>
        </nete:xprcond>
      </nete:default>
    </nete:cond>
  </nete:proxyrules>

The first matching case, top to bottom, decides. Each path from the root to a forward or redirect becomes one route:
the conditions on the way (all must hold), in document order, so the first route whose conditions hold is the one the
gateway takes ($0 is the whole request URI, $1 what follows a beginswith match). A DOCTYPE is how XML files attack their
readers (core xml_document refuses one): exactly one external DOCTYPE for the proxy rules root (a SYSTEM or PUBLIC id,
no internal subset) is removed before the file is read; any other declaration is still refused.
"""
import re
from typing import NamedTuple, Optional

from opsdir.core.sources import xml_document, xml_name

ROOT = "proxyrules"
COND, CASE, DEFAULT = "cond", "case", "default"
XPR_COND, XPR, XPR_DEFAULT, XPR_RULE, XPR_RESULT = "xprcond", "xpr", "xpr-default", "rule", "result"
ACTIONS = ("forward", "redirect")       # what a route does (a 'local' action is reserved: not read)
TYPE, CRITERIA, CASE_VALUE, HEADER_NAME = "type", "criteria", "value", "headername"
FILTER, SERVICE = "filter", "service"         # a forward's filter class; a regular expression result's action
DEFAULT_TYPE, DEFAULT_CRITERIA, REGEX = "uri", "equals", "regex"
SKIPPED = ("description",)              # elements that say nothing about routing

_ID = r"""(?:"[^"<>\[\]]*"|'[^'<>\[\]]*')"""
_DOCTYPE = re.compile(r"<!DOCTYPE\s+(?:[\w.-]+:)?" + ROOT
                      + r"\s+(?:SYSTEM\s+" + _ID + r"|PUBLIC\s+" + _ID + r"\s+" + _ID + r")\s*>")

# A route: the conditions that must all hold ("<type> <criteria> <value>", a header's type as header:<name>), what it
# does (forward or redirect), where to (the URL as written) and the filter class a forward runs, if any
Route = NamedTuple("Route", [("conditions", tuple), ("action", str), ("target", str), ("filter", Optional[str])])


def rules_document(text):
    """(root element, None), or (None, why not): the proxy rules document, its one external DOCTYPE removed."""
    stripped = _DOCTYPE.sub("", text, count=1) if len(_DOCTYPE.findall(text)) == 1 else text
    root, why = xml_document(stripped)
    if root is not None and xml_name(root.tag) != ROOT:
        return None, f"its root element is {xml_name(root.tag)}, not {ROOT}"
    return root, why


def condition(kind, criteria, value, header=None):
    """A route condition: "<type> <criteria> <value>" ("<type> exists" with no value)."""
    head = f"{kind}:{header}" if header else kind
    return f"{head} {criteria}" + (f" {value}" if value else "")


def parts(c):
    """(type, header name or None, criteria, value) of a route condition."""
    head, criteria, *rest = c.split(" ", 2)
    kind, _, header = head.partition(":")
    return kind, header or None, criteria, rest[0] if rest else ""


def _joined(found):
    return tuple(r for rs, _ in found for r in rs), tuple(n for _, ns in found for n in ns)


def _children(e, conds):
    return _joined(tuple(_walk(c, conds) for c in e if xml_name(c.tag) not in SKIPPED))


def _case_condition(cond, case):
    return condition((cond.get(TYPE) or DEFAULT_TYPE).lower(), (cond.get(CRITERIA) or DEFAULT_CRITERIA).lower(),
                     case.get(CASE_VALUE) or "", cond.get(HEADER_NAME))


def _leaf(e, conds, action=None):
    return (Route(conds, action or xml_name(e.tag), (e.text or "").strip(), e.get(FILTER)),), ()


def _xpr(e, kind, conds):
    tag = xml_name(e.tag)
    rule = next((c for c in e if xml_name(c.tag) == XPR_RULE), None)
    result = next((c for c in e if xml_name(c.tag) == XPR_RESULT), None)
    if tag == XPR and rule is not None and result is not None:
        return _leaf(result, (*conds, condition(kind, REGEX, (rule.text or "").strip())),
                     (result.get(SERVICE) or ACTIONS[0]).lower())
    if tag == XPR_DEFAULT:
        inner = tuple(c for c in e if xml_name(c.tag) in ACTIONS)
        return _children(e, conds) if inner else _leaf(e, conds, (e.get(SERVICE) or ACTIONS[0]).lower())
    return (), (f"{tag}: not a regular expression rule or the default of one: not read",)


def _walk(e, conds):
    tag = xml_name(e.tag)
    if tag in ACTIONS:
        return _leaf(e, conds)
    if tag == COND:
        return _joined(tuple(_children(c, (*conds, _case_condition(e, c)) if xml_name(c.tag) == CASE else conds)
                             for c in e if xml_name(c.tag) in (CASE, DEFAULT)))
    if tag == XPR_COND:
        return _joined(tuple(_xpr(c, (e.get(TYPE) or DEFAULT_TYPE).lower(), conds) for c in e))
    if tag in (ROOT, CASE, DEFAULT):
        return _children(e, conds)
    return (), (f"a {tag} action or element: not read (rebuild what it does in the target gateway)",)


def routes(root):
    """((Route, ...) in the order the gateway tries them, notices) of a proxy rules document."""
    return _walk(root, ())
