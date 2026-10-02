"""XML files as captured settings (core.capture): every attribute value and the text of every leaf element (one with
no child elements) is a setting; tags, comments, processing instructions, the DOCTYPE and whitespace between
elements are layout.

Locators are XPath-like: /config/server[2]/@port for an attribute, /config/timeout/text() for a leaf's text. A step
carries its position among same-named siblings ([n], from 1) only when there are several. Values are the decoded
text (the five predefined entities and character references resolved; a CDATA leaf's content as is).
"""
import re
from collections import Counter
from functools import reduce
from itertools import accumulate
from types import MappingProxyType

from ..contract import Codec
from .lines import first_gap, line_col

_TOKEN = re.compile(
    r"(?P<comment><!--.*?-->)|(?P<cdata><!\[CDATA\[.*?\]\]>)|(?P<pi><\?.*?\?>)"
    r"|(?P<doctype><!DOCTYPE(?:[^\[>]|\[.*?\])*>)|(?P<end></(?P<end_name>[^\s>]+)\s*>)"
    r"|(?P<start><(?P<name>[^\s/>!?]+)(?P<attrs>(?:\s+[^\s=/>]+\s*=\s*(?:\"[^\"]*\"|'[^']*'))*)\s*(?P<empty>/?)>)"
    r"|(?P<text>[^<]+)", re.DOTALL)
_ATTR = re.compile(r"([^\s=/>]+)(\s*=\s*)(?:\"([^\"]*)\"|'([^']*)')")
_ENTITY = re.compile(r"&(lt|gt|amp|quot|apos|#[0-9]+|#x[0-9a-fA-F]+);")
_NAMED = MappingProxyType({"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"})


def _advance(stack, indexed):
    """The open-element stack after a token: frames are (element id, {child name: count so far})."""
    i, m = indexed
    if m.group("start"):
        pid, counts = stack[-1]
        parent = (pid, {**counts, m.group("name"): counts.get(m.group("name"), 0) + 1})
        return stack[:-1] + (parent,) + (() if m.group("empty") else ((i, {}),))
    if m.group("end"):
        return stack[:-1]
    return stack


def _elements(tokens):
    """{element id (its start token's index): (parent id, name, position among same-named siblings)}."""
    states = accumulate(enumerate(tokens), _advance, initial=((None, {}),))
    return {i: (stack[-1][0], m.group("name"), stack[-1][1].get(m.group("name"), 0) + 1)
            for (i, m), stack in zip(enumerate(tokens), states) if m.group("start")}


def _paths(elements):
    totals = Counter((parent, name) for parent, name, _ in elements.values())

    def path(eid):
        parent, name, nth = elements[eid]
        step = f"{name}[{nth}]" if totals[(parent, name)] > 1 else name
        return (path(parent) if parent is not None else "") + "/" + step
    return {eid: path(eid) for eid in elements}


def _tag_parts(m, path):
    """A start tag cut at each attribute value: literal text and (path/@name, raw value) settings."""
    text, base = m.group(0), m.start()
    offset = m.start("attrs") - base
    groups = ((a, 3 if a.group(3) is not None else 4) for a in _ATTR.finditer(m.group("attrs")))
    cuts = tuple((offset + a.start(g), offset + a.end(g), a.group(1)) for a, g in groups)
    bounds = (0, *(x for start, end, _ in cuts for x in (start, end)), len(text))
    literals = tuple(text[bounds[k]:bounds[k + 1]] for k in range(0, len(bounds), 2))
    slots = tuple((f"{path}/@{name}", text[start:end]) for start, end, name in cuts)
    return tuple(p for pair in zip(literals, (*slots, None)) for p in pair if p is not None)


def _leaf(tokens, i):
    """Whether token i opens a leaf element: its end tag follows directly, or after one text or CDATA token."""
    m = tokens[i]
    if not m.group("start") or m.group("empty"):
        return False
    follow = tokens[i + 1:i + 3]
    if follow and follow[0].group("end"):
        return True
    content = len(follow) == 2 and (follow[0].group("text") or follow[0].group("cdata"))
    return bool(content) and bool(follow[1].group("end"))


def _parts(tokens, paths):
    leaves = {i for i in range(len(tokens)) if _leaf(tokens, i)}
    texts = {i + 1: paths[i] for i in leaves if not tokens[i + 1].group("end")}
    empties = {i: paths[i] for i in leaves if tokens[i + 1].group("end")}
    for i, m in enumerate(tokens):
        yield from _tag_parts(m, paths[i]) if m.group("start") else ()
        if i in empties:
            yield (f"{empties[i]}/text()", "")
        if i in texts:
            yield (f"{texts[i]}/text()", m.group(0))
        elif not m.group("start"):
            yield m.group(0)


def _open_names(state, m):
    """(names of the open elements, the first end tag that closes the wrong one) after a token."""
    names, wrong = state
    if wrong is not None:
        return state
    if m.group("start") and not m.group("empty"):
        return names + (m.group("name"),), None
    if m.group("end"):
        return (names[:-1], None) if names and names[-1] == m.group("end_name") else (names, m)
    return state


def split(text):
    tokens = tuple(_TOKEN.finditer(text))
    gap = first_gap(text, [m.span() for m in tokens])
    if gap is not None:
        raise ValueError("line %d, column %d: not XML here" % line_col(text, gap))
    names, wrong = reduce(_open_names, tokens, ((), None))
    if wrong is not None:
        where = line_col(text, wrong.start())
        raise ValueError(f"line {where[0]}, column {where[1]}: </{wrong.group('end_name')}> doesn't close "
                         + (f"<{names[-1]}>" if names else "any open element"))
    if names:
        raise ValueError(f"end of file: <{names[-1]}> is never closed")
    return tuple(_parts(tokens, _paths(_elements(tokens))))


def _entity(m):
    ref = m.group(1)
    if ref.startswith("#x"):
        return chr(int(ref[2:], 16))
    return chr(int(ref[1:])) if ref.startswith("#") else _NAMED[ref]


def decode(raw):
    return raw[9:-3] if raw.startswith("<![CDATA[") else _ENTITY.sub(_entity, raw)


def encode(value, raw):
    if raw.startswith("<![CDATA["):
        return "<![CDATA[" + value.replace("]]>", "]]]]><![CDATA[>") + "]]>"
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&apos;"))


CODEC = Codec(split, decode, encode)
