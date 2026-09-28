"""A small, pure XML writer: elements are immutable records, the text is a function of them (deterministic
attribute order, two-space indentation), so rendered metadata is byte-stable."""
from typing import NamedTuple, Optional
from xml.sax.saxutils import escape, quoteattr

Element = NamedTuple("Element", [("tag", str), ("attrs", tuple), ("children", tuple), ("text", Optional[str])])
Comment = NamedTuple("Comment", [("text", str)])


def element(tag, attrs=(), children=(), text=None):
    """An element; attrs is ((name, value), ...) in output order, None values left out."""
    return Element(tag, tuple((k, v) for k, v in attrs if v is not None), tuple(children), text)


def _attrs(attrs):
    return "".join(f" {k}={quoteattr(str(v))}" for k, v in attrs)


def _lines(node, depth):
    pad = "  " * depth
    if isinstance(node, Comment):
        return (f"{pad}<!-- {node.text.replace('--', '- -')} -->",)
    head = f"{pad}<{node.tag}{_attrs(node.attrs)}"
    if node.text is not None:
        return (f"{head}>{escape(node.text)}</{node.tag}>",)
    if not node.children:
        return (f"{head}/>",)
    return (f"{head}>", *(line for c in node.children for line in _lines(c, depth + 1)), f"{pad}</{node.tag}>")


def document(root):
    """The XML document text of a root element."""
    return "\n".join(('<?xml version="1.0" encoding="UTF-8"?>', *_lines(root, 0))) + "\n"
