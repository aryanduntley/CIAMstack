"""JSON values as the record holds them: one canonical text per value, and values that may be secret withheld.
Product adapters that keep a product's settings as JSON (journeys, connectors, policies) share these. Pure."""
import json

from .environment import UNBOUND
from .secrets import withheld

WITHHELD = "${withheld}"          # a withheld value nothing supplies: the deployment must
RENDERED_IN_PLACE = ("${secret:", WITHHELD, UNBOUND)     # what opsdir renders where a value was withheld


def canonical(value):
    """JSON text with sorted keys and no spacing: one text for one value, so re-importing it changes nothing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _never(value):
    return False


def without_secrets(value, patterns, pointer="", sealed=_never):
    """(value with every leaf that may be secret replaced by None, JSON Pointers of what was withheld). sealed(value)
    says a whole object is secret material (a product's encrypted-value wrapper): it is withheld as one."""
    if sealed(value):
        return None, (pointer,)
    if isinstance(value, dict):
        parts = [(k, without_secrets(v, patterns, f"{pointer}/{k}", sealed)) for k, v in value.items()]
        return {k: v for k, (v, _) in parts}, tuple(p for _, (_, ps) in parts for p in ps)
    if isinstance(value, list):
        parts = [without_secrets(v, patterns, f"{pointer}/{n}", sealed) for n, v in enumerate(value)]
        return [v for v, _ in parts], tuple(p for _, ps in parts for p in ps)
    if isinstance(value, str) and withheld(pointer, value, patterns):
        return None, (pointer,)
    return value, ()


def rendered_in_place(value):
    """Whether a value is what opsdir renders in place of a withheld or per-environment one (${secret:<ref>},
    ${withheld}, UNBOUND:<role>): importers hold it as withheld, so a rendered file imports back unchanged."""
    return isinstance(value, str) and value.startswith(RENDERED_IN_PLACE)


def _step(key):
    return key.replace("~1", "/").replace("~0", "~")


def with_value(value, pointer, new):
    """The value with `new` at a JSON Pointer (objects on the way created when missing; a list index must exist)."""
    if not pointer:
        return new
    head, _, rest = pointer[1:].partition("/")
    rest = "/" + rest if rest else ""
    if isinstance(value, list):
        i = int(head)
        return [with_value(v, rest, new) if n == i else v for n, v in enumerate(value)]
    base = value if isinstance(value, dict) else {}
    key = _step(head)
    return {**base, key: with_value(base.get(key), rest, new)}


def with_values(value, pointers, new):
    """The value with `new` at each of the JSON Pointers (a withheld value's places, say)."""
    return value if not pointers else with_values(with_value(value, pointers[0], new), pointers[1:], new)
