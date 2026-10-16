"""PingAccess's objects named by name: each object of a Read with its name, its application (a resource's), its
settings with every id it names replaced by the ${pingaccess-id:<collection>/<name>} of that object, and the objects
it names. Pure.

PingAccess names objects by numeric ids it assigns itself, so ids differ between two PingAccess deployments of the
same configuration; names don't. An object is named by its name; a settings object `settings`; a virtual host by the
service name role its host is (else the host) and its port, so it is named alike in every environment. An id the
import doesn't hold the object for is kept as it is, and named.
"""
from typing import NamedTuple

from opsdir.core.environment import UNBOUND, published_role
from .api import (APPLICATION_ID, ELEMENT_TYPE, HOST, ID, NAME, NAME_FIELDS, NO_REFERENCE, POLICY, POLICY_TYPES, PORT,
                  REFERENCES, RESOURCES, collection)
from .naming import SETTINGS, reference, referenced

# One object of an import: its collection, name, application name (a resource's, else None), settings (references by
# name, no id), the (collection, name) of the objects it names, and the ids it names that the import doesn't hold
Obj = NamedTuple("Obj", [("path", str), ("name", object), ("application", object), ("item", dict), ("uses", tuple),
                         ("unresolved", tuple)])


def host_role(d, host):
    """The role a virtual host's or site target's host is: a service name's (or external system's) in the record,
    or the role a rendered UNBOUND:<role> names; None for a host the record doesn't know."""
    if isinstance(host, str) and host.startswith(UNBOUND):
        return host[len(UNBOUND):]
    return published_role(d, host) if isinstance(host, str) else None


def object_name(d, path, item):
    """An object's name in the record (None when it has none)."""
    c = collection(path)
    if c is not None and c.settings:
        return SETTINGS
    if path == "virtualhosts":
        host = item.get(HOST)
        return f"{host_role(d, host) or host}:{item.get(PORT)}" if host else None
    name = item.get(NAME_FIELDS.get(path, NAME))
    return name if isinstance(name, str) else None


def mapped(value, pattern, fn):
    """The value with fn applied to every leaf at a field path ("*" any list item or object member)."""
    if not pattern:
        return fn(value)
    head, rest = pattern[0], pattern[1:]
    if head == "*":
        return [mapped(v, rest, fn) for v in value] if isinstance(value, list) else \
            {k: mapped(v, rest, fn) for k, v in value.items()} if isinstance(value, dict) else value
    return {**value, head: mapped(value[head], rest, fn)} if isinstance(value, dict) and head in value else value


def leaves(value, pattern):
    """The leaves at a field path."""
    if not pattern:
        return (value,)
    head, rest = pattern[0], pattern[1:]
    if head == "*":
        inner = value if isinstance(value, list) else tuple(value.values()) if isinstance(value, dict) else ()
        return tuple(x for v in inner for x in leaves(v, rest))
    return leaves(value[head], rest) if isinstance(value, dict) and head in value else ()


def placeholders(value):
    """The (collection, name) of every ${pingaccess-id:...} reference in a value."""
    if isinstance(value, dict):
        return tuple(r for v in value.values() for r in placeholders(v))
    if isinstance(value, list):
        return tuple(r for v in value for r in placeholders(v))
    found = referenced(value)
    return (found,) if found else ()


def _key(v):
    return str(v) if isinstance(v, (int, str)) and not isinstance(v, bool) else None


def _by_id(names, target):
    """fn replacing an id of the target collection by its reference (an id the import doesn't hold kept)."""
    def fn(v):
        name = names.get((target, _key(v)))
        return reference(target, name) if name and v not in NO_REFERENCE else v
    return fn


def _policy_member(names):
    def fn(member):
        if not isinstance(member, dict) or member.get("type") not in POLICY_TYPES:
            return member
        return {**member, ID: _by_id(names, POLICY_TYPES[member["type"]])(member.get(ID))}
    return fn


def _policy(path, item, names):
    """An object's policy with each rule and rule set named by reference: an application's or resource's {"Web":
    [{"type", "id"}], "API": [...]}, a rule set's member ids (rules or rule sets by its elementType)."""
    if path == "rulesets":
        target = POLICY_TYPES.get(item.get(ELEMENT_TYPE), "rules")
        return mapped(item, (POLICY, "*"), _by_id(names, target))
    return mapped(item, (POLICY, "*", "*"), _policy_member(names)) if path in ("applications", RESOURCES) else item


def _unresolved(path, item, names):
    """(target collection, id) of the ids an object names that the import doesn't hold."""
    refs = REFERENCES.get(path, ())
    plain = tuple((t, v) for pattern, t in refs for v in leaves(item, pattern)
                  if v not in NO_REFERENCE and referenced(v) is None and (t, _key(v)) not in names)
    members = tuple((POLICY_TYPES[m["type"]], m.get(ID)) for m in leaves(item, (POLICY, "*", "*"))
                    if path in ("applications", RESOURCES) and isinstance(m, dict) and m.get("type") in POLICY_TYPES
                    and referenced(m.get(ID)) is None and (POLICY_TYPES[m["type"]], _key(m.get(ID))) not in names)
    rule_set = tuple((POLICY_TYPES.get(item.get(ELEMENT_TYPE), "rules"), v) for v in leaves(item, (POLICY, "*"))
                     if path == "rulesets" and referenced(v) is None
                     and (POLICY_TYPES.get(item.get(ELEMENT_TYPE), "rules"), _key(v)) not in names)
    return (*plain, *members, *rule_set)


def _application(item, names):
    app = item.get(APPLICATION_ID)
    found = referenced(app)
    return found[1] if found else names.get(("applications", _key(app)))


def resolved(d, items):
    """The Objs of a Read's items ({collection: items}), in collection order."""
    names = {(p, _key(i.get(ID))): object_name(d, p, i) for p, its in items.items() for i in its
             if _key(i.get(ID)) is not None and object_name(d, p, i)}

    def obj(path, item):
        named = {k: v for k, v in _apply(_policy(path, item, names), REFERENCES.get(path, ()), names).items()
                 if k not in (ID, APPLICATION_ID)}
        return Obj(path, object_name(d, path, item), _application(item, names) if path == RESOURCES else None,
                   named, tuple(dict.fromkeys(placeholders(named))), _unresolved(path, item, names))
    return tuple(obj(p, i) for p, its in items.items() for i in its)


def _apply(item, refs, names):
    """The item with every reference field's ids replaced (refs: ((field path, target collection), ...))."""
    return item if not refs else _apply(mapped(item, refs[0][0], _by_id(names, refs[0][1])), refs[1:], names)
