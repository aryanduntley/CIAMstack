"""PingFederate Admin API payloads checked against the version's own spec, offline. Pure, but for load_spec.

Each supported PingFederate version (VERSIONS: major.minor) has its Admin API spec vendored as package data (specs/,
from Ping's pingfederate-go-client, Apache License 2.0: see specs/NOTICE.md; regenerated with
scripts/vendor-admin-api-specs.py): the body schema of every POST and PUT, and the schemas. A rendered payload is
validated against the body schema of its request as PingFederate's OpenAPI document declares it:

  $ref, allOf      followed and merged: a subtype has its base's properties and required ones
  unions           oneOf, a discriminator's mapping (the value of its property picks the schema), or a base schema with
                   subtypes (DataStore: LdapDataStore, JdbcDataStore, ...): valid when one alternative is
  objects          required properties present, each property checked, a property the schema doesn't name refused (a
                   misspelt one would be ignored by PingFederate, silently), maps (additionalProperties) checked per value
  values           type (string, integer, number, boolean, array, object), enum, pattern, length, unique items

Formats (date-time, ...) aren't checked. Problems are lines '<JSON path>: <what>', none when the payload is valid.
"""
import functools
import json
import re
from importlib import resources

VERSIONS = ("12.1", "12.2", "12.3", "13.0", "13.1")
REF = "#/components/schemas/"
_TYPES = {"string": (str,), "integer": (int,), "number": (int, float), "boolean": (bool,), "array": (list,),
          "object": (dict,)}


def spec_version(product_version):
    """The vendored spec version (major.minor) of a PingFederate version ('PingFederate 12.1.4', '13.1'), or None when
    none is vendored for it."""
    found = re.search(r"(\d+)\.(\d+)", product_version or "")
    version = f"{found.group(1)}.{found.group(2)}" if found else None
    return version if version in VERSIONS else None


def indexed(spec):
    """A spec with its subtypes index: {base schema: (schemas whose allOf refers to it, ...)}."""
    subtypes = {}
    for name, schema in spec["schemas"].items():
        for part in schema.get("allOf") or ():
            base = (part.get("$ref") or "")[len(REF):]
            if base:
                subtypes = {**subtypes, base: (*subtypes.get(base, ()), name)}
    return {**spec, "subtypes": subtypes}


@functools.lru_cache(maxsize=None)
def load_spec(version):
    """Effect (reads package data): the indexed spec of a vendored version (VERSIONS)."""
    text = resources.files(__package__).joinpath("specs", f"admin-api-{version}.json").read_text()
    return indexed(json.loads(text))


def request_schema(spec, method, path):
    """The schema name of a request's body ('PUT', '/oauth/clients/app' -> 'Client'), or None when the spec has no
    such request."""
    exact = spec["requests"].get(f"{method} {path}")
    if exact:
        return exact
    return next((name for key, name in spec["requests"].items()
                 if key.split(" ", 1)[0] == method and re.fullmatch(
                     re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(key.split(" ", 1)[1])), path)), None)


def _resolved(spec, schema):
    """(name or None, schema) after following $ref."""
    name = None
    while "$ref" in schema:
        name = schema["$ref"][len(REF):]
        schema = spec["schemas"][name]
    return name, schema


def _flat(spec, schema):
    """A schema with its allOf parts merged in (properties and required united; other keywords, the last given)."""
    _, schema = _resolved(spec, schema)
    parts = (*(_flat(spec, p) for p in schema.get("allOf") or ()), {k: v for k, v in schema.items() if k != "allOf"})
    return {**{k: v for p in parts for k, v in p.items() if k not in ("properties", "required")},
            "properties": {n: s for p in parts for n, s in (p.get("properties") or {}).items()},
            "required": tuple(dict.fromkeys(r for p in parts for r in p.get("required") or ()))}


def _alternatives(spec, name, schema, value):
    """The schemas a union lets the value be (None when the schema isn't a union)."""
    mapping = (schema.get("discriminator") or {}).get("mapping") or {}
    chosen = isinstance(value, dict) and mapping.get(value.get((schema.get("discriminator") or {}).get("propertyName")))
    if chosen:
        return ({"$ref": chosen},)
    own = {k: v for k, v in schema.items() if k not in ("oneOf", "discriminator")}
    if schema.get("oneOf"):
        return tuple({"allOf": [o, own]} if own.get("properties") else o for o in schema["oneOf"])
    subtypes = spec["subtypes"].get(name) if name else None
    return tuple({"$ref": REF + s} for s in subtypes) if subtypes and schema.get("discriminator") else None


def _value_problems(schema, value, at):
    kind = schema.get("type")
    if kind and not (isinstance(value, _TYPES[kind]) and (kind == "boolean" or not isinstance(value, bool))):
        return (f"{at}: {type(value).__name__} where the spec wants {kind}",)
    return (*((f"{at}: {value!r} is not one of {', '.join(map(str, schema['enum']))}",)
              if "enum" in schema and value not in schema["enum"] else ()),
            *((f"{at}: {value!r} doesn't match {schema['pattern']}",)
              if isinstance(value, str) and "pattern" in schema and not re.search(schema["pattern"], value) else ()),
            *((f"{at}: shorter than {schema['minLength']}",)
              if isinstance(value, str) and len(value) < schema.get("minLength", 0) else ()),
            *((f"{at}: longer than {schema['maxLength']}",)
              if isinstance(value, str) and "maxLength" in schema and len(value) > schema["maxLength"] else ()),
            *((f"{at}: repeated items",) if isinstance(value, list) and schema.get("uniqueItems")
              and len({json.dumps(v, sort_keys=True) for v in value}) < len(value) else ()))


def _object_problems(spec, schema, value, at):
    props, extra = schema.get("properties") or {}, schema.get("additionalProperties")
    return (*(f"{at}: lacks {r}" for r in schema.get("required") or () if r not in value),
            *(p for k, v in value.items() for p in (
                validate(spec, props[k], v, f"{at}.{k}") if k in props else
                validate(spec, extra, v, f"{at}.{k}") if isinstance(extra, dict) else
                () if extra or not props else (f"{at}.{k}: not a property the spec names",))))


def validate(spec, schema, value, at="$"):
    """The problems of value against schema (a schema, or {'$ref': ...}) in spec (load_spec), () when it is valid."""
    name, resolved = _resolved(spec, schema)
    alternatives = _alternatives(spec, name, resolved, value)
    if alternatives:
        found = tuple(validate(spec, a, value, at) for a in alternatives)
        return () if not all(found) else min(found, key=len)
    flat = _flat(spec, resolved)
    own = _value_problems(flat, value, at)
    if own:
        return own
    if isinstance(value, list) and "items" in flat:
        return tuple(p for i, v in enumerate(value) for p in validate(spec, flat["items"], v, f"{at}[{i}]"))
    return _object_problems(spec, flat, value, at) if isinstance(value, dict) else ()


def request_problems(spec, method, path, body):
    """The problems of a request body against its request's schema; a request the spec doesn't have is one."""
    name = request_schema(spec, method, path)
    if name is None:
        return (f"{method} {path}: not a request of the Admin API {spec['version']}",)
    return validate(spec, {"$ref": REF + name}, body)
