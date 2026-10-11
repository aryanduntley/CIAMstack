"""Cloud Logging query language for log sinks and exclusions, from the neutral kept-line clauses
(domains/observability/sources.kept_clauses): a line is kept when any clause holds, a clause holding when its rule
matches (a top-level JSON field whose string value starts with the prefix, case-sensitive as the record classifies:
=~ with an anchored RE2 pattern; "" for the field being there: :*) and none of its excluded rules does. JSON lines are
parsed into jsonPayload (the Ops Agent's parse_json, GKE's structured logging), so fields are read from there.
docs.cloud.google.com/logging/docs/view/logging-query-language (research note 2363). Pure.
"""
import re

NOTHING = "NOT logName:*"           # no entry lacks a log name: keeps no line
LIMIT = 20000                       # characters in a query
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RE2 = re.compile(r"([\\.^$|?*+()\[\]{}])")


def literal(text):
    """A query string literal."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def prefix_pattern(prefix):
    """The RE2 pattern of a string starting with prefix."""
    return "^" + _RE2.sub(r"\\\1", prefix)


def field_of(root):
    """A function giving the query path of a top-level field of a JSON payload (jsonPayload), quoted when the name
    isn't a plain identifier."""
    return lambda name: f"{root}.{name}" if _NAME.match(name) else f"{root}.{literal(name)}"


def _rule(field, rule):
    name, prefix = rule
    return f"{field(name)}:*" if prefix == "" else f"{field(name)} =~ {literal(prefix_pattern(prefix))}"


def _clause(field, clause):
    parts = (*((_rule(field, clause.match),) if clause.match else ()),
             *(f"NOT ({_rule(field, r)})" for r in clause.excluded))
    return " AND ".join(parts) if parts else None


def kept(clauses, field):
    """The query keeping the lines the clauses keep: None when one keeps every line, NOTHING when there are none."""
    found = tuple(_clause(field, c) for c in clauses)
    if not found:
        return NOTHING
    if None in found:
        return None
    return found[0] if len(found) == 1 else " OR ".join(f"({c})" for c in found)


def all_of(*parts):
    """The query of parts all holding (None parts skipped), each grouped."""
    found = tuple(p for p in parts if p)
    return " AND ".join(f"({p})" if " OR " in p else p for p in found)


def any_of(parts):
    """The query of any of parts holding, each grouped."""
    found = tuple(dict.fromkeys(p for p in parts if p))
    return found[0] if len(found) == 1 else " OR ".join(f"({p})" for p in found)
