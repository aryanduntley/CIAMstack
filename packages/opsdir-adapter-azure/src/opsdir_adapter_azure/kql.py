"""Kusto (KQL) predicates for Azure Monitor data collection rule transformations, from the neutral kept-line clauses
(domains/observability/sources.kept_clauses): a line is kept when any clause holds, a clause holding when its rule
matches (a top-level JSON field whose string value starts with the prefix, case-sensitive as the record classifies;
"" for the field being there) and none of its excluded rules does. Where a field is read from is the caller's: a
function from a field name to the expression reading it (a text log's RawData parsed as JSON, a container log's
LogMessage). Pure.
"""
TRUE, FALSE = "true", "false"


def literal(text):
    """A KQL string literal."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def field_of(column):
    """A function giving the KQL expression of a top-level field of the JSON a dynamic or string column holds."""
    return lambda name: f"tostring(parse_json({column})[{literal(name)}])"


def _rule(field, rule):
    name, prefix = rule
    return f"isnotempty({field(name)})" if prefix == "" else f"{field(name)} startswith_cs {literal(prefix)}"


def _clause(field, clause):
    parts = (*((_rule(field, clause.match),) if clause.match else ()),
             *(f"not({_rule(field, r)})" for r in clause.excluded))
    return " and ".join(parts) if parts else TRUE


def kept(clauses, field):
    """The KQL predicate keeping the lines the clauses keep (false when there are none)."""
    found = tuple(_clause(field, c) for c in clauses)
    if not found:
        return FALSE
    if TRUE in found:
        return TRUE
    return found[0] if len(found) == 1 else " or ".join(f"({c})" for c in found)
