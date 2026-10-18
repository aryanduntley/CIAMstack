"""What the API reads from requests and writes in responses: an edit's pairs and the catalog action of its mode, the
Area an entry lies in, uploaded files as text, and the JSON documents of the operations' results (rows, previews,
import plans, applied changes); the HTTP status of an operation's refusal. Pure."""
import gzip
from typing import NamedTuple

from opsdir.core.directory import gtime_at, norm_dn
from opsdir.core.interchange import ldif
from opsdir.core.naming import env_label
from opsdir.domains.governance.authorization import Area
from opsdir.domains.governance.imports import environment_of_scope

WHOLE_RECORD = Area("")
EDIT_ACTIONS = {"preview": "read", "propose": "propose", "apply": "apply"}
CHANGE_STATUS = {"approve": "approved", "reject": "rejected"}
NOT_FOUND = ("no entry ", "no area ", "no kind ", "no change ", "no system boundary ", "unknown report ")
CONFLICTING = ("already exists", "undecided", "can't become", "not approved", "is no proposed change")

Edit = NamedTuple("Edit", [("dn", str), ("sets", tuple), ("adds", tuple), ("removes", tuple), ("mode", str),
                           ("change", object), ("title", object)])


def status_of(message):
    """The HTTP status of an operation's refusal by its message: 404 for what isn't there, 409 for what the record's
    state refuses (a change that exists, can't move, isn't approved; undecided import conflicts), 400 otherwise."""
    text = message.lower()
    if text.startswith(NOT_FOUND):
        return 404
    return 409 if any(c in text for c in CONFLICTING) else 400


def _values(field, attr, values, empty_allowed):
    if not isinstance(values, list) or not all(isinstance(v, str) and v.strip() for v in values):
        raise ValueError(f"{field}.{attr}: give a list of non-empty strings")
    if not values and not empty_allowed:
        raise ValueError(f"{field}.{attr}: give at least one value (to clear a field: remove {{\"{attr}\": []}})")
    return values


def pairs_of(field, mapping, empty_allowed=False):
    """((attribute, value), ...) of {attribute: [values]}; for remove, [] removes the whole attribute (value None)."""
    if mapping is None:
        return ()
    if not isinstance(mapping, dict):
        raise ValueError(f"{field}: give an object {{attribute: [values]}}")
    return tuple(pair for attr, values in mapping.items()
                 for pair in (tuple((attr, v.strip()) for v in _values(field, attr, values, empty_allowed))
                              or ((attr, None),)))


def edit_of(body):
    """The Edit an edit request asks for; ValueError for a malformed one (a mode without what it needs)."""
    if not isinstance(body, dict) or not isinstance(body.get("dn"), str) or not body["dn"].strip():
        raise ValueError("give the entry's dn")
    mode = body.get("mode", "preview")
    if mode not in EDIT_ACTIONS:
        raise ValueError(f"mode {mode}: give preview, propose or apply")
    change, title = body.get("change"), body.get("title")
    if mode != "preview" and not (isinstance(change, str) and change.strip()):
        raise ValueError(f"mode {mode} needs change (its id)")
    if mode == "propose" and not (isinstance(title, str) and title.strip()):
        raise ValueError("mode propose needs title: what the approver reads")
    return Edit(body["dn"].strip(), pairs_of("set", body.get("set")), pairs_of("add", body.get("add")),
                pairs_of("remove", body.get("remove"), empty_allowed=True), mode, change, title)


def entry_area(dn):
    """The Area an edit to the entry at dn acts on: its environment, the whole record outside environments (as the
    command line's `opsdir edit`)."""
    env = environment_of_scope(norm_dn(dn))
    return Area(env_label(env) if env else "")


def at_of(text):
    """When an export was taken: YYYYMMDDhhmmssZ (UTC), or None when not given; ValueError otherwise."""
    if text in (None, ""):
        return None
    try:
        return gtime_at(text)
    except (ValueError, TypeError):
        raise ValueError(f"at {text}: give the time as YYYYMMDDhhmmssZ (UTC), e.g. 20260930141500Z") from None


def _text(name, raw):
    try:
        return (gzip.decompress(raw) if name.endswith(".gz") else raw).decode("utf-8")
    except (UnicodeDecodeError, OSError, EOFError):
        return None


def texts_of(uploads):
    """({relative path: text}, skipped paths) of uploaded files ((name, bytes), ...): UTF-8 text, .gz decompressed
    under its name without .gz (as the command line reads an export); not UTF-8 text skipped."""
    decoded = tuple((name[:-3] if name.endswith(".gz") else name, _text(name, raw)) for name, raw in uploads)
    return ({n: t for n, t in decoded if t is not None}, tuple(n for n, t in decoded if t is None))


def files_of(field, mapping):
    """{relative path: text} of a JSON request's files; ValueError when it isn't that."""
    if not isinstance(mapping, dict) or not mapping or not all(
            isinstance(k, str) and k and isinstance(v, str) for k, v in mapping.items()):
        raise ValueError(f"{field}: give an object {{relative path: text}} with at least one file")
    return mapping


def keys_of(field, value):
    """Conflict keys (take or keep) as a tuple: a list of strings, one string, or none."""
    if value in (None, ""):
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return tuple(value)
    raise ValueError(f"{field}: give conflict keys (or 'all')")


def sources_of(body):
    """((importer, files), ...) of an onboarding verification request; ValueError for a malformed one."""
    sources = body.get("sources") if isinstance(body, dict) else None
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources: give [{importer, files: {relative path: text}}, ...]")
    if not all(isinstance(s, dict) and isinstance(s.get("importer"), str) and s["importer"] for s in sources):
        raise ValueError("sources: each names its importer ('adapter[/importer]')")
    return tuple((s["importer"], files_of(f"sources[{i}].files", s.get("files"))) for i, s in enumerate(sources))


# ------------------------------------------------------------------ responses
def rows_doc(rows):
    """Rows as {"headers": [...], "rows": [[...], ...]}."""
    return {"headers": list(rows.headers), "rows": [list(r) for r in rows.rows]}


def changes_doc(records):
    """Change records as LDIF texts, one per record."""
    return [ldif.write_record(r) for r in records]


def preview_doc(preview):
    """A previewed write: {"changes": [LDIF of each record], "notices": [...]}."""
    return {"changes": changes_doc(preview.changes), "notices": list(preview.notices)}


def applied_doc(applied):
    """An applied change: its id and one line per change record applied."""
    return {"change": applied.change_id, "applied": list(applied.lines)}


def entries_doc(entries):
    """Search hits: each entry's DN, object classes and attributes."""
    return {"entries": [{"dn": e.dn, "objectClass": list(e.classes),
                         "attributes": {k: list(v) for k, v in e.attrs.items()}} for e in entries]}


def conflict_doc(c):
    return {"key": c.key, "dn": c.dn, "attribute": c.attr, "record": list(c.held), "live": list(c.live)}


def import_doc(plan, skipped=()):
    """An import's preview: the importer, its change records as LDIF, notices, conflicts (decided with take or keep)
    and the scopes it reads; the uploaded files skipped as not UTF-8 text."""
    return {"importer": plan.importer, "changes": changes_doc(plan.changes), "notices": list(plan.notices),
            "conflicts": [conflict_doc(c) for c in plan.conflicts], "scopes": list(plan.scopes),
            "skipped": list(skipped)}
