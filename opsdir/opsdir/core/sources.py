"""Reading the files an importer is given: tolerant parsing (a file that isn't the expected format is named by the
importer, not raised) and an import's files grouped by folder. Importers in every package share these. Pure."""
import json


def parsed(load, text, errors=(ValueError,), kind=None):
    """load(text), or None when it raises one of errors or the document isn't of kind. The loader is the caller's
    (json.loads, a YAML loader), so the core depends on no parser."""
    try:
        doc = load(text)
    except errors:
        return None
    return doc if kind is None or isinstance(doc, kind) else None


def json_document(text, kind=None):
    """A JSON text's value, or None when it isn't JSON (or isn't of kind)."""
    return parsed(json.loads, text, (ValueError,), kind)


def json_records(text):
    """The records of a JSON text: a list's items, a single value as one record, or JSON lines (one value per
    non-blank line, as Cloud Asset Inventory exports write); None when it is none of these."""
    doc = json_document(text)
    if doc is not None:
        return doc if isinstance(doc, list) else [doc]
    lines = [json_document(line) for line in text.splitlines() if line.strip()]
    return lines if lines and all(x is not None for x in lines) else None


def under(files, root):
    """{path within root: text} of the files inside folder root."""
    return {p[len(root) + 1:]: text for p, text in files.items() if p.startswith(root + "/")}


def folders(files, roots):
    """{folder: {path within it: text}} for each of roots, in their order."""
    return {r: under(files, r) for r in roots}


def by_folder(files):
    """{top folder: {path within it: text}}: one folder per server, repository, ...; files at the top are left out."""
    return folders(files, sorted({p.split("/", 1)[0] for p in files if "/" in p}))
