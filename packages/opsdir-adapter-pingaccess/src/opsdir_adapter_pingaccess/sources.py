"""What an import is given, as PingAccess's objects by collection. Pure.

Three shapes, each to the same Read ({collection path: (items, ...)}, the version they were read from, notices):

  Admin API reads        <collection>.json or <collection>/page-<n>.json: {"items": [...]} (a list), or one object
                         (a settings object); applications/<id>/resources[...] an application's resources (each item
                         given the application's id); version.json the product version (what the collector saves)
  this adapter's render  pingaccess/admin-api/requests.json, any folder: each request's body an item of the collection
                         its createWith (else its path) names: references already as ${pingaccess-id:...}
  the export             a saved GET /config/export: {"version", "data": {section: [items]}} (or the sections at the
                         top level); resources in a section of their own (each with its application's id) or inside
                         their application; the export's encryption material is dropped, its presence named

A collection nothing was read for isn't in the Read: the importer leaves what the record holds for it.
"""
import re
from functools import reduce
from typing import NamedTuple

from opsdir.core.secrets import sensitive_name
from opsdir.core.sources import json_document
from .api import (APPLICATION_ID, EXPORT_DATA, EXPORT_KEY_MATERIAL, EXPORT_SECTIONS, EXPORT_VERSION, ITEMS, RESOURCES,
                  VERSION, collection)

Read = NamedTuple("Read", [("items", dict), ("version", object), ("notices", tuple)])
_PAGE = re.compile(r"/page-\d+$")
_RESOURCES = re.compile(r"^applications/([^/]+)/resources$")
_RENDERED_RESOURCES = re.compile(r"^applications/(\$\{pingaccess-id:[^}]+\})/resources")
REQUESTS = "requests.json"


def response_items(doc):
    """A collection response's items, or a settings object as its one item."""
    if isinstance(doc, list):
        return tuple(i for i in doc if isinstance(i, dict))
    if isinstance(doc, dict) and isinstance(doc.get(ITEMS), list):
        return tuple(i for i in doc[ITEMS] if isinstance(i, dict))
    return (doc,) if isinstance(doc, dict) else ()


def _merged(parts):
    """{collection: items} of ((collection, items), ...), pages joined in order."""
    return reduce(lambda out, part: {**out, part[0]: (*out.get(part[0], ()), *part[1])}, parts, {})


def _api_part(path, doc):
    """(collection, items) of one saved Admin API response, or None when the path is no collection."""
    stem = _PAGE.sub("", path[:-len(".json")])
    app = _RESOURCES.match(stem)
    if app:
        return RESOURCES, tuple({**i, APPLICATION_ID: i.get(APPLICATION_ID, app.group(1))} for i in response_items(doc))
    c = collection(stem)
    return (c.path, response_items(doc) if not c.settings else ((doc,) if isinstance(doc, dict) else ())) if c else None


def _request_part(request):
    """(collection, (body,)) of one rendered request: the collection its createWith (else its path) names."""
    create = request.get("createWith")
    path = (create.split(" ", 1)[1] if isinstance(create, str) and " " in create else request.get("path") or "")
    path = path.strip("/")
    app = _RENDERED_RESOURCES.match(path)
    body = request.get("body") if isinstance(request.get("body"), dict) else None
    if body is None:
        return None
    if app:
        return RESOURCES, ({**body, APPLICATION_ID: app.group(1)},)
    c = collection(path)
    return (c.path, (body,)) if c else None


def is_render(doc):
    """Whether a JSON document is this adapter's rendered requests.json."""
    return isinstance(doc, dict) and isinstance(doc.get("requests"), list) and "pingAccess" in doc


def admin_api_read(files):
    """Read of saved Admin API responses and of this adapter's own rendered requests."""
    docs = {p: json_document(t) for p, t in sorted(files.items()) if p.endswith(".json")}
    renders = {p: d for p, d in docs.items() if p.rsplit("/", 1)[-1] == REQUESTS and is_render(d)}
    api = {p: d for p, d in docs.items() if p not in renders and d is not None and p != f"{VERSION}.json"}
    parts = {p: _api_part(p, d) for p, d in api.items()}
    version = docs.get(f"{VERSION}.json")
    found = [*(part for p, part in parts.items() if part), *(part for d in renders.values()
                                                          for r in d["requests"] if isinstance(r, dict)
                                                          for part in (_request_part(r),) if part)]
    return Read(_merged(found), version.get("version") if isinstance(version, dict) else None,
                (*(f"not JSON, not imported: {p}" for p, d in docs.items() if d is None),
                 *(f"no PingAccess collection this adapter reads, not imported: {p}" for p, part in parts.items()
                   if part is None),
                 *(f"not an Admin API response, not imported: {p}" for p in sorted(files) if not p.endswith(".json"))))


def _key_material(name):
    return name in EXPORT_KEY_MATERIAL or (sensitive_name(name) and name not in EXPORT_SECTIONS)


def _sections(data):
    """((collection, items), ...) of an export's sections, an application's own resources hoisted (with its id)."""
    known = [(EXPORT_SECTIONS[k], response_items(v)) for k, v in data.items() if k in EXPORT_SECTIONS]
    nested = [(RESOURCES, tuple({**r, APPLICATION_ID: r.get(APPLICATION_ID, a.get("id"))}
                                for r in a.get("resources") or () if isinstance(r, dict)))
              for path, items in known if path == "applications" for a in items if a.get("resources")]
    apps = [(path, tuple({k: v for k, v in a.items() if k != "resources"} for a in items)
             if path == "applications" else items) for path, items in known]
    return (*apps, *nested)


def export_read(files):
    """Read of saved configuration exports (one per file; several are joined)."""
    docs = {p: json_document(t, dict) for p, t in sorted(files.items())}
    good = {p: d for p, d in docs.items() if d is not None}
    datas = {p: (d[EXPORT_DATA] if isinstance(d.get(EXPORT_DATA), dict) else d) for p, d in good.items()}
    dropped = sorted({(p, k) for p, d in good.items() for k in d if _key_material(k)} |
                     {(p, k) for p, data in datas.items() for k in data if _key_material(k)})
    unknown = sorted({(p, k) for p, data in datas.items() for k in data
                      if k not in EXPORT_SECTIONS and not _key_material(k) and k not in (EXPORT_VERSION, EXPORT_DATA)})
    versions = tuple(dict.fromkeys(str(d[EXPORT_VERSION]) for d in good.values() if d.get(EXPORT_VERSION)))
    return Read(_merged([part for data in datas.values() for part in _sections(data)]),
                versions[0] if len(versions) == 1 else None,
                (*(f"{p}: the export's {k} (its encryption material) dropped, never stored" for p, k in dropped),
                 *(f"{p}: section {k} is no collection this adapter reads, not imported" for p, k in unknown),
                 *((f"exports of several versions ({', '.join(versions)}) read at once: no source version recorded; "
                    "import each version's export on its own",) if len(versions) > 1 else ()),
                 *(f"not a JSON export, not imported: {p}" for p, d in docs.items() if d is None)))
