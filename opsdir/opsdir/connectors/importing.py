"""Importing a product's own export into the record: the adapter's importer reads the files; here what it yields
becomes change records (pure). The CLI reads the files and applies the change records under an approved change."""
from ..core.changeset import diff
from ..core.directory import get, norm_dn, subtree
from .registry import ADAPTERS, pattern_records


def importer_named(spec, installed=ADAPTERS):
    """(adapter, importer) for 'adapter[/importer]': the adapter's only importer when none is named. Refused, with
    what there is to choose from, when the adapter isn't installed, has no importer or none of that name."""
    name, _, wanted = spec.partition("/")
    adapter = next((a for a in installed if a.name == name), None)
    offered = ", ".join(f"{a.name}/{i.name}" for a in installed for i in a.importers) or "none"
    if adapter is None or not adapter.importers:
        raise SystemExit(f"no installed adapter named {name} has importers (installed importers: {offered})")
    if not wanted and len(adapter.importers) == 1:
        return adapter, adapter.importers[0]
    found = next((i for i in adapter.importers if i.name == wanted), None)
    if found is None:
        raise SystemExit(f"name one of {name}'s importers: {', '.join(i.name for i in adapter.importers)}")
    return adapter, found


def _outside(scope, entries):
    s = norm_dn(scope)
    return [e.dn for e in entries if e.norm != s and not e.norm.endswith("," + s)]


def import_changes(d, imported):
    """Change records turning the record into what the import says: the missing containers something imported goes
    under added, and each group's subtree made exactly its entries (entries the importer keeps are unchanged, so they
    keep their history). Refused when a group holds an entry outside its scope."""
    stray = [dn for scope, entries in imported.groups for dn in _outside(scope, entries)]
    if stray:
        raise SystemExit(f"importer produced entries outside what it imports: {', '.join(stray)}")
    needed = tuple(c for c in imported.containers
                   if any(not _outside(c.dn, (e,)) for _, entries in imported.groups for e in entries))
    containers = tuple(c for c in needed if get(d, c.dn) is None)
    before = {e.norm: e for scope, _ in imported.groups for e in subtree(d, scope)}
    after = {e.norm: e for e in (*containers, *(e for _, entries in imported.groups for e in entries))}
    return diff(d._replace(entries=before), d._replace(entries=after))


def preview_import(d, spec, files, installed=ADAPTERS):
    """(change records, notices) of importing files ({relative path: text}) with the importer spec names."""
    _, importer = importer_named(spec, installed)
    imported = importer.read(files, d, pattern_records(installed))
    return import_changes(d, imported), imported.notices
