"""Azure's region list read into the estate's region catalog (opsdir.domains.estate.regions): the output of
`az account list-locations -o json`, the regions of the cloud the caller is signed in to (public or US Government),
each with its display name and geography. Only physical regions are regions resources go in: logical entries
(geographies such as `unitedstates`, `global`) are left out and named. Every region listed is available to the
subscription. The importer runs the command itself with `opsdir import azure/regions --run`, under the operator's own
Azure login. Pure."""
from functools import partial

from opsdir.core.contract import Importer, Prerequisite
from opsdir.core.sources import json_document
from opsdir.domains.estate.regions import RegionRow, holds_regions, named, region_import
from .inventory import PROVIDER

COMMAND = ("az", "account", "list-locations", "-o", "json")
EXPORT = "regions.json"
PHYSICAL = "Physical"


def _physical(location):
    return (location.get("metadata") or {}).get("regionType") == PHYSICAL


def region_rows(locations):
    """RegionRows of a list-locations output's physical regions: name, display name, geography."""
    return tuple(RegionRow(loc["name"], loc.get("displayName"), (loc.get("metadata") or {}).get("geography"))
                 for loc in locations if isinstance(loc, dict) and loc.get("name") and _physical(loc))


def _logical(locations):
    return [loc["name"] for loc in locations if isinstance(loc, dict) and loc.get("name") and not _physical(loc)]


def read_regions(files, d, patterns, at=None):
    """Imported: the region catalog's azure regions from list-locations outputs (other files named, not read; logical
    entries named, not regions)."""
    docs = {p: json_document(t, list) for p, t in sorted(files.items())}
    read = {p: doc for p, doc in docs.items() if doc is not None}
    imported = region_import(d, PROVIDER, tuple(r for doc in read.values() for r in region_rows(doc)))
    logical = [name for doc in read.values() for name in _logical(doc)]
    return imported._replace(notices=(
        *imported.notices,
        *((f"{PROVIDER}: {len(logical)} logical location(s) left out (geographies, not regions): "
           f"{named(logical)}",) if logical else ()),
        *(f"{p}: not `az account list-locations` output; not read" for p in docs if p not in read)))


REGIONS = Importer("regions", "Azure's region list (az account list-locations -o json), as the region catalog's "
                              "azure regions", read_regions, ((EXPORT, COMMAND),))
PREREQUISITE = Prerequisite("azure-regions", "Azure's region list, for the region catalog (residencies and the "
                                             "planner's region checks)", REGIONS.name,
                            partial(holds_regions, provider=PROVIDER))
