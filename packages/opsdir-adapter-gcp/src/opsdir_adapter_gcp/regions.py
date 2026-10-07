"""Google Cloud's region list read into the estate's region catalog (opsdir.domains.estate.regions): the output of
`gcloud compute regions list --format=json`, the Compute Engine regions the project can see. Every region listed is
available and public (Google Cloud has one partition); the list gives no display names or geography: operators may
add them, and a refresh keeps them. The importer runs the command itself with `opsdir import gcp/regions --run`, under
the operator's own gcloud login. Pure."""
from functools import partial

from opsdir.core.contract import Importer, Prerequisite
from opsdir.core.sources import json_document
from opsdir.domains.estate.regions import RegionRow, holds_regions, region_import
from .inventory import PROVIDER

COMMAND = ("gcloud", "compute", "regions", "list", "--format=json")
EXPORT = "regions.json"
KIND = "compute#region"


def region_rows(regions):
    """RegionRows of a regions list output: each region by name, available, public."""
    return tuple(RegionRow(r["name"], None, None, "available", "public") for r in regions
                 if isinstance(r, dict) and r.get("name") and r.get("kind", KIND) == KIND)


def read_regions(files, d, patterns, at=None):
    """Imported: the region catalog's gcp regions from regions list outputs (other files named, not read)."""
    docs = {p: json_document(t, list) for p, t in sorted(files.items())}
    read = {p: doc for p, doc in docs.items() if doc is not None}
    imported = region_import(d, PROVIDER, tuple(r for doc in read.values() for r in region_rows(doc)))
    return imported._replace(notices=(*imported.notices,
                                      *(f"{p}: not `gcloud compute regions list` output; not read"
                                        for p in docs if p not in read)))


REGIONS = Importer("regions", "Google Cloud's region list (gcloud compute regions list --format=json), as the region "
                              "catalog's gcp regions", read_regions, ((EXPORT, COMMAND),))
PREREQUISITE = Prerequisite("gcp-regions", "Google Cloud's region list, for the region catalog (residencies and the "
                                           "planner's region checks)", REGIONS.name,
                            partial(holds_regions, provider=PROVIDER))
