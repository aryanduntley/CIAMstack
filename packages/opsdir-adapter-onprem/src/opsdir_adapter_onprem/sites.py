"""The organization's own sites (data centers, server rooms) read into the estate's region catalog
(opsdir.domains.estate.regions) as the onprem provider's regions: an on-prem environment's cloud names its site as its
region (ciamRegion), so residencies allow sites as they allow cloud regions and the planner checks a site the catalog
doesn't list. No provider publishes the list: the operators keep it, a JSON file of their sites:

    [{"code": "hq-dc1", "name": "Headquarters data center 1", "geography": "United States", "status": "available"}]

code is required (what ciamRegion names); name and geography as the organization calls them; status available (the
default) or not-listed (a site retired). A refresh keeps what the file doesn't give; a site the record holds that the
file lacks stays, marked not-listed. Pure."""
from functools import partial

from opsdir.core.contract import Importer, Prerequisite
from opsdir.core.sources import json_document
from opsdir.domains.estate.regions import RegionRow, holds_regions, region_import

PROVIDER = "onprem"
PARTITION = "on-premises"                 # the provider's one cloud environment (ciamCloudEnvironment)
EXPORT = "sites.json"
STATUSES = ("available", "not-listed")


def site_rows(sites):
    """RegionRows of a sites list: each site by its code, with its name and geography, in the on-prem partition."""
    return tuple(RegionRow(s["code"], s.get("name"), s.get("geography"),
                           s.get("status") if s.get("status") in STATUSES else "available", PARTITION)
                 for s in sites if isinstance(s, dict) and s.get("code"))


def read_sites(files, d, patterns, at=None):
    """Imported: the region catalog's onprem regions (the sites) from sites lists (other files named, not read)."""
    docs = {p: json_document(t, list) for p, t in sorted(files.items())}
    read = {p: doc for p, doc in docs.items() if doc is not None}
    imported = region_import(d, PROVIDER, tuple(r for doc in read.values() for r in site_rows(doc)))
    return imported._replace(notices=(*imported.notices,
                                      *(f"{p}: not a sites list (a JSON list of sites); not read"
                                        for p in docs if p not in read)))


SITES = Importer("sites", "the organization's sites (a JSON list: code, name, geography, status), as the region "
                          "catalog's onprem regions", read_sites)
PREREQUISITE = Prerequisite("onprem-sites", "the organization's own sites, for the region catalog (an on-prem "
                                            "environment's region is its site; residencies and the planner's region "
                                            "checks)", SITES.name, partial(holds_regions, provider=PROVIDER))
