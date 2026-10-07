"""AWS's region list read into the estate's region catalog (opsdir.domains.estate.regions): the output of
`aws ec2 describe-regions --all-regions --output json`, every region of the partition the caller's credentials are in,
whether or not the account opted in. A region open only to accounts that opt in (OptInStatus opted-in or not-opted-in)
is opt-in, the rest available; a region whose endpoint is under amazonaws.com is in the public (commercial) partition.
The list gives no display names or geography: operators may add them, and a refresh keeps them. The importer runs
the command itself with `opsdir import aws/regions --run`, under the operator's own AWS login. Pure."""
from functools import partial

from opsdir.core.contract import Importer, Prerequisite
from opsdir.core.sources import json_document
from opsdir.domains.estate.regions import RegionRow, holds_regions, region_import
from .inventory import PROVIDER

COMMAND = ("aws", "ec2", "describe-regions", "--all-regions", "--output", "json")
EXPORT = "regions.json"
OPT_IN = ("opted-in", "not-opted-in")
PUBLIC_DOMAIN = ".amazonaws.com"


def region_rows(doc):
    """RegionRows of a describe-regions output document."""
    return tuple(RegionRow(r["RegionName"], None, None, "opt-in" if r.get("OptInStatus") in OPT_IN else "available",
                           "public" if r.get("Endpoint", "").endswith(PUBLIC_DOMAIN) else None)
                 for r in doc.get("Regions", ()) if isinstance(r, dict) and r.get("RegionName"))


def read_regions(files, d, patterns, at=None):
    """Imported: the region catalog's aws regions from describe-regions outputs (other files named, not read)."""
    docs = {p: json_document(t, dict) for p, t in sorted(files.items())}
    read = {p: doc for p, doc in docs.items() if doc is not None and "Regions" in doc}
    imported = region_import(d, PROVIDER, tuple(r for doc in read.values() for r in region_rows(doc)))
    return imported._replace(notices=(*imported.notices, *(f"{p}: not `aws ec2 describe-regions` output; not read"
                                                            for p in docs if p not in read)))


REGIONS = Importer("regions", "AWS's region list (aws ec2 describe-regions --all-regions --output json), as the "
                              "region catalog's aws regions", read_regions, ((EXPORT, COMMAND),))
PREREQUISITE = Prerequisite("aws-regions", "AWS's region list, for the region catalog (residencies and the planner's "
                                           "region checks)", REGIONS.name, partial(holds_regions, provider=PROVIDER))
