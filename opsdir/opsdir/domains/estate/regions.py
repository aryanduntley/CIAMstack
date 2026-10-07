"""The estate's region catalog: each provider's regions as the provider lists them, one catalog per provider under
ou=regions (cn=<provider>), each region named by the provider's region code. The cloud adapters read the provider's
own list (their region importers, run from the provider's command: a prerequisite) into neutral RegionRows; here they
become the catalog. A fetch never deletes: a region the provider no longer lists stays, marked not-listed, so the
environments and residencies naming it keep their links and the planner can say so; every changed name or detail is a
conflict of the import that the operator takes or keeps. Pure."""
from collections import namedtuple

from ...core.contract import Imported
from ...core.directory import children, get, make_entry, merged_attrs, one, ou_entry, rdn_value
from .naming import REGIONS

CATALOG = "ciamRegionCatalog"
REGION = "ciamCloudRegion"
# One region as a provider lists it: code (eu-west-1, westeurope, europe-west1), name as the provider shows it, where it
# is (geography), status (naming.REGION_STATUSES) and partition (a ciamCloudEnvironment value), None when not given.
RegionRow = namedtuple("RegionRow", ("code", "name", "geography", "status", "partition"),
                       defaults=(None, None, "available", None))
OWNED = ("cn", "ciamRegionName", "ciamGeography", "ciamRegionStatus", "ciamCloudEnvironment")
NAMED = 5                         # regions named in a notice


def catalog_dn(provider):
    """DN of a provider's region catalog."""
    return f"cn={provider},{REGIONS}"


def region_dn(provider, code):
    """DN of a provider's region in the catalog."""
    return f"cn={code},{catalog_dn(provider)}"


def catalog_regions(d, provider):
    """The provider's regions the catalog holds, by code."""
    return children(d, catalog_dn(provider), REGION)


def holds_regions(d, provider):
    """Whether the catalog holds any of the provider's regions (the provider's region prerequisite is met)."""
    return bool(catalog_regions(d, provider))


def _catalog(d, provider):
    dn = catalog_dn(provider)
    return make_entry(dn, ("top", CATALOG),
                      merged_attrs(get(d, dn), {"cn": (provider,), "ciamCloudProvider": (provider,)},
                                   ("cn", "ciamCloudProvider")))


def _region(d, provider, row):
    dn = region_dn(provider, row.code)
    given = {name: (v,) for name, v in zip(OWNED, (row.code, row.name, row.geography, row.status, row.partition))
             if v is not None}
    return make_entry(dn, ("top", REGION), merged_attrs(get(d, dn), given, tuple(given)))


def _unlisted(e):
    return make_entry(e.dn, e.classes, {**e.attrs, "ciamRegionStatus": ("not-listed",)})


def named(names, limit=NAMED):
    """Names for a notice: the first few, comma-joined, and how many more there are."""
    more = f" and {len(names) - limit} more" if len(names) > limit else ""
    return ", ".join(names[:limit]) + more


def region_import(d, provider, rows):
    """Imported: the provider's catalog as its list (RegionRows) says, merged with what the record holds (attributes the
    list doesn't give stay); regions the record holds that the list lacks stay, marked not-listed. Notices: how many
    regions the list has, which are new, which are no longer listed. Refused when the list has no region (a wrong or
    empty export would mark every region not-listed)."""
    listed = {r.code: r for r in rows}
    if not listed:
        raise SystemExit(f"{provider}: the export lists no regions; nothing imported (an empty list would mark every "
                         "region not-listed)")
    gone = tuple(e for e in catalog_regions(d, provider) if rdn_value(e) not in listed)
    new = [c for c in listed if get(d, region_dn(provider, c)) is None]
    newly_gone = [rdn_value(e) for e in gone if one(e, "ciamRegionStatus") != "not-listed"]
    return Imported(
        containers=(ou_entry(REGIONS),),
        groups=((catalog_dn(provider), (_catalog(d, provider), *(_region(d, provider, r) for r in listed.values()),
                                        *(_unlisted(e) for e in gone))),),
        notices=(f"{provider}: the provider lists {len(listed)} region(s)",
                 *((f"{provider}: {len(new)} new region(s): {named(new)}",) if new else ()),
                 *((f"{provider}: {len(newly_gone)} region(s) no longer listed, kept and marked not-listed: "
                    f"{named(newly_gone)}",) if newly_gone else ())))
