"""The estate's region catalog, residencies and FIPS endpoints: a provider's list read into the catalog (new regions
added, changed details a conflict to take or keep, regions no longer listed kept and marked, never deleted); the
residency an environment is held to and the regions it allows; the planner's region, residency and FIPS checks; the
regions and residency reports."""
import pytest

from opsdir.connectors.importing import import_changes, import_conflicts
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.estate.checks import check_fips, check_regions, check_residency
from opsdir.domains.estate.regions import RegionRow, holds_regions, region_import
from opsdir.domains.estate.reports import region_rows, residency_rows
from opsdir.domains.estate.residency import allowed_regions, residency_breach, residency_of
from mini_estate import PROVIDER
from network_fixtures import ALPHA, BETA, context, entry, model

OU = "dn: ou={0},dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: {0}\n"
CATALOG = f"cn={PROVIDER},ou=regions,dc=ciam-ops"
ROWS = (RegionRow("region-1", "Region One", "Europe"), RegionRow("region-2", "Region Two", "Europe", "opt-in"),
        RegionRow("region-3", "Region Three", "Americas"))


def _region(code, name, status="available"):
    return entry(CATALOG, code, "ciamCloudRegion", ciamRegionName=name, ciamRegionStatus=status)


def _catalog(*regions):
    return (OU.format("regions"),
            f"dn: {CATALOG}\nobjectClass: top\nobjectClass: ciamRegionCatalog\ncn: {PROVIDER}\n"
            f"ciamCloudProvider: {PROVIDER}\n", *regions)


def _residency(cn, *codes):
    return entry("ou=residencies,dc=ciam-ops", cn, "ciamResidency",
                 ciamAllowedRegion=tuple(f"cn={c},{CATALOG}" for c in codes))


def _held(env, residency):
    return LdifRecord(env, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                          ("replace", "ciamResidencyRef", (f"cn={residency},ou=residencies,dc=ciam-ops",))))


def _in_region(env, region):
    return LdifRecord(env.split(",", 1)[1], "modify", {}, (("replace", "ciamRegion", (region,)),))


def _estate(regions=(), residencies=(), changes=()):
    tree = (*(_catalog(*regions) if regions else ()), OU.format("residencies"), *residencies)
    d, alpha, beta = model(tree=tree, changes=changes)
    return context(d, alpha, beta, cutover="2026-12-01"), d, alpha, beta


CATALOGUED = (_region("region-1", "Region One"), _region("region-2", "Region Two", "opt-in"),
              _region("region-9", "Region Nine", "not-listed"))


# ------------------------------------------------------------------ the catalog from a provider's list
def test_a_first_fetch_adds_the_providers_regions():
    _, d, *_ = _estate()
    imported = region_import(d, PROVIDER, ROWS)
    changes = import_changes(d, imported)
    assert [r.dn for r in changes] == ["ou=regions,dc=ciam-ops", CATALOG,
                                       *(f"cn=region-{n},{CATALOG}" for n in (1, 2, 3))]
    assert import_conflicts(d, changes) == ()
    assert imported.notices == (f"{PROVIDER}: the provider lists 3 region(s)",
                                f"{PROVIDER}: 3 new region(s): region-1, region-2, region-3")


def test_a_refresh_adds_new_regions_and_never_deletes_or_silently_overwrites():
    renamed = (RegionRow("region-1", "Region 1 (renamed)", None), RegionRow("region-2", "Region Two", None, "opt-in"),
               RegionRow("region-3", "Region Three", "Americas"))
    _, d, *_ = _estate(regions=(_region("region-1", "Region One"), _region("region-2", "Region Two", "opt-in"),
                                _region("region-4", "Region Four")))
    imported = region_import(d, PROVIDER, renamed)
    changes = import_changes(d, imported)
    assert not any(r.changetype == "delete" for r in changes)
    conflicts = {(c.dn.split(",")[0], c.attr): (c.held, c.live) for c in import_conflicts(d, changes)}
    assert conflicts == {("cn=region-1", "ciamRegionName"): (("Region One",), ("Region 1 (renamed)",)),
                         ("cn=region-4", "ciamRegionStatus"): (("available",), ("not-listed",))}
    assert [r.dn for r in changes if r.changetype == "add"] == [f"cn=region-3,{CATALOG}"]
    assert imported.notices[1:] == (f"{PROVIDER}: 1 new region(s): region-3",
                                    f"{PROVIDER}: 1 region(s) no longer listed, kept and marked not-listed: region-4")


def test_details_the_list_doesnt_give_stay_and_a_region_already_marked_isnt_named_again():
    _, d, *_ = _estate(regions=(_region("region-1", "Region One"), _region("region-9", "Gone", "not-listed")))
    imported = region_import(d, PROVIDER, (RegionRow("region-1", "Region One"),))   # no geography given
    assert import_changes(d, imported) == ()
    assert imported.notices == (f"{PROVIDER}: the provider lists 1 region(s)",)
    assert holds_regions(d, PROVIDER) and not holds_regions(d, "other")


def test_an_export_listing_no_region_is_refused():
    _, d, *_ = _estate(regions=(_region("region-1", "Region One"),))
    with pytest.raises(SystemExit, match=f"{PROVIDER}: the export lists no regions; nothing imported"):
        region_import(d, PROVIDER, ())


# ------------------------------------------------------------------ residency
def test_the_residency_an_environment_is_held_to_and_the_regions_it_allows():
    _, d, alpha, beta = _estate(CATALOGUED, (_residency("eu", "region-1", "region-2"),),
                                (_held(ALPHA, "eu"), _in_region(BETA, "region-3")))
    eu = residency_of(alpha)
    assert eu.dn == "cn=eu,ou=residencies,dc=ciam-ops"
    assert allowed_regions(eu, PROVIDER) == ("region-1", "region-2") and allowed_regions(eu, "other") == ()
    assert residency_breach(alpha) is None and residency_of(beta) is None and residency_breach(beta) is None


def test_a_target_outside_its_residency_is_a_blocker_a_source_outside_its_own_an_action():
    ctx, *_ = _estate(CATALOGUED, (_residency("eu", "region-1"),),
                      (_held(ALPHA, "eu"), _held(BETA, "eu"), _in_region(ALPHA, "region-2"),
                       _in_region(BETA, "region-2")))
    f = check_residency(ctx)
    assert [b[1] for b in f.blockers] == [
        f"beta/prod runs in {PROVIDER} region region-2, outside residency eu (it allows region-1): the move would "
        "hold data where its residency doesn't allow."]
    assert [a[1] for a in f.actions] == [f"alpha/prod runs in {PROVIDER} region region-2, outside residency eu (it "
                                         "allows region-1)."]


def test_a_residency_allowing_none_of_the_providers_regions_and_a_target_held_to_none():
    ctx, *_ = _estate(CATALOGUED, (_residency("eu"), _residency("us", "region-1")),
                      (_held(ALPHA, "us"), _held(BETA, "eu")))
    assert [b[1] for b in check_residency(ctx).blockers] == [
        f"residency eu allows no {PROVIDER} region, so beta/prod can't meet it (allow the regions it may use; the "
        "region catalog must hold them: `opsdir prerequisites`): the move would hold data where its residency doesn't "
        "allow."]
    ctx, *_ = _estate(CATALOGUED, (_residency("us", "region-1"),), (_held(ALPHA, "us"),))
    assert [(a[1], a[3]) for a in check_residency(ctx).actions] == [
        ("beta/prod is held to no residency while alpha/prod's data is held to us: record the target's "
         "(ciamResidencyRef) so the move is checked against it.", "2026-12-01")]
    assert check_residency(_estate(CATALOGUED)[0]) == check_residency(_estate()[0])     # nothing held: nothing found


# ------------------------------------------------------------------ regions against the catalog
def test_regions_the_catalog_cant_check_or_doesnt_list():
    ctx, *_ = _estate()
    assert [a[1] for a in check_regions(ctx).actions] == [
        f"The region catalog holds no {PROVIDER} regions, so {label}'s region region-1 can't be checked against the "
        "provider's list: fetch the list (`opsdir prerequisites`)." for label in ("alpha/prod", "beta/prod")]
    ctx, *_ = _estate(CATALOGUED, changes=(_in_region(ALPHA, "region-7"), _in_region(BETA, "region-9")))
    f = check_regions(ctx)
    assert [b[1] for b in f.blockers] == [f"beta/prod runs in {PROVIDER} region region-9, which the provider no "
                                          "longer lists (region catalog): check the region."]
    assert [a[1] for a in f.actions] == [f"alpha/prod runs in {PROVIDER} region region-7, which the provider doesn't "
                                         "list (region catalog): check the region."]
    ctx, *_ = _estate(CATALOGUED, changes=(_in_region(BETA, "region-2"),))
    f = check_regions(ctx)
    assert f.blockers == () and [a[1] for a in f.actions] == [
        f"beta/prod runs in {PROVIDER} region region-2, open only to accounts that opt in: make sure its account has."]


def test_fips_endpoints_the_target_drops_are_a_blocker():
    fips = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {},
                      (("add", "objectClass", ("ciamCloudEndpoints",)), ("replace", "ciamFipsEndpoints", ("TRUE",))))
    ctx, d, alpha, beta = _estate(changes=(fips,))
    assert [b[1] for b in check_fips(ctx).blockers] == [
        "alpha/prod's cloud uses FIPS 140 validated endpoints and beta/prod's doesn't (ciamFipsEndpoints): the move "
        "would drop them."]
    assert check_fips(context(d, beta, alpha)).blockers == ()           # gaining FIPS endpoints is no problem


# ------------------------------------------------------------------ reports
def test_the_regions_and_residency_reports():
    _, d, *_ = _estate(CATALOGUED, (_residency("eu", "region-1", "region-2"), _residency("uk", "region-1")),
                       (_held(ALPHA, "eu"), _in_region(BETA, "region-2"), _held(BETA, "uk")))
    assert region_rows(d) == [
        (PROVIDER, "region-1", "Region One", "", "available", "", "alpha/prod", "eu, uk"),
        (PROVIDER, "region-2", "Region Two", "", "opt-in", "", "beta/prod", "eu"),
        (PROVIDER, "region-9", "Region Nine", "", "not-listed", "", "", "")]
    assert residency_rows(d) == [
        ("alpha/prod", "eu", PROVIDER, "region-1", "ok"),
        ("beta/prod", "uk", PROVIDER, "region-2",
         f"beta/prod runs in {PROVIDER} region region-2, outside residency uk (it allows region-1)")]
    assert residency_rows(_estate()[1])[0] == ("alpha/prod", "none", PROVIDER, "region-1", "not held to a residency")
