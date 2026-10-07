"""Data residency: the residency an environment's data is held to (ciamResidencyRef: one the estate defines under
ou=residencies) and whether the region its cloud runs in is one the residency allows. A residency allows regions of
the region catalog by reference, so it can only allow regions the catalog holds; one that allows no region of an
environment's provider can't be met there. What the cloud adapters render from it: the regions an environment may
hold resources in (their region guardrails) and whether its cloud's clients use FIPS endpoints. Pure."""
from ...core.directory import get, is_a, norm_dn, one, rdn_of, rdn_value, values
from .regions import catalog_dn, region_dn

RESIDENCY = "ciamResidency"


def residency_of(m):
    """The residency environment m's data is held to, or None (none named, or what it names isn't a residency)."""
    ref = one(m.env, "ciamResidencyRef")
    e = get(m.d, ref) if ref else None
    return e if e is not None and is_a(e, RESIDENCY) else None


def allowed_regions(residency, provider):
    """The provider's region codes a residency allows, in the order it lists them."""
    catalog = norm_dn(catalog_dn(provider))
    return tuple(rdn_of(ref) for ref in values(residency, "ciamAllowedRegion")
                 if "," in ref and norm_dn(ref.split(",", 1)[1]) == catalog)


def residency_breach(m):
    """Why environment m's region breaks the residency its data is held to, or None (it doesn't, or none is named)."""
    residency = residency_of(m)
    if residency is None:
        ref = one(m.env, "ciamResidencyRef")
        return f"{m.label} names {ref} as its residency, which isn't a residency (ciamResidency)" if ref else None
    region, name = one(m.cloud, "ciamRegion"), rdn_value(residency)
    allowed = allowed_regions(residency, m.provider)
    if not allowed:
        return (f"residency {name} allows no {m.provider} region, so {m.label} can't meet it (allow the regions it may "
                f"use; the region catalog must hold them: `opsdir prerequisites`)")
    if region not in allowed:
        return (f"{m.label} runs in {m.provider} region {region}, outside residency {name} (it allows "
                f"{', '.join(allowed)})")
    return None


def region_entry(m):
    """The catalog's entry for the region environment m's cloud runs in, or None."""
    return get(m.d, region_dn(m.provider, one(m.cloud, "ciamRegion")))


def permitted_regions(m):
    """The regions of its provider environment m may hold resources in: its cloud's region, then the other regions its
    residency allows (only its cloud's region when it is held to none; the planner reports a region outside it)."""
    residency = residency_of(m)
    allowed = allowed_regions(residency, m.provider) if residency is not None else ()
    return tuple(dict.fromkeys((one(m.cloud, "ciamRegion"), *allowed)))


def fips_endpoints(m):
    """Whether environment m's cloud says its clients use the provider's FIPS 140 validated endpoints."""
    return one(m.cloud, "ciamFipsEndpoints") == "TRUE"
