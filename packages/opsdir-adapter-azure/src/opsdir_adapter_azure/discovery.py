"""Data discovery on Azure (core estate: ciamDataDiscovery) as Defender for Cloud's sensitive data discovery. Pure.

A data discovery the platform team keeps turns on the SensitiveDataDiscovery extension of the subscription's Defender
CSPM plan (CloudPosture), merged into the one azurerm_security_center_subscription_pricing the security services render
for it (discovery_plans). The rest is Microsoft's and said in comments: it examines every supported store in the
subscription (block blob, Azure Files over SMB and ADLS Gen2 storage accounts, Azure SQL databases; other stores the
record names aren't examined), refreshes object storage within eight days of a change and databases weekly (a comment
when the record asks for more often), takes the organization's own data types as Microsoft Purview custom sensitive
information types imported into its data sensitivity settings (no Terraform: named in a comment), keeps its results
itself (a comment when ciamResultsRole names a store), and its findings are Defender recommendations and alerts that
reach their destination through the security services' continuous export. Microsoft documents it as sampling: complete
cataloguing needs Microsoft Purview scanning (not rendered).

In Azure Government: Defender for Cloud's support matrix lists Defender CSPM's "Sensitive data scanning (DSPM)" GA (and
Defender for Storage's sensitive data threat detection not available), while the data security posture prerequisites
page lists only commercial regions for storage accounts (2026-10-08): rendered, with a comment to confirm.

Read back from Terraform state: the CloudPosture pricing (tier Standard) with the SensitiveDataDiscovery extension ->
data discovery (kind discovery)."""
from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.discovery import custom_identifiers, discovery_services, rescan_days
from .security import CSPM, PRICING

EXTENSION = "SensitiveDataDiscovery"
SUPPORTED_ENGINES = ("sqlserver",)          # Azure SQL Database (ENGINES in boundary: SQL Database)
GOV_NOTE = ("Azure Government: Defender for Cloud's support matrix lists Defender CSPM's sensitive data scanning "
            "(DSPM) GA, its data security posture prerequisites page only commercial regions for storage accounts "
            "(2026-10-08): rendered, confirm with the account team")


def _keeper(m, s):
    holder = get(m.d, one(s, "ciamManagedBy"))
    return rdn_value(holder) if holder is not None else one(s, "ciamManagedBy")


def _kept(m):
    return [s for s in discovery_services(m) if not one(s, "ciamManagedBy")]


def discovery_plans(m):
    """((plan, subplan, extensions), ...) environment m's kept data discovery needs of Defender (merged with the
    security services' plans by render_security)."""
    return ((CSPM, None, (EXTENSION,)),) if _kept(m) else ()


def _unsupported(m, s):
    """The store roles discovery s examines that Defender's sensitive data discovery doesn't."""
    def supported(b):
        return b is not None and (is_kind(m.d, b, "ciamObjectStore") or (
            is_kind(m.d, b, "ciamDatabase") and one(b, "ciamDbEngine") in SUPPORTED_ENGINES))
    return [r for r in values(s, "ciamScansRole")
            if not supported(next((x for x in m.bindings if one(x, "ciamBindingRole") == r), None))]


def _notes(m, s):
    cn, days = rdn_value(s), rescan_days([s])
    others, own = _unsupported(m, s), custom_identifiers(s)
    return (f"# {cn}: Defender for Cloud's sensitive data discovery (Defender CSPM, SensitiveDataDiscovery) "
            "examines every block blob, Azure Files and ADLS Gen2 storage account and Azure SQL database in the "
            "subscription, by sampling (complete cataloguing needs Microsoft Purview scanning, not rendered)",
            *((f"# {cn}: {', '.join(others)}: not a store it examines",) if others else ()),
            *((f"# {cn}: it refreshes object storage within eight days of a change and databases weekly; the record "
               f"asks every {days} days",) if days is not None and days < 7 else ()),
            *((f"# {cn}: its own data types ({', '.join(f'{n}: {rx}' for n, rx in own)}) are Microsoft Purview custom "
               "sensitive information types imported into Defender's data sensitivity settings: not rendered",)
              if own else ()),
            *((f"# {cn}: its findings are Defender recommendations and alerts: they reach "
               f"{one(s, 'ciamFindingsRole')} through the security services' continuous export",)
              if one(s, "ciamFindingsRole") else ()),
            *((f"# {cn}: Defender keeps its results itself: {one(s, 'ciamResultsRole')} isn't written to",)
              if one(s, "ciamResultsRole") else ()))


def render_discovery(m):
    """Comments for environment m's data discovery (its Defender plan extension is rendered with the security
    services' plans)."""
    held = tuple(f"# Data discovery {rdn_value(s)}: kept by {_keeper(m, s)}, not rendered here"
                 for s in discovery_services(m) if one(s, "ciamManagedBy"))
    kept = _kept(m)
    gov = (f"# {GOV_NOTE}",) if kept and one(m.cloud, "ciamCloudEnvironment") == "usgovernment" else ()
    return (*held, *gov, *(x for s in kept for x in _notes(m, s)))


def discovery_resources(pairs):
    """Data discovery of (azurerm type, attributes) pairs: a Standard CloudPosture pricing with the extension."""
    return tuple(resource("discovery", f"{a.get('id')}/{EXTENSION}", {}, name="defender-sensitive-data")
                 for a in of_types(pairs, PRICING)
                 if a.get("resource_type") == CSPM and (a.get("tier") or "").lower() == "standard" and a.get("id")
                 and EXTENSION in {(e.get("name") or "") for e in a.get("extension") or ()})
