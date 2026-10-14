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
page lists only commercial regions for storage accounts (2026-10-08): rendered, with an action to confirm (gov_note,
flow 43), written as its comment.

Read back from Terraform state: the CloudPosture pricing (tier Standard) with the SensitiveDataDiscovery extension ->
data discovery (kind discovery)."""
from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.core.notes import note, note_comment
from opsdir.domains.estate.discovery import custom_identifiers, discovery_services, rescan_days
from opsdir_format_terraform.hcl import comment, from_entry
from .purview import purview_read, renders as purview_renders, scanned
from .security import CSPM, PRICING

EXTENSION = "SensitiveDataDiscovery"
SUPPORTED_ENGINES = ("sqlserver",)          # Azure SQL Database (ENGINES in boundary: SQL Database)
GOV_NOTE = ("Defender for Cloud's support matrix lists Defender CSPM's sensitive data scanning (DSPM) GA, its data "
            "security posture prerequisites page only commercial regions for storage accounts (2026-10-08): rendered, "
            "confirm with the account team")


def discovery_plans(m):
    """((plan, subplan, extensions, origin), ...) environment m's data discovery needs of Defender (merged with the
    security services' plans by render_security; origin: the first discovery service, whose keeper's root takes the
    plan when no security service needs it first)."""
    found = discovery_services(m)
    return ((CSPM, None, (EXTENSION,), found[0].dn),) if found else ()


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
    purview = purview_renders(m) and any(x.dn == s.dn for x, _, _ in scanned(m))
    return (comment(f"{cn}: Defender for Cloud's sensitive data discovery (Defender CSPM, SensitiveDataDiscovery) "
                    "examines every block blob, Azure Files and ADLS Gen2 storage account and Azure SQL database in "
                    "the subscription, by sampling (complete cataloguing needs Microsoft Purview scanning: "
                    f"{'its scans below' if purview else 'not rendered'})"),
            *((comment(f"{cn}: {', '.join(others)}: not a store it examines"),) if others else ()),
            *((comment(f"{cn}: it refreshes object storage within eight days of a change and databases weekly; the "
                       f"record asks every {days} days"),) if days is not None and days < 7 and not purview else ()),
            *((comment(f"{cn}: its own data types ({', '.join(f'{n}: {rx}' for n, rx in own)}) are Microsoft Purview "
                       "custom sensitive information types imported into Defender's data sensitivity settings: not "
                       f"rendered{' (the Purview scans have classification rules of them below)' if purview else ''}"),)
              if own else ()),
            *((comment(f"{cn}: its findings are Defender recommendations and alerts: they reach "
                       f"{one(s, 'ciamFindingsRole')} through the security services' continuous export"),)
              if one(s, "ciamFindingsRole") else ()),
            *((comment(f"{cn}: Defender keeps its results itself: {one(s, 'ciamResultsRole')} isn't written to"),)
              if one(s, "ciamResultsRole") else ()))


def gov_note(m):
    """The render note of data discovery in Azure Government, rendered though one of Microsoft's pages lists only
    commercial regions for it (an action: confirm with the account team), or None."""
    found = discovery_services(m)
    if not found or one(m.cloud, "ciamCloudEnvironment") != "usgovernment":
        return None
    return note("Data discovery", "action", f"data discovery {', '.join(rdn_value(s) for s in found)} in Azure "
                "Government", GOV_NOTE,
                ("Ask Microsoft's account team whether Defender CSPM's sensitive data scanning covers the "
                 "environment's storage accounts in its Azure Government region before relying on it",),
                found[0].dn, m.label)


def discovery_notes(m):
    """The render notes of environment m's data discovery (render_discovery writes their comments)."""
    return tuple(n for n in (gov_note(m),) if n is not None)


def render_discovery(m):
    """Comments for environment m's data discovery (its Defender plan extension is rendered with the security
    services' plans), gov_note's first in Azure Government."""
    found, missing = discovery_services(m), gov_note(m)
    gov = from_entry(found[0].dn, (comment(note_comment(missing)),)) if missing is not None else ()
    return (*gov, *(x for s in found for x in from_entry(s.dn, _notes(m, s))))


def discovery_resources(pairs):
    """Data discovery of (azurerm type, attributes) pairs: a Standard CloudPosture pricing with the extension, and
    the subscription's Purview scan triggers' interval (the fewest days) as its rescan interval."""
    days = min((r.days for r in purview_read(pairs)), default=None)
    return tuple(resource("discovery", f"{a.get('id')}/{EXTENSION}", {"ciamRescanDays": days},
                          name="defender-sensitive-data")
                 for a in of_types(pairs, PRICING)
                 if a.get("resource_type") == CSPM and (a.get("tier") or "").lower() == "standard" and a.get("id")
                 and EXTENSION in {(e.get("name") or "") for e in a.get("extension") or ()})
