"""Data discovery on Azure through Microsoft Purview scans that recur exactly every ciamRescanDays days (core estate:
ciamDataDiscovery with ciamCatalogRef). Pure.

Defender for Cloud's sensitive data discovery (discovery.py) has no interval of its own. Where the record names the
organization's Purview account (ciamCatalogRef: its resource id; Purview allows one account per tenant, so the account
is referenced, never created) and an interval, each blob container the service examines gets, through Microsoft's azapi
provider (data plane, scanning API 2023-09-01, at <account>.purview.azure.com; only where the cloud allows the add-on:
ciamProviderAddOn azapi):
  a data source (kind AzureStorage) for the container's storage account, in the account's root collection
  a scan of it with the account's managed identity (AzureStorageMsi), Microsoft's system scan rule set
  its trigger: a full scan every N days (frequency Day, interval N: Purview's own schedule, exact for any N), first at
  the input purview_scan_start
  the Storage Blob Data Reader role for the account's identity on the storage account (the stack's own accounts;
  another keeper's is named in a comment)
and the organization's own data types (ciamCustomIdentifier) become Purview classification rules (kind Custom, the
regular expression as a data pattern). Purview applies them only through a custom scan rule set, which azapi can't
manage, and their classifications are made in Purview first: the planner asks for both (catalog-custom-rules).
A scan scans the whole storage account the container is in. An Azure SQL database it examines is named in a comment:
the record holds no server endpoint and database name to register it with (Purview scans Azure SQL with
AzureSqlDatabaseMsi once its identity may read it: catalog-database-access).

Azure Government: not rendered (decision 2527). azapi asks for Purview's commercial token audience
(https://purview.azure.net) and nothing documents the one <account>.purview.azure.us takes, so the planner names the
gap until a live test settles it (deferred note on discovery.py). What the deploying identity needs in Purview (Data
Source Administrator and Data Curator on the collection: not Azure RBAC, so not rendered) is a planner prerequisite
(catalog-scan-permission).

Read back from Terraform state: the trigger (frequency Day, its interval) and its scan's data source -> the account,
the examined account's endpoint and N (purview_read).
"""
import re
from types import MappingProxyType
from typing import NamedTuple

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.findings import findings, responsible
from opsdir.domains.estate.authorizations import unmet_configurations
from opsdir.domains.estate.discovery import ANY_DAYS, custom_identifiers, discovery_services, rescan_line, rescan_plan
from opsdir.domains.data.storage import kept_store
from opsdir.domains.network.stack import kept_by
from opsdir_format_terraform.hcl import comment, from_entry, ref, tf_block, tf_name
from .account import azapi_allowed
from .storage import container_of

DATA_PLANE = "azapi_data_plane_resource"
API = "2023-09-01"
SCANNING = "Microsoft.Purview/accounts/Scanning"
SOURCES, RULES = f"{SCANNING}/datasources", f"{SCANNING}/classificationrules"
SCANS, TRIGGERS = f"{SOURCES}/scans", f"{SOURCES}/scans/triggers"
HOST = "purview.azure.com"
ACCOUNT_API = "Microsoft.Purview/accounts@2021-12-01"       # the account's ARM resource (its managed identity)
BLOB_READER = "Storage Blob Data Reader"
START = "purview_scan_start"
AREA = "Data discovery"
_ACCOUNT = re.compile(r"/providers/Microsoft\.Purview/accounts/([^/]+)", re.IGNORECASE)


def account_name(catalog_ref):
    """The Purview account a catalog reference (its resource id) names, or None."""
    found = _ACCOUNT.search(catalog_ref or "")
    return found.group(1) if found else None


def _government(m):
    return one(m.cloud, "ciamCloudEnvironment") == "usgovernment"


def _store(m, role):
    return next((b for b in m.bindings if one(b, "ciamBindingRole") == role), None)


def scanned(m):
    """((service, account, N), ...): environment m's data discovery services (whoever keeps them) that scan through a
    Purview account every N days (an account and an interval recorded), whatever renders them."""
    found = ((s, account_name(one(s, "ciamCatalogRef")), rescan_plan(s, ANY_DAYS)) for s in discovery_services(m))
    return tuple((s, a, plan.days) for s, a, plan in found if a and plan is not None)


def renders(m):
    """Whether environment m's root renders Purview scans: commercial Azure, the azapi add-on allowed, a service to
    scan."""
    return not _government(m) and azapi_allowed(m) and bool(scanned(m))


def _containers(m, s):
    """(store, storage account) of each blob container a service examines."""
    return tuple((b, container_of(one(b, "ciamStorageRef"))[0]) for r in values(s, "ciamScansRole")
                 for b in (_store(m, r),) if b is not None and is_kind(m.d, b, "ciamObjectStore")
                 and container_of(one(b, "ciamStorageRef")))


def _databases(m, s):
    return tuple(r for r in values(s, "ciamScansRole") for b in (_store(m, r),)
                 if b is not None and is_kind(m.d, b, "ciamDatabase"))


def source_name(s, account):
    """The Purview data source name of a service's storage account."""
    return f"{rdn_value(s)}-{account}"


def rule_name(s, name):
    """The Purview classification rule (and classification) name of one of a service's own data types."""
    return f"{rdn_value(s)}-{name}"


def classification(s, name):
    """The custom classification a rule assigns: CIAM.<SERVICE>.<NAME>."""
    return f"CIAM.{rdn_value(s)}.{name}".upper().replace("-", "_")


def _collection(account):
    return {"referenceName": account, "type": "CollectionReference"}


def _source(s, purview, account):
    n = tf_name(f"{rdn_value(s)}_{account}")
    src, scan = source_name(s, account), rdn_value(s)
    return n, (tf_block("resource", [DATA_PLANE, f"{n}_source"], [
                   ("type", f"{SOURCES}@{API}"), ("parent_id", f"{purview}.{HOST}/scan"), ("name", src),
                   ("body", {"kind": "AzureStorage", "properties": {
                       "endpoint": f"https://{account}.blob.core.windows.net/",
                       "collection": _collection(purview)}})]),
               tf_block("resource", [DATA_PLANE, f"{n}_scan"], [
                   ("type", f"{SCANS}@{API}"), ("parent_id", f"{purview}.{HOST}/scan/datasources/{src}"),
                   ("name", scan),
                   ("body", {"kind": "AzureStorageMsi", "properties": {
                       "scanRulesetName": "AzureStorage", "scanRulesetType": "System",
                       "collection": _collection(purview)}}),
                   ("depends_on", [ref(f"{DATA_PLANE}.{n}_source")])]))


def _trigger(n, purview, src, scan, days):
    return tf_block("resource", [DATA_PLANE, f"{n}_trigger"], [
        ("type", f"{TRIGGERS}@{API}"), ("parent_id", f"{purview}.{HOST}/scan/datasources/{src}/scans/{scan}"),
        ("name", "default"),
        ("body", {"properties": {"state": "Enabled", "scanLevel": "Full", "recurrence": {
            "frequency": "Day", "interval": days, "startTime": ref(f"var.{START}"), "timeZone": "UTC"}}}),
        ("depends_on", [ref(f"{DATA_PLANE}.{n}_scan")])])


def _reader(m, s, store, account, purview):
    """The Storage Blob Data Reader grant for the Purview account's identity on the store's storage account: the
    stack's own account (rendered), or one the record references by its ARM id; a comment naming another keeper's,
    or one the record names no id for."""
    n = tf_name(f"{rdn_value(s)}_{account}_purview_reader")
    recorded = (one(store, "ciamProviderRef") or "").split("/blobServices/")[0]
    scope = ref(f"azurerm_storage_account.{tf_name(account)}.id") if kept_store(store) else \
        recorded if "/storageAccounts/" in recorded and not one(store, "ciamManagedBy") else None
    if scope is None:
        whose = f"ask its keeper ({kept_by(m, store)}) to give" if one(store, "ciamManagedBy") else \
            "the record names no ARM id for it: give"
        return (comment(f"{rdn_value(s)}: storage account {account}: {whose} Purview account {purview}'s managed "
                        f"identity {BLOB_READER} on it"),)
    return (tf_block("resource", ["azurerm_role_assignment", n], [
        ("scope", scope), ("role_definition_name", BLOB_READER),
        ("principal_id", ref(f"data.azapi_resource.{tf_name(f'purview_{purview}')}.output.identity.principalId"))]),)


def _rules(s, purview):
    return tuple(tf_block("resource", [DATA_PLANE, tf_name(f"{rule_name(s, name)}_rule")], [
        ("type", f"{RULES}@{API}"), ("parent_id", f"{purview}.{HOST}/scan"), ("name", rule_name(s, name)),
        ("body", {"kind": "Custom", "properties": {
            "classificationName": classification(s, name), "dataPatterns": [{"kind": "Regex", "pattern": rx}],
            "minimumPercentageMatch": 60, "ruleStatus": "Enabled",
            "description": f"{name}: an own data type of data discovery {rdn_value(s)} (ciamCustomIdentifier)"}})])
        for name, rx in custom_identifiers(s))


def _account_data(s, purview):
    """The Purview account, read through azapi (azurerm has no data source for it): its managed identity."""
    return tf_block("data", ["azapi_resource", tf_name(f"purview_{purview}")], [
        ("type", ACCOUNT_API), ("resource_id", one(s, "ciamCatalogRef")),
        ("response_export_values", ["identity.principalId"])])


def _service(m, s, purview, days):
    stores = _containers(m, s)
    parts = [(_source(s, purview, a), b, a) for b, a in stores]
    named = ", ".join(a for _, a in stores) or "nothing"
    return (comment(f"{rdn_value(s)}: Microsoft Purview account {purview} scans {named} every {days} days (its "
                    "trigger), each storage account whole"),
            *(comment(f"{rdn_value(s)}: Azure SQL database {r}: register it in Purview (the record holds no server "
                      "endpoint and database name) and scan it with AzureSqlDatabaseMsi") for r in _databases(m, s)),
            *(x for (n, (source, scan)), b, a in parts
              for x in (source, scan, _trigger(n, purview, source_name(s, a), rdn_value(s), days),
                        *_reader(m, s, b, a, purview))),
            *_rules(s, purview))


def render_purview(m):
    """HCL and comments for environment m's Purview scans (see the module); a comment where the cloud is Azure
    Government or the azapi add-on isn't allowed."""
    found = scanned(m)
    if not found:
        return ()
    if _government(m):
        return tuple(x for s, _, d in found for x in from_entry(s.dn, (
            comment(f"{rdn_value(s)}: Microsoft Purview scans every {d} days aren't rendered in Azure Government: "
                    "azapi's Purview token audience there is unverified (see the plan)"),)))
    if not azapi_allowed(m):
        return tuple(x for s, _, d in found for x in from_entry(s.dn, (
            comment(f"{rdn_value(s)}: Microsoft Purview scans every {d} days need the azapi add-on (ciamProviderAddOn "
                    "azapi): not rendered"),)))
    accounts = {a: s for s, a, _ in reversed(found)}           # each account once, by its first service
    return (*(_account_data(s, a) for a, s in accounts.items()),
            *(x for s, a, d in found for x in from_entry(s.dn, _service(m, s, a, d))))


def purview_inputs(m):
    """The inputs of environment m's root its Purview scans need (providers.tf): when they first run."""
    return (tf_block("variable", [START], [
        ("type", ref("string")),
        ("description", "When the Microsoft Purview scans first run (RFC 3339, UTC: 2026-11-01T02:00:00Z); each then "
                        "recurs every ciamRescanDays days")]),) if renders(m) else ()


# ------------------------------------------------------------------ planner
PREREQUISITES = MappingProxyType({
    "catalog-scan-permission": "the identity deploying its Terraform needs Data Source Administrator and Data Curator "
                               "on the Purview account's root collection (Purview's own roles, not Azure RBAC) to "
                               "register the sources and set up their scans",
    "catalog-database-access": "Purview's managed identity needs read access to the Azure SQL databases it scans (a "
                               "Microsoft Entra user for it in each database, db_datareader)",
    "catalog-custom-rules": "Purview applies its classification rules only through a custom scan rule set: create "
                            "their classifications and a custom scan rule set including the rules in Purview (azapi "
                            "can't), then point the scans at it"})


def _needed(m, s):
    return (*(("catalog-scan-permission",) if _containers(m, s) else ()),
            *(("catalog-database-access",) if _databases(m, s) else ()),
            *(("catalog-custom-rules",) if custom_identifiers(s) else ()))


def check_discovery_cadence(ctx):
    """How each data discovery the target keeps honours its interval on Azure: Purview's trigger (an OK line, and the
    prerequisites as actions); an action where the record asks for an interval and names no Purview account, where the
    cloud is Azure Government, or where the azapi add-on isn't allowed (Defender's own refresh then stands)."""
    m = ctx.dst
    kept = [(s, rescan_plan(s, ANY_DAYS)) for s in discovery_services(m) if not one(s, "ciamManagedBy")]
    kept = [(s, plan) for s, plan in kept if plan is not None]
    owner = responsible(ctx.d, m.env)
    via = {s.dn: a for s, a, _ in scanned(m)}
    gap = lambda s, why: (AREA, f"{m.label}'s data discovery `{rdn_value(s)}` asks for every "
                                f"{rescan_plan(s, ANY_DAYS).days} days: {why}; Defender for Cloud's sensitive data "
                                "discovery refreshes object storage within eight days of a change and databases "
                                "weekly.",
                          responsible(ctx.d, s, m.env), ctx.cutover)
    unnamed = [gap(s, "name the organization's Microsoft Purview account it scans through (ciamCatalogRef: its "
                      "resource id; Purview allows one account per tenant)") for s, _ in kept if s.dn not in via]
    gov = [gap(s, f"Microsoft Purview scans aren't rendered in Azure Government: azapi asks for Purview's commercial "
                  f"token audience and nothing documents the one {via[s.dn]}.purview.azure.us takes; set them up in "
                  "Purview (US Gov Virginia only, partial Data Map support) or confirm azapi there with a live test")
           for s, _ in kept if s.dn in via and _government(m)]
    add_on = [gap(s, "allow the azapi add-on (ciamProviderAddOn azapi) for its Microsoft Purview scans")
              for s, _ in kept if s.dn in via and not _government(m) and not azapi_allowed(m)]
    rendered = [(s, plan) for s, plan in kept if s.dn in via and renders(m)]
    prerequisites = [(AREA, f"{m.label}'s data discovery `{rdn_value(s)}` through Microsoft Purview: {PREREQUISITES[c]}"
                            f". Record {c} (ciamConfigurationMet) once it is in place.", owner, ctx.cutover)
                     for s, _ in rendered for c in unmet_configurations(m, _needed(m, s))]
    return findings(actions=[*unnamed, *gov, *add_on, *prerequisites],
                    ok=tuple(rescan_line(m, s, plan, f"Microsoft Purview account {via[s.dn]}'s scan trigger (every "
                                                     f"{plan.days} days)", "")
                             for s, plan in rendered))


# ------------------------------------------------------------------ read back
# What a rendered or applied Purview trigger says of a data discovery service: the account, the storage accounts it
# scans and the interval
PurviewRead = NamedTuple("PurviewRead", [("scan", str), ("account", str), ("storage", tuple), ("days", int)])
_PARENT = re.compile(r"^([^.]+)\.purview\.azure\.(?:com|us)/scan/datasources/([^/]+)/scans/([^/]+)$")


def _body(a):
    body = a.get("body")
    return body if isinstance(body, dict) else {}


def purview_read(pairs):
    """(PurviewRead, ...) of (type, attributes) pairs: each azapi trigger recurring by days, with the endpoint of its
    scan's data source."""
    planes = [a for t, a in pairs if t == DATA_PLANE]
    sources = {(m.group(1), a.get("name")): (_body(a).get("properties") or {}).get("endpoint") or ""
               for a in planes if (a.get("type") or "").startswith(f"{SOURCES}@")
               for m in (re.match(r"^([^.]+)\.purview\.azure\.(?:com|us)/scan$", a.get("parent_id") or ""),) if m}
    reads = []
    for a in planes:
        found = _PARENT.match(a.get("parent_id") or "") if (a.get("type") or "").startswith(f"{TRIGGERS}@") else None
        recurrence = (_body(a).get("properties") or {}).get("recurrence") or {}
        if found and recurrence.get("frequency") == "Day" and recurrence.get("interval"):
            account, source, scan = found.groups()
            endpoint = sources.get((account, source), "")
            storage = re.match(r"^https://([^.]+)\.blob\.", endpoint)
            reads.append(PurviewRead(scan, account, (storage.group(1),) if storage else (),
                                     int(recurrence["interval"])))
    return tuple(reads)
