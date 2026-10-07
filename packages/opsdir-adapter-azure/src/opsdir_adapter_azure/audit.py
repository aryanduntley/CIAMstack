"""Control-plane audit trails on Azure (core observability: ciamAuditTrail) as the subscription's Activity Log exported
by a diagnostic setting. Pure.

The Activity Log records who did what to a subscription's resources, in every region (it is global), kept 90 days by
Azure itself; a diagnostic setting on the subscription keeps it longer, where the record says.

Rendered in the platform's own root: each account trail the platform team keeps (no ciamManagedBy) as an
azurerm_monitor_diagnostic_setting on the subscription (data.azurerm_subscription.current) exporting the audit
categories (Administrative, Security, Policy) to what its ciamLogDestinationRole names: an object store's storage
account (Azure writes into its container insights-activity-logs) or a Log Analytics workspace (ciamLogDestination);
the destination's ID from its ciamProviderRef, the account the stack renders, or an input. Not rendered, and said so:
a trail someone else keeps (named with its keeper), an organization trail (Azure has none: each subscription's
setting, usually deployed by the landing zone's policy), data reads and writes (each resource's own diagnostic
settings log them), another destination. Azure keeps no digest of the logs it writes: integrity is a container with
a locked immutability policy (ciamStorageImmutability compliance; core observability.audit grades it as validation's
equal), noted when the trail asks for integrity validation without one (an unlocked policy can be lifted).

Read back from (azurerm type, attributes) pairs (Terraform state as it is; `az monitor diagnostic-settings
subscription list` and an ARM template's subscription diagnostic settings normalized to it, audit_items):
azurerm_monitor_diagnostic_setting whose target is a subscription -> audit trail (kind audit): account scope,
control-plane when Administrative is exported, every region, and where its records go (the insights-activity-logs
container of its storage account, or its workspace) as the role of that object store or log destination.
"""
import re

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.domains.observability.audit import (PROTECTED, audit_trails, store_protection, trail_destination,
                                               trail_keeper)
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .arm_ids import arm_segment
from .storage import container_of, kept_containers

SETTING = "azurerm_monitor_diagnostic_setting"
DIAGNOSTIC = "microsoft.insights/diagnosticsettings"
READ = (DIAGNOSTIC,)                # what an ARM template's reader reads of these
CATEGORIES = ("Administrative", "Security", "Policy")    # the Activity Log's audit categories
CONTAINER = "insights-activity-logs"                     # where Azure writes the Activity Log in a storage account
SUBSCRIPTION = "data.azurerm_subscription.current"
_TARGET = re.compile(r"^(/subscriptions/[^/]+)(?:/resourcegroups/[^/]+)?/providers/microsoft\.insights/"
                     r"diagnosticsettings/([^/]+)$", re.IGNORECASE)


def _name(trail):
    pref = one(trail, "ciamProviderRef") or ""
    return re.split(r"/diagnosticSettings/|\|", pref, flags=re.IGNORECASE)[-1] if pref else rdn_value(trail)


def _variable(name, what):
    return block("variable", [name], [("type", ref("string")), ("description", what)])


def _store(m, n, dest):
    """(destination argument, notes, variables) of an object store destination."""
    account, container = container_of(one(dest, "ciamStorageRef"))
    pref = one(dest, "ciamProviderRef") or ""
    elsewhere = (f"# NOTE: Azure writes the Activity Log to container {CONTAINER} of storage account {account}, not "
                 f"{container}: record that container as the object store",) if container != CONTAINER else ()
    if any(container_of(one(b, "ciamStorageRef"))[0] == account for b in kept_containers(m)):
        return ("storage_account_id", ref(f"azurerm_storage_account.{tf_name(account)}.id")), elsewhere, ()
    if "/blobservices/" in pref.lower():
        return ("storage_account_id", re.split("/blobServices/", pref, flags=re.IGNORECASE)[0]), elsewhere, ()
    var = f"{n}_storage_account_id"
    return (("storage_account_id", ref(f"var.{var}")), elsewhere,
            (_variable(var, f"The ID of storage account {account}, which keeps the Activity Log"),))


def _workspace(n, dest):
    pref = one(dest, "ciamProviderRef") or ""
    if "/microsoft.operationalinsights/workspaces/" in pref.lower():
        return ("log_analytics_workspace_id", pref), (), ()
    var = f"{n}_workspace_id"
    return (("log_analytics_workspace_id", ref(f"var.{var}")), (),
            (_variable(var, f"The ID of Log Analytics workspace {rdn_value(dest)}, which keeps the Activity Log"),))


def _destination(m, n, dest):
    """(destination argument, notes, variables), or None when Azure can't export to it."""
    if is_kind(m.d, dest, "ciamObjectStore") and container_of(one(dest, "ciamStorageRef")):
        return _store(m, n, dest)
    if is_kind(m.d, dest, "ciamLogDestination") and one(dest, "ciamDestinationKind") == "workspace":
        return _workspace(n, dest)
    return None


def _not_rendered(cn, why):
    return (f"# NOTE: audit trail {cn}: not rendered: {why}",)


def _trail(m, t):
    cn, keeper, dest = rdn_value(t), trail_keeper(m, t), trail_destination(m, t)
    if keeper is not None:
        return (f"# Audit trail {cn} ({one(t, 'ciamAuditScope')}): kept by {rdn_value(keeper)}, not rendered here",)
    if one(t, "ciamAuditScope") == "organization":
        return _not_rendered(cn, "Azure has no organization trail: each subscription's Activity Log is exported by its "
                                 "own diagnostic setting (the landing zone's policy deploys them); record it kept by "
                                 "the landing zone (ciamManagedBy)")
    n = tf_name(cn)
    found = _destination(m, n, dest) if dest is not None else None
    if found is None:
        return _not_rendered(cn, "no storage account or Log Analytics workspace here keeps its records "
                                 "(ciamLogDestinationRole)" if dest is None else
                                 f"Azure exports the Activity Log to a storage account, a Log Analytics workspace or "
                                 f"an event hub, and {rdn_value(dest)} is none of those")
    target, notes, variables = found
    data = [e for e in values(t, "ciamAuditEvents") if e != "control-plane"]
    unlocked = one(t, "ciamIntegrityValidation") == "TRUE" and store_protection(m, t) < PROTECTED
    return (*notes, *variables, block("resource", [SETTING, n], [
        *((("#", f"{', '.join(data)} events: each resource's own diagnostic settings log them (not rendered)"),)
          if data else ()),
        *((("#", "integrity: Azure keeps no digest of the Activity Log; keep it in a container with a locked "
                 "immutability policy (ciamStorageImmutability compliance)"),) if unlocked else ()),
        ("name", _name(t)), ("target_resource_id", ref(f"{SUBSCRIPTION}.id")), target,
        *(("enabled_log", Block((("category", c),))) for c in CATEGORIES)]))


def render_trails(m):
    """HCL (and comments) for environment m's control-plane audit trails: the subscription data source once, when a
    diagnostic setting is rendered."""
    out = tuple(x for t in audit_trails(m) for x in _trail(m, t))
    return ((block("data", ["azurerm_subscription", "current"], []),) if any(
        x.startswith(f'resource "{SETTING}"') for x in out) else ()) + out


# ------------------------------------------------------------------ read back
def _target(a):
    """The subscription a diagnostic setting exports (/subscriptions/<id>), or None for a resource's own."""
    t = (a.get("target_resource_id") or "").rstrip("/")
    return t if re.fullmatch(r"/subscriptions/[^/]+", t, re.IGNORECASE) else None


def _categories(a):
    return {(x.get("category") or x.get("category_group") or "").lower()
            for x in (*(a.get("enabled_log") or ()), *(x for x in a.get("log") or () if x.get("enabled", True)))}


def trail_events(a):
    """The activity a subscription diagnostic setting exports: control-plane when its enabled logs include the
    Administrative category (or every log: allLogs, audit), else none."""
    return ("control-plane",) if _categories(a) & {"administrative", "alllogs", "audit"} else ()


def _destination_refs(a):
    """The refs of what keeps a setting's records: its workspace, or the container Azure writes to in its storage
    account (by the forms an importer gives a container: ARM ID, blob URL, account/container)."""
    if a.get("log_analytics_workspace_id"):
        return a["log_analytics_workspace_id"]
    sid = a.get("storage_account_id")
    account = arm_segment(sid, "storageAccounts")
    return (f"{sid}/blobServices/default/containers/{CONTAINER}",
            f"https://{account}.blob.core.windows.net/{CONTAINER}", f"{account}/{CONTAINER}") if account else None


def trail_resources(pairs):
    """Subscription diagnostic settings of (azurerm type, attributes) pairs, as audit trails."""
    return tuple(resource("audit", f"{target}/providers/Microsoft.Insights/diagnosticSettings/{a['name']}", {
        "ciamAuditScope": "account", "ciamAuditEvents": trail_events(a), "ciamAllRegions": "TRUE"},
        links={"ciamLogDestinationRole": _destination_refs(a)}, name=a["name"])
        for a in of_types(pairs, SETTING) for target in (_target(a),) if target and a.get("name"))


def audit_items(items):
    """(azurerm type, attributes) pairs of the subscription diagnostic settings among (kind, item) pairs in the CLI's
    shape (`az monitor diagnostic-settings subscription list`; an ARM template's, flattened: no scope)."""
    return [(SETTING, {"name": hit.group(2), "target_resource_id": hit.group(1),
                       "storage_account_id": i.get("storageAccountId"),
                       "log_analytics_workspace_id": i.get("workspaceId"),
                       "enabled_log": [{"category": x.get("category"), "category_group": x.get("categoryGroup")}
                                       for x in i.get("logs") or () if x.get("enabled")]})
            for k, i in items if k == DIAGNOSTIC and not i.get("scope")
            for hit in (_TARGET.match(i.get("id") or ""),) if hit]
