"""Control-plane audit trails on Azure (core observability: ciamAuditTrail) as the subscription's Activity Log exported
by a diagnostic setting. Pure.

The Activity Log records who did what to a subscription's resources, in every region (it is global), kept 90 days by
Azure itself; a diagnostic setting on the subscription keeps it longer, where the record says.

Rendered for every trail, stamped with its entry (placed by its keeper: governance.keepers): each account trail as an
azurerm_monitor_diagnostic_setting on the subscription (data.azurerm_subscription.current) exporting the audit
categories (Administrative, Security, Policy) to what its ciamLogDestinationRole names: an object store's storage
account (Azure writes into its container insights-activity-logs) or a Log Analytics workspace (ciamLogDestination);
the destination's ID from its ciamProviderRef, the account the stack renders, or an input. Not rendered, and said so:
an organization trail (Azure has none: each subscription's
setting, usually deployed by the landing zone's policy), data reads and writes (each resource's own diagnostic
settings log them), another destination. Azure keeps no digest of the logs it writes: integrity is a container with
a locked immutability policy (ciamStorageImmutability compliance; core observability.audit grades it as validation's
equal), noted when the trail asks for integrity validation without one (an unlocked policy can be lifted). What isn't
rendered, or is left to a person, is a render note (audit_notes, flow 43), written as its comment.

Read back from (azurerm type, attributes) pairs (Terraform state as it is; `az monitor diagnostic-settings
subscription list` and an ARM template's subscription diagnostic settings normalized to it, audit_items):
azurerm_monitor_diagnostic_setting whose target is a subscription -> audit trail (kind audit): account scope,
control-plane when Administrative is exported, every region, and where its records go (the insights-activity-logs
container of its storage account, or its workspace) as the role of that object store or log destination.
"""
import re

from opsdir.core.directory import is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.observability.audit import PROTECTED, audit_trails, store_protection, trail_destination
from opsdir_format_terraform.hcl import Block, blocks_of, comment, from_entry, ref, tf_block, tf_name
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
    return tf_block("variable", [name], [("type", ref("string")), ("description", what)])


def _store(m, n, dest):
    """(destination argument, notes, variables) of an object store destination (notes: container_note's comment)."""
    account, container = container_of(one(dest, "ciamStorageRef"))
    pref = one(dest, "ciamProviderRef") or ""
    found = container_note(m, dest)
    elsewhere = (comment(note_comment(found)),) if found is not None else ()
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


def container_note(m, dest):
    """The render note of an object store the Activity Log is recorded in whose container isn't the one Azure writes
    it to (insights-activity-logs: an action, the record's change), or None."""
    account, container = container_of(one(dest, "ciamStorageRef"))
    if container == CONTAINER:
        return None
    return note("Audit", "action", f"Activity Log in {rdn_value(dest)}", f"Azure writes the Activity Log to container "
                f"{CONTAINER} of storage account {account}, not {container}: record that container as the object store",
                (f"Record {rdn_value(dest)}'s ciamStorageRef as container {CONTAINER} of storage account {account}, "
                 f"{RECORD}",), dest.dn, f"storage account {account}")


def unrendered_note(m, t):
    """The render note of trail t when environment m doesn't render it (a blocker: the Activity Log isn't exported),
    or None: an organization trail (Azure has none: the landing zone's policy deploys each subscription's), or no
    destination Azure exports to."""
    cn, dest = rdn_value(t), trail_destination(m, t)
    if one(t, "ciamAuditScope") == "organization":
        return note("Audit", "blocker", f"audit trail {cn}", "not rendered: Azure has no organization trail: each "
                    "subscription's Activity Log is exported by its own diagnostic setting (the landing zone's policy "
                    "deploys them); record it kept by the landing zone (ciamManagedBy)",
                    (f"Record the trail kept by the landing zone (ciamManagedBy), whose policy deploys each "
                     f"subscription's diagnostic setting, {RECORD}",), t.dn, "the organization")
    if dest is not None and _destination(m, tf_name(cn), dest) is not None:
        return None
    return note("Audit", "blocker", f"audit trail {cn}", "not rendered: " + (
                "no storage account or Log Analytics workspace here keeps its records (ciamLogDestinationRole)"
                if dest is None else f"Azure exports the Activity Log to a storage account, a Log Analytics "
                f"workspace or an event hub, and {rdn_value(dest)} is none of those"),
                (f"Bind the trail's ciamLogDestinationRole to an object store (a storage account's container) or a "
                 f"Log Analytics workspace, {RECORD}",), t.dn, m.label)


def audit_notes(m):
    """The render notes of environment m's audit trails (render_trails writes their comments): a trail it doesn't
    render, else its object store's container."""
    def of(t):
        found = unrendered_note(m, t)
        if found is not None:
            return found
        dest = trail_destination(m, t)
        return container_note(m, dest) if is_kind(m.d, dest, "ciamObjectStore") else None
    return tuple(n for t in audit_trails(m) for n in (of(t),) if n is not None)


def _trail(m, t):
    cn, dest = rdn_value(t), trail_destination(m, t)
    missing = unrendered_note(m, t)
    if missing is not None:
        return (comment(note_comment(missing)),)
    n = tf_name(cn)
    found = _destination(m, n, dest)
    target, notes, variables = found
    data = [e for e in values(t, "ciamAuditEvents") if e != "control-plane"]
    unlocked = one(t, "ciamIntegrityValidation") == "TRUE" and store_protection(m, t) < PROTECTED
    return (*notes, *variables, tf_block("resource", [SETTING, n], [
        *((("#", f"{', '.join(data)} events: each resource's own diagnostic settings log them (not rendered)"),)
          if data else ()),
        *((("#", "integrity: Azure keeps no digest of the Activity Log; keep it in a container with a locked "
                 "immutability policy (ciamStorageImmutability compliance)"),) if unlocked else ()),
        ("name", _name(t)), ("target_resource_id", ref(f"{SUBSCRIPTION}.id")), target,
        *(("enabled_log", Block((("category", c),))) for c in CATEGORIES)]))


def render_trails(m):
    """HCL (and comments) for environment m's control-plane audit trails: the subscription data source once, when a
    diagnostic setting is rendered."""
    out = tuple(x for t in audit_trails(m) for x in from_entry(t.dn, _trail(m, t)))
    return ((tf_block("data", ["azurerm_subscription", "current"], []),) if blocks_of(out, "resource", SETTING)
            else ()) + out


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
