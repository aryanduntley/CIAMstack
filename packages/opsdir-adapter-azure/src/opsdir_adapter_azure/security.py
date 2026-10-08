"""Cloud security services on Azure (core estate: ciamSecurityService) as Microsoft Defender for Cloud and Azure
Policy. Pure.

Rendered in the stack's main.tf for the services the platform team keeps (no ciamManagedBy; one someone else keeps is
named in a comment). Defender's plans are one setting per subscription, so the plans every kept service needs are
merged into one azurerm_security_center_subscription_pricing (tier Standard) per plan:

  threat-detection        control-plane Arm; compute VirtualMachines P2 (agentless scanning); network VirtualMachines
                          P2 (Defender for Servers Plan 2 carries DNS threat detection); containers Containers;
                          storage StorageAccounts DefenderForStorageV2 (malware scanning on upload); databases
                          SqlServers, SqlServerVirtualMachines, OpenSourceRelationalDatabases, CosmosDbs; key-vaults
                          KeyVaults PerKeyVault; applications AppServices, Api; identity has no Defender for Cloud plan
                          (Entra ID Protection watches sign-ins: a comment)
  vulnerability-scanning  compute: VirtualMachines P2 and the server vulnerability assessment setting (Microsoft
                          Defender Vulnerability Management, MdeTvm); containers: Containers with registry vulnerability
                          assessment; applications: no Defender scanner (a comment); compute when no area is named
  config-recording        Azure records resource changes itself (Resource Graph change history, about 14 days): nothing
                          to enable, a comment; keeping it longer needs an export, not rendered
  posture                 CloudPosture (Defender CSPM) and a subscription policy assignment of each framework's built-in
                          initiative, found by display name (nist-800-53-r5 NIST SP 800-53 Rev. 5, nist-800-171-r2 NIST
                          SP 800-171 Rev. 2, fedramp-high, fedramp-moderate, cmmc-l2 CMMC 2.0 Level 2, cmmc-l3, dod-il4,
                          dod-il5, cis, pci-dss, iso-27001, soc2); the Microsoft cloud security benchmark is Defender's
                          own default assignment (a comment); other clouds' baselines are named in a comment

In Azure Government (ciamCloudEnvironment usgovernment) every plan is rendered (decision: a government cloud is assumed
to offer what the record asks for), and a plan or feature one of Microsoft's availability pages lists as unavailable
there carries a comment naming the page, to confirm with the account team. Findings go where ciamFindingsRole says
through continuous export (azurerm_security_center_automation: alerts for threat detection, sub-assessments for
vulnerability scanning, assessments and regulatory compliance for posture) to a Log Analytics workspace (a log
destination's ciamProviderRef); an Event Hub (its connection string is a secret) or another binding is a NOTE. An
organization-wide service is enabled on the management group by Azure Policy (a comment). Defender covers the whole
subscription, every region.

Read back from Terraform state: azurerm_security_center_subscription_pricing (tier Standard) -> threat detection over
the areas its plans watch, vulnerability scanning (azurerm_security_center_server_vulnerability_assessments_setting, a
Containers plan's registry vulnerability assessment), posture (CloudPosture, azurerm_subscription_policy_assignment of
a known initiative by its display name) -> security services (kind security), each covering every region, with the
workspace or Event Hub a continuous export of its findings goes to as their destination.
"""
from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.security import findings_destination, security_services
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .identities import LOC, RG

PRICING = "azurerm_security_center_subscription_pricing"
VA_SETTING = "azurerm_security_center_server_vulnerability_assessments_setting"
ASSIGNMENT = "azurerm_subscription_policy_assignment"
AUTOMATION = "azurerm_security_center_automation"
SUBSCRIPTION = "data.azurerm_subscription.current"
CSPM = "CloudPosture"
# area -> Defender plans (resource type, subplan, extensions) watching it
AREA_PLANS = {"control-plane": (("Arm", "PerSubscription", ()),),
              "network": (("VirtualMachines", "P2", ()),),
              "compute": (("VirtualMachines", "P2", ("AgentlessVmScanning",)),),
              "containers": (("Containers", None, ()),),
              "storage": (("StorageAccounts", "DefenderForStorageV2", ("OnUploadMalwareScanning",)),),
              "databases": (("SqlServers", None, ()), ("SqlServerVirtualMachines", None, ()),
                            ("OpenSourceRelationalDatabases", None, ()), ("CosmosDbs", None, ())),
              "key-vaults": (("KeyVaults", "PerKeyVault", ()),),
              "applications": (("AppServices", None, ()), ("Api", "P1", ()))}
SCAN_PLANS = {"compute": (("VirtualMachines", "P2", ("AgentlessVmScanning",)),),
              "containers": (("Containers", None, ("ContainerRegistriesVulnerabilityAssessments",)),)}
# plan -> the area it watches (read back); VirtualMachines P2 also network
PLAN_AREAS = {"Arm": "control-plane", "Dns": "network", "VirtualMachines": "compute", "Containers": "containers",
              "KubernetesService": "containers", "ContainerRegistry": "containers", "StorageAccounts": "storage",
              "SqlServers": "databases", "SqlServerVirtualMachines": "databases",
              "OpenSourceRelationalDatabases": "databases", "CosmosDbs": "databases", "KeyVaults": "key-vaults",
              "AppServices": "applications", "Api": "applications"}
AREAS = ("control-plane", "identity", "network", "compute", "containers", "storage", "databases", "key-vaults",
         "applications")
# framework -> its built-in initiative's display name (Microsoft: "List of built-in policy initiatives")
INITIATIVES = {"nist-800-53-r5": "NIST SP 800-53 Rev. 5", "nist-800-171-r2": "NIST SP 800-171 Rev. 2",
               "fedramp-high": "FedRAMP High", "fedramp-moderate": "FedRAMP Moderate",
               "cmmc-l2": "CMMC 2.0 Level 2", "cmmc-l3": "CMMC Level 3", "dod-il4": "DoD Impact Level 4",
               "dod-il5": "DoD Impact Level 5", "cis": "CIS Microsoft Azure Foundations Benchmark v2.0.0",
               "pci-dss": "PCI DSS v4.0.1", "iso-27001": "ISO 27001:2013", "soc2": "SOC 2 Type 2"}
BASELINE = "microsoft-cloud-security-benchmark"
BASELINE_NAME = "Microsoft cloud security benchmark"
_REGIONAL = "Microsoft's \"Microsoft Defender for Cloud regional availability\" (2026-10)"
_GOV_PAGE = "Microsoft's \"Cloud feature availability for US Government customers\" (2026-09)"
# Azure Government: plans and features one of Microsoft's pages lists as unavailable there (rendered all the same)
GOV_NOTES = {
    "Containers": f"{_REGIONAL} doesn't list the US Gov regions for Defender for Containers; {_GOV_PAGE} lists it GA",
    "CosmosDbs": f"{_REGIONAL} doesn't list the US Gov regions for Defender for Azure Cosmos DB; {_GOV_PAGE} lists "
                 "it GA",
    "Api": f"{_REGIONAL} doesn't list the US Gov regions for Defender for APIs; {_GOV_PAGE} doesn't list it",
    "AppServices": f"{_REGIONAL} and {_GOV_PAGE} list Defender for App Service as unavailable in Azure Government",
    VA_SETTING: f"{_GOV_PAGE} lists integrated vulnerability assessment for machines as not available in Azure "
                "Government",
    "cmmc-l2": "Azure Government's built-in initiatives list CMMC Level 3, not CMMC 2.0 Level 2 (NIST SP 800-171 Rev. "
               "2 covers its practices)"}
GOV_ONLY = frozenset(("dod-il4", "dod-il5"))
# continuous export: the sources a service's findings come from
EXPORTS = {"threat-detection": ("Alerts",), "vulnerability-scanning": ("SubAssessments",),
           "posture": ("Assessments", "RegulatoryComplianceAssessment")}


def _gov(m):
    return one(m.cloud, "ciamCloudEnvironment") == "usgovernment"


def _confirm(m, key):
    """The Azure Government comment for a plan, feature or initiative a Microsoft page lists as unavailable, or ()."""
    return ((f"{GOV_NOTES[key]}: rendered, confirm with the account team",) if _gov(m) and key in GOV_NOTES else ())


def _kept(m):
    return [s for s in security_services(m) if not one(s, "ciamManagedBy")]


def _plans(services):
    """((plan, subplan, extensions), ...) the kept services need, one per plan, extensions merged."""
    wanted = [p for s in services for p in _service_plans(s)]
    names = list(dict.fromkeys(p for p, _, _ in wanted))
    return tuple((p, next((sub for q, sub, _ in wanted if q == p and sub), None),
                  tuple(dict.fromkeys(x for q, _, ext in wanted if q == p for x in ext))) for p in names)


def _service_plans(s):
    kind, areas = one(s, "ciamSecurityKind"), values(s, "ciamSecurityCoverage")
    if kind == "threat-detection":
        return tuple(p for a in areas for p in AREA_PLANS.get(a, ()))
    if kind == "vulnerability-scanning":
        return tuple(p for a in (areas or ("compute",)) for p in SCAN_PLANS.get(a, ()))
    return ((CSPM, None, ()),) if kind == "posture" else ()


def _pricing(m, plan, subplan, extensions):
    return block("resource", [PRICING, tf_name(plan)], [
        *(("#", note) for note in _confirm(m, plan)),
        ("tier", "Standard"), ("resource_type", plan), *((("subplan", subplan),) if subplan else ()),
        *(("extension", Block((("name", x),))) for x in extensions)])


def _scanner(m, s):
    areas = values(s, "ciamSecurityCoverage") or ("compute",)
    return (*((block("resource", [VA_SETTING, tf_name(rdn_value(s))], [
                *(("#", note) for note in _confirm(m, VA_SETTING)),
                ("vulnerability_assessment_provider", "MdeTvm")]),) if "compute" in areas else ()),
            *((f"# {rdn_value(s)}: Defender for Cloud has no vulnerability scanner for application code (not "
               "rendered)",) if "applications" in areas else ()))


def _posture(m, s):
    cn = rdn_value(s)
    frameworks = values(s, "ciamComplianceStandard")
    known = [k for k in frameworks if k in INITIATIVES and not (k in GOV_ONLY and not _gov(m))]
    unknown = [k for k in frameworks if k not in known]
    others = [b for b in values(s, "ciamSecurityBaseline") if b != BASELINE]
    return (*(x for k in known for x in (
                block("data", ["azurerm_policy_set_definition", tf_name(k)], [("display_name", INITIATIVES[k])]),
                block("resource", [ASSIGNMENT, tf_name(f"{cn}_{k}")], [
                    *(("#", note) for note in _confirm(m, k)),
                    ("name", f"ciam-{k}"), ("display_name", INITIATIVES[k]),
                    ("policy_definition_id", ref(f"data.azurerm_policy_set_definition.{tf_name(k)}.id")),
                    ("subscription_id", ref(f"{SUBSCRIPTION}.id"))]))),
            *((f"# {cn}: Defender for Cloud assigns the {BASELINE_NAME} itself (its default assignment)",)
              if BASELINE in values(s, "ciamSecurityBaseline") else ()),
            *((f"# {cn}: Azure has no built-in initiative here for {', '.join(unknown)} (not rendered)",)
              if unknown else ()),
            *((f"# {cn}: {', '.join(others)}: another cloud's baseline, not Azure's (not rendered)",)
              if others else ()))


def _export(m, s, kind):
    """The continuous export of a service's findings to the workspace its ciamFindingsRole names, or a note."""
    cn, dest = rdn_value(s), findings_destination(m, s)
    if dest is None or kind not in EXPORTS:
        return ()
    workspace = one(dest, "ciamProviderRef") if is_kind(m.d, dest, "ciamLogDestination") and \
        one(dest, "ciamDestinationKind") == "workspace" else None
    if not workspace:
        return (f"# NOTE: {cn}'s findings to {one(s, 'ciamFindingsRole')}: not rendered: continuous export is rendered "
                "to a Log Analytics workspace (ciamProviderRef); an Event Hub needs a connection string (a secret)",)
    return (block("resource", [AUTOMATION, tf_name(f"{cn}_export")], [
        ("name", f"{cn}-export"), ("location", LOC), ("resource_group_name", RG),
        ("scopes", [ref(f"{SUBSCRIPTION}.id")]),
        ("action", Block((("type", "loganalytics"), ("resource_id", workspace)))),
        *(("source", Block((("event_source", src),))) for src in EXPORTS[kind])]),)


def _service(m, s):
    cn, kind, keeper = rdn_value(s), one(s, "ciamSecurityKind"), one(s, "ciamManagedBy")
    if keeper:
        holder = get(m.d, keeper)
        return (f"# Security service {cn} ({kind}): kept by {rdn_value(holder) if holder is not None else keeper}, "
                "not rendered here",)
    body = (_scanner(m, s) if kind == "vulnerability-scanning" else _posture(m, s) if kind == "posture" else
            (f"# {cn}: Azure records resource changes itself (Resource Graph change history, about 14 days): nothing "
             "to enable; keeping them longer needs an export (not rendered)",) if kind == "config-recording" else
            (f"# {cn}: Defender for Cloud has no plan for identity: Microsoft Entra ID Protection watches sign-ins "
             "(not rendered)",) if "identity" in values(s, "ciamSecurityCoverage") else ())
    return (*body, *_export(m, s, kind),
            *((f"# {cn}: organization-wide: enable it on the management group with Azure Policy (not rendered here)",)
              if one(s, "ciamAuditScope") == "organization" else ()))


def render_security(m):
    """HCL (and comments) for environment m's security services: the subscription data source when anything refers
    to it, the merged Defender plans, then each service's own blocks and comments."""
    kept = _kept(m)
    out = (*(_pricing(m, *p) for p in _plans(kept)), *(x for s in security_services(m) for x in _service(m, s)))
    return ((block("data", ["azurerm_subscription", "current"], []),)
            if any(SUBSCRIPTION in x for x in out) else ()) + out


# ------------------------------------------------------------------ read back
def _ext(a):
    return {(e.get("name") or "") for e in a.get("extension") or ()}


def _subscription_ref(a, suffix):
    pid = a.get("id") or ""
    return pid.rsplit("/", 1)[0] + suffix if "/pricings/" in pid else None


def _routes(pairs):
    """{kind: the destination its findings' continuous export sends to}."""
    found = {}
    for a in of_types(pairs, AUTOMATION):
        dest = next((x.get("resource_id") for x in a.get("action") or () if x.get("resource_id")), None)
        sources = {x.get("event_source") for x in a.get("source") or ()}
        for kind, wanted in EXPORTS.items():
            if dest and sources & set(wanted):
                found.setdefault(kind, dest)
    return found


def security_resources(pairs):
    """Security services of (azurerm type, attributes) pairs."""
    pricings = [a for a in of_types(pairs, PRICING) if (a.get("tier") or "").lower() == "standard"]
    plans = {a.get("resource_type"): a for a in pricings}
    routes = _routes(pairs)
    every = {"ciamAuditScope": "account", "ciamAllRegions": "TRUE"}
    watched = {PLAN_AREAS[p] for p in plans if p in PLAN_AREAS} | (
        {"network"} if (plans.get("VirtualMachines") or {}).get("subplan") == "P2" else set())
    threat = tuple(resource("security", _subscription_ref(pricings[0], "/defender"), {
        "ciamSecurityKind": "threat-detection", "ciamSecurityCoverage": tuple(a for a in AREAS if a in watched),
        **every}, links={"ciamFindingsRole": routes.get("threat-detection")}, name="defender-for-cloud")
        for _ in (1,) if watched and _subscription_ref(pricings[0], "/defender"))
    va = next(iter(of_types(pairs, VA_SETTING)), None)
    registries = "ContainerRegistriesVulnerabilityAssessments" in _ext(plans.get("Containers") or {})
    scanned = (*(("compute",) if va is not None else ()), *(("containers",) if registries else ()))
    ref_of = (va or {}).get("id") or (_subscription_ref(pricings[0], "/vulnerability") if pricings else None)
    scan = tuple(resource("security", ref_of, {
        "ciamSecurityKind": "vulnerability-scanning", "ciamSecurityCoverage": scanned, **every},
        links={"ciamFindingsRole": routes.get("vulnerability-scanning")}, name="defender-vulnerability")
        for _ in (1,) if scanned and ref_of)
    names = {v: k for k, v in INITIATIVES.items()}
    assignments = [a for a in of_types(pairs, ASSIGNMENT) if a.get("display_name") in (*names, BASELINE_NAME)]
    cspm = plans.get(CSPM)
    posture_ref = (cspm or {}).get("id") or next((a.get("id") for a in assignments if a.get("id")), None)
    posture = tuple(resource("security", posture_ref, {
        "ciamSecurityKind": "posture",
        "ciamComplianceStandard": tuple(sorted({names[a["display_name"]] for a in assignments
                                                if a.get("display_name") in names})),
        "ciamSecurityBaseline": (BASELINE,) if cspm is not None or any(
            a.get("display_name") == BASELINE_NAME for a in assignments) else (), **every},
        links={"ciamFindingsRole": routes.get("posture")}, name="defender-cspm")
        for _ in (1,) if posture_ref)
    return (*threat, *scan, *posture)
