"""The Google Cloud services an environment uses, as Google's Assured Workloads "Supported products" page names them
(its Data Boundary for FedRAMP High / Moderate and IL2/IL4/IL5 control packages; footnote markers matched as
qualifiers), so the planner can check them against the in-scope list of the authorization the environment relies on
(opsdir.domains.estate.authorizations); and the Assured Workloads workload an environment that records the
assured-workload configuration has in place (Google's FedRAMP High use requires one), rendered in its landing zone with
the compliance regime of the level it requires (IL5, IL4, FEDRAMP_HIGH, FEDRAMP_MODERATE, IL2: the most demanding) and
named in an import notice when read back. Google has no mail service: a sending identity is named nowhere. Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.core.inventory import of_types
from opsdir.domains.edge.records import is_hosted
from opsdir.domains.estate.authorizations import boundary_findings, required_levels, services_used
from opsdir.domains.estate.regulated import placement_findings, regulated_data
from opsdir_format_terraform.hcl import Block, comment, tf_block, tf_name
from .account import DATA_REGIMES, data_regime, level_regime, regime

VPC, MONITORING, STORAGE = "Virtual Private Cloud (VPC)", "Cloud Monitoring", "Cloud Storage"
EDGE = {"waf": "Google Cloud Armor", "ddos": "Google Cloud Armor", "cdn": "Cloud CDN", "api-gateway": "API Gateway"}
NAMES = {
    "ciamDatabase": "Cloud SQL", "ciamObjectStore": STORAGE, "ciamVolume": "Persistent Disk",
    "ciamSnapshotPolicy": "Compute Engine", "ciamBackupVault": "Backup and DR Service",
    "ciamBackupPlan": "Backup and DR Service",
    "ciamKeyRef": "Cloud Key Management Service (Cloud KMS)", "ciamSecretRef": "Secret Manager",
    "ciamCertificateRef": "Certificate Manager",
    "ciamAlertChannel": MONITORING, "ciamAlarmBinding": MONITORING, "ciamCanaryBinding": MONITORING,
    "ciamLogDestination": lambda b: {"log-group": "Cloud Logging", "bucket": STORAGE}.get(
        one(b, "ciamDestinationKind")),
    "ciamAuditTrail": "Cloud Logging",
    "ciamSecurityService": lambda b: "Cloud Asset Inventory" if one(b, "ciamSecurityKind") == "config-recording"
    else "Security Command Center", "ciamDataDiscovery": "Sensitive Data Protection",
    "ciamComputeGroup": "Compute Engine", "ciamCluster": "Google Kubernetes Engine (GKE)",
    "ciamStreamBinding": "Pub/Sub", "ciamEdgeService": lambda b: EDGE.get(one(b, "ciamEdgeKind")),
    "ciamServiceName": "Cloud Load Balancing",
    "ciamDnsZoneBinding": "Cloud DNS", "ciamDnsRecord": "Cloud DNS",
    "ciamDnsForwarder": lambda b: "Compute Engine" if is_hosted(b) else "Cloud DNS",
    "ciamIdentityBinding": "Identity and Access Management (IAM)", "ciamGuardrail": "Organization Policy Service",
    "ciamFirewallPolicy": "Cloud Next Generation Firewall Essentials",
    "ciamInterconnect": lambda b: "Cloud Interconnect"
    if "interconnect" in (one(b, "ciamInterconnectKind") or "").lower() else "Cloud VPN",
    **{oc: VPC for oc in ("ciamNetwork", "ciamSubnetBinding", "ciamRouteTable", "ciamNetworkAcl", "ciamFirewallRule",
                          "ciamFlowLog", "ciamPrivateEndpoint", "ciamEndpointService", "ciamEgress")},
}
WORKLOAD = "google_assured_workloads_workload"


def gcp_services(m):
    """The Google Cloud services environment m's servers and bindings use."""
    return services_used(m, NAMES, "Compute Engine")


def check_boundary(ctx):
    """The target's services outside the authorization it relies on."""
    return boundary_findings(ctx, gcp_services(ctx.dst))


def render_workload(m):
    """The Assured Workloads workload environment m records as in place (ciamConfigurationMet assured-workload), in its
    landing zone, or a note when its organization, billing account or required level isn't recorded."""
    if "assured-workload" not in (m.env.attrs.get("ciamConfigurationMet") or ()):
        return ()
    regime_ = regime(m)
    org = (one(m.cloud, "ciamOrganizationRef") or "").rsplit("/", 1)[-1]
    billing = one(m.cloud, "ciamBillingAccountRef")
    missing = [w for w, have in (("a required level or regulated data (ciamRequiredAuthorization, "
                                  "ciamRegulatedData)", regime_),
                                 ("its organization (ciamOrganizationRef)", org),
                                 ("its billing account (ciamBillingAccountRef)", billing)) if not have]
    if missing:
        return (comment(f"NOTE: {m.label}'s Assured Workloads workload: not rendered: "
                        f"the record names no {', '.join(missing)}"),)
    return (tf_block("resource", [WORKLOAD, tf_name(f"ciam_{rdn_value(m.env)}")], [
        ("compliance_regime", regime_), ("display_name", f"ciam-{rdn_value(m.env)}"[:30]),
        ("location", one(m.cloud, "ciamRegion")), ("organization", org),
        ("billing_account", f"billingAccounts/{billing}"),
        ("lifecycle", Block((("#", "its compliance regime can't change: replacing it would move every project out of "
                                   "the regime's controls"), ("prevent_destroy", True))))]),)


def workload_notices(pairs):
    """Import notices naming the Assured Workloads workloads Terraform state holds (the environment records the
    configuration as ciamConfigurationMet assured-workload)."""
    return tuple(f"Assured Workloads workload {a.get('display_name') or a.get('name')}: {a.get('compliance_regime')} "
                 "(record it on the environment: ciamConfigurationMet assured-workload)"
                 for a in of_types(pairs, WORKLOAD) if a.get("compliance_regime"))


# Where Google says it can hold regulated data (Assured Workloads' control packages and locations; research note 2805):
# in an Assured Workloads folder of its regime only, one regime per folder, ITAR, CJIS and IRS 1075 in US locations;
# ITAR and CJIS with customer-managed encryption keys; no package for EAR.
US_ONLY = ("itar", "cjis", "irs-1075")
CMEK = ("itar", "cjis")


def _us(region):
    return region == "us" or region.startswith("us-")


def regulated_verdicts(m):
    """((regime, 'blocker' or 'action', why), ...) of the regulated data environment m holds on Google Cloud."""
    held, region = regulated_data(m), one(m.cloud, "ciamRegion") or ""
    folder, has = data_regime(m), "assured-workload" in (m.env.attrs.get("ciamConfigurationMet") or ())
    regimes = dict(DATA_REGIMES)
    per = tuple(v for r in held for v in (
        ((r, "action", "Google has no Assured Workloads package for EAR: its ITAR folder (US locations, US-person "
                       "support) is the nearest; confirm the export classification with the export compliance "
                       "officer."),) if r == "ear" else (
            *(((r, "blocker", f"Google holds it in an Assured Workloads {regimes[r]} folder and {m.label} records "
                              "none (ciamConfigurationMet assured-workload)."),) if not has else ()),
            *(((r, "blocker", f"one Assured Workloads folder holds one regime and {m.label}'s takes {folder}: hold "
                              f"{r} data in an environment of its own."),) if regimes[r] != folder else ()),
            *(((r, "blocker", f"Google offers {regimes[r]} in US locations only and {region or 'its region'} isn't "
                              "one."),) if r in US_ONLY and not _us(region) else ()),
            *(((r, "action", "Google requires customer-managed encryption keys (Cloud KMS) for it."),)
              if r in CMEK else ()))))
    level = level_regime(m)
    return per + (((next(r for r in held if regimes.get(r) == folder), "action",
                    f"{m.label} requires {', '.join(required_levels(m))} and its Assured Workloads folder applies "
                    f"{folder}'s package, not {level}'s: confirm with the authorizing official."),)
                   if folder and level else ())


def check_regulated_placement(ctx):
    """The regulated data the target holds where Google says it may not, and what Google leaves to the customer."""
    return placement_findings(ctx, regulated_verdicts(ctx.dst))
