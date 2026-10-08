"""The Google Cloud services an environment uses, as Google's Assured Workloads "Supported products" page names them
(its Data Boundary for FedRAMP High / Moderate and IL2/IL4/IL5 control packages; footnote markers matched as
qualifiers), so the planner can check them against the in-scope list of the authorization the environment relies on
(opsdir.domains.estate.authorizations); and the Assured Workloads workload an environment that records the
assured-workload configuration has in place (Google's FedRAMP High use requires one), rendered in its landing zone with
the compliance regime of the level it requires (IL5, IL4, FEDRAMP_HIGH, FEDRAMP_MODERATE, IL2: the most demanding) and
named in an import notice when read back. Google has no mail service: a sending identity is named nowhere. Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.core.inventory import of_types
from opsdir.domains.estate.authorizations import boundary_findings, required_levels, services_used
from opsdir_format_terraform.hcl import block, tf_name

VPC, MONITORING, STORAGE = "Virtual Private Cloud (VPC)", "Cloud Monitoring", "Cloud Storage"
EDGE = {"waf": "Google Cloud Armor", "ddos": "Google Cloud Armor", "cdn": "Cloud CDN", "api-gateway": "API Gateway"}
NAMES = {
    "ciamDatabase": "Cloud SQL", "ciamObjectStore": STORAGE, "ciamVolume": "Persistent Disk",
    "ciamSnapshotPolicy": "Compute Engine", "ciamBackupVault": "Backup and DR Service",
    "ciamBackupPlan": "Backup and DR Service",
    "ciamKeyRef": "Cloud Key Management Service (Cloud KMS)", "ciamSecretRef": "Secret Manager",
    "ciamCertificateRef": "Certificate Manager",
    "ciamAlertChannel": MONITORING, "ciamAlarmBinding": MONITORING, "ciamCanaryBinding": MONITORING,
    "ciamLogDestination": lambda b: {"log-group": "Cloud Logging", "bucket": STORAGE}.get(one(b, "ciamDestinationKind")),
    "ciamAuditTrail": "Cloud Logging",
    "ciamSecurityService": lambda b: "Cloud Asset Inventory" if one(b, "ciamSecurityKind") == "config-recording"
    else "Security Command Center",
    "ciamComputeGroup": "Compute Engine", "ciamCluster": "Google Kubernetes Engine (GKE)",
    "ciamStreamBinding": "Pub/Sub", "ciamEdgeService": lambda b: EDGE.get(one(b, "ciamEdgeKind")),
    "ciamServiceName": "Cloud Load Balancing",
    "ciamDnsZoneBinding": "Cloud DNS", "ciamDnsRecord": "Cloud DNS", "ciamDnsForwarder": "Cloud DNS",
    "ciamIdentityBinding": "Identity and Access Management (IAM)", "ciamGuardrail": "Organization Policy Service",
    "ciamFirewallPolicy": "Cloud Next Generation Firewall Essentials",
    "ciamInterconnect": lambda b: "Cloud Interconnect" if "interconnect" in (one(b, "ciamInterconnectKind") or "").lower()
    else "Cloud VPN",
    **{oc: VPC for oc in ("ciamNetwork", "ciamSubnetBinding", "ciamRouteTable", "ciamNetworkAcl", "ciamFirewallRule",
                          "ciamFlowLog", "ciamPrivateEndpoint", "ciamEndpointService", "ciamEgress")},
}
WORKLOAD = "google_assured_workloads_workload"
# the compliance regime of each required level, the most demanding first
REGIMES = (("dod-il5", "IL5"), ("dod-il4", "IL4"), ("fedramp-high", "FEDRAMP_HIGH"),
           ("fedramp-moderate", "FEDRAMP_MODERATE"), ("dod-il2", "IL2"))


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
    regime = next((r for level, r in REGIMES if level in required_levels(m)), None)
    org = (one(m.cloud, "ciamOrganizationRef") or "").rsplit("/", 1)[-1]
    billing = one(m.cloud, "ciamBillingAccountRef")
    missing = [w for w, have in (("a required level (ciamRequiredAuthorization)", regime),
                                 ("its organization (ciamOrganizationRef)", org),
                                 ("its billing account (ciamBillingAccountRef)", billing)) if not have]
    if missing:
        return (f"# NOTE: {m.label}'s Assured Workloads workload: not rendered: the record names no {', '.join(missing)}",)
    return (block("resource", [WORKLOAD, tf_name(f"ciam_{rdn_value(m.env)}")], [
        ("compliance_regime", regime), ("display_name", f"ciam-{rdn_value(m.env)}"[:30]),
        ("location", one(m.cloud, "ciamRegion")), ("organization", org),
        ("billing_account", f"billingAccounts/{billing}")]),)


def workload_notices(pairs):
    """Import notices naming the Assured Workloads workloads Terraform state holds (the environment records the
    configuration as ciamConfigurationMet assured-workload)."""
    return tuple(f"Assured Workloads workload {a.get('display_name') or a.get('name')}: {a.get('compliance_regime')} "
                 "(record it on the environment: ciamConfigurationMet assured-workload)"
                 for a in of_types(pairs, WORKLOAD) if a.get("compliance_regime"))
