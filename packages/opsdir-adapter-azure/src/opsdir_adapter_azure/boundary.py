"""The Azure services an environment uses, as Microsoft's "Azure, Dynamics 365, Microsoft 365, and Power Platform
services compliance scope" page names them (its Azure and Azure Government tables, FedRAMP High and DoD IL2-IL6; a
name may carry a qualifier there: Azure Monitor (incl. ...), Storage: Blobs (incl. ...)), so the planner can check them
against the in-scope list of the authorization the environment relies on (opsdir.domains.estate.authorizations).
Neither table names Azure Communication Services or the DNS Private Resolver (2026-10): an environment sending mail
through Communication Services, or forwarding through the resolver, is told so; a forwarder on the environment's own
DNS servers (ciamResolverHost) runs on Virtual Machines. In Azure Government, Microsoft's GA roadmap (2026-10-07) lists
Azure DNS Private Resolver as GA and authorized at FedRAMP High, DoD IL4 and IL5 forecasted (record it in an Azure
Government authorization's in-scope list from there; for IL4/IL5, forwarders on virtual machines), and Communication
Services in Azure Government "has achieved FedRAMP High accreditation as part of the Microsoft 365 Government Community
Cloud (GCC) - High service offering" (a separate package, FR1824057433), with no SMTP endpoint there. Microsoft Entra
External ID has no row of its own: the Azure table's Microsoft Entra ID row carries a footnote applying Entra ID's
FedRAMP High and DoD IL2 authorizations to it (COVERED; the Azure Government table has neither, and external tenants
don't exist there). Budgets and quotas hold no customer data and are named nowhere. Pure."""
from opsdir.core.directory import one
from opsdir.domains.edge.records import is_hosted
from opsdir.domains.estate.authorizations import boundary_findings, services_used
from opsdir.domains.estate.regulated import placement_findings, regulated_data
from .account import government

VNET, MONITOR, KEY_VAULT, BLOBS = "Virtual Network", "Azure Monitor", "Key Vault", "Storage: Blobs"
VMS = "Virtual Machines"
EXTERNAL_ID = "Microsoft Entra External ID"
# a service Microsoft documents as covered by a listed one -> (that service, Microsoft's basis)
COVERED = {EXTERNAL_ID: ("Microsoft Entra ID", "the scope page's Microsoft Entra ID row applies its FedRAMP High and "
                                               "DoD IL2 authorizations to Microsoft Entra External ID (its footnote, "
                                               "read 2026-10-16)")}
ENGINES = {"postgresql": "Azure Database for PostgreSQL", "mysql": "Azure Database for MySQL",
           "sqlserver": "SQL Database"}
STREAMS = {"queue": "Service Bus", "topic": "Service Bus", "event-hub": "Event Hubs", "bus": "Event Grid"}
EDGE = {"waf": "Web Application Firewall", "cdn": "Front Door", "ddos": "DDoS Protection",
        "api-gateway": "API Management"}
NAMES = {
    "ciamDatabase": lambda b: ENGINES.get(one(b, "ciamDbEngine")),
    "ciamObjectStore": BLOBS, "ciamVolume": "Storage: Disks",
    "ciamSnapshotPolicy": "Backup", "ciamBackupVault": "Backup", "ciamBackupPlan": "Backup",
    "ciamKeyRef": KEY_VAULT, "ciamSecretRef": KEY_VAULT, "ciamCertificateRef": KEY_VAULT,
    "ciamAlertChannel": MONITOR, "ciamAlarmBinding": MONITOR, "ciamCanaryBinding": MONITOR, "ciamAuditTrail": MONITOR,
    "ciamLogDestination": lambda b: {"workspace": MONITOR, "bucket": BLOBS}.get(one(b, "ciamDestinationKind")),
    "ciamSecurityService": lambda b: "Resource Graph" if one(b, "ciamSecurityKind") == "config-recording"
    else "Microsoft Defender for Cloud", "ciamDataDiscovery": "Microsoft Defender for Cloud",
    "ciamComputeGroup": "Virtual Machine Scale Sets", "ciamCluster": "Azure Kubernetes Service (AKS)",
    "ciamSendingIdentity": "Azure Communication Services",
    "ciamStreamBinding": lambda b: STREAMS.get(one(b, "ciamStreamKind")),
    "ciamEdgeService": lambda b: EDGE.get(one(b, "ciamEdgeKind")),
    "ciamServiceName": "Load Balancer",
    "ciamDnsZoneBinding": "DNS", "ciamDnsRecord": "DNS",
    "ciamDnsForwarder": lambda b: VMS if is_hosted(b) else "DNS Private Resolver",
    "ciamIdentityBinding": "Microsoft Entra ID", "ciamGuardrail": "Azure Policy", "ciamFirewallPolicy": "Firewall",
    # External ID by the name Microsoft's External ID FAQ gives it; covered by Microsoft Entra ID (COVERED)
    "ciamManagedIdentity": lambda b: EXTERNAL_ID
    if one(b, "ciamManagedService") == "entra-external-id" else None,
    "ciamManagedDirectory": lambda b: "Microsoft Entra Domain Services"
    if one(b, "ciamManagedService") == "entra-domain-services" else None,
    "ciamPrivateEndpoint": "Private Link", "ciamEndpointService": "Private Link",
    "ciamInterconnect": lambda b: "ExpressRoute" if "express" in (one(b, "ciamInterconnectKind") or "").lower()
    else "VPN Gateway",
    **{oc: VNET for oc in ("ciamNetwork", "ciamSubnetBinding", "ciamRouteTable", "ciamNetworkAcl", "ciamFirewallRule",
                          "ciamFlowLog", "ciamEgress")},
}


def azure_services(m):
    """The Azure services environment m's servers and bindings use."""
    return services_used(m, NAMES, VMS)


def check_boundary(ctx):
    """The target's services outside the authorization it relies on."""
    return boundary_findings(ctx, azure_services(ctx.dst), COVERED)


# Where Microsoft says Azure can hold regulated data (its ITAR, EAR, CJIS, HIPAA and IRS 1075 offering pages; research
# note 2805): Azure and Azure Government alike, with Azure Government adding US storage and screened US persons for
# export-controlled data and CJIS personnel checks; in commercial Azure the customer's end-to-end encryption, with keys
# under its control, carries it (decision 2807: an action). IRS 1075 takes Microsoft's contractual amendment, HIPAA its
# Business Associate Agreement (the Product Terms) and in-scope services, in either cloud.
COMMERCIAL = ("commercial Azure holds it only behind the customer's end-to-end encryption with keys under its "
              "control (customer-managed keys in a Key Vault HSM); Microsoft names Azure Government as the better fit "
              "(US storage and screened US persons by contract).")


def regulated_verdicts(m):
    """((regime, 'action', why), ...) of the regulated data environment m holds on Azure."""
    return tuple(v for r in regulated_data(m) for v in (
        ((r, "action", COMMERCIAL),) if r in ("itar", "ear", "cjis") and not government(m) else
        ((r, "action", "Microsoft's IRS 1075 contractual amendment is in place, and FTI is encrypted with FIPS 140 "
                       "validated cryptography under customer-managed keys."),) if r == "irs-1075" else
        ((r, "action", "keep it on in-scope services under Microsoft's Business Associate Agreement (the Product "
                       "Terms)."),) if r == "hipaa" else ()))


def check_regulated_placement(ctx):
    """What Azure leaves to the customer for the regulated data the target holds."""
    return placement_findings(ctx, regulated_verdicts(ctx.dst))
