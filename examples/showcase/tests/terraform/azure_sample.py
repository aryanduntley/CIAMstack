"""The Azure renders the ARM tests translate beyond the showcase, each environment rendered whole in a region given (the
clouds moved there by a change record, on a subscription; Azure Government's when the region is a US Gov one): every
kind of network plumbing (the plumbing sample, its peer's network bound so the peering renders), the front before a
cluster's gateway behind Front Door with address rules (the gateway sample), DNS records of every type in a public and
a private zone with weighted and failover names (Traffic Manager) and forwarders (the edge fixtures' DNS estate), a
MySQL server, a blob container copied to another account, a suppression, an availability test, a NAT gateway
for egress, a private endpoint to blob storage and a compute group with its role's disks (a scale set and its autoscale
setting), an Entra Domain Services managed domain with a replica set (flow 76): every resource and
data source type the Azure renderers write that the showcase doesn't."""
import pathlib

from opsdir.connectors.registry import services
from opsdir.core.contract import Endpoint
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import LdifRecord, parse
from opsdir.domains.observability.naming import CANARIES
from opsdir_adapter_azure.terraform import render_files
from opsdir_format_terraform.hcl import written
import edge_fixtures
import gateway_sample
import mini_estate
import plumbing_sample
from network_fixtures import ALPHA, entry, model
from support import REGISTRY, build_directory

SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
GROUP = f"/subscriptions/{SUBSCRIPTION}/resourceGroups"
DES = f"{GROUP}/rg-ciam-prod/providers/Microsoft.Compute/diskEncryptionSets/des-ciam-prod"
IMAGE = f"{GROUP}/rg-ciam-images/providers/Microsoft.Compute/images/pingds-7.5.1-rhel9"
PEER = f"{GROUP}/rg-peer/providers/Microsoft.Network/virtualNetworks/vnet-peer"
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"
# a region's paired region (geo-redundant backups go there)
PAIRS = {"eastus2": "centralus", "usgovvirginia": "usgovtexas"}


def government(region):
    return region.startswith("usgov")


def placed(region):
    """The change records putting both mini-estate clouds in region, on the subscription (Azure Government's cloud
    when the region is a US Gov one)."""
    return tuple(LdifRecord(f"cloud={c},ou=environments,dc=ciam-ops", "modify", {}, (
        ("add", "objectClass", ("ciamCloudAccount",)), ("replace", "ciamRegion", (region,)),
        ("replace", "ciamCloudProvider", ("azure",)), ("replace", "ciamAccountRef", (SUBSCRIPTION,)),
        ("replace", "ciamCloudEnvironment", ("usgovernment" if government(region) else "public",)),
        ("replace", "ciamManagementRef", ("corp-security",))))          # the management group (5.7b)
        for c in ("alpha", "beta"))


def _modify(dn, **attrs):
    return LdifRecord(dn, "modify", {}, tuple(("replace", k, (v,)) for k, v in attrs.items()))


def bound(servers=True):
    """The change records binding what the mini estate leaves unbound (which Terraform's apply would fail on as
    well): the network's resource group and virtual network, the disk-encryption key as a Key Vault key with its disk
    encryption set, and (servers) the network fixtures' subnets (in the virtual network) and servers' image and
    size."""
    net = _modify(f"cn=net,ou=bindings,{ALPHA}", ciamResourceGroup="rg-ciam-prod", ciamProviderRef="vnet-ciam-prod")
    key = _modify(f"cn=key-disk,ou=bindings,{ALPHA}", ciamRefUri="azkv-key://kv-ciam/keys/disk-cmk",
                  ciamProviderRef=DES)
    subnets = tuple(_modify(f"cn=subnet-{s},ou=bindings,{ALPHA}", ciamProviderRef=f"vnet-ciam-prod/snet-{s}")
                    for s in (("ds", "web") if servers else ()))
    return (net, key, *subnets, *(_modify(f"cn={n},{ALPHA}", ciamImageRef=IMAGE, ciamInstanceSize="Standard_D4s_v5")
                                  for n in (("ds-1", "ds-2", "web-1") if servers else ())))


def _gateway(region):
    """The gateway sample, its protection policy asking for a CDN (Front Door) with address rules."""
    refs = gateway_sample.CLOUDS["azure"][1]
    records = tuple(r.replace("ciamWafCategory: core-rules\n", "ciamWafCategory: core-rules\nciamCdn: TRUE\n"
                              "ciamIpRule: allow 198.51.100.0/24\nciamIpRule: deny 203.0.113.0/24\n")
                    for r in gateway_sample._records(refs))
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *records)))),
                        (*gateway_sample._changes(refs), *placed(region), *bound(False)))
    return env_model(d, "alpha/prod")


def _record(cn, name, rtype, *values):
    return entry(ALPHA, cn, "ciamDnsRecord", ciamBindingRole=cn, ciamRecordName=name, ciamRecordType=rtype,
                 ciamRecordValue=values)


# the record types the edge fixtures don't have, public (example.test) and private (corp.example.test); a TXT value
# longer than one 255-character string
RECORDS = (_record("a-host", "host.example.test", "A", "198.51.100.30"),
           _record("aaaa-host", "host.example.test", "AAAA", "2001:db8::30"),
           _record("ns-sub", "sub.example.test", "NS", "ns1.example.net.", "ns2.example.net."),
           _record("srv-sip", "_sip._tcp.example.test", "SRV", "10 60 5060 sip.example.test"),
           _record("txt-long", "_long.example.test", "TXT", "v=" + "x" * 300),
           _record("a-db", "db.corp.example.test", "A", "10.1.1.40"),
           _record("aaaa-db", "db.corp.example.test", "AAAA", "fd00::40"),
           _record("cname-db", "sql.corp.example.test", "CNAME", "db.corp.example.test"),
           _record("mx-corp", "corp.example.test", "MX", "10 mx.corp.example.test"),
           _record("txt-corp", "_check.corp.example.test", "TXT", "ok"))


def _dns(region):
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *edge_fixtures.DNS_RECORDS, *RECORDS)))),
                        (*placed(region), *bound(False)))
    return env_model(d, "alpha/prod")


KEY_DB = entry(ALPHA, "key-db", "ciamKeyRef", ciamBindingRole="db-key", ciamRefUri="azkv-key://kv-ciam/keys/db-key")
SECRET_DB = entry(ALPHA, "sec-db", "ciamSecretRef", ciamBindingRole="db-admin", ciamRefUri="azkv://kv-ciam/db-admin")


def _db(region):
    return entry(ALPHA, "db-sess", "ciamDatabase", ciamBindingRole="sessions-db", ciamDbEngine="mysql",
                 ciamDbEngineVersion="8.0", ciamInstanceSize="GP_Standard_D2ds_v4", ciamDbStorageGb="64",
                 ciamZone="1", ciamDbHighAvailability="zone-redundant", ciamRetentionDays="14",
                 ciamCopyRegion=PAIRS[region], ciamDbTlsRequired="FALSE", ciamEncryptedByRole="db-key",
                 ciamDbCredentialRole="db-admin", ciamDbParameter="slow_query_log=ON", ciamSubnetRole="subnet-ds")


STORE = entry(ALPHA, "backups", "ciamObjectStore", ciamBindingRole="ds-backups",
              ciamStorageRef="azblob://stciambackups/ds-backups", ciamStorageVersioning="TRUE",
              ciamEncryptedByRole="disk-encryption", ciamStorageReplicaRef="azblob://stciambackupsdr/ds-backups")
EXC = "cn=EXC-7,ou=exceptions,dc=ciam-ops"
EXCEPTIONS = (OU.format("ou=exceptions,dc=ciam-ops", "exceptions"),
              f"dn: {EXC}\nobjectClass: top\nobjectClass: ciamRiskException\ncn: EXC-7\n"
              "ciamExceptionKind: risk-acceptance\nciamExceptionStatus: approved\n"
              f"ciamAffectedEnvironment: {ALPHA}\nciamExpiresAt: 20270331000000Z\n")
SUPPRESSION = entry(ALPHA, "exc-EXC-7", "ciamSuppression", ciamBindingRole="suppression-EXC-7",
                    ciamExceptionRef=EXC, ciamFindingRef=("azure:policy:nist-800-171-r2/ref-a",))
# an availability test of an internet-facing sign-in name (its health endpoint, from the products' endpoints)
CANARY = (OU.format(CANARIES, "canaries"),
          f"dn: cn=sso-alive,{CANARIES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamCanary\n"
          "cn: sso-alive\nciamCheckedService: sso\nciamCanaryFlow: health\nciamInterval: 7m\n")
SSO = entry(ALPHA, "svc-sso", "ciamServiceName", ciamBindingRole="sso", ciamFqdn="sso.example.test",
            ciamTargetRole="web", ciamFrontendIp="203.0.113.10")
ENDPOINTS = (Endpoint("health", "/pf/heartbeat.ping", "web"),)
# a private endpoint to the blob store (its storage account read as data)
BLOB_ENDPOINT = entry(ALPHA, "pe-blob", "ciamPrivateEndpoint", ciamBindingRole="pe-blob",
                      ciamPrivateService="object-storage", ciamPrivateEndpointKind="interface",
                      ciamSubnetRole="subnet-ds", ciamReachesRole="ds-backups")
# egress through a NAT gateway the stack creates (its subnet associations rendered: the plumbing sample's is adopted)
EGRESS = entry(ALPHA, "egress", "ciamEgress", ciamBindingRole="pf-egress", ciamCidr="203.0.113.200/32",
               ciamNatAllocation="static")


# Defender's findings continuously exported to an Event Hub (its connection string a Key Vault reference) and its high
# incidents by email to the security contact (5.7b)
SECURITY = (entry(ALPHA, "sec-hub-send", "ciamSecretRef", ciamBindingRole="sec-hub-send",
                  ciamRefUri="azkv://kv-ciam-prod/sec-hub-send"),
            entry(ALPHA, "sec-hub", "ciamStreamBinding", ciamBindingRole="sec-hub", ciamStreamKind="event-hub",
                  ciamSendSecretRole="sec-hub-send",
                  ciamProviderRef="/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/"
                                  "providers/Microsoft.EventHub/namespaces/ehn-ciam/eventhubs/security"),
            entry(ALPHA, "soc-mail", "ciamAlertChannel", ciamBindingRole="soc-mail", ciamChannelKind="email",
                  ciamProviderRef="mailto:soc@example.test"),
            entry(ALPHA, "defender", "ciamSecurityService", ciamBindingRole="defender",
                  ciamSecurityKind="threat-detection", ciamSecurityCoverage=("control-plane", "compute"),
                  ciamFindingsRole="sec-hub", ciamIncidentRole="soc-mail", ciamIncidentSeverity="high"),
            # resource changes kept 2557 days, copied hourly from Resource Graph into the workspace (5.7b)
            entry(ALPHA, "security-logs", "ciamLogDestination", ciamBindingRole="security-logs",
                  ciamDestinationKind="workspace",
                  ciamProviderRef="/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam/"
                                  "providers/Microsoft.OperationalInsights/workspaces/law-ciam-security"),
            entry(ALPHA, "changes", "ciamSecurityService", ciamBindingRole="changes",
                  ciamSecurityKind="config-recording", ciamFindingsRole="security-logs", ciamRetentionDays="2557"),
            # enabled for every subscription on the management group, with its frameworks (5.7b)
            entry(ALPHA, "org-defender", "ciamSecurityService", ciamBindingRole="org-defender",
                  ciamSecurityKind="posture", ciamAuditScope="organization",
                  ciamComplianceStandard="nist-800-171-r2"))


# a compute group of a role no server runs, designed, with its role's boot and provisioned data disk
GROUP = (entry(ALPHA, "vmss-app", "ciamComputeGroup", ciamBindingRole="compute-app", ciamTargetRole="app",
               ciamImageRef=IMAGE, ciamInstanceSize="Standard_D2s_v5", ciamMinSize="1", ciamMaxSize="3",
               ciamDesiredSize="2", ciamSpansZone=("1", "2"), ciamSubnetRole="subnet-web"),
         entry(ALPHA, "vol-app-boot", "ciamVolume", ciamBindingRole="volume-app-boot", ciamTargetRole="app",
               ciamVolumeKind="boot", ciamVolumeSizeGb="64", ciamVolumeClass="ssd"),
         entry(ALPHA, "vol-app-data", "ciamVolume", ciamBindingRole="volume-app-data", ciamTargetRole="app",
               ciamVolumeKind="data", ciamVolumeSizeGb="128", ciamVolumeClass="provisioned", ciamIops="5000",
               ciamThroughputMb="200"))


# an Entra External ID target (task 547): its tenant through azapi, recorded, and a SAML application registered in it
# through the tenant-aliased azuread provider (public regions only: Azure Government has no external tenants)
INTEGRATIONS = "ou=integrations,dc=ciam-ops"
EXTERNAL_ID = (entry(ALPHA, "sso-tenant", "ciamManagedIdentity", ciamBindingRole="sso-tenant",
                     ciamManagedService="entra-external-id", ciamRealizes="sso", ciamDataGeography="united-states",
                     ciamProviderRef="8d3e1f02-6a5b-4c7d-9e8f-0a1b2c3d4e5f"),)
APPS = (OU.format(INTEGRATIONS, "integrations"),
        entry(INTEGRATIONS, "crm", "ciamIntegration", ciamProtocolType="saml2-sp",
              ciamEntityId="https://crm.example.test", ciamAcsUrl="https://crm.example.test/acs"))

# an Entra Domain Services managed domain holding the user directory (flow 76), a replica set in another region and a
# forest trust (an action: its password is shared)
DIRECTORY = (entry(ALPHA, "user-dir", "ciamManagedDirectory", ciamBindingRole="user-dir",
                   ciamManagedService="entra-domain-services", ciamRealizes="ds", ciamFqdn="corp.example.test",
                   ciamDirectoryEdition="enterprise", ciamSubnetRole="subnet-ds", ciamReplicaRegion="westus3",
                   ciamLdapsMode="private"),
             entry(f"cn=user-dir,ou=bindings,{ALPHA}", "hq", "ciamDirectoryTrust", ciamFqdn="hq.example.test",
                   ciamTrustType="forest", ciamTrustDirection="one-way-outgoing"))


def environments(region):
    """((name, environment model, services), ...): the sample's environments in region, each rendered with
    services."""
    found = services()
    plumbing = plumbing_sample._model(plumbing_sample.CLOUDS["azure"][1], peer=PEER,
                                      changes=(*placed(region), *bound()))
    return (("plumbing", plumbing, found),
            ("gateway", _gateway(region), found),
            ("dns", _dns(region), found),
            ("services", model(alpha=(KEY_DB, SECRET_DB, _db(region), STORE, SUPPRESSION, SSO, EGRESS, BLOB_ENDPOINT,
                                      *GROUP, *SECURITY, *EXTERNAL_ID, *DIRECTORY),
                               tree=(*EXCEPTIONS, *CANARY, *APPS), changes=(*placed(region), *bound()))[1],
             found._replace(endpoints=(*found.endpoints, *ENDPOINTS))))


def renders(region):
    """((name, environment model, its Azure render {path: TfFile | text}), ...) of the sample in region."""
    return tuple((name, m, render_files(m, found)) for name, m, found in environments(region))


def write_samples(root, region="eastus2", names=("services",)):
    """Write the Terraform roots of the sample's environments named (in region) under root/<name>/; the root."""
    for name, _, files in renders(region):
        if name in names:
            for path, text in written({p: f for p, f in files.items() if p.startswith("terraform/")}).items():
                out = pathlib.Path(root) / name / path
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(text)
    return root
