"""The AWS renders the CloudFormation tests translate beyond the showcase, each environment rendered whole in a region
given (the clouds moved there by a change record, on an account): every kind of network plumbing (the plumbing sample,
its peer's network bound so the peering renders), the front before a cluster's gateway behind CloudFront with address
rules and Shield Advanced's automatic response (the gateway sample), a failover pair's health checks (the edge
fixtures' DNS estate), an Aurora cluster, a Cognito user pool with its domain, clients, resource server and SAML
partner, a suppression, a quota request, Macie's scheduled job, a compute group with
its role's boot and data disks (a launch template and an autoscaling group), and Fluent Bit's role
its pods assume through the cluster's OIDC provider (IRSA), and an AWS Managed Microsoft AD directory as its
CloudFormation stack with a further region and a conditional forwarder (flow 76), and a log group forwarded on to a
Splunk index through Firehose (the siem sample, milestone 109), and an ALB checking client certificates under an
edge trust policy (its trust store, and the bundle object it loads, task 591): every resource and data source type the
AWS renderers write that the showcase doesn't."""
import pathlib

from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import LdifRecord, parse
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_adapter_aws.terraform import render_files
from opsdir_format_terraform.hcl import written
import edge_fixtures
import gateway_sample
import mini_estate
import plumbing_sample
from network_fixtures import ALPHA, entry, model
from pki_samples import CA_PEM, edge_trust_records
from support import REGISTRY, build_directory

# the account (its standard one, where CloudFront runs, holding the certificates), the GovCloud account
ACCOUNT, GOV_ACCOUNT = "111122223333", "444455556666"
KEY_ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/k-1"
OU = "dn: {}\nobjectClass: top\nobjectClass: organizationalUnit\nou: {}\n"


def placed(region):
    """The change records putting both mini-estate clouds in region, on the account (in GovCloud, the GovCloud
    account associated with it)."""
    gov = region.startswith("us-gov-")
    standard = (("replace", "ciamBillingAccountRef", (ACCOUNT,)),) if gov else ()
    return tuple(LdifRecord(f"cloud={c},ou=environments,dc=ciam-ops", "modify", {}, (
        ("add", "objectClass", ("ciamCloudAccount",)), ("replace", "ciamRegion", (region,)),
        ("replace", "ciamCloudProvider", ("aws",)), ("replace", "ciamAccountRef", (GOV_ACCOUNT if gov else ACCOUNT,)),
        # the organization's management account and its security services' delegated administrator (5.7b)
        ("replace", "ciamManagementRef", ("999988887777",)), ("replace", "ciamSecurityAdminRef", ("555566667777",)),
        *standard))
        for c in ("alpha", "beta"))


def _modify(dn, **attrs):
    return LdifRecord(dn, "modify", {}, tuple(("replace", k, (v,)) for k, v in attrs.items()))


def bound(region, servers=True):
    """The change records binding what the mini estate leaves unbound (which Terraform's apply would fail on as
    well): the disk-encryption key as a KMS key in region, and (servers) the network fixtures' servers' image and
    size."""
    partition = "aws-us-gov" if region.startswith("us-gov-") else "aws"
    account = GOV_ACCOUNT if region.startswith("us-gov-") else ACCOUNT
    key = _modify(f"cn=key-disk,ou=bindings,{ALPHA}",
                  ciamRefUri=f"aws-kms://arn:{partition}:kms:{region}:{account}:key/0a1b2c3d-1111-2222-3333-444455556666")
    return (key, *(_modify(f"cn={n},{ALPHA}", ciamImageRef="ami-0123456789abcdef0",
                           ciamInstanceSize="m6i.large") for n in (("ds-1", "ds-2", "web-1") if servers else ())))


def _gateway(region):
    """The gateway sample, its protection policy asking for CloudFront, address rules and Shield Advanced."""
    refs = gateway_sample.CLOUDS["aws"][1]
    records = tuple(r.replace("ciamWafCategory: core-rules\n", "ciamWafCategory: core-rules\nciamCdn: TRUE\n"
                              "ciamDdosTier: application-advanced\nciamIpRule: allow 198.51.100.0/24\n"
                              "ciamIpRule: deny 203.0.113.0/24\nciamIpRule: deny 2001:db8::/32\n")
                    for r in gateway_sample._records(refs))
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *records)))),
                        (*gateway_sample._changes(refs), *placed(region), *bound(region, False)))
    return env_model(d, "alpha/prod")


def _dns(region):
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(edge_fixtures.DNS_RECORDS))),
                        (*placed(region), *bound(region, False)))
    return env_model(d, "alpha/prod")


DB = dict(ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql", ciamDbEngineVersion="16.4",
          ciamDbService="aurora", ciamInstanceSize="db.r6g.large", ciamPort="5432",
          ciamDbHighAvailability="zone-redundant", ciamRetentionDays="14", ciamDbDeletionProtection="TRUE",
          ciamEncryptedByRole="db-key", ciamDbParameter="log_min_duration_statement=500", ciamSubnetRole="subnet-ds")
EXC = "cn=EXC-7,ou=exceptions,dc=ciam-ops"
EXCEPTIONS = (OU.format("ou=exceptions,dc=ciam-ops", "exceptions"),
              f"dn: {EXC}\nobjectClass: top\nobjectClass: ciamRiskException\ncn: EXC-7\n"
              "ciamExceptionKind: false-positive\nciamExceptionStatus: approved\n"
              f"ciamAffectedEnvironment: {ALPHA}\nciamExpiresAt: 20270331000000Z\n",
              # the region catalog a service in every region runs through (5.7b): a second region per partition
              OU.format("ou=regions,dc=ciam-ops", "regions"),
              "dn: cn=aws,ou=regions,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamRegionCatalog\ncn: aws\n"
              "ciamCloudProvider: aws\n",
              *(entry("cn=aws,ou=regions,dc=ciam-ops", code, "ciamCloudRegion", ciamRegionStatus="available")
                for code in ("us-east-1", "us-west-2", "us-gov-west-1", "us-gov-east-1")))
STORES = (entry(ALPHA, "backups", "ciamObjectStore", ciamBindingRole="ds-backups", ciamStorageRef="s3://ea-backups"),
          entry(ALPHA, "audit", "ciamObjectStore", ciamBindingRole="audit-archive", ciamStorageRef="s3://ea-audit",
                ciamEncryptedByRole="db-key"),
          entry(ALPHA, "security-alerts", "ciamAlertChannel", ciamBindingRole="security-alerts",
                ciamChannelKind="topic", ciamProviderRef=f"arn:aws:sns:us-east-1:{ACCOUNT}:security-alerts"),
          # a trail into a bucket this render creates (its delivery policy rendered) logging data writes (5.7b)
          entry(ALPHA, "trail", "ciamAuditTrail", ciamBindingRole="audit-trail", ciamAuditScope="account",
                ciamAuditEvents=("control-plane", "data-write"), ciamAllRegions="TRUE",
                ciamIntegrityValidation="TRUE", ciamLogDestinationRole="audit-archive"))
# a compute group of a role no server runs (its own security group), designed (no provider ref), with its role's
# disks: a boot volume and a data volume one snapshot policy copies
GROUP = (entry(ALPHA, "asg-app", "ciamComputeGroup", ciamBindingRole="compute-app", ciamTargetRole="app",
               ciamImageRef="ami-0123456789abcdef0", ciamInstanceSize="m6i.large", ciamMinSize="1", ciamMaxSize="3",
               ciamDesiredSize="2", ciamSubnetRole=("subnet-ds", "subnet-web"), ciamMetadataTokens="TRUE"),
         entry(ALPHA, "vol-app-boot", "ciamVolume", ciamBindingRole="volume-app-boot", ciamTargetRole="app",
               ciamVolumeKind="boot", ciamVolumeSizeGb="40", ciamVolumeClass="ssd",
               ciamSnapshotPolicyRole="app-snapshots"),
         entry(ALPHA, "vol-app-data", "ciamVolume", ciamBindingRole="volume-app-data", ciamTargetRole="app",
               ciamVolumeKind="data", ciamMountPath="/opt/app", ciamVolumeSizeGb="100", ciamVolumeClass="ssd",
               ciamSnapshotPolicyRole="app-snapshots"),
         entry(ALPHA, "app-snapshots", "ciamSnapshotPolicy", ciamBindingRole="app-snapshots", ciamRetentionDays="7",
               ciamSnapshotAt="02:00"))
# a Cognito user pool running the identity service (flow 63): its custom domain, a confidential OIDC client with a
# custom scope (its own stack: Cognito generates its secret), a public one (a native app, no secret: the user pool
# client itself), a partner SAML identity provider
INTEGRATIONS = "ou=integrations,dc=ciam-ops"
IDENTITY = (OU.format(INTEGRATIONS, "integrations"),
            "dn: cn=sso-tls,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCertificate\ncn: sso-tls\n"
            "ciamCertPurpose: tls-server\n",
            entry(INTEGRATIONS, "portal", "ciamIntegration", ciamProtocolType="oidc-client", ciamClientId="portal",
                  ciamGrantType=("authorization_code", "refresh_token"), ciamTokenAuthMethod="client_secret_basic",
                  ciamRedirectUri="https://portal.example.test/cb", ciamScope=("openid", "orders.read")),
            entry(INTEGRATIONS, "mobile", "ciamIntegration", ciamProtocolType="oidc-client", ciamClientId="mobile",
                  ciamGrantType=("authorization_code", "refresh_token"), ciamTokenAuthMethod="none",
                  ciamRedirectUri="com.example.mobile:/cb", ciamScope=("openid", "profile")),
            entry(INTEGRATIONS, "skyline", "ciamIntegration", ciamProtocolType="saml2-idp",
                  ciamEntityId="https://idp.skyline.test", ciamSsoUrl="https://idp.skyline.test/sso"))
POOL = (entry(ALPHA, "cert-sso", "ciamCertificateRef", ciamBindingRole="sso-cert",
              ciamRefUri=f"aws-acm://arn:aws:acm:us-east-1:{ACCOUNT}:certificate/c-1",
              ciamHoldsCertificate="cn=sso-tls,dc=ciam-ops"),
        entry(ALPHA, "sso-pool", "ciamManagedIdentity", ciamBindingRole="sso-pool",
              ciamManagedService="cognito-user-pool", ciamRealizes="sso", ciamFqdn="sso.example.test",
              ciamTlsCertificate="cn=sso-tls,dc=ciam-ops"))
# an AWS Managed Microsoft AD directory holding the user directory (flow 76): its stack (the Admin password a Secrets
# Manager dynamic reference), a further region on variables, a forwarder for its trust's domain
AD_SECRET = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:ciam/prod/ad-admin-AbCdEf"
DIRECTORY = (entry(ALPHA, "ad-admin", "ciamSecretRef", ciamBindingRole="ad-admin", ciamRefUri=f"aws-sm://{AD_SECRET}"),
             entry(ALPHA, "user-dir", "ciamManagedDirectory", ciamBindingRole="user-dir",
                   ciamManagedService="aws-managed-ad", ciamRealizes="ds", ciamFqdn="corp.example.test",
                   ciamNetbiosName="CORP", ciamDirectoryEdition="enterprise",
                   ciamSubnetRole=("subnet-ds", "subnet-web"), ciamCredentialRole="ad-admin",
                   ciamReplicaRegion="us-west-2"),
             entry(f"cn=user-dir,ou=bindings,{ALPHA}", "hq", "ciamDirectoryTrust", ciamFqdn="hq.example.test",
                   ciamTrustType="forest", ciamTrustDirection="two-way", ciamForwardTarget=("10.9.0.10", "10.9.0.11")))
RECORDS = (
    *GROUP, *POOL, *DIRECTORY,
    entry(ALPHA, "key-db", "ciamKeyRef", ciamBindingRole="db-key", ciamRefUri=f"aws-kms://{KEY_ARN}"),
    entry(ALPHA, "db-grants", "ciamDatabase", **DB),
    entry(ALPHA, "exc-EXC-7", "ciamSuppression", ciamBindingRole="suppression-EXC-7", ciamExceptionRef=EXC,
          ciamFindingRef=("aws:securityhub:IAM.6", "aws:guardduty:Recon:EC2/PortProbeUnprotectedPort")),
    entry(ALPHA, "cpus", "ciamQuotaNeed", ciamBindingRole="cpus", ciamQuotaKind="vcpus", ciamQuotaNeeded="16",
          ciamQuotaDecision="request"),
    *STORES,
    entry(ALPHA, "security-hub", "ciamSecurityService", ciamBindingRole="security-hub", ciamSecurityKind="posture",
          ciamAllRegions="TRUE", ciamSecurityBaseline="aws-foundational"),
    # organization-wide services (5.7b): enabled by the delegated administrator, the landing zone's root
    *(entry(ALPHA, cn, "ciamSecurityService", ciamBindingRole=cn, ciamSecurityKind=kind, ciamAuditScope="organization",
            **more)
      for cn, kind, more in (("org-guardduty", "threat-detection",
                              {"ciamAllRegions": "TRUE", "ciamSecurityCoverage": ("control-plane", "compute")}),
                             ("org-inspector", "vulnerability-scanning", {"ciamSecurityCoverage": ("containers",)}),
                             ("org-hub", "posture", {"ciamComplianceStandard": "nist-800-53-r5"}),
                             ("org-config", "config-recording", {"ciamFindingsRole": "ds-backups"}))),
    entry(ALPHA, "macie-weekly", "ciamDataDiscovery", ciamBindingRole="data-discovery", ciamScansRole="ds-backups",
          ciamCustomIdentifier=("cui-marking: CUI//[A-Z-]+",), ciamRescanDays="7",
          ciamFindingsRole="security-alerts", ciamResultsRole="audit-archive"))

# Fluent Bit shipping am's logs from an EKS cluster (its role assumed through the cluster's OIDC provider)
AM = LogSource("am", "kubernetes", None, "mixed", "debug", (("eventName", "", "audit"),))
LOGS = (OU.format(WORKLOADS, "workloads"),
        f"dn: {workload_dn('am')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: am\nciamWorkloadKind: deployment\n"
        "ciamTargetRole: am\nciamNamespace: ciam\nciamClusterRole: k8s\nciamWorkloadRole: am-workload\n",
        OU.format(LOG_ROUTES, "log-routes"),
        f"dn: cn=audit-logs,{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\n"
        "cn: audit-logs\nciamLogKind: audit\nciamPublishedBy: am\nciamLogDestinationRole: audit-logs\n")
CLUSTER = (entry(ALPHA, "am", "ciamWorkloadBinding", ciamBindingRole="am-workload",
                 ciamContainerImage="openam=registry.example.test/am:7.5.1"),
           entry(ALPHA, "eks", "ciamCluster", ciamBindingRole="k8s",
                 ciamProviderRef=f"arn:aws:eks:us-east-1:{ACCOUNT}:cluster/ciam-eks"),
           entry(ALPHA, "audit", "ciamLogDestination", ciamBindingRole="audit-logs", ciamDestinationKind="log-group",
                 ciamProviderRef=f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/ciam/audit"))

# a log group forwarded on to a Splunk index (milestone 109, siem_forwarding.py): subscribed to a Firehose stream that
# reads the HEC token from Secrets Manager and keeps what it can't deliver in S3
SIEM = (entry(ALPHA, "security-logs", "ciamLogDestination", ciamBindingRole="security-logs",
              ciamDestinationKind="log-group", ciamRetentionDays="30", ciamForwardsToRole="siem",
              ciamProviderRef=f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/ciam/security",
              ciamStorageRef="s3://ciam-siem-failed/firehose"),
        entry(ALPHA, "siem", "ciamLogDestination", ciamBindingRole="siem", ciamDestinationKind="siem-index",
              ciamProviderRef="ciam_security", ciamRetentionDays="90", ciamCredentialRole="siem-intake",
              ciamIntakeUrl="https://hec.example.test"),
        entry(ALPHA, "siem-intake", "ciamSecretRef", ciamBindingRole="siem-intake",
              ciamRefUri=f"aws-sm://arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:ciam/hec-AbCdEf"))


# client certificates checked at the ALB under an edge trust policy (task 591): its bundle's bucket, and the edge
# policy terminating TLS at the load balancer
TRUST_BUCKET = entry(ALPHA, "trust-bucket", "ciamObjectStore", ciamBindingRole="trust-store",
                     ciamStorageRef="s3://ciam-trust/pki")
TERMINATE = (OU.format("ou=edge-policies,dc=ciam-ops", "edge-policies"),
             entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                   ciamTlsMode="terminate"))


def environments(region):
    """((name, environment model, services), ...): the sample's environments in region, each rendered with
    services."""
    found = services()
    plumbing = plumbing_sample._model(plumbing_sample.CLOUDS["aws"][1], peer="vpc-0b2c3d4e5f6a78901",
                                      changes=(*placed(region), *bound(region)))
    return (("plumbing", plumbing, found),
            ("gateway", _gateway(region), found),
            ("dns", _dns(region), found),
            ("services", model(alpha=RECORDS, tree=(*EXCEPTIONS, *IDENTITY),
                               changes=(*placed(region), *bound(region)))[1], found),
            ("logs", model(alpha=CLUSTER, tree=LOGS, changes=(*placed(region), *bound(region)))[1],
             found._replace(logs=lambda m: (AM,))),
            # the index kept by the Splunk adapter, as a stack declaring it would
            ("siem", model(alpha=SIEM, changes=(*placed(region), *bound(region)))[1],
             found._replace(siem_keeper=lambda m, b: "splunk")),
            ("mtls", model(alpha=(TRUST_BUCKET,), tree=(*edge_trust_records(CA_PEM), *TERMINATE),
                           changes=(*placed(region), *bound(region)))[1], found))


def renders(region):
    """((name, environment model, its AWS render {path: TfFile | text}), ...) of the sample in region."""
    return tuple((name, m, render_files(m, found)) for name, m, found in environments(region))


def write_samples(root, region="us-east-1", names=("services", "siem")):
    """Write the Terraform roots of the sample's environments named (in region) under root/<name>/; the root."""
    for name, _, files in renders(region):
        if name in names:
            for path, text in written({p: f for p, f in files.items() if p.startswith("terraform/")}).items():
                out = pathlib.Path(root) / name / path
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(text)
    return root
