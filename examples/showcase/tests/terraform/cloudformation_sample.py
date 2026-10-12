"""The AWS renders the CloudFormation tests translate beyond the showcase, each environment rendered whole in a region
given (the clouds moved there by a change record, on an account): every kind of network plumbing (the plumbing sample,
its peer's network bound so the peering renders), the front before a cluster's gateway behind CloudFront with address
rules and Shield Advanced's automatic response (the gateway sample), a failover pair's health checks (the edge
fixtures' DNS estate), an Aurora cluster, a suppression, a quota request, Macie's scheduled job, and Fluent Bit's role
its pods assume through the cluster's OIDC provider (IRSA): every resource and data source type the AWS renderers
write that the showcase doesn't."""
from opsdir.connectors.registry import services
from opsdir.core.contract import LogSource
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import LdifRecord, parse
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir_adapter_aws.terraform import render_files
import edge_fixtures
import gateway_sample
import mini_estate
import plumbing_sample
from network_fixtures import ALPHA, entry, model
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
              f"ciamAffectedEnvironment: {ALPHA}\nciamExpiresAt: 20270331000000Z\n")
STORES = (entry(ALPHA, "backups", "ciamObjectStore", ciamBindingRole="ds-backups", ciamStorageRef="s3://ea-backups"),
          entry(ALPHA, "audit", "ciamObjectStore", ciamBindingRole="audit-archive", ciamStorageRef="s3://ea-audit",
                ciamEncryptedByRole="db-key"),
          entry(ALPHA, "security-alerts", "ciamAlertChannel", ciamBindingRole="security-alerts",
                ciamChannelKind="topic", ciamProviderRef=f"arn:aws:sns:us-east-1:{ACCOUNT}:security-alerts"))
RECORDS = (
    entry(ALPHA, "key-db", "ciamKeyRef", ciamBindingRole="db-key", ciamRefUri=f"aws-kms://{KEY_ARN}"),
    entry(ALPHA, "db-grants", "ciamDatabase", **DB),
    entry(ALPHA, "exc-EXC-7", "ciamSuppression", ciamBindingRole="suppression-EXC-7", ciamExceptionRef=EXC,
          ciamFindingRef=("aws:securityhub:IAM.6", "aws:guardduty:Recon:EC2/PortProbeUnprotectedPort")),
    entry(ALPHA, "cpus", "ciamQuotaNeed", ciamBindingRole="cpus", ciamQuotaKind="vcpus", ciamQuotaNeeded="16",
          ciamQuotaDecision="request"),
    *STORES,
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


def environments(region):
    """((name, environment model, services), ...): the sample's environments in region, each rendered with
    services."""
    found = services()
    plumbing = plumbing_sample._model(plumbing_sample.CLOUDS["aws"][1], peer="vpc-0b2c3d4e5f6a78901",
                                      changes=(*placed(region), *bound(region)))
    return (("plumbing", plumbing, found),
            ("gateway", _gateway(region), found),
            ("dns", _dns(region), found),
            ("services", model(alpha=RECORDS, tree=EXCEPTIONS, changes=(*placed(region), *bound(region)))[1], found),
            ("logs", model(alpha=CLUSTER, tree=LOGS, changes=(*placed(region), *bound(region)))[1],
             found._replace(logs=lambda m: (AM,))))


def renders(region):
    """((name, environment model, its AWS render {path: TfFile | text}), ...) of the sample in region."""
    return tuple((name, m, render_files(m, found)) for name, m, found in environments(region))
