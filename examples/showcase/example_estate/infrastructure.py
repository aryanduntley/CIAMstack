"""Infrastructure fixture data: the current AWS environment (40-env-source), the target environment
being built (45-env-target, with planted gaps), and external allowlists that hold our addresses
(80-external-allowlists)."""
from .common import AWS, AZ, CON, ENVS, XA, cert, chg, owner, spec, t
from .custom import RESIDENCY

SECRET_ROLES = ("ds-deployment-id", "ds-deployment-password", "ds-root-password", "ds-tls-keystore",
                "sso-tls-keystore", "pf-signing-key", "pf-admin-password")
DS_V, PF_V = "PingDS 7.5.1", "PingFederate 12.1.4"
IMG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-images/providers/Microsoft.Compute/images/"

SOURCE = {
    "stack": (("provider", "aws"), ("directory", "pingds"), ("federation", "pingfederate")),
    "net": ("vpc", "vpc-0a1b2c3d4e5f67890", "10.20.0.0/16"),
    "subnets": [("subnet-ds-a", "subnet-ds", "subnet-0a11b22c33d44e55a", "10.20.1.0/24", "us-east-1a"),
                ("subnet-ds-b", "subnet-ds", "subnet-0a11b22c33d44e55b", "10.20.2.0/24", "us-east-1b"),
                ("subnet-ds-c", "subnet-ds", "subnet-0a11b22c33d44e55c", "10.20.3.0/24", "us-east-1c"),
                ("subnet-pf-a", "subnet-pf", "subnet-0f66e77d88c99b00a", "10.20.4.0/24", "us-east-1a"),
                ("subnet-pf-b", "subnet-pf", "subnet-0f66e77d88c99b00b", "10.20.5.0/24", "us-east-1b")],
    "services": [("svc-ldaps", "ds-ldaps-service", "ldap.id.example-aero.test", "id.example-aero.test",
                  "Z0EXAMPLE1PRIVATE", "ds", [1636], "10.20.1.100", None, "ds-ldaps-2026"),
                 ("svc-sso", "pf-sso-service", "sso.example-aero.test", "example-aero.test",
                  "Z0EXAMPLE2PUBLIC", "pf-engine", [443], "198.51.100.20", "eipalloc-0a1b2c3d4e5f60001", "sso-tls-2026")],
    "fw": [("fw-pf-ds-svc", "fw-consumer-pf-ds-svc", ["10.20.4.0/24", "10.20.5.0/24"], [1636], "ds", "pf-ds-svc", "CHG-0877"),
           ("fw-customer-portal", "fw-consumer-customer-portal-svc", ["10.30.8.0/24"], [1636], "ds", "customer-portal-svc", None),
           ("fw-supplier-portal", "fw-consumer-supplier-portal-svc", ["10.31.2.0/24"], [1636], "ds", "supplier-portal-svc", None),
           ("fw-mro-batch", "fw-consumer-mro-batch-export", ["10.40.12.0/24"], [1636], "ds", "mro-batch-export", None),
           ("fw-legacy-rptuser", "fw-consumer-legacy-rptuser", ["10.40.7.22/32"], [1636], "ds", "legacy-rptuser", None),
           ("fw-idm-sync", "fw-consumer-idm-sync", ["10.20.6.0/24"], [1636], "ds", "idm-sync", None),
           ("fw-replication", "fw-replication", ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24", "10.60.1.0/24"],
            [8989], "ds", None, "CHG-2040"),
           ("fw-admin", "fw-admin", ["10.20.9.0/28"], [4444], "ds", None, None),
           ("fw-sso-public", "fw-sso-public", ["0.0.0.0/0"], [443], "pf-engine", None, None)],
    "egress": ("nat-0123456789abcdef0", "203.0.113.10/32"),
    "secret": lambda role: f"aws-sm://arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/{role}",
    "key": ("aws-kms://arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", None),
    "backup": "s3://example-aero-ciam-prod-ds-backups",
    "servers": [("ds-1", "ds", "ds-1.aws.internal.example-aero.test", "10.20.1.11", "us-east-1a", "m6i.xlarge", "ami-0abcdef1234567890", "subnet-ds-a", DS_V),
                ("ds-2", "ds", "ds-2.aws.internal.example-aero.test", "10.20.2.11", "us-east-1b", "m6i.xlarge", "ami-0abcdef1234567890", "subnet-ds-b", DS_V),
                ("ds-3", "ds", "ds-3.aws.internal.example-aero.test", "10.20.3.11", "us-east-1c", "m6i.xlarge", "ami-0abcdef1234567890", "subnet-ds-c", DS_V),
                ("pf-engine-1", "pf-engine", "pf-engine-1.aws.internal.example-aero.test", "10.20.4.21", "us-east-1a", "m6i.large", "ami-0fedcba9876543210", "subnet-pf-a", PF_V),
                ("pf-engine-2", "pf-engine", "pf-engine-2.aws.internal.example-aero.test", "10.20.5.21", "us-east-1b", "m6i.large", "ami-0fedcba9876543210", "subnet-pf-b", PF_V),
                ("pf-admin-1", "pf-admin", "pf-admin-1.aws.internal.example-aero.test", "10.20.4.10", "us-east-1a", "m6i.large", "ami-0fedcba9876543210", "subnet-pf-a", PF_V)],
}
TARGET = {
    "stack": (("provider", "azure"), ("directory", "pingds"), ("federation", "pingfederate")),
    "net": ("vnet", "vnet-ciam-prod", "10.60.0.0/16"), "rg": "rg-ciam-prod", "pinned_priorities": True,
    "subnets": [("snet-ds", "subnet-ds", "vnet-ciam-prod/snet-ds", "10.60.1.0/24", None),
                ("snet-pf", "subnet-pf", "vnet-ciam-prod/snet-pf", "10.60.2.0/24", None)],
    "services": [("svc-ldaps", "ds-ldaps-service", "ldap.id.cloud.example-aero.test", "id.cloud.example-aero.test",
                  None, "ds", [1636], "10.60.1.100", None, None),     # no certificate covers this (planted) name
                 ("svc-sso", "pf-sso-service", "sso.example-aero.test", "example-aero.test",
                  None, "pf-engine", [443], "198.51.100.77", "pip-ciam-sso-prod", "sso-tls-2026")],
    "fw": [("fw-pf-ds-svc", "fw-consumer-pf-ds-svc", ["10.60.2.0/24"], [1636], "ds", "pf-ds-svc", None),
           ("fw-customer-portal", "fw-consumer-customer-portal-svc", ["10.30.8.0/24"], [1636], "ds", "customer-portal-svc", None),
           ("fw-supplier-portal", "fw-consumer-supplier-portal-svc", ["10.31.2.0/24"], [1636], "ds", "supplier-portal-svc", None),
           ("fw-idm-sync", "fw-consumer-idm-sync", ["10.60.6.0/24"], [1636], "ds", "idm-sync", None),
           ("fw-replication", "fw-replication", ["10.60.1.0/24", "10.20.0.0/16"], [8989], "ds", None, None),
           ("fw-admin", "fw-admin", ["10.60.9.0/28"], [4444], "ds", None, None),
           ("fw-sso-public", "fw-sso-public", ["0.0.0.0/0"], [443], "pf-engine", None, None)],
    "egress": ("natgw-ciam-prod", "203.0.113.200/32"),
    "secret": lambda role: f"azkv://kv-ciam-prod/{role}",
    "key": ("azkv-key://kv-ciam-prod/keys/disk-cmk",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/Microsoft.Compute/diskEncryptionSets/des-ciam-prod"),
    "backup": None,   # deliberately missing: the demo's migration plan should catch it
    "interconnect": ("link-source", "site-to-site VPN (landing-zone managed)", AWS, ["10.20.0.0/16"]),
    "servers": [("ds-1", "ds", "ds-1.az.internal.example-aero.test", "10.60.1.11", "1", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("ds-2", "ds", "ds-2.az.internal.example-aero.test", "10.60.1.12", "2", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("ds-3", "ds", "ds-3.az.internal.example-aero.test", "10.60.1.13", "3", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("pf-engine-1", "pf-engine", "pf-engine-1.az.internal.example-aero.test", "10.60.2.21", "1", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V),
                ("pf-engine-2", "pf-engine", "pf-engine-2.az.internal.example-aero.test", "10.60.2.22", "2", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V),
                ("pf-admin-1", "pf-admin", "pf-admin-1.az.internal.example-aero.test", "10.60.2.10", "1", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V)],
}
ALLOWLISTS = (
    ("mro-dc-egress-to-ldaps", "mro-analytics-team", "MRO data-center egress firewall", "consumer-egress",
     "ds-ldaps-service", ["10.20.1.100/32"], 21, "to-request", "mro-batch-export"),
    ("supplier-portal-egress-sg", "supplier-portal-team", "Supplier portal outbound security group (Terraform)",
     "consumer-egress", "ds-ldaps-service", ["10.20.1.100/32"], 5, "to-request", "supplier-portal-svc"),
    ("customer-portal-egress", "customer-portal-team", "Customer portal egress policy", "consumer-egress",
     "ds-ldaps-service", ["10.0.0.0/8"], 5, "not-needed", "customer-portal-svc"),
    ("skyline-air-ingress", "skyline-air", "Skyline Air IdP ingress allowlist (metadata and back-channel)",
     "partner-ingress", "pf-egress", ["203.0.113.10/32"], 45, "to-request", None),
    ("harbor-mro-ingress", "harbor-mro", "Harbor MRO SSO ingress allowlist", "partner-ingress", "pf-egress",
     ["203.0.113.10/32", "203.0.113.200/32"], 30, "done", None),
)


def _bindings(file, env, p):
    """Every binding of one environment, in data-file order."""
    B = f"ou=bindings,{env}"
    b = lambda cn: f"cn={cn},{B}"  # noqa: E731
    return (spec(file, B, ["top", "organizationalUnit"], ou="bindings"),
            spec(file, b(p["net"][0]), ["top", "ciamNetwork"], cn=p["net"][0], ciamBindingRole="network",
                 ciamProviderRef=p["net"][1], ciamCidr=p["net"][2], ciamResourceGroup=p.get("rg"),
                 ciamOwner=owner("network-security")),
            *(spec(file, b(cn), ["top", "ciamSubnetBinding"], cn=cn, ciamBindingRole=role, ciamProviderRef=ref,
                   ciamCidr=cidr, ciamZone=zone) for cn, role, ref, cidr, zone in p["subnets"]),
            *(spec(file, b(cn), ["top", "ciamServiceName"], cn=cn, ciamBindingRole=role, ciamFqdn=fqdn,
                   ciamDnsZone=zone, ciamDnsZoneRef=zref, ciamTargetRole=trole, ciamPort=ports, ciamFrontendIp=ip,
                   ciamProviderRef=pref, ciamTlsCertificate=cert(tls)[0] if tls else None)
              for cn, role, fqdn, zone, zref, trole, ports, ip, pref, tls in p["services"]),
            *(spec(file, b(cn), ["top", "ciamFirewallRule"], cn=cn, ciamBindingRole=role, ciamSourceCidr=cidrs,
                   ciamPort=ports, ciamTargetRole=trole, ciamProtocol="tcp",
                   ciamRulePriority=100 + 10 * i if p.get("pinned_priorities") else None,
                   ciamAllowsConsumer=f"cn={consumer},{CON}" if consumer else None,
                   ciamChangeRef=chg(chg_) if chg_ else None)
              for i, (cn, role, cidrs, ports, trole, consumer, chg_) in enumerate(p["fw"])),
            spec(file, b("egress-pf"), ["top", "ciamEgress"], cn="egress-pf", ciamBindingRole="pf-egress",
                 ciamProviderRef=p["egress"][0], ciamCidr=p["egress"][1]),
            *(spec(file, b(f"secret-{role}"), ["top", "ciamSecretRef"], cn=f"secret-{role}", ciamBindingRole=role,
                   ciamRefUri=p["secret"](role)) for role in SECRET_ROLES),
            spec(file, b("key-disk"), ["top", "ciamKeyRef"], cn="key-disk", ciamBindingRole="disk-encryption",
                 ciamRefUri=p["key"][0], ciamProviderRef=p["key"][1]),
            *((spec(file, b("backup"), ["top", "ciamBackupTarget"], cn="backup", ciamBindingRole="backup-target",
                    ciamStorageRef=p["backup"], ciamRetentionDays=35),) if p.get("backup") else ()),
            *((_interconnect(file, b, *p["interconnect"]),) if p.get("interconnect") else ()))


def _interconnect(file, b, cn, kind, peer, cidr):
    return spec(file, b(cn), ["top", "ciamInterconnect"], cn=cn, ciamBindingRole="cross-cloud-replication",
                ciamInterconnectKind=kind, ciamPeerEnvironment=peer, ciamSourceCidr=cidr, ciamPort=8989,
                ciamOwner=owner("network-security"))


ADAPTER_SOURCE = "https://github.com/aryanduntley/CIAMstack/tree/main/packages/opsdir-adapter-{}"


def _stack(file, env, p):
    """The environment's declared stack: which adapter fills each role."""
    S = f"ou=stack,{env}"
    return (spec(file, S, ["top", "organizationalUnit"], ou="stack"),
            *(spec(file, f"cn={role},{S}", ["top", "ciamStackComponent"], cn=role, ciamStackRole=role,
                   ciamAdapter=adapter, ciamAdapterVersion=">=0.1,<1", ciamAdapterSource=ADAPTER_SOURCE.format(adapter))
              for role, adapter in p["stack"]))


def environment(file, env, p):
    """An environment's bindings, its declared stack, then its servers (placed in bindings by role)."""
    b = lambda cn: f"cn={cn},ou=bindings,{env}"  # noqa: E731
    return (*_bindings(file, env, p), *_stack(file, env, p),
            *(spec(file, f"cn={cn},{env}", ["top", "ciamServer"], cn=cn, ciamServerRole=role, ciamHostname=host,
                   ciamPrivateIp=ip, ciamZone=zone, ciamInstanceSize=size, ciamImageRef=image, ciamSubnet=b(subnet),
                   ciamProductVersion=version, ciamOwner=owner("ciam-platform"))
              for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]))


def environments():
    aws, az = "40-env-source", "45-env-target"
    return (spec(aws, f"cloud=source,{ENVS}", ["top", "ciamCloud"], cloud="source",
                 ciamCloudProvider="aws", ciamRegion="us-east-1", ciamCloudEnvironment="public", ciamLifecycle="active",
                 description="Current cloud hosting environment (AWS)"),
            spec(aws, AWS, ["top", "ciamEnvironment"], env="prod", ciamLifecycle="active", ciamOwner=owner("ciam-platform"),
                 xDataResidency=RESIDENCY["source"]),
            *environment(aws, AWS, SOURCE),
            spec(az, f"cloud=target,{ENVS}", ["top", "ciamCloud"], cloud="target",
                 ciamCloudProvider="azure", ciamRegion="usgovvirginia", ciamCloudEnvironment="usgovernment",
                 ciamLifecycle="building",
                 description="New cloud landing zone being built (Azure Government)"),
            spec(az, AZ, ["top", "ciamEnvironment"], env="prod", ciamLifecycle="building",
                 ciamPlannedCutover=t("2027-01-15"), ciamJoinsDeploymentOf=AWS, ciamOwner=owner("ciam-platform"),
                 xDataResidency=RESIDENCY["target"]),
            *environment(az, AZ, TARGET))


def external_allowlists():
    return tuple(spec("80-external-allowlists", f"cn={cn},{XA}", ["top", "ciamExternalAllowlist"], cn=cn,
                      ciamManagedBy=owner(mgr)[0], ciamExternalSystem=system, ciamAllowlistDirection=direction,
                      ciamRefersToRole=role, ciamRecordedCidr=recorded, ciamLeadTimeDays=lead, ciamRequestStatus=status,
                      ciamAllowsConsumer=f"cn={consumer},{CON}" if consumer else None, ciamOwner=owner("ciam-platform"))
                 for cn, mgr, system, direction, role, recorded, lead, status, consumer in ALLOWLISTS)
