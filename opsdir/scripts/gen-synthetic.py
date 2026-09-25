#!/usr/bin/env python3
"""Generate the synthetic CIAM estate as LDIF files in data/.

Everything here is fictional: company "Example Aero", partners "Skyline Air" and "Harbor MRO",
documentation IP ranges (RFC 5737), the AWS documentation account 111122223333, and made-up
resource ids. Nothing describes any real organization's environment.

The estate is seeded with realistic problems for the demo to find:
  - ds-2 is missing the `mail` index (unrecorded change → incident INC-2231); ds-3 has an extra,
    unrecorded `description` substring index and a different lockout threshold
  - a legacy consumer binds with a person account, reads every attribute, has no owner
  - the rtx-next (Azure) environment is missing firewall rules and a backup target, and its
    LDAPS service name breaks the stable-name contract
  - partner and consumer allowlists pin our old IP addresses
  - certificates expire before the planned cutover; one work instruction is stale
"""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from opsdir.ldif import write_entry  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent.parent / "data"
R = "dc=ciam-ops"
USERS = "dc=partners,dc=example-aero,dc=test"          # base DN of the (fictional) user directory
PEOPLE = f"ou=people,{USERS}"
files = {}


def E(file, dn, classes, **attrs):
    clean = {}
    for k, v in attrs.items():
        if v is None:
            continue
        clean[k] = [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]
    files.setdefault(file, []).append(write_entry(dn, classes, clean))


def ou(file, name, parent=R, desc=None):
    E(file, f"ou={name},{parent}", ["top", "organizationalUnit"], ou=name, description=desc)
    return f"ou={name},{parent}"


def t(date, hms="000000"):
    return date.replace("-", "") + hms + "Z"


def fp(name):
    h = hashlib.sha256(name.encode()).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, 64, 2))


# ------------------------------------------------------------------ tree
E("00-base", R, ["top", "domain"], dc="ciam-ops",
  description="Operations directory for the external identity (CIAM) platform. Synthetic demo data.")
for name, desc in [("environments", "Clouds, environments, servers and bindings"),
                   ("config", "Directory server configuration: declared (desired) and observed (snapshots)"),
                   ("user-schema", "Records describing attributes of the user directory"),
                   ("consumers", "Clients of the user directory, discovered from access logs"),
                   ("acis", "Access control instructions on the user directory"),
                   ("integrations", "Federation integrations (SAML / OIDC) and their claim maps"),
                   ("certificates", "Certificates (public facts only — never keys)"),
                   ("external-allowlists", "Allowlists in consumer and partner systems that contain our addresses"),
                   ("runbooks", "Work instructions"),
                   ("changes", "Change records mirrored from ITSM"),
                   ("incidents", "Incidents and postmortems"),
                   ("owners", "Teams, partners and vendors")]:
    ou("00-base", name, desc=desc)
DECL = ou("00-base", "declared", f"ou=config,{R}", "Desired, environment-neutral DS configuration")
OBS = ou("00-base", "observed", f"ou=config,{R}", "Read-only snapshots captured from live servers")

# ------------------------------------------------------------------ owners
OWN = f"ou=owners,{R}"
for cn, kind, mail, url in [
    ("ciam-platform", "team", "ciam-platform@example-aero.test", None),
    ("customer-portal-team", "team", "customer-portal@example-aero.test", None),
    ("supplier-portal-team", "team", "supplier-portal@example-aero.test", None),
    ("mro-analytics-team", "team", "mro-analytics@example-aero.test", None),
    ("tech-pubs-team", "team", "tech-pubs@example-aero.test", None),
    ("mobile-team", "team", "mobile@example-aero.test", None),
    ("network-security", "team", "netsec@example-aero.test", None),
    ("skyline-air", "partner", "identity-ops@skyline-air.example", "https://partners.skyline-air.example/it-requests"),
    ("harbor-mro", "partner", "it-security@harbor-mro.example", "https://portal.harbor-mro.example/support"),
]:
    E("10-owners", f"cn={cn},{OWN}", ["top", "ciamParty"], cn=cn, ciamOwnerKind=kind, mail=mail, ciamContactUrl=url)


def owner(*names):
    return [f"cn={n},{OWN}" for n in names]


# ------------------------------------------------------------------ changes and incidents
CHG = f"ou=changes,{R}"
for cn, title, status, by, when in [
    ("CHG-0877", "Grant PingFederate read access to profile attributes", "applied", "CAB 2024-01-02", "2024-01-03"),
    ("CHG-0931", "Reconfigure mail index (equality only)", "applied", "CAB 2026-06-11", "2026-06-14"),
    ("CHG-2040", "Allow rtx-next DS subnet on the replication port", "applied", "CAB 2026-09-04", "2026-09-06"),
    ("CHG-2001", "Add NSG rule for the MRO batch export in rtx-next", "approved", "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2003", "Restore the stable LDAPS service name in rtx-next", "approved", "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2002", "Grant legacy report account write access", "proposed", None, None),
]:
    E("20-changes", f"cn={cn},{CHG}", ["top", "ciamChange"], cn=cn, ciamTitle=title, ciamChangeStatus=status,
      ciamApprovedBy=by, ciamPlannedAt=t(when) if when else None)


def chg(c):
    return f"cn={c},{CHG}"


# ------------------------------------------------------------------ user-directory attribute records
US = f"ou=user-schema,{R}"
for name, pii, export, purpose in [
    ("uid", "low", None, "Login identifier (the user's email address)"),
    ("mail", "moderate", None, "Contact and login email"),
    ("givenName", "low", None, "Display name"),
    ("sn", "low", None, "Display name"),
    ("telephoneNumber", "moderate", None, "Account recovery and support contact"),
    ("companyId", "none", None, "Link to the customer / supplier organization record"),
    ("soldToAccount", "low", None, "Commercial account for aftermarket entitlements"),
    ("registrationStatus", "none", None, "Registration workflow state (pending / approved / active / disabled)"),
    ("exportScreeningStatus", "high", "TRUE", "Result of restricted-party / export screening from the authoritative system"),
    ("challengeAnswer", "high", None, "Legacy knowledge-based recovery answers; candidate for retirement"),
    ("lastLoginTime", "low", None, "Inactivity detection for lifecycle cleanup"),
    ("appEntitlement", "low", None, "Application entitlements (app:role)"),
    ("description", "low", None, "Free text; used by a legacy export for account notes"),
]:
    E("25-user-schema", f"cn={name},{US}", ["top", "ciamUserAttribute"], cn=name, ciamLdapName=name,
      ciamPiiClass=pii, ciamExportControlled=export, ciamPurpose=purpose)


def ua(*names):
    return [f"cn={n},{US}" for n in names]


# ------------------------------------------------------------------ declared DS configuration (environment-neutral)
BK = ou("30-config-declared", "backends", DECL)
PP = ou("30-config-declared", "password-policies", DECL)
CH = ou("30-config-declared", "connection-handlers", DECL)
LP = ou("30-config-declared", "log-publishers", DECL)
RP = ou("30-config-declared", "replication", DECL)

INDEXES = [("uid", ["equality", "presence"], None), ("mail", ["equality"], "2026-06-14"),
           ("companyId", ["equality"], None), ("registrationStatus", ["equality"], None),
           ("lastLoginTime", ["ordering"], None), ("soldToAccount", ["equality"], None),
           ("appEntitlement", ["equality"], None)]
POLICIES = [("customers", "PBKDF2-HMAC-SHA256", 5, "15 m", 5, None, "customers"),
            ("suppliers", "PBKDF2-HMAC-SHA256", 5, "15 m", 8, "365 d", "suppliers"),
            ("service-accounts", "PBKDF2-HMAC-SHA512", 0, None, 0, None, None)]


def config_tree(file, base, overrides=None, drop=(), extra_index=None):
    """Declared config, or an observed snapshot of it with deviations."""
    overrides = overrides or {}
    ou(file, "backends", base) if base != DECL else None
    ou(file, "password-policies", base) if base != DECL else None
    bdn = f"cn=userData,ou=backends,{base}"
    E(file, bdn, ["top", "ciamBackend"], cn="userData", ciamBackendType="je", ciamBaseDn=USERS)
    for name, types, changed in INDEXES + ([extra_index] if extra_index else []):
        if name in drop:
            continue
        E(file, f"cn={name},{bdn}", ["top", "ciamIndex"], cn=name, ciamIndexedAttribute=ua(name)[0],
          ciamIndexType=types, ciamLastChanged=t(changed) if (changed and base == DECL) else None,
          ciamChangeRef=chg("CHG-0931") if (name == "mail" and base == DECL) else None)
    for name, scheme, lock, dur, hist, age, pop in POLICIES:
        lock = overrides.get(("lockout", name), lock)
        E(file, f"cn={name},ou=password-policies,{base}", ["top", "ciamPasswordPolicy"], cn=name,
          ciamStorageScheme=scheme, ciamLockoutFailureCount=lock, ciamLockoutDuration=dur,
          ciamPasswordHistoryCount=hist, ciamMaxPasswordAge=age, ciamPopulation=pop)


config_tree("30-config-declared", DECL)
for name, enabled, port in [("LDAPS", "TRUE", 1636), ("LDAP", "FALSE", 1389), ("HTTPS", "TRUE", 8443)]:
    E("30-config-declared", f"cn={name},{CH}", ["top", "ciamConnectionHandler"], cn=name, ciamEnabled=enabled,
      ciamListenPort=port)
E("30-config-declared", f"cn=Json File-Based Access Logger,{LP}", ["top", "ciamLogPublisher"],
  cn="Json File-Based Access Logger", ciamEnabled="TRUE")
E("30-config-declared", f"cn=topology,{RP}", ["top", "ciamReplicationTopology"], cn="topology", ciamReplicaCount=3,
  ciamReplicationPurgeDelay="3 d", ciamOwner=owner("ciam-platform"))

# ------------------------------------------------------------------ environments
ENVS = f"ou=environments,{R}"
AWS = f"env=prod,cloud=aws-current,{ENVS}"
AZ = f"env=prod,cloud=rtx-next,{ENVS}"
E("40-env-aws-current", f"cloud=aws-current,{ENVS}", ["top", "ciamCloud"], cloud="aws-current",
  ciamCloudProvider="aws", ciamRegion="us-east-1", ciamCloudEnvironment="public", ciamLifecycle="active",
  description="Existing cloud hosting environment")
E("40-env-aws-current", AWS, ["top", "ciamEnvironment"], env="prod", ciamLifecycle="active")
E("45-env-rtx-next", f"cloud=rtx-next,{ENVS}", ["top", "ciamCloud"], cloud="rtx-next",
  ciamCloudProvider="azure", ciamRegion="usgovvirginia", ciamCloudEnvironment="usgovernment",
  ciamLifecycle="building",
  description="Next-gen cloud landing zone (ASSUMED Azure Government for the demo; the real target is unconfirmed)")
E("45-env-rtx-next", AZ, ["top", "ciamEnvironment"], env="prod", ciamLifecycle="building",
  ciamPlannedCutover=t("2027-01-15"), ciamJoinsDeploymentOf=AWS)

SECRET_ROLES = ["ds-deployment-id", "ds-deployment-password", "ds-root-password", "ds-tls-keystore",
                "sso-tls-keystore", "pf-signing-key", "pf-admin-password"]


def environment(file, env, p):
    B = ou(file, "bindings", env)
    b = lambda cn: f"cn={cn},{B}"  # noqa: E731
    E(file, b(p["net"][0]), ["top", "ciamNetwork"], cn=p["net"][0], ciamBindingRole="network",
      ciamProviderRef=p["net"][1], ciamCidr=p["net"][2], ciamResourceGroup=p.get("rg"))
    for cn, role, ref, cidr, zone in p["subnets"]:
        E(file, b(cn), ["top", "ciamSubnetBinding"], cn=cn, ciamBindingRole=role, ciamProviderRef=ref,
          ciamCidr=cidr, ciamZone=zone)
    for cn, role, fqdn, zone, zref, trole, ports, ip, pref in p["services"]:
        E(file, b(cn), ["top", "ciamServiceName"], cn=cn, ciamBindingRole=role, ciamFqdn=fqdn, ciamDnsZone=zone,
          ciamDnsZoneRef=zref, ciamTargetRole=trole, ciamPort=ports, ciamFrontendIp=ip, ciamProviderRef=pref)
    for i, (cn, role, cidrs, ports, trole, consumer, chg_) in enumerate(p["fw"]):
        E(file, b(cn), ["top", "ciamFirewallRule"], cn=cn, ciamBindingRole=role, ciamSourceCidr=cidrs,
          ciamPort=ports, ciamTargetRole=trole, ciamProtocol="tcp",
          ciamRulePriority=100 + 10 * i if p.get("pinned_priorities") else None,
          ciamAllowsConsumer=f"cn={consumer},ou=consumers,{R}" if consumer else None,
          ciamChangeRef=chg(chg_) if chg_ else None)
    E(file, b("egress-pf"), ["top", "ciamEgress"], cn="egress-pf", ciamBindingRole="pf-egress",
      ciamProviderRef=p["egress"][0], ciamCidr=p["egress"][1])
    for role in SECRET_ROLES:
        E(file, b(f"secret-{role}"), ["top", "ciamSecretRef"], cn=f"secret-{role}", ciamBindingRole=role,
          ciamRefUri=p["secret"](role))
    E(file, b("key-disk"), ["top", "ciamKeyRef"], cn="key-disk", ciamBindingRole="disk-encryption",
      ciamRefUri=p["key"][0], ciamProviderRef=p["key"][1])
    if p.get("backup"):
        E(file, b("backup"), ["top", "ciamBackupTarget"], cn="backup", ciamBindingRole="backup-target",
          ciamStorageRef=p["backup"], ciamRetentionDays=35)
    if p.get("interconnect"):
        cn, kind, peer, cidr = p["interconnect"]
        E(file, b(cn), ["top", "ciamInterconnect"], cn=cn, ciamBindingRole="cross-cloud-replication",
          ciamInterconnectKind=kind, ciamPeerEnvironment=peer, ciamSourceCidr=cidr, ciamPort=8989,
          ciamOwner=owner("network-security"))
    for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]:
        E(file, f"cn={cn},{env}", ["top", "ciamServer"], cn=cn, ciamServerRole=role, ciamHostname=host,
          ciamPrivateIp=ip, ciamZone=zone, ciamInstanceSize=size, ciamImageRef=image, ciamSubnet=b(subnet),
          ciamProductVersion=version, ciamOwner=owner("ciam-platform"))


DS_V, PF_V = "PingDS 7.5.1", "PingFederate 12.1.4"
environment("40-env-aws-current", AWS, {
    "net": ("vpc", "vpc-0a1b2c3d4e5f67890", "10.20.0.0/16"),
    "subnets": [("subnet-ds-a", "subnet-ds", "subnet-0a11b22c33d44e55a", "10.20.1.0/24", "us-east-1a"),
                ("subnet-ds-b", "subnet-ds", "subnet-0a11b22c33d44e55b", "10.20.2.0/24", "us-east-1b"),
                ("subnet-ds-c", "subnet-ds", "subnet-0a11b22c33d44e55c", "10.20.3.0/24", "us-east-1c"),
                ("subnet-pf-a", "subnet-pf", "subnet-0f66e77d88c99b00a", "10.20.4.0/24", "us-east-1a"),
                ("subnet-pf-b", "subnet-pf", "subnet-0f66e77d88c99b00b", "10.20.5.0/24", "us-east-1b")],
    "services": [("svc-ldaps", "ds-ldaps-service", "ldap.id.example-aero.test", "id.example-aero.test",
                  "Z0EXAMPLE1PRIVATE", "ds", [1636], "10.20.1.100", None),
                 ("svc-sso", "pf-sso-service", "sso.example-aero.test", "example-aero.test",
                  "Z0EXAMPLE2PUBLIC", "pf-engine", [443], "198.51.100.20", "eipalloc-0a1b2c3d4e5f60001")],
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
})
IMG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-images/providers/Microsoft.Compute/images/"
environment("45-env-rtx-next", AZ, {
    "net": ("vnet", "vnet-ciam-prod", "10.60.0.0/16"), "rg": "rg-ciam-prod", "pinned_priorities": True,
    "subnets": [("snet-ds", "subnet-ds", "vnet-ciam-prod/snet-ds", "10.60.1.0/24", None),
                ("snet-pf", "subnet-pf", "vnet-ciam-prod/snet-pf", "10.60.2.0/24", None)],
    "services": [("svc-ldaps", "ds-ldaps-service", "ldap.id.cloud.example-aero.test", "id.cloud.example-aero.test",
                  None, "ds", [1636], "10.60.1.100", None),
                 ("svc-sso", "pf-sso-service", "sso.example-aero.test", "example-aero.test",
                  None, "pf-engine", [443], "198.51.100.77", "pip-ciam-sso-prod")],
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
    "interconnect": ("link-aws-current", "site-to-site VPN (landing-zone managed)", AWS, ["10.20.0.0/16"]),
    "servers": [("ds-1", "ds", "ds-1.az.internal.example-aero.test", "10.60.1.11", "1", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("ds-2", "ds", "ds-2.az.internal.example-aero.test", "10.60.1.12", "2", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("ds-3", "ds", "ds-3.az.internal.example-aero.test", "10.60.1.13", "3", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("pf-engine-1", "pf-engine", "pf-engine-1.az.internal.example-aero.test", "10.60.2.21", "1", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V),
                ("pf-engine-2", "pf-engine", "pf-engine-2.az.internal.example-aero.test", "10.60.2.22", "2", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V),
                ("pf-admin-1", "pf-admin", "pf-admin-1.az.internal.example-aero.test", "10.60.2.10", "1", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V)],
})

# ------------------------------------------------------------------ observed snapshots (aws-current)
for srv, kw in [("ds-1", {}),
                ("ds-2", {"drop": ("mail",)}),
                ("ds-3", {"extra_index": ("description", ["substring"], None),
                          "overrides": {("lockout", "customers"): 10}})]:
    snap = f"snap={srv}-20260920,{OBS}"
    E("50-config-observed", snap, ["top", "ciamSnapshot"], snap=f"{srv}-20260920",
      ciamServerRef=f"cn={srv},{AWS}", ciamCapturedAt=t("2026-09-20", "030000"))
    config_tree("50-config-observed", snap, **kw)

# ------------------------------------------------------------------ consumers (as discovered from DS access logs)
CON = f"ou=consumers,{R}"
for cn, bind, src, mix, attrs, unidx, tls, peak, first, own, crit, status in [
    ("pf-ds-svc", "uid=pf-svc,ou=service-accounts", ["10.20.4.0/24", "10.20.5.0/24"],
     "bind 61%, search 38%, modify 1%", ["uid", "mail", "givenName", "sn", "companyId", "appEntitlement", "registrationStatus"],
     0, "TRUE", 850, "2024-01-03", "ciam-platform", "critical", "tested"),
    ("customer-portal-svc", "uid=portal-svc,ou=service-accounts", ["10.30.8.0/24"],
     "search 70%, modify 25%, add 5%", ["mail", "registrationStatus", "telephoneNumber", "companyId", "challengeAnswer"],
     0, "TRUE", 120, "2023-05-17", "customer-portal-team", "critical", "tested"),
    ("supplier-portal-svc", "uid=supplier-svc,ou=service-accounts", ["10.31.2.0/24"],
     "search 88%, modify 12%", ["mail", "companyId", "soldToAccount"],
     0, "TRUE", 60, "2023-11-02", "supplier-portal-team", "high", "contacted"),
    ("mro-batch-export", "uid=mro-export,ou=service-accounts", ["10.40.12.0/24"],
     "search 100% (nightly 02:00-02:40 UTC)", ["mail", "companyId", "soldToAccount", "exportScreeningStatus", "description"],
     14, "TRUE", 40, "2024-08-20", "mro-analytics-team", "medium", "identified"),
    ("legacy-rptuser", "uid=rptuser,ou=customers,ou=people", ["10.40.7.22/32"],
     "search 100%, filter (objectClass=*) over ou=people", ["uid", "mail", "givenName", "sn", "telephoneNumber",
                                                             "challengeAnswer", "exportScreeningStatus"],
     96, "FALSE", 5, "2021-03-09", None, None, "unknown"),
    ("idm-sync", "uid=idm-sync,ou=service-accounts", ["10.20.6.0/24"],
     "search 55%, modify 45%", ["uid", "mail", "companyId", "appEntitlement", "registrationStatus", "lastLoginTime"],
     0, "TRUE", 200, "2024-01-03", "ciam-platform", "high", "tested"),
]:
    E("55-consumers", f"cn={cn},{CON}", ["top", "ciamConsumer"], cn=cn, ciamBindDn=f"{bind},{USERS}",
      ciamObservedSource=src, ciamOperationMix=mix, ciamSubtreeRead=PEOPLE, ciamAttrRead=ua(*attrs),
      ciamUnindexedSearchesPerDay=unidx, ciamTlsOnly=tls, ciamPeakOpsPerSec=peak, ciamFirstSeen=t(first),
      ciamLastSeen=t("2026-09-22"), ciamOwner=owner(own) if own else None, ciamCriticality=crit,
      ciamMigrationStatus=status)

# ------------------------------------------------------------------ ACIs
ACI = f"ou=acis,{R}"
for cn, grantee, attrs, rights, just, reviewed, own, ch in [
    ("aci-pf-read", "pf-ds-svc", ["uid", "mail", "givenName", "sn", "companyId", "appEntitlement", "registrationStatus"],
     ["read", "search", "compare"], "PingFederate reads profile attributes to build assertions and tokens",
     "2026-03-02", "ciam-platform", "CHG-0877"),
    ("aci-portal-write", "customer-portal-svc", ["mail", "registrationStatus", "telephoneNumber", "challengeAnswer"],
     ["read", "search", "write"], "Customer portal registration and profile management", "2026-03-02",
     "customer-portal-team", None),
    ("aci-supplier-read", "supplier-portal-svc", ["mail", "companyId", "soldToAccount"], ["read", "search"],
     "Supplier portal account lookup", "2026-03-02", "supplier-portal-team", None),
    ("aci-mro-read", "mro-batch-export", ["mail", "companyId", "soldToAccount", "exportScreeningStatus", "description"],
     ["read", "search"], "Nightly aftermarket entitlement reconciliation", "2025-09-11", "mro-analytics-team", None),
    ("aci-legacy-all", "legacy-rptuser", None, ["read", "search"], None, None, None, None),
    ("aci-idm-write", "idm-sync", ["uid", "mail", "companyId", "appEntitlement", "registrationStatus", "lastLoginTime"],
     ["read", "search", "write"], "Identity sync from the registration workflow", "2026-03-02", "ciam-platform", None),
]:
    E("60-acis", f"cn={cn},{ACI}", ["top", "ciamAci"], cn=cn, ciamAciTargetDn=PEOPLE,
      ciamAciGrantee=f"cn={grantee},{CON}", ciamAciTargetAttr=ua(*attrs) if attrs else None,
      ciamAciAllAttributes=None if attrs else "TRUE", ciamAciRight=rights, ciamJustification=just,
      ciamReviewedOn=t(reviewed) if reviewed else None, ciamOwner=owner(own) if own else None,
      ciamChangeRef=chg(ch) if ch else None)

# ------------------------------------------------------------------ runbooks (before certs: certs point at them)
RB = f"ou=runbooks,{R}"
CERTS = f"ou=certificates,{R}"
INTS = f"ou=integrations,{R}"
for cn, title, validated, applies in [
    ("WI-CIAM-001", "Rotate a partner SAML signing certificate", "2026-05-10",
     [f"cn=skyline-air-idp-signing,{CERTS}", f"cn=harbor-mro-idp-signing,{CERTS}"]),
    ("WI-CIAM-002", "Rotate the directory LDAPS certificate", "2026-08-01", [f"cn=ds-ldaps-2026,{CERTS}"]),
    ("WI-CIAM-004", "Add or rebuild a backend index", "2026-02-01",
     [f"cn=mail,cn=userData,ou=backends,{DECL}", f"cn=uid,cn=userData,ou=backends,{DECL}"]),
    ("WI-CIAM-007", "Recover replication after a replica outage", "2026-08-01", [f"cn=topology,ou=replication,{DECL}"]),
    ("WI-CIAM-010", "Onboard a SAML application", "2026-03-15",
     [f"cn=customer-portal,{INTS}", f"cn=pf-signing-2025,{CERTS}"]),
]:
    E("65-runbooks", f"cn={cn},{RB}", ["top", "ciamRunbook"], cn=cn, ciamTitle=title, ciamVersion="1.0",
      ciamLastValidated=t(validated), ciamAppliesTo=applies,
      ciamDocUrl=f"https://wiki.example-aero.test/ciam/{cn}", ciamOwner=owner("ciam-platform"))

# ------------------------------------------------------------------ certificates (public facts only)
for cn, purpose, subject, issuer, nb, na, sans, keyrole, own, partner, rb, changed in [
    ("ds-ldaps-2026", "tls-server", "CN=ldap.id.example-aero.test", "CN=Example Aero Issuing CA 2",
     "2025-12-20", "2026-12-20", ["ldap.id.example-aero.test"], "ds-tls-keystore", "ciam-platform", None, "WI-CIAM-002", None),
    ("sso-tls-2026", "tls-server", "CN=sso.example-aero.test", "CN=Public CA R11",
     "2026-02-10", "2027-02-10", ["sso.example-aero.test"], "sso-tls-keystore", "ciam-platform", None, None, None),
    ("pf-signing-2025", "saml-signing", "CN=Example Aero SSO Signing 2025", "self-signed",
     "2025-07-01", "2027-06-30", None, "pf-signing-key", "ciam-platform", None, "WI-CIAM-010", "2025-07-01"),
    ("customer-portal-sp-signing", "saml-signing", "CN=portal.example-aero.test SP", "self-signed",
     "2024-03-01", "2027-03-01", None, None, "customer-portal-team", None, None, None),
    ("supplier-portal-sp-signing", "saml-signing", "CN=suppliers.example-aero.test SP", "self-signed",
     "2023-11-30", "2026-11-30", None, None, "supplier-portal-team", None, None, None),
    ("skyline-air-idp-signing", "partner-signing", "CN=Skyline Air IdP Signing", "self-signed",
     "2024-11-02", "2026-11-02", None, None, "ciam-platform", "skyline-air", "WI-CIAM-001", None),
    ("harbor-mro-idp-signing", "partner-signing", "CN=Harbor MRO SSO", "self-signed",
     "2025-01-15", "2028-01-15", None, None, "ciam-platform", "harbor-mro", "WI-CIAM-001", None),
]:
    E("70-certificates", f"cn={cn},{CERTS}", ["top", "ciamCertificate"], cn=cn, ciamFingerprint=fp(cn),
      ciamCertPurpose=purpose, ciamSubject=subject, ciamIssuer=issuer, ciamNotBefore=t(nb), ciamNotAfter=t(na),
      ciamSubjectAltName=sans, ciamKeyRole=keyrole, ciamOwner=owner(own),
      ciamPartnerContact=owner(partner)[0] if partner else None,
      ciamRotationRunbook=f"cn={rb},{RB}" if rb else None, ciamLastChanged=t(changed) if changed else None)


def cert(*names):
    return [f"cn={n},{CERTS}" for n in names]


# ------------------------------------------------------------------ integrations and claim maps
for cn, ptype, kw, claims in [
    ("customer-portal", "saml2-sp", dict(
        ciamEntityId="https://portal.example-aero.test/saml/sp", ciamAcsUrl="https://portal.example-aero.test/saml/acs",
        ciamPopulation="customers", ciamMfaRequired="TRUE", ciamCriticality="critical",
        ciamUsesCertificate=cert("pf-signing-2025", "customer-portal-sp-signing", "sso-tls-2026"),
        ciamOwner=owner("customer-portal-team")),
     [("email", "mail", None), ("given_name", "givenName", None), ("family_name", "sn", None),
      ("company", "companyId", None), ("roles", "appEntitlement", "keep values with prefix 'customer-portal:', strip prefix")]),
    ("supplier-portal", "saml2-sp", dict(
        ciamEntityId="https://suppliers.example-aero.test/saml/sp", ciamAcsUrl="https://suppliers.example-aero.test/saml/acs",
        ciamPopulation="suppliers", ciamMfaRequired="TRUE", ciamCriticality="high",
        ciamUsesCertificate=cert("pf-signing-2025", "supplier-portal-sp-signing", "sso-tls-2026"),
        ciamOwner=owner("supplier-portal-team")),
     [("email", "mail", None), ("company", "companyId", None), ("sold_to", "soldToAccount", None),
      ("roles", "appEntitlement", "keep values with prefix 'supplier-portal:', strip prefix")]),
    ("tech-pubs", "oidc-client", dict(
        ciamClientId="tech-pubs-web", ciamRedirectUri="https://techpubs.example-aero.test/oidc/callback",
        ciamGrantType=["authorization_code", "refresh_token"], ciamPkceRequired="TRUE",
        ciamPopulation=["customers", "suppliers"], ciamMfaRequired="FALSE", ciamCriticality="high",
        ciamUsesCertificate=cert("pf-signing-2025", "sso-tls-2026"), ciamOwner=owner("tech-pubs-team")),
     [("email", "mail", None), ("org", "companyId", None), ("entitlements", "appEntitlement", None),
      ("export_status", "exportScreeningStatus", None)]),
    ("mobile-ops", "oidc-client", dict(
        ciamClientId="mobile-ops", ciamRedirectUri="https://mobile.example-aero.test/oauth2/callback",
        ciamGrantType=["authorization_code", "refresh_token"], ciamPkceRequired="TRUE",
        ciamPopulation="customers", ciamMfaRequired="TRUE", ciamCriticality="medium",
        ciamUsesCertificate=cert("pf-signing-2025", "sso-tls-2026"), ciamOwner=owner("mobile-team")),
     [("sub", "uid", None), ("email", "mail", None), ("org", "companyId", None)]),
    ("skyline-air-federation", "saml2-idp", dict(
        ciamEntityId="https://idp.skyline-air.example/saml", ciamPopulation="partners", ciamCriticality="high",
        ciamJitBaseDn=f"ou=partners,{PEOPLE}", ciamUsesCertificate=cert("skyline-air-idp-signing", "sso-tls-2026"),
        ciamOwner=owner("ciam-platform", "skyline-air")), []),
    ("harbor-mro-federation", "saml2-idp", dict(
        ciamEntityId="https://sso.harbor-mro.example/idp", ciamPopulation="partners", ciamCriticality="medium",
        ciamJitBaseDn=f"ou=partners,{PEOPLE}", ciamUsesCertificate=cert("harbor-mro-idp-signing", "sso-tls-2026"),
        ciamOwner=owner("ciam-platform", "harbor-mro")), []),
]:
    idn = f"cn={cn},{INTS}"
    E("75-integrations", idn, ["top", "ciamIntegration"], cn=cn, ciamProtocolType=ptype, **kw)
    if claims:
        ou("75-integrations", "claims", idn)
    for claim, src, transform in claims:
        E("75-integrations", f"cn={claim},ou=claims,{idn}", ["top", "ciamClaimMap"], cn=claim, ciamClaimName=claim,
          ciamSourceAttribute=ua(src)[0], ciamTransform=transform)

# ------------------------------------------------------------------ external allowlists (other people's systems)
XA = f"ou=external-allowlists,{R}"
for cn, mgr, system, direction, role, recorded, lead, status, consumer in [
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
]:
    E("80-external-allowlists", f"cn={cn},{XA}", ["top", "ciamExternalAllowlist"], cn=cn, ciamManagedBy=owner(mgr)[0],
      ciamExternalSystem=system, ciamAllowlistDirection=direction, ciamRefersToRole=role, ciamRecordedCidr=recorded,
      ciamLeadTimeDays=lead, ciamRequestStatus=status,
      ciamAllowsConsumer=f"cn={consumer},{CON}" if consumer else None, ciamOwner=owner("ciam-platform"))

# ------------------------------------------------------------------ incidents
E("85-incidents", f"cn=INC-2231,ou=incidents,{R}", ["top", "ciamIncident"], cn="INC-2231",
  ciamTitle="Search latency spike on ds-2", ciamOpenedAt=t("2026-09-14", "141200"), ciamSeverity="sev3",
  ciamInvolved=[f"cn=ds-2,{AWS}", f"cn=mail,cn=userData,ou=backends,{DECL}"],
  ciamRootCause="mail equality index missing on ds-2 (unrecorded manual change); searches by mail went unindexed",
  ciamOwner=owner("ciam-platform"))

# ------------------------------------------------------------------ what the tools should find
# Every problem planted above, and how the migration planner should report it. The demo checks the
# planner against this list, so "NOT READY" reads as "found what was planted", not as a failure.
EXPECTED = {
    "blockers": [
        ("B1", "Contract", "`ds-ldaps-service` changes name", "rtx-next binds a new LDAPS name (landing-zone DNS default)", "CHG-2003"),
        ("B2", "Binding", "Role `backup-target`", "rtx-next has no backup target", None),
        ("B3", "Binding", "Consumer `legacy-rptuser`", "no rtx-next firewall rule for the unowned legacy account", None),
        ("B4", "Binding", "Consumer `mro-batch-export`", "no rtx-next firewall rule for the MRO export", "CHG-2001"),
        ("B5", "Consumer", "Consumer `legacy-rptuser`", "legacy account: unknown status, no owner, no TLS", None),
        ("B6", "Consumer", "Consumer `mro-batch-export`", "MRO export only 'identified', not tested", None),
        ("B7", "Consumer", "Consumer `supplier-portal-svc`", "supplier portal only 'contacted', not tested", None),
    ],
    "actions": [
        ("A1", "Certificate", "`skyline-air-idp-signing`", "partner cert expires 2026-11-02", None),
        ("A2", "Certificate", "`supplier-portal-sp-signing`", "SP cert expires 2026-11-30", None),
        ("A3", "Certificate", "`ds-ldaps-2026`", "LDAPS cert expires 2026-12-20", None),
        ("A4", "Certificate", "`sso-tls-2026`", "SSO TLS cert expires within 30 days after cutover", None),
        ("A5", "Allowlist", "`skyline-air-ingress`", "partner allowlist pins our old egress IP", None),
        ("A6", "Allowlist", "`mro-dc-egress-to-ldaps`", "consumer firewall pins our old LDAPS IP", None),
        ("A7", "Allowlist", "`supplier-portal-egress-sg`", "consumer security group pins our old LDAPS IP", None),
        ("A8", "Drift", "ds-2: missing on server: `cn=mail", "mail index missing on ds-2 (INC-2231)", None),
        ("A9", "Drift", "ds-3: not declared (unrecorded change): `cn=description", "unrecorded index on ds-3", None),
        ("A10", "Drift", "ds-3: differs: `cn=customers", "lockout threshold changed on ds-3", None),
        ("A11", "Access", "ACI `aci-legacy-all`", "ACI with no owner or justification", None),
    ],
}
files["expected-findings"] = EXPECTED

# ------------------------------------------------------------------ write
OUT.mkdir(exist_ok=True)
for old in OUT.glob("*.ldif"):
    old.unlink()
expected = files.pop("expected-findings")
keys = ("id", "area", "match", "planted", "cleared_by")
(OUT / "expected-findings.json").write_text(json.dumps(
    {"_comment": "Generated by scripts/gen-synthetic.py: the problems planted in the synthetic data.",
     **{k: [dict(zip(keys, row)) for row in v] for k, v in expected.items()}}, indent=2) + "\n")
hdr = "# Generated by scripts/gen-synthetic.py. Synthetic, fictional data. Do not edit by hand.\n\n"
n = 0
for name, entries in files.items():
    (OUT / f"{name}.ldif").write_text(hdr + "\n".join(entries))
    n += len(entries)
print(f"wrote {n} entries in {len(files)} files to {OUT}")
