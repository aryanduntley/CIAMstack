"""Infrastructure fixture data: the current AWS environment (40-env-source), its stage environment (42-env-source-
stage: an overlay of production that shares its network and overrides a few values), the target environment being
built (45-env-target, with planted gaps), a warm standby on Google Cloud being built (47-env-standby), and external
allowlists that hold our addresses (80-external-allowlists)."""
from types import MappingProxyType

from .common import AWS, AZ, CON, DECL, ENVS, GCP, INTS, XA, cert, chg, owner, spec, t
from .databases import DATABASES
from .storage import BACKUP
from .volumes import VOLUMES
from .access import ACCESS
from .edge import EDGE, SERVICE_ATTRS
from .network import NETWORK
from .observability import MONITORING
from .estate import ACCOUNTS, CLASSIFICATION, SECURITY
from .recovery import STANDBY_INTENT

SECRET_ROLES = ("ds-deployment-id", "ds-deployment-password", "ds-root-password", "ds-tls-keystore",
                "sso-tls-keystore", "pf-signing-key", "pf-admin-password", "am-admin-password", "am-keystore",
                "am-ds-bind-password", "idm-admin-password", "idm-keystore", "idm-ds-bind-password", "idm-hrdb-password",
                "ig-keystore", "pf-ds-bind-password", "pf-grants-db-password", "pf-smtp-password", "pf-captcha-secret",
                "pf-corp-ad-bind-password")
DS_V, PF_V, AM_V, IDM_V, IG_V = "PingDS 7.5.1", "PingFederate 12.1.4", "PingAM 7.5.1", "PingIDM 7.5.0", "PingGateway 2024.11.0"
IMG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-images/providers/Microsoft.Compute/images/"

SOURCE = MappingProxyType({
    "stack": (("provider", "aws"), ("directory", "pingds"), ("federation", "pingfederate"), ("access", "pingam"),
              ("identity-management", "pingidm"), ("gateway", "pinggateway")),
    "net": ("vpc", "vpc-0a1b2c3d4e5f67890", "10.20.0.0/16"),
    "subnets": [("subnet-ds-a", "subnet-ds", "subnet-0a11b22c33d44e55a", "10.20.1.0/24", "us-east-1a"),
                ("subnet-ds-b", "subnet-ds", "subnet-0a11b22c33d44e55b", "10.20.2.0/24", "us-east-1b"),
                ("subnet-ds-c", "subnet-ds", "subnet-0a11b22c33d44e55c", "10.20.3.0/24", "us-east-1c"),
                ("subnet-pf-a", "subnet-pf", "subnet-0f66e77d88c99b00a", "10.20.4.0/24", "us-east-1a"),
                ("subnet-pf-b", "subnet-pf", "subnet-0f66e77d88c99b00b", "10.20.5.0/24", "us-east-1b"),
                ("subnet-am-a", "subnet-am", "subnet-0c77d88e99fa00b1a", "10.20.7.0/24", "us-east-1a"),
                ("subnet-am-b", "subnet-am", "subnet-0c77d88e99fa00b1b", "10.20.8.0/24", "us-east-1b"),
                ("subnet-idm-a", "subnet-idm", "subnet-0d88e99fa00b11c2a", "10.20.6.0/24", "us-east-1a"),
                ("subnet-ig-a", "subnet-ig", "subnet-0e99fa00b11c22d3a", "10.20.10.0/24", "us-east-1a")],
    "services": [("svc-ldaps", "ds-ldaps-service", "ldap.id.example-aero.test", "id.example-aero.test",
                  "Z0EXAMPLE1PRIVATE", "ds", [1636], "10.20.1.100", None, "ds-ldaps-2026"),
                 # the public names are on the corporate DNS team's Infoblox (edge: zone-public); Route 53's public
                 # zone (the pipeline may change it) delegates them there
                 ("svc-sso", "pf-sso-service", "sso.example-aero.test", "example-aero.test",
                  "Z0EXAMPLE2PUBLIC", "pf-engine", [443], "198.51.100.20", "eipalloc-0a1b2c3d4e5f60001", "sso-tls-2026"),
                 ("svc-login", "am-service", "login.example-aero.test", "example-aero.test",
                  "Z0EXAMPLE2PUBLIC", "am", [443], "198.51.100.21", "eipalloc-0a1b2c3d4e5f60003", None),
                 ("svc-apps", "ig-service", "apps.example-aero.test", "example-aero.test",
                  "Z0EXAMPLE2PUBLIC", "ig", [443], "198.51.100.22", "eipalloc-0a1b2c3d4e5f60005", None)],
    "fw": [("fw-pf-ds-svc", "fw-consumer-pf-ds-svc", ["10.20.4.0/24", "10.20.5.0/24"], [1636], "ds", "pf-ds-svc", "CHG-0877"),
           ("fw-customer-portal", "fw-consumer-customer-portal-svc", ["10.30.8.0/24"], [1636], "ds", "customer-portal-svc", None),
           ("fw-supplier-portal", "fw-consumer-supplier-portal-svc", ["10.31.2.0/24"], [1636], "ds", "supplier-portal-svc", None),
           ("fw-mro-batch", "fw-consumer-mro-batch-export", ["10.40.12.0/24"], [1636], "ds", "mro-batch-export", None),
           ("fw-legacy-rptuser", "fw-consumer-legacy-rptuser", ["10.40.7.22/32"], [1636], "ds", "legacy-rptuser", None),
           ("fw-idm-sync", "fw-consumer-idm-sync", ["10.20.6.0/24"], [1636], "ds", "idm-sync", None),
           ("fw-replication", "fw-replication", ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24", "10.60.1.0/24"],
            [8989], "ds", None, "CHG-2040"),
           ("fw-admin", "fw-admin", ["10.20.9.0/28"], [4444], "ds", None, None),
           ("fw-sso-public", "fw-sso-public", ["0.0.0.0/0"], [443], "pf-engine", None, None),
           ("fw-login-public", "fw-login-public", ["0.0.0.0/0"], [443], "am", None, None),
           ("fw-apps-public", "fw-apps-public", ["0.0.0.0/0"], [443], "ig", None, None),
           # the PingFederate nodes' cluster traffic (JGroups bind and failure-detection ports), engines and console
           ("fw-pf-cluster", "fw-pf-cluster", ["10.20.4.0/24", "10.20.5.0/24"], [7600, 7700], "pf-engine", None, None),
           ("fw-pf-cluster-admin", "fw-pf-cluster-admin", ["10.20.4.0/24", "10.20.5.0/24"], [7600, 7700], "pf-admin", None, None)],
    "egress": ("nat-0123456789abcdef0", "203.0.113.10/32"),
    "time": (["169.254.169.123"], "provider"),        # Amazon Time Sync, the address every instance reaches
    "secret": lambda role: f"aws-sm://arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/{role}",
    "key": ("aws-kms://arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab", None),
    # what each store does for the material, by role (cloud key-service facts)
    "key_facts": {
        "ds-root-password": {"ciamLastRotated": t("2026-03-02"),
                             "ciamCopyRef": "cyberark://ciam-ops/CIAM-PROD/ds-root-password"},
        "pf-admin-password": {"ciamAutoRotate": "TRUE", "ciamLastRotated": t("2026-09-01"),
                              "ciamRotationFunction": "arn:aws:lambda:us-east-1:111122223333:function:ciam-rotate-pf-admin"},
        "pf-signing-key": {"ciamKeyUser": "arn:aws:iam::111122223333:role/ciam-pf-admin"},
        "disk-encryption": {"ciamProtectionLevel": "hsm", "ciamAutoRotate": "TRUE", "ciamReplicaRegion": "us-west-2",
                            "ciamKeyUser": "arn:aws:iam::111122223333:role/ciam-server-instance",
                            "ciamKeyAdmin": "arn:aws:iam::111122223333:role/ciam-key-admins"},
    },
    "backup": "s3://example-aero-ciam-prod-ds-backups", "backup_depth": BACKUP["source"],
    "discovery": "s3://example-aero-ciam-prod-pf-cluster",   # where PingFederate's nodes find each other
    # sending identities: (name, binding role, domain, provider ref, DKIM verified, SPF authorized, DMARC policy)
    "sending": (("mail-ses", "mail-sending", "example-aero.test",
                 "arn:aws:ses:us-east-1:111122223333:identity/example-aero.test", "TRUE", "TRUE", "reject"),),
    # event stream carriers: (name, binding role, provider ref, kind)
    "streams": (("audit-bus", "audit-events", "arn:aws:events:us-east-1:111122223333:event-bus/ciam-audit", "bus"),),
    # alert channels, log destinations, and the alarms and checks CloudWatch runs (observability)
    "monitoring": MONITORING["source"],
    "security": SECURITY["source"],   # the cloud security services it runs (estate)
    # the cloud identities the principals act as, the guardrails over it, the ways operators come in (access)
    "access": ACCESS["source"],
    # DNS zones, forwarders, the SSO certificate in the cloud's store, edge subnets; what the source's edge runs (edge)
    "edge": EDGE["source"], "service_attrs": SERVICE_ATTRS["source"],
    "network": NETWORK["source"], "databases": DATABASES["source"], "volumes": VOLUMES["source"],
    # compute groups: (name, binding role, server role, provider ref, image, size, min, desired, max, zones, tokens)
    "compute": (("asg-pf-engine", "compute-pf-engine", "pf-engine",
                 "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:6d4c1f0e-0000-4000-8000-00000000a001:"
                 "autoScalingGroupName/ciam-prod-pf-engine", "ami-0fedcba9876543210", "m6i.large", 2, 2, 4,
                 ("us-east-1a", "us-east-1b"), "TRUE"),),
    "servers": [("ds-1", "ds", "ds-1.aws.internal.example-aero.test", "10.20.1.11", "us-east-1a", "m6i.xlarge", "ami-0abcdef1234567890", "subnet-ds-a", DS_V),
                ("ds-2", "ds", "ds-2.aws.internal.example-aero.test", "10.20.2.11", "us-east-1b", "m6i.xlarge", "ami-0abcdef1234567890", "subnet-ds-b", DS_V),
                ("ds-3", "ds", "ds-3.aws.internal.example-aero.test", "10.20.3.11", "us-east-1c", "m6i.xlarge", "ami-0abcdef1234567890", "subnet-ds-c", DS_V),
                ("pf-engine-1", "pf-engine", "pf-engine-1.aws.internal.example-aero.test", "10.20.4.21", "us-east-1a", "m6i.large", "ami-0fedcba9876543210", "subnet-pf-a", PF_V),
                ("pf-engine-2", "pf-engine", "pf-engine-2.aws.internal.example-aero.test", "10.20.5.21", "us-east-1b", "m6i.large", "ami-0fedcba9876543210", "subnet-pf-b", PF_V),
                ("pf-admin-1", "pf-admin", "pf-admin-1.aws.internal.example-aero.test", "10.20.4.10", "us-east-1a", "m6i.large", "ami-0fedcba9876543210", "subnet-pf-a", PF_V),
                ("am-1", "am", "am-1.aws.internal.example-aero.test", "10.20.7.21", "us-east-1a", "m6i.large", "ami-0a9b8c7d6e5f40321", "subnet-am-a", AM_V),
                ("am-2", "am", "am-2.aws.internal.example-aero.test", "10.20.8.21", "us-east-1b", "m6i.large", "ami-0a9b8c7d6e5f40321", "subnet-am-b", AM_V),
                ("idm-1", "idm", "idm-1.aws.internal.example-aero.test", "10.20.6.21", "us-east-1a", "m6i.large", "ami-0b1c2d3e4f5a60987", "subnet-idm-a", IDM_V),
                ("ig-1", "ig", "ig-1.aws.internal.example-aero.test", "10.20.10.21", "us-east-1a", "m6i.large", "ami-0c2d3e4f5a6b70123", "subnet-ig-a", IG_V)],
})
TARGET = MappingProxyType({
    "stack": (("provider", "azure"), ("directory", "pingds"), ("federation", "pingfederate"), ("access", "pingam"),
              ("identity-management", "pingidm"), ("gateway", "pinggateway")),
    "net": ("vnet", "vnet-ciam-prod", "10.60.0.0/16"), "rg": "rg-ciam-prod", "pinned_priorities": True,
    "subnets": [("snet-ds", "subnet-ds", "vnet-ciam-prod/snet-ds", "10.60.1.0/24", None),
                ("snet-pf", "subnet-pf", "vnet-ciam-prod/snet-pf", "10.60.2.0/24", None),
                ("snet-am", "subnet-am", "vnet-ciam-prod/snet-am", "10.60.3.0/24", None),
                ("snet-idm", "subnet-idm", "vnet-ciam-prod/snet-idm", "10.60.6.0/24", None),
                ("snet-ig", "subnet-ig", "vnet-ciam-prod/snet-ig", "10.60.10.0/24", None),
                ("snet-db", "subnet-db", "vnet-ciam-prod/snet-db", "10.60.8.0/24", None)],     # Flexible Server's
    "services": [("svc-ldaps", "ds-ldaps-service", "ldap.id.cloud.example-aero.test", "id.cloud.example-aero.test",
                  None, "ds", [1636], "10.60.1.100", None, None),     # no certificate covers this (planted) name
                 ("svc-sso", "pf-sso-service", "sso.example-aero.test", "example-aero.test",
                  None, "pf-engine", [443], "198.51.100.77", "pip-ciam-sso-prod", "sso-tls-2026"),
                 ("svc-login", "am-service", "login.example-aero.test", "example-aero.test",
                  None, "am", [443], "198.51.100.78", "pip-ciam-login-prod", None),
                 ("svc-apps", "ig-service", "apps.example-aero.test", "example-aero.test",
                  None, "ig", [443], "198.51.100.79", "pip-ciam-apps-prod", None)],
    "fw": [("fw-pf-ds-svc", "fw-consumer-pf-ds-svc", ["10.60.2.0/24"], [1636], "ds", "pf-ds-svc", None),
           ("fw-customer-portal", "fw-consumer-customer-portal-svc", ["10.30.8.0/24"], [1636], "ds", "customer-portal-svc", None),
           ("fw-supplier-portal", "fw-consumer-supplier-portal-svc", ["10.31.2.0/24"], [1636], "ds", "supplier-portal-svc", None),
           ("fw-idm-sync", "fw-consumer-idm-sync", ["10.60.6.0/24"], [1636], "ds", "idm-sync", None),
           ("fw-replication", "fw-replication", ["10.60.1.0/24", "10.20.0.0/16"], [8989], "ds", None, None),
           ("fw-admin", "fw-admin", ["10.60.9.0/28"], [4444], "ds", None, None),
           ("fw-sso-public", "fw-sso-public", ["0.0.0.0/0"], [443], "pf-engine", None, None),
           ("fw-login-public", "fw-login-public", ["0.0.0.0/0"], [443], "am", None, None),
           ("fw-apps-public", "fw-apps-public", ["0.0.0.0/0"], [443], "ig", None, None),
           # the PingFederate nodes' cluster traffic (JGroups bind and failure-detection ports), engines and console
           ("fw-pf-cluster", "fw-pf-cluster", ["10.60.2.0/24"], [7600, 7700], "pf-engine", None, None),
           ("fw-pf-cluster-admin", "fw-pf-cluster-admin", ["10.60.2.0/24"], [7600, 7700], "pf-admin", None, None)],
    "egress": ("natgw-ciam-prod", "203.0.113.200/32"),
    "time": (["ptp:/dev/ptp_hyperv"], "ptp"),          # the Azure host's clock, as chrony reads it on Linux VMs
    "secret": lambda role: f"azkv://kv-ciam-prod/{role}",
    "key": ("azkv-key://kv-ciam-prod/keys/disk-cmk",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/Microsoft.Compute/diskEncryptionSets/des-ciam-prod"),
    # planted: the disk key is software-protected (standard vault) and neither rotates nor replicates; the PingFederate
    # admin password loses its automatic rotation; the signing key is not recorded as carried over from the source
    "key_facts": {
        "ds-deployment-id": {"ciamMaterialFrom": f"cn=secret-ds-deployment-id,ou=bindings,{AWS}"},
        "ds-deployment-password": {"ciamMaterialFrom": f"cn=secret-ds-deployment-password,ou=bindings,{AWS}"},
        "am-keystore": {"ciamMaterialFrom": f"cn=secret-am-keystore,ou=bindings,{AWS}"},
        "idm-keystore": {"ciamMaterialFrom": f"cn=secret-idm-keystore,ou=bindings,{AWS}"},
        "pf-captcha-secret": {"ciamMaterialFrom": f"cn=secret-pf-captcha-secret,ou=bindings,{AWS}"},
        "ds-root-password": {"ciamCopyRef": "cyberark://ciam-ops/CIAM-TARGET/ds-root-password"},
        "pf-admin-password": {"ciamAutoRotate": "FALSE"},
        "disk-encryption": {"ciamProtectionLevel": "software",
                            "ciamKeyUser": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
                                           "rg-ciam-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
                                           "id-ciam-servers"},
    },
    "backup": None,   # deliberately missing: the demo's migration plan should catch it
    "discovery": None,   # deliberately missing too: the nodes' tcp.xml discovery is cloud-specific (S3 on AWS)
    # alert channels, log destinations, alarms and checks Azure Monitor runs (planted: audit retention, no disk alarm)
    "monitoring": MONITORING["target"],
    "security": SECURITY["target"],   # the cloud security services it runs (estate)
    "access": ACCESS["target"],
    # DNS zones, forwarders, the SSO certificate in the cloud's store, edge subnets; what the source's edge runs (edge)
    "edge": EDGE["target"], "service_attrs": SERVICE_ATTRS["target"],
    "network": NETWORK["target"], "databases": DATABASES["target"], "volumes": VOLUMES["target"],
    # planted: the domain's Communication Services identity isn't DKIM-verified yet and its DMARC is weaker; no bus
    # carries the identity audit stream
    "sending": (("mail-acs", "mail-sending", "example-aero.test",
                 "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
                 "Microsoft.Communication/emailServices/ecs-ciam-prod/domains/example-aero.test", "FALSE", "TRUE",
                 "quarantine"),),
    # planted: the engines' scale set sits in one zone (the source spreads them over two)
    "compute": (("vmss-pf-engine", "compute-pf-engine", "pf-engine",
                 "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers/"
                 "Microsoft.Compute/virtualMachineScaleSets/vmss-ciam-pf-engine", IMG + "pingfederate-12.1.4-rhel9",
                 "Standard_D2s_v5", 2, 2, 4, ("1",), None),),
    "interconnect": ("link-source", "site-to-site VPN (landing-zone managed)", AWS, ["10.20.0.0/16"]),
    "servers": [("ds-1", "ds", "ds-1.az.internal.example-aero.test", "10.60.1.11", "1", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("ds-2", "ds", "ds-2.az.internal.example-aero.test", "10.60.1.12", "2", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("ds-3", "ds", "ds-3.az.internal.example-aero.test", "10.60.1.13", "3", "Standard_D4s_v5", IMG + "pingds-7.5.1-rhel9", "snet-ds", DS_V),
                ("pf-engine-1", "pf-engine", "pf-engine-1.az.internal.example-aero.test", "10.60.2.21", "1", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V),
                ("pf-engine-2", "pf-engine", "pf-engine-2.az.internal.example-aero.test", "10.60.2.22", "2", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V),
                ("pf-admin-1", "pf-admin", "pf-admin-1.az.internal.example-aero.test", "10.60.2.10", "1", "Standard_D2s_v5", IMG + "pingfederate-12.1.4-rhel9", "snet-pf", PF_V),
                ("am-1", "am", "am-1.az.internal.example-aero.test", "10.60.3.21", "1", "Standard_D2s_v5", IMG + "pingam-7.5.1-rhel9", "snet-am", AM_V),
                ("am-2", "am", "am-2.az.internal.example-aero.test", "10.60.3.22", "2", "Standard_D2s_v5", IMG + "pingam-7.5.1-rhel9", "snet-am", AM_V),
                ("idm-1", "idm", "idm-1.az.internal.example-aero.test", "10.60.6.21", "1", "Standard_D2s_v5", IMG + "pingidm-7.5.0-rhel9", "snet-idm", IDM_V),
                ("ig-1", "ig", "ig-1.az.internal.example-aero.test", "10.60.10.21", "1", "Standard_D2s_v5", IMG + "pinggateway-2024.11.0-rhel9", "snet-ig", IG_V)],
    # the PingFederate nodes run clustered here too (what discovery they use is the planted gap, not whether)
    "nodes": {"pf-engine-1": "CLUSTERED_ENGINE", "pf-engine-2": "CLUSTERED_ENGINE", "pf-admin-1": "CLUSTERED_CONSOLE"},
})
# A warm standby on Google Cloud: production's directory replicas join it over a VPN, the rest stands ready. Network
# and subnetworks belong to the landing zone's Shared VPC host project; the environment's own project holds the rest.
PROJECT, HOST = "projects/example-aero-ciam-standby", "projects/example-aero-net"
GIMG = "projects/example-aero-images/global/images/"
STANDBY = MappingProxyType({
    "stack": (("provider", "gcp"), ("directory", "pingds"), ("federation", "pingfederate"), ("access", "pingam"),
              ("identity-management", "pingidm"), ("gateway", "pinggateway")),
    "net": ("vpc", f"{HOST}/global/networks/ciam-standby", "10.70.0.0/16"), "pinned_priorities": True,
    "subnets": [(f"subnet-{r}", f"subnet-{r}", f"{HOST}/regions/us-central1/subnetworks/ciam-standby-{r}", cidr, None)
                for r, cidr in (("ds", "10.70.1.0/24"), ("pf", "10.70.2.0/24"), ("am", "10.70.3.0/24"),
                                ("idm", "10.70.6.0/24"), ("ig", "10.70.10.0/24"))],
    "services": [("svc-ldaps", "ds-ldaps-service", "ldap.id.example-aero.test", "id.example-aero.test",
                  "ciam-standby-private", "ds", [1636], "10.70.1.100", None, "ds-ldaps-2026"),
                 ("svc-sso", "pf-sso-service", "sso.example-aero.test", "example-aero.test",
                  "example-aero-public", "pf-engine", [443], "198.51.100.90", "ciam-standby-sso", "sso-tls-2026"),
                 ("svc-login", "am-service", "login.example-aero.test", "example-aero.test",
                  "example-aero-public", "am", [443], "198.51.100.91", "ciam-standby-login", None),
                 ("svc-apps", "ig-service", "apps.example-aero.test", "example-aero.test",
                  "example-aero-public", "ig", [443], "198.51.100.92", "ciam-standby-apps", None)],
    "fw": [("fw-pf-ds-svc", "fw-consumer-pf-ds-svc", ["10.70.2.0/24"], [1636], "ds", "pf-ds-svc", None),
           ("fw-customer-portal", "fw-consumer-customer-portal-svc", ["10.30.8.0/24"], [1636], "ds", "customer-portal-svc", None),
           ("fw-supplier-portal", "fw-consumer-supplier-portal-svc", ["10.31.2.0/24"], [1636], "ds", "supplier-portal-svc", None),
           ("fw-idm-sync", "fw-consumer-idm-sync", ["10.70.6.0/24"], [1636], "ds", "idm-sync", None),
           ("fw-replication", "fw-replication", ["10.70.1.0/24", "10.20.0.0/16"], [8989], "ds", None, None),
           ("fw-admin", "fw-admin", ["10.70.9.0/28"], [4444], "ds", None, None),
           ("fw-sso-public", "fw-sso-public", ["0.0.0.0/0"], [443], "pf-engine", None, None),
           ("fw-login-public", "fw-login-public", ["0.0.0.0/0"], [443], "am", None, None),
           ("fw-apps-public", "fw-apps-public", ["0.0.0.0/0"], [443], "ig", None, None),
           # the PingFederate nodes' cluster traffic (JGroups bind and failure-detection ports), engines and console
           ("fw-pf-cluster", "fw-pf-cluster", ["10.70.2.0/24"], [7600, 7700], "pf-engine", None, None),
           ("fw-pf-cluster-admin", "fw-pf-cluster-admin", ["10.70.2.0/24"], [7600, 7700], "pf-admin", None, None)],
    "egress": ("example-aero-ciam-standby/us-central1/ciam-standby-router/ciam-standby-nat", "203.0.113.150/32"),
    "time": (["metadata.google.internal"], "provider"),   # the Compute Engine metadata server's NTP
    "secret": lambda role: f"gcp-sm://{PROJECT}/secrets/{role}",
    "key": (f"gcp-kms://{PROJECT}/locations/us-central1/keyRings/ciam/cryptoKeys/disk", None),
    # the material production's replicas need is carried over, as the target's is
    "key_facts": {
        **{role: {"ciamMaterialFrom": f"cn=secret-{role},ou=bindings,{AWS}"}
           for role in ("ds-deployment-id", "ds-deployment-password", "am-keystore", "idm-keystore",
                        "pf-captcha-secret")},
        "disk-encryption": {"ciamProtectionLevel": "hsm", "ciamAutoRotate": "TRUE"},
    },
    "backup": "gs://example-aero-ciam-standby-ds-backups", "backup_depth": BACKUP["standby"],
    "discovery_protocol": "TCPPING",       # no Cloud Storage protocol for PingFederate: the nodes are listed
    "streams": (("audit-topic", "audit-events", f"{PROJECT}/topics/ciam-audit", "topic"),),
    "monitoring": MONITORING["standby"],
    "security": SECURITY["standby"],   # the cloud security services it runs (estate)
    "access": ACCESS["standby"],
    # DNS zones, forwarders, the SSO certificate in the cloud's store, edge subnets; what the source's edge runs (edge)
    "edge": EDGE["standby"], "service_attrs": SERVICE_ATTRS["standby"],
    "network": NETWORK["standby"], "firewall_model": "policy",   # rules by secure tag, in a network policy
    "databases": DATABASES["standby"], "volumes": VOLUMES["standby"],
    "compute": (("mig-pf-engine", "compute-pf-engine", "pf-engine",
                 f"{PROJECT}/regions/us-central1/instanceGroupManagers/ciam-pf-engine",
                 GIMG + "pingfederate-12-1-4-rhel9", "n2-standard-2", 2, 2, 4, ("us-central1-a", "us-central1-b"),
                 None),),
    "interconnect": ("link-source", "Cloud VPN to AWS (landing-zone managed)", AWS, ["10.20.0.0/16"]),
    "servers": [("ds-1", "ds", "ds-1.gcp.internal.example-aero.test", "10.70.1.11", "us-central1-a", "n2-standard-4", GIMG + "pingds-7-5-1-rhel9", "subnet-ds", DS_V),
                ("ds-2", "ds", "ds-2.gcp.internal.example-aero.test", "10.70.1.12", "us-central1-b", "n2-standard-4", GIMG + "pingds-7-5-1-rhel9", "subnet-ds", DS_V),
                ("pf-engine-1", "pf-engine", "pf-engine-1.gcp.internal.example-aero.test", "10.70.2.21", "us-central1-a", "n2-standard-2", GIMG + "pingfederate-12-1-4-rhel9", "subnet-pf", PF_V),
                ("pf-engine-2", "pf-engine", "pf-engine-2.gcp.internal.example-aero.test", "10.70.2.22", "us-central1-b", "n2-standard-2", GIMG + "pingfederate-12-1-4-rhel9", "subnet-pf", PF_V),
                ("pf-admin-1", "pf-admin", "pf-admin-1.gcp.internal.example-aero.test", "10.70.2.10", "us-central1-a", "n2-standard-2", GIMG + "pingfederate-12-1-4-rhel9", "subnet-pf", PF_V),
                ("am-1", "am", "am-1.gcp.internal.example-aero.test", "10.70.3.21", "us-central1-a", "n2-standard-2", GIMG + "pingam-7-5-1-rhel9", "subnet-am", AM_V),
                ("idm-1", "idm", "idm-1.gcp.internal.example-aero.test", "10.70.6.21", "us-central1-a", "n2-standard-2", GIMG + "pingidm-7-5-0-rhel9", "subnet-idm", IDM_V),
                ("ig-1", "ig", "ig-1.gcp.internal.example-aero.test", "10.70.10.21", "us-central1-a", "n2-standard-2", GIMG + "pinggateway-2024-11-0-rhel9", "subnet-ig", IG_V)],
    # what TCPPING lists: the clustered PingFederate nodes (the source's come from its node files)
    "nodes": {"pf-engine-1": "CLUSTERED_ENGINE", "pf-engine-2": "CLUSTERED_ENGINE", "pf-admin-1": "CLUSTERED_CONSOLE"},
})
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
                 ciamFirewallModel=p.get("firewall_model"), ciamOwner=owner("network-security")),
            *(spec(file, b(cn), ["top", "ciamSubnetBinding"], cn=cn, ciamBindingRole=role, ciamProviderRef=ref,
                   ciamCidr=cidr, ciamZone=zone) for cn, role, ref, cidr, zone in p["subnets"]),
            *(spec(file, b(cn), ["top", "ciamServiceName"], cn=cn, ciamBindingRole=role, ciamFqdn=fqdn,
                   ciamDnsZone=zone, ciamDnsZoneRef=zref, ciamTargetRole=trole, ciamPort=ports, ciamFrontendIp=ip,
                   ciamProviderRef=pref, ciamTlsCertificate=cert(tls)[0] if tls else None,
                   **(p.get("service_attrs") or {}).get(cn, {}))
              for cn, role, fqdn, zone, zref, trole, ports, ip, pref, tls in p["services"]),
            *(spec(file, b(cn), ["top", "ciamFirewallRule"], cn=cn, ciamBindingRole=role, ciamSourceCidr=cidrs,
                   ciamPort=ports, ciamTargetRole=trole, ciamProtocol="tcp",
                   ciamRulePriority=100 + 10 * i if p.get("pinned_priorities") else None,
                   ciamPolicyRole="firewall-policy" if p.get("firewall_model") == "policy" else None,
                   ciamAllowsConsumer=f"cn={consumer},{CON}" if consumer else None,
                   ciamChangeRef=chg(chg_) if chg_ else None)
              for i, (cn, role, cidrs, ports, trole, consumer, chg_) in enumerate(p["fw"])),
            spec(file, b("egress-pf"), ["top", "ciamEgress"], cn="egress-pf", ciamBindingRole="pf-egress",
                 ciamProviderRef=p["egress"][0], ciamCidr=p["egress"][1], ciamNatAllocation="static"),
            *((spec(file, b("time"), ["top", "ciamTimeSource"], cn="time", ciamBindingRole="time-source",
                    ciamTimeServer=p["time"][0], ciamTimeKind=p["time"][1], ciamOwner=owner("network-security")),)
              if p.get("time") else ()),
            *(spec(file, b(f"secret-{role}"), ["top", "ciamSecretRef"], cn=f"secret-{role}", ciamBindingRole=role,
                   ciamRefUri=p["secret"](role), **p["key_facts"].get(role, {})) for role in SECRET_ROLES),
            spec(file, b("key-disk"), ["top", "ciamKeyRef"], cn="key-disk", ciamBindingRole="disk-encryption",
                 ciamRefUri=p["key"][0], ciamProviderRef=p["key"][1], **p["key_facts"].get("disk-encryption", {})),
            *((spec(file, b("backup"), ["top", "ciamBackupTarget"], cn="backup", ciamBindingRole="backup-target",
                    ciamStorageRef=p["backup"], ciamRetentionDays=35, **(p.get("backup_depth") or {})),)
              if p.get("backup") else ()),
            *((spec(file, b("pf-discovery"), ["top", "ciamObjectStore"], cn="pf-discovery",
                    ciamBindingRole="pf-cluster-discovery", ciamStorageRef=p["discovery"],
                    description="PingFederate cluster discovery (NATIVE_S3_PING bucket)"),)
              if p.get("discovery") else ()),
            *((spec(file, b("pf-discovery"), ["top", "pingfedClusterDiscovery"], cn="pf-discovery",
                    ciamBindingRole="pf-cluster-discovery", pingfedDiscoveryProtocol=p["discovery_protocol"],
                    description="PingFederate cluster discovery: the nodes listed (TCPPING)"),)
              if p.get("discovery_protocol") else ()),
            *(spec(file, b(cn), ["top", "ciamComputeGroup"], cn=cn, ciamBindingRole=role, ciamTargetRole=target,
                   ciamProviderRef=ref, ciamImageRef=image, ciamInstanceSize=size, ciamMinSize=least,
                   ciamDesiredSize=runs, ciamMaxSize=most, ciamSpansZone=list(zones), ciamMetadataTokens=tokens)
              for cn, role, target, ref, image, size, least, runs, most, zones, tokens in p.get("compute") or ()),
            *(spec(file, b(cn), ["top", "ciamSendingIdentity"], cn=cn, ciamBindingRole=role, ciamSenderDomain=domain,
                   ciamProviderRef=ref, ciamDkimVerified=dkim, ciamSpfAuthorized=spf, ciamDmarcPolicy=dmarc)
              for cn, role, domain, ref, dkim, spf, dmarc in p.get("sending") or ()),
            *(spec(file, b(cn), ["top", "ciamStreamBinding"], cn=cn, ciamBindingRole=role, ciamProviderRef=ref,
                   ciamStreamKind=kind) for cn, role, ref, kind in p.get("streams") or ()),
            *(spec(file, b(cn), ["top", oc], cn=cn, ciamBindingRole=role, **attrs)
              for oc, cn, role, attrs in (*(p.get("monitoring") or ()), *(p.get("security") or ()),
                                          *(p.get("access") or ()),
                                          *(p.get("edge") or ()), *(p.get("network") or ()),
                                          *(p.get("databases") or ()), *(p.get("volumes") or ()))),
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
    """An environment's bindings, its declared stack, then its servers (placed in bindings by role; a PingFederate
    node's operational mode where the environment states it)."""
    b = lambda cn: f"cn={cn},ou=bindings,{env}"  # noqa: E731
    nodes = p.get("nodes") or {}
    return (*_bindings(file, env, p), *_stack(file, env, p),
            *(spec(file, f"cn={cn},{env}", ["top", "ciamServer", *(("pingfedNode",) if cn in nodes else ())], cn=cn,
                   ciamServerRole=role, ciamHostname=host, ciamPrivateIp=ip, ciamZone=zone, ciamInstanceSize=size,
                   ciamImageRef=image, ciamSubnet=b(subnet), ciamProductVersion=version,
                   pingfedOperationalMode=nodes.get(cn), ciamOwner=owner("ciam-platform"))
              for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]))


def environments():
    aws, az, gcp = "40-env-source", "45-env-target", "47-env-standby"
    return (spec(aws, f"cloud=source,{ENVS}", ["top", "ciamCloud", "ciamCloudAccount"], cloud="source",
                 ciamAccountRef=ACCOUNTS["source"],
                 ciamCloudProvider="aws", ciamRegion="us-east-1", ciamCloudEnvironment="public", ciamLifecycle="active",
                 description="Primary hosting environment (AWS)"),
            spec(aws, AWS, ["top", "ciamEnvironment", "ciamEnvironmentPlacement"], env="prod", ciamLifecycle="active",
                 ciamDataClassification=CLASSIFICATION["source"], ciamOwner=owner("ciam-platform")),
            *environment(aws, AWS, SOURCE), *required_roles(aws, AWS),
            *stage(),
            spec(az, f"cloud=target,{ENVS}", ["top", "ciamCloud", "ciamCloudAccount"], cloud="target",
                 ciamAccountRef=ACCOUNTS["target"],
                 ciamCloudProvider="azure", ciamRegion="eastus2", ciamCloudEnvironment="public",
                 ciamLifecycle="building",
                 description="Second hosting environment (Azure)"),
            spec(az, AZ, ["top", "ciamEnvironment"], env="prod", ciamLifecycle="building",
                 ciamPlannedCutover=t("2027-01-15"), ciamJoinsDeploymentOf=AWS, ciamOwner=owner("ciam-platform")),
            *environment(az, AZ, TARGET), *required_roles(az, AZ),
            spec(gcp, f"cloud=standby,{ENVS}", ["top", "ciamCloud", "ciamCloudAccount"], cloud="standby",
                 ciamAccountRef=ACCOUNTS["standby"],
                 ciamCloudProvider="gcp", ciamRegion="us-central1", ciamCloudEnvironment="public",
                 ciamLifecycle="building", description="Warm standby (Google Cloud)"),
            spec(gcp, GCP, ["top", "ciamEnvironment", "ciamStandby", "ciamEnvironmentPlacement"], env="prod",
                 ciamLifecycle="building", ciamDataClassification=CLASSIFICATION["standby"],
                 ciamJoinsDeploymentOf=AWS, **STANDBY_INTENT, ciamOwner=owner("ciam-platform"),
                 description="Warm standby of production: directory replicas join its deployment over a VPN"),
            *environment(gcp, GCP, STANDBY))


STAGE = f"env=stage,cloud=source,{ENVS}"
# what stage has of its own; everything else (network, subnets, egress, disk key, firewall rules) it shares with prod
STAGE_SERVICES = (("svc-ldaps", "ds-ldaps-service", "ldap.stage.id.example-aero.test", "id.example-aero.test",
                   "Z0EXAMPLE1PRIVATE", "ds", 1636, "10.20.1.150", None),
                  ("svc-sso", "pf-sso-service", "sso.stage.example-aero.test", "example-aero.test",
                   "Z0EXAMPLE2PUBLIC", "pf-engine", 443, "198.51.100.30", "eipalloc-0a1b2c3d4e5f60002"),
                  ("svc-login", "am-service", "login.stage.example-aero.test", "example-aero.test",
                   "Z0EXAMPLE2PUBLIC", "am", 443, "198.51.100.31", "eipalloc-0a1b2c3d4e5f60004"),
                  ("svc-apps", "ig-service", "apps.stage.example-aero.test", "example-aero.test",
                   "Z0EXAMPLE2PUBLIC", "ig", 443, "198.51.100.32", "eipalloc-0a1b2c3d4e5f60006"))
STAGE_SERVERS = (("ds-s1", "ds", "10.20.1.31", "us-east-1a", "subnet-ds-a", "ami-0abcdef1234567890", DS_V),
                 ("pf-engine-s1", "pf-engine", "10.20.4.31", "us-east-1a", "subnet-pf-a", "ami-0fedcba9876543210", PF_V),
                 ("pf-admin-s1", "pf-admin", "10.20.4.32", "us-east-1a", "subnet-pf-a", "ami-0fedcba9876543210", PF_V),
                 ("am-s1", "am", "10.20.7.31", "us-east-1a", "subnet-am-a", "ami-0a9b8c7d6e5f40321", AM_V),
                 ("idm-s1", "idm", "10.20.6.31", "us-east-1a", "subnet-idm-a", "ami-0b1c2d3e4f5a60987", IDM_V),
                 ("ig-s1", "ig", "10.20.10.31", "us-east-1a", "subnet-ig-a", "ami-0c2d3e4f5a6b70123", IG_V))
# consumers reach production only (its firewall rules, its LDAPS endpoint service); the private endpoint and the egress
# firewall are the shared VPC's, kept by production's root; stage's disks aren't snapshotted or backed up (stage is
# rebuilt, and a backup selection by tag in the shared account would back up production's volumes twice); the
# account's CloudTrail trail and the bucket keeping its log files are production's too (one trail records the account),
# and so are its security services, the topic their findings go to and AWS Config's bucket (each covers the account)
STAGE_DROPS = (*(role for _, role, *_ in SOURCE["fw"] if role.startswith("fw-consumer-") and role != "fw-consumer-pf-ds-svc"),
               "ldaps-endpoint-service", "private-secrets", "egress-firewall", "snapshots-daily", "backup-daily",
               "backup-vault", "audit-trail", "audit-archive",
               *(role for oc, _, role, _ in SECURITY["source"]))
# (name, overridden entry, attribute, value, why)
STAGE_OVERRIDES = (
    ("replicas", f"cn=topology,ou=replication,{DECL}", "ciamReplicaCount", 1, "stage runs one directory replica"),
    ("customer-lockout", f"cn=customers,ou=password-policies,{DECL}", "ciamLockoutFailureCount", 20,
     "test automation signs in repeatedly"),
    ("tech-pubs-token", f"cn=tech-pubs,{INTS}", "xTokenLifetimeMinutes", 5, "short tokens to test refresh"),
)
# roles declared required as data (beyond what domains and adapters require): (environment, role, why)
REQUIRED_ROLES = ((AWS, "backup-target", "every production-grade environment keeps directory backups (RPO 24 h)"),
                  (AZ, "cross-cloud-replication", "target replicas join the source's deployment over the interconnect"))


def stage():
    """source/stage, an overlay of source/prod: its own servers, service names, secrets and backups, prod's network
    and firewall rules (except the consumers'), and overrides of shared intent."""
    file, B = "42-env-source-stage", f"ou=bindings,{STAGE}"
    return (spec(file, STAGE, ["top", "ciamEnvironment", "ciamEnvironmentPlacement"], env="stage",
                 ciamLifecycle="active", ciamDataClassification=CLASSIFICATION["stage"], ciamOverlayOf=AWS,
                 ciamDropsRole=STAGE_DROPS, ciamOwner=owner("ciam-platform"),
                 description="Stage: an overlay of production (shared network, own servers and secrets)"),
            spec(file, B, ["top", "organizationalUnit"], ou="bindings"),
            *(spec(file, f"cn={cn},{B}", ["top", "ciamServiceName"], cn=cn, ciamBindingRole=role, ciamFqdn=fqdn,
                   ciamDnsZone=zone, ciamDnsZoneRef=zref, ciamTargetRole=trole, ciamPort=port, ciamFrontendIp=ip,
                   ciamProviderRef=pref) for cn, role, fqdn, zone, zref, trole, port, ip, pref in STAGE_SERVICES),
            *(spec(file, f"cn=secret-{role},{B}", ["top", "ciamSecretRef"], cn=f"secret-{role}", ciamBindingRole=role,
                   ciamRefUri=f"aws-sm://arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/stage/{role}")
              for role in SECRET_ROLES),
            spec(file, f"cn=backup,{B}", ["top", "ciamBackupTarget"], cn="backup", ciamBindingRole="backup-target",
                 ciamStorageRef="s3://example-aero-ciam-stage-ds-backups", ciamRetentionDays=7),
            spec(file, f"cn=pf-discovery,{B}", ["top", "ciamObjectStore"], cn="pf-discovery",
                 ciamBindingRole="pf-cluster-discovery",
                 ciamStorageRef="s3://example-aero-ciam-stage-pf-cluster",
                 description="Stage's own PingFederate cluster discovery: never prod's"),
            *(spec(file, f"cn={cn},{B}", ["top", oc], cn=cn, ciamBindingRole=role, **attrs)
              for oc, cn, role, attrs in (*DATABASES["stage"], *VOLUMES["stage"])),
            spec(file, f"ou=overrides,{STAGE}", ["top", "organizationalUnit"], ou="overrides"),
            *(spec(file, f"cn={cn},ou=overrides,{STAGE}", ["top", "ciamOverride"], cn=cn, ciamOverrides=target,
                   ciamOverrideAttribute=attr, ciamOverrideValue=value, description=why, ciamOwner=owner("ciam-platform"))
              for cn, target, attr, value, why in STAGE_OVERRIDES),
            *(spec(file, f"cn={cn},{STAGE}", ["top", "ciamServer"], cn=cn, ciamServerRole=role,
                   ciamHostname=f"{cn}.aws.internal.example-aero.test", ciamPrivateIp=ip, ciamZone=zone,
                   ciamInstanceSize="m6i.large", ciamImageRef=image, ciamSubnet=f"cn={subnet},ou=bindings,{AWS}",
                   ciamProductVersion=version, ciamOwner=owner("ciam-platform"))
              for cn, role, ip, zone, subnet, image, version in STAGE_SERVERS))


def required_roles(file, env):
    """The roles an environment declares it must bind, under its ou=stack."""
    return tuple(spec(file, f"cn={role},ou=stack,{e}", ["top", "ciamRequiredRole"], cn=role, ciamBindingRole=role,
                      description=why, ciamOwner=owner("ciam-platform"))
                 for e, role, why in REQUIRED_ROLES if e == env)


def external_allowlists():
    return tuple(spec("80-external-allowlists", f"cn={cn},{XA}", ["top", "ciamExternalAllowlist"], cn=cn,
                      ciamManagedBy=owner(mgr)[0], ciamExternalSystem=system, ciamAllowlistDirection=direction,
                      ciamRefersToRole=role, ciamRecordedCidr=recorded, ciamLeadTimeDays=lead, ciamRequestStatus=status,
                      ciamAllowsConsumer=f"cn={consumer},{CON}" if consumer else None, ciamOwner=owner("ciam-platform"))
                 for cn, mgr, system, direction, role, recorded, lead, status, consumer in ALLOWLISTS)
