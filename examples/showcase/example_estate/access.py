"""Access fixture data (80-access): who and what may act on the platform. Permission sets name what may be done as
verbs on binding roles, so one set means each environment's own secrets, keys, buckets and log destinations;
principals hold them: PingFederate's and PingDS's servers (workloads), the ciam-ops pipeline (deployer), the platform
admins (operators, by MFA and just-in-time elevation) and the break-glass account. What realizes them is a binding per
environment (ACCESS below, used by infrastructure: SOURCE / TARGET / STANDBY): the cloud identity each acts as with
what the cloud grants it, the organization guardrails over the environment, and the ways operators come in.

Planted for the planner to find:
  - the source's directory role is granted s3:* on everything, wider than its permissions
  - the platform admins' access review is over a year old; the break-glass account was last tested 2025-11-03
  - the source runs an IDM role nobody records as acting as it, and the target doesn't bind it
  - the target's guardrails don't stop audit logs being disabled; operators can't come in by a session manager there
  - in the target the admins' Key Vault rights are PIM-eligible only: whether they may manage the keys can't be told
"""
from .common import RB, R, ou, owner, spec, t

FILE = "80-access"
SETS, PRINCIPALS = f"ou=permission-sets,{R}", f"ou=principals,{R}"
PERMISSION_SETS = (
    ("pf-runtime", "What PingFederate's servers read and write",
     ("read-secret pf-admin-password", "read-secret pf-signing-key", "read-secret pf-ds-bind-password",
      "write-logs audit-logs")),
    ("ds-runtime", "What the directory servers read and write",
     ("read-secret ds-root-password", "use-key disk-encryption", "write-storage backup-target", "write-logs audit-logs")),
    ("release", "What the ciam-ops pipeline changes when it releases",
     ("write-secret pf-admin-password", "manage pf-sso-service")),
    ("platform-admin", "What the platform admins manage",
     ("manage pf-admin-password", "manage-key disk-encryption", "read-logs audit-logs")),
)
# cn, kind, identity role, server role it runs on, permission set, conditions, reviewed on, extra attributes
PRINCIPAL_ROWS = (
    ("pingfederate", "workload", "identity-pf", "pf-engine", "pf-runtime", (), "2026-06-01", {}),
    ("pingds", "workload", "identity-ds", "ds", "ds-runtime", (), "2026-06-01", {}),
    ("ciam-ops-ci", "deployer", "identity-ci", None, "release", (), "2026-04-15", {}),
    # planted: reviewed 2025-06-30, more than a year before the plan
    ("ciam-admins", "operator", "identity-admins", None, "platform-admin", ("mfa", "jit"), "2025-06-30", {}),
    # planted: the procedure was last exercised 2025-11-03, over 180 days ago
    ("break-glass-root", "break-glass", "identity-break-glass", None, None, ("mfa",), "2026-03-01",
     {"ciamUsesRole": "ds-root-password", "ciamRunbookRef": f"cn=WI-CIAM-012,{RB}",
      "ciamLastTested": t("2025-11-03")}),
)
GITHUB = "https://token.actions.githubusercontent.com"


def entries():
    return (ou(FILE, "permission-sets"),
            *(spec(FILE, f"cn={cn},{SETS}", ["top", "ciamObject", "ciamPermissionSet"], cn=cn, description=desc,
                   ciamPermits=list(permits), ciamOwner=owner("ciam-platform"))
              for cn, desc, permits in PERMISSION_SETS),
            ou(FILE, "principals"),
            *(spec(FILE, f"cn={cn},{PRINCIPALS}", ["top", "ciamObject", "ciamPrincipal"], cn=cn,
                   ciamPrincipalKind=kind, ciamIdentityRole=role, ciamTargetRole=target,
                   ciamHoldsSet=f"cn={held},{SETS}" if held else None, ciamCondition=list(conditions) or None,
                   ciamReviewedOn=t(reviewed), ciamOwner=owner("ciam-platform"), **extra)
              for cn, kind, role, target, held, conditions, reviewed, extra in PRINCIPAL_ROWS))


# ------------------------------------------------------------------ each environment's access bindings
ACCT = "arn:aws:iam::111122223333"
SM = "arn:aws:secretsmanager:us-east-1:111122223333:secret:ciam/prod/"
KMS = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab"
AUDIT = "arn:aws:logs:us-east-1:111122223333:log-group:/ciam/prod/audit:*"
ELB = "arn:aws:elasticloadbalancing:*:*"
ADMINS_AWS = "9a4f7c2e-0000-4000-8000-0000000000a1"          # the Identity Center group's id
# AWS identities: (cn, kind, provider ref, trusted by, grants)
AWS_IDENTITIES = (
    ("identity-pf", "role", f"{ACCT}:role/ciam-prod-pf", ("ec2.amazonaws.com",),
     (f"secretsmanager:GetSecretValue on {SM}*", f"logs:PutLogEvents on {AUDIT}", f"logs:CreateLogStream on {AUDIT}")),
    # planted: s3:* on everything, wider than writing backups
    ("identity-ds", "role", f"{ACCT}:role/ciam-prod-ds", ("ec2.amazonaws.com",),
     (f"secretsmanager:GetSecretValue on {SM}ds-root-password-??????", "s3:* on *", f"logs:PutLogEvents on {AUDIT}",
      f"logs:CreateLogStream on {AUDIT}", f"kms:Decrypt on {KMS}", f"kms:Encrypt on {KMS}",
      f"kms:GenerateDataKey on {KMS}")),
    # planted: nobody records what acts as it, and the target doesn't bind it
    ("identity-idm", "role", f"{ACCT}:role/ciam-prod-idm", ("ec2.amazonaws.com",),
     (f"secretsmanager:GetSecretValue on {SM}idm-*",)),
    ("identity-ci", "federated", f"{ACCT}:role/ciam-prod-deploy",
     (f"{GITHUB} repo:example-aero/ciam-ops:environment:prod",),
     (f"secretsmanager:PutSecretValue on {SM}pf-admin-password-??????",
      f"elasticloadbalancing:ModifyListener on {ELB}:listener/net/ciam-prod-svc-sso/*",
      f"elasticloadbalancing:RegisterTargets on {ELB}:targetgroup/ciam-prod-svc-sso-*",
      f"elasticloadbalancing:DeregisterTargets on {ELB}:targetgroup/ciam-prod-svc-sso-*",
      "route53:ChangeResourceRecordSets on arn:aws:route53:::hostedzone/Z0EXAMPLE2PUBLIC")),
    ("identity-admins", "permission-set", ADMINS_AWS, (),
     (*(f"secretsmanager:{a} on {SM}pf-admin-password-??????"
        for a in ("PutSecretValue", "UpdateSecret", "RotateSecret", "DeleteSecret")),
      *(f"kms:{a} on {KMS}" for a in ("DescribeKey", "EnableKeyRotation", "PutKeyPolicy")),
      f"logs:GetLogEvents on {AUDIT}", f"logs:FilterLogEvents on {AUDIT}")),
    ("identity-break-glass", "role", f"{ACCT}:role/ciam-prod-break-glass", (f"{ACCT}:root",), ()),
)
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-ciam-prod"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-ciam-prod"
MI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities"
AZURE_IDENTITIES = (
    ("identity-pf", "managed-identity", f"{MI}/id-ciam-prod-pf", (),
     (f"Key Vault Secrets User on {VAULT}", f"Monitoring Metrics Publisher on {RG}")),
    ("identity-ds", "managed-identity", f"{MI}/id-ciam-prod-ds", (),
     (f"Key Vault Secrets User on {VAULT}", f"Key Vault Crypto User on {VAULT}",
      f"Monitoring Metrics Publisher on {RG}")),
    ("identity-ci", "federated", f"{MI}/id-ciam-prod-deploy",
     (f"{GITHUB} repo:example-aero/ciam-ops:environment:target-prod",),
     (f"Key Vault Secrets Officer on {VAULT}", f"Network Contributor on {RG}", f"DNS Zone Contributor on {RG}")),
    # planted: the admins' vault rights are PIM-eligible only
    ("identity-admins", "group", "5b2c0000-0000-4000-8000-0000000000a1", (),
     (f"Key Vault Administrator on {VAULT} (eligible)", f"Log Analytics Reader on {RG}")),
    ("identity-break-glass", "user", "7e1d0000-0000-4000-8000-0000000000b9", (), ()),
)
GCP_PROJECT = "projects/example-aero-ciam-standby"
SA = "{}@example-aero-ciam-standby.iam.gserviceaccount.com"
GCP_IDENTITIES = (
    ("identity-pf", "service-account", SA.format("ciam-standby-pf"), (),
     (f"roles/secretmanager.secretAccessor on {GCP_PROJECT}", f"roles/logging.logWriter on {GCP_PROJECT}")),
    ("identity-ds", "service-account", SA.format("ciam-standby-ds"), (),
     (f"roles/secretmanager.secretAccessor on {GCP_PROJECT}",
      "roles/storage.objectCreator on projects/_/buckets/example-aero-ciam-standby-ds-backups",
      f"roles/cloudkms.cryptoKeyEncrypterDecrypter on {GCP_PROJECT}/locations/us-central1/keyRings/ciam",
      f"roles/logging.logWriter on {GCP_PROJECT}")),
    ("identity-ci", "federated", SA.format("ciam-standby-deploy"),
     (f"{GITHUB} repo:example-aero/ciam-ops:environment:standby",),
     (f"roles/secretmanager.secretVersionAdder on {GCP_PROJECT}", f"roles/compute.loadBalancerAdmin on {GCP_PROJECT}",
      f"roles/dns.admin on {GCP_PROJECT}")),
    ("identity-admins", "group", "ciam-admins@example-aero.test", (),
     (f"roles/secretmanager.admin on {GCP_PROJECT}", f"roles/cloudkms.admin on {GCP_PROJECT}",
      f"roles/logging.viewer on {GCP_PROJECT}")),
    ("identity-break-glass", "user", "breakglass@example-aero.test", (), (f"roles/owner on {GCP_PROJECT}",)),
)


def _identities(rows):
    return tuple(("ciamIdentityBinding", cn, cn, {"ciamIdentityKind": kind, "ciamProviderRef": ref,
                                                  "ciamTrustedBy": list(trusted) or None,
                                                  "ciamGrant": list(grants) or None})
                 for cn, kind, ref, trusted, grants in rows)


def _guardrail(kind, ref, denies):
    return ("ciamGuardrail", "org-guardrails", "org-guardrails",
            {"ciamGuardrailKind": kind, "ciamProviderRef": ref, "ciamDenies": list(denies),
             "ciamOwner": owner("cloud-landing-zone")})


def _path(cn, kind, ref, trusted=None):
    return ("ciamAccessPath", cn, cn, {"ciamAccessKind": kind, "ciamProviderRef": ref, "ciamTrustedBy": trusted})


# Each environment's access bindings: (class, name, binding role, attributes), as infrastructure lays them out
ACCESS = {
    "source": (*_identities(AWS_IDENTITIES),
               _guardrail("service-control", "arn:aws:organizations::111122223333:policy/o-exampleaero1/"
                                             "service_control_policy/p-ciamfence1",
                          ("region-escape", "audit-log-disable", "key-deletion")),
               _path("operator-sso", "workforce-sso", "arn:aws:sso:::instance/ssoins-72231a2b3c4d5e6f",
                     "d-9067a1b2c3"),
               _path("operator-console", "session",
                     "arn:aws:ssm:us-east-1:111122223333:document/SSM-SessionManagerRunShell")),
    "target": (*_identities(AZURE_IDENTITIES),
               # planted: nothing stops audit logs being disabled in the target
               _guardrail("policy-assignment", f"{SUB}/providers/Microsoft.Authorization/policyAssignments",
                          ("region-escape", "public-storage", "key-deletion")),
               _path("operator-sso", "workforce-sso", "https://login.microsoftonline.com/example-aero.test"),
               # planted: operators reach the target's servers by a bastion, not a session manager
               _path("operator-console", "bastion", f"{RG}/providers/Microsoft.Network/bastionHosts/bas-ciam-prod")),
    "standby": (*_identities(GCP_IDENTITIES),
                _guardrail("org-constraint", f"{GCP_PROJECT}/policies",
                           ("region-escape", "public-storage", "audit-log-disable", "service-account-keys",
                            "key-deletion")),
                _path("operator-sso", "workforce-sso", "https://accounts.google.com/o/saml2?idpid=C0example"),
                _path("operator-console", "iap", f"{GCP_PROJECT}/iap_tunnel")),
}
