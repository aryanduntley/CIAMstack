"""Access domain schema: who and what may act on the platform. Permission sets and principals are intent, the same in
every environment: a permission is a neutral verb on a binding role (read-secret pf-admin-password), so one set means
each environment's own secret, key or bucket. What realizes them is a binding per environment: the cloud identity a
principal acts as (a role, a managed identity, a service account) with the grants the cloud gives it in its own terms,
the organization guardrails over the environment, and the paths operators come in by."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import ACCESS_KINDS, GUARDRAIL_KINDS, IDENTITY_KINDS, PERMIT, PRINCIPAL_KINDS

ATTRIBUTES = (
    # ------------------------------------------------------------------ intent
    AttributeDef(326, 'ciamPermits', 'string', 'intent', False,
                 "What a permission set allows: a verb on a binding role (read-secret pf-admin-password, use-key "
                 "disk-encryption, write-storage backup-target); each environment's binding of the role is the "
                 "resource",
                 (("X-PATTERN", PERMIT),)),
    AttributeDef(327, 'ciamPrincipalKind', enum_type(PRINCIPAL_KINDS), 'intent', True,
                 'What acts: a workload (servers of a role, a compute group, a Kubernetes workload, a job), a deployer '
                 '(a CI pipeline), an operator role, a break-glass account, a service'),
    AttributeDef(328, 'ciamHoldsSet', 'dn', 'intent', False, 'A permission set a principal holds'),
    AttributeDef(329, 'ciamCondition', 'string', 'intent', False,
                 'A condition on what a principal may do, stated neutrally (mfa, source-network 10.20.9.0/28, '
                 'approval, business-hours)'),
    AttributeDef(330, 'ciamReviewIntervalDays', 'int', 'meta', True,
                 "How often a principal's access must be reviewed, in days (365 when not stated)"),
    AttributeDef(331, 'ciamLastTested', 'time', 'meta', True,
                 'When a break-glass procedure was last exercised end to end'),
    # ------------------------------------------------------------------ bindings
    AttributeDef(332, 'ciamIdentityKind', enum_type(IDENTITY_KINDS), 'binding', True,
                 'What realizes a principal in an environment: a role (IAM role, instance profile), a managed '
                 'identity, a service account, a federated trust, a permission set, a group'),
    AttributeDef(333, 'ciamGrant', 'string', 'binding', False,
                 "What the cloud grants an identity, in its own terms: '<action or role> on <resource>', with "
                 "' (resource policy)' when a resource's policy grants it rather than the identity's"),
    AttributeDef(334, 'ciamTrustedBy', 'string', 'binding', False,
                 'Who may act as an identity or come in by a path: a service (ec2.amazonaws.com), an OIDC issuer '
                 'and subject (a CI pipeline), a Kubernetes service account (namespace/name), an identity provider'),
    AttributeDef(335, 'ciamGuardrailKind', enum_type(GUARDRAIL_KINDS), 'binding', True,
                 'What an organization guardrail is: a service or resource control policy, a policy or deny '
                 'assignment, an organization policy constraint'),
    AttributeDef(336, 'ciamDenies', 'string', 'binding', False,
                 'What a guardrail prevents, named neutrally (region-escape, public-storage, audit-log-disable, '
                 'service-account-keys, metadata-v1, root-use, key-deletion)',
                 (("X-PATTERN", "^[a-z0-9][a-z0-9-]*$"),)),
    AttributeDef(337, 'ciamAccessKind', enum_type(ACCESS_KINDS), 'binding', True,
                 'How operators come in: workforce single sign-on, a session manager, a bastion, identity-aware '
                 'proxy forwarding, a VPN, just-in-time elevation'),
    # ------------------------------------------------------------------ what limits or decides it
    AttributeDef(338, 'ciamDenial', 'string', 'binding', False,
                 "An explicit deny over an identity (its own policies, a resource's, a deny assignment or policy) or "
                 "every identity under a guardrail, in the cloud's terms: '<action> on <resource>'; an action "
                 "'!<pattern>' denies every action but those (NotAction); ' (if <condition>)' when conditional"),
    AttributeDef(339, 'ciamBoundary', 'string', 'binding', False,
                 "A ceiling on what an identity (a permissions boundary) or every identity under a guardrail (a "
                 "service or resource control policy's allows) may be granted, in the cloud's terms: '<action> on "
                 "<resource>'; when any is recorded, a grant outside every one is not effective"),
    AttributeDef(340, 'ciamEvaluated', 'string', 'binding', False,
                 "A cloud evaluator's verdict on one of an identity's permissions: '<verb> <role>: allowed|denied|"
                 "unknown (<evaluator> <YYYY-MM-DD>)', preferred over evaluating the recorded policies",
                 (("X-PATTERN", "^[a-z-]+ [a-z0-9][a-z0-9-]*: (allowed|denied|unknown) \\(.+\\)$"),)),
    AttributeDef(621, 'ciamIdentityClientId', 'string', 'binding', True,
                 "The client id of a cloud identity, where the cloud addresses it by one apart from its resource "
                 "(an Azure user-assigned managed identity: what AKS workload identity and the Key Vault CSI provider "
                 "name)"),
)
CLASSES = (
    ClassDef(69, 'ciamPermissionSet', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamPermits'), (),
             'What may be done, as verbs on binding roles: the same set means each environment\'s own resources'),
    ClassDef(70, 'ciamPrincipal', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamPrincipalKind', 'ciamIdentityRole'),
             ('ciamHoldsSet', 'ciamTargetRole', 'ciamCondition', 'ciamReviewedOn', 'ciamReviewIntervalDays',
              'ciamUsesRole', 'ciamRunbookRef', 'ciamLastTested'),
             'Who or what acts on the platform: the binding role of the identity each environment gives it, the '
             'permission sets it holds, the server role that runs as it, its conditions and reviews; a break-glass '
             "account's credential role, procedure and last test"),
    ClassDef(71, 'ciamIdentityBinding', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef',),
             ('ciamIdentityKind', 'ciamGrant', 'ciamTrustedBy', 'ciamDenial', 'ciamBoundary', 'ciamEvaluated',
              'ciamIdentityClientId'),
             'The cloud identity a principal acts as in an environment, what the cloud grants it and who may act as '
             'it'),
    ClassDef(72, 'ciamGuardrail', 'ciamBinding', 'STRUCTURAL', ('ciamGuardrailKind',),
             ('ciamProviderRef', 'ciamDenies', 'ciamDenial', 'ciamBoundary'),
             'An organization guardrail over an environment and what it prevents (kept by the landing zone)'),
    ClassDef(73, 'ciamAccessPath', 'ciamBinding', 'STRUCTURAL', ('ciamAccessKind',),
             ('ciamProviderRef', 'ciamTrustedBy', 'ciamGrant'),
             'How operators come into an environment: single sign-on, a session manager, a bastion, a proxy, '
             'just-in-time elevation'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
