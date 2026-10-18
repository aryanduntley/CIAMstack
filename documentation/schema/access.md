# Access

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 5 object classes · 16 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Access domain schema: who and what may act on the platform. Permission sets and principals are intent, the same in every environment: a permission is a neutral verb on a binding role (read-secret pf-admin-password), so one set means each environment's own secret, key or bucket. What realizes them is a binding per environment: the cloud identity a principal acts as (a role, a managed identity, a service account) with the grants the cloud gives it in its own terms, the organization guardrails over the environment, and the paths operators come in by.

**Branches:** `ou=permission-sets,dc=ciam-ops`, `ou=principals,dc=ciam-ops`

## Object classes

<a id="c-ciamaccesspath"></a>
### ciamAccessPath

How operators come into an environment: single sign-on, a session manager, a bastion, a proxy, just-in-time elevation

OID `1.3.6.1.4.1.32473.1.2.73` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamAccessKind`](#a-ciamaccesskind) | yes | `enum` | single | How operators come in: workforce single sign-on, a session manager, a bastion, identity-aware proxy forwarding, a VPN, just-in-time elevation |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamTrustedBy`](#a-ciamtrustedby) |  | `string` | multi | Who may act as an identity or come in by a path: a service (ec2.amazonaws.com), an OIDC issuer and subject (a CI pipeline), a Kubernetes service account (namespace/name), an identity provider |
| [`ciamGrant`](governance.md#c-ciamgrant) |  | `string` | multi | What the cloud grants an identity, in its own terms: '<action or role> on <resource>', with ' (resource policy)' when a resource's policy grants it rather than the identity's |

<a id="c-ciamguardrail"></a>
### ciamGuardrail

An organization guardrail over an environment and what it prevents (kept by the landing zone)

OID `1.3.6.1.4.1.32473.1.2.72` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamGuardrailKind`](#a-ciamguardrailkind) | yes | `enum` | single | What an organization guardrail is: a service or resource control policy, a policy or deny assignment, an organization policy constraint |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamDenies`](#a-ciamdenies) |  | `string` | multi | What a guardrail prevents, named neutrally (region-escape, public-storage, audit-log-disable, service-account-keys, metadata-v1, root-use, key-deletion) |
| [`ciamDenial`](#a-ciamdenial) |  | `string` | multi | An explicit deny over an identity (its own policies, a resource's, a deny assignment or policy) or every identity under a guardrail, in the cloud's terms: '<action> on <resource>'; an action '!<pattern>' denies every action but those (NotAction); ' (if <condition>)' when conditional |
| [`ciamBoundary`](#a-ciamboundary) |  | `string` | multi | A ceiling on what an identity (a permissions boundary) or every identity under a guardrail (a service or resource control policy's allows) may be granted, in the cloud's terms: '<action> on <resource>'; when any is recorded, a grant outside every one is not effective |

<a id="c-ciamidentitybinding"></a>
### ciamIdentityBinding

The cloud identity a principal acts as in an environment, what the cloud grants it and who may act as it

OID `1.3.6.1.4.1.32473.1.2.71` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) | yes | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamIdentityKind`](#a-ciamidentitykind) |  | `enum` | single | What realizes a principal in an environment: a role (IAM role, instance profile), a managed identity, a service account, a federated trust, a permission set, a group |
| [`ciamGrant`](governance.md#c-ciamgrant) |  | `string` | multi | What the cloud grants an identity, in its own terms: '<action or role> on <resource>', with ' (resource policy)' when a resource's policy grants it rather than the identity's |
| [`ciamTrustedBy`](#a-ciamtrustedby) |  | `string` | multi | Who may act as an identity or come in by a path: a service (ec2.amazonaws.com), an OIDC issuer and subject (a CI pipeline), a Kubernetes service account (namespace/name), an identity provider |
| [`ciamDenial`](#a-ciamdenial) |  | `string` | multi | An explicit deny over an identity (its own policies, a resource's, a deny assignment or policy) or every identity under a guardrail, in the cloud's terms: '<action> on <resource>'; an action '!<pattern>' denies every action but those (NotAction); ' (if <condition>)' when conditional |
| [`ciamBoundary`](#a-ciamboundary) |  | `string` | multi | A ceiling on what an identity (a permissions boundary) or every identity under a guardrail (a service or resource control policy's allows) may be granted, in the cloud's terms: '<action> on <resource>'; when any is recorded, a grant outside every one is not effective |
| [`ciamEvaluated`](#a-ciamevaluated) |  | `string` | multi | A cloud evaluator's verdict on one of an identity's permissions: '<verb> <role>: allowed\|denied\|unknown (<evaluator> <YYYY-MM-DD>)', preferred over evaluating the recorded policies |
| [`ciamIdentityClientId`](#a-ciamidentityclientid) |  | `string` | single | The client id of a cloud identity, where the cloud addresses it by one apart from its resource (an Azure user-assigned managed identity: what AKS workload identity and the Key Vault CSI provider name) |

<a id="c-ciampermissionset"></a>
### ciamPermissionSet

What may be done, as verbs on binding roles: the same set means each environment's own resources

OID `1.3.6.1.4.1.32473.1.2.69` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamPermits`](#a-ciampermits) | yes | `string` | multi | What a permission set allows: a verb on a binding role (read-secret pf-admin-password, use-key disk-encryption, write-storage backup-target); each environment's binding of the role is the resource |

<a id="c-ciamprincipal"></a>
### ciamPrincipal

Who or what acts on the platform: the binding role of the identity each environment gives it, the permission sets it holds, the server role that runs as it, its conditions and reviews; a break-glass account's credential role, procedure and last test

OID `1.3.6.1.4.1.32473.1.2.70` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamPrincipalKind`](#a-ciamprincipalkind) | yes | `enum` | single | What acts: a workload (servers of a role, a compute group, a Kubernetes workload, a job), a deployer (a CI pipeline), an operator role, a break-glass account, a service |
| [`ciamIdentityRole`](compute.md#a-ciamidentityrole) | yes | `string` | single | The binding role whose cloud identity a workload assumes (workload identity): each environment binds it |
| [`ciamHoldsSet`](#a-ciamholdsset) |  | `dn` | multi | A permission set a principal holds |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) |  | `vocab` | single | Server role a service or rule targets |
| [`ciamCondition`](#a-ciamcondition) |  | `string` | multi | A condition on what a principal may do, stated neutrally (mfa, source-network 10.20.9.0/28, approval, business-hours) |
| [`ciamReviewedOn`](directory.md#a-ciamreviewedon) |  | `time` | single | Last review (of the access an ACI grants, of a consumer record) |
| [`ciamReviewIntervalDays`](#a-ciamreviewintervaldays) |  | `int` | single | How often a principal's access must be reviewed, in days (365 when not stated) |
| [`ciamUsesRole`](automation.md#a-ciamusesrole) |  | `string` | multi | A binding role the job uses (a secret, a service name, a storage location): each environment binds it |
| [`ciamRunbookRef`](custom.md#a-ciamrunbookref) |  | `dn` | multi | Runbooks about it |
| [`ciamLastTested`](#a-ciamlasttested) |  | `time` | single | When a break-glass procedure was last exercised end to end |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamaccesskind"></a>`ciamAccessKind` | `1.3.6.1.4.1.32473.1.1.337` | enum: `workforce-sso`, `session`, `bastion`, `iap`, `vpn`, `jit-elevation`, `other` | binding | single |  | How operators come in: workforce single sign-on, a session manager, a bastion, identity-aware proxy forwarding, a VPN, just-in-time elevation |
| <a id="a-ciamboundary"></a>`ciamBoundary` | `1.3.6.1.4.1.32473.1.1.339` | `string` | binding | multi |  | A ceiling on what an identity (a permissions boundary) or every identity under a guardrail (a service or resource control policy's allows) may be granted, in the cloud's terms: '<action> on <resource>'; when any is recorded, a grant outside every one is not effective |
| <a id="a-ciamcondition"></a>`ciamCondition` | `1.3.6.1.4.1.32473.1.1.329` | `string` | intent | multi |  | A condition on what a principal may do, stated neutrally (mfa, source-network 10.20.9.0/28, approval, business-hours) |
| <a id="a-ciamdenial"></a>`ciamDenial` | `1.3.6.1.4.1.32473.1.1.338` | `string` | binding | multi |  | An explicit deny over an identity (its own policies, a resource's, a deny assignment or policy) or every identity under a guardrail, in the cloud's terms: '<action> on <resource>'; an action '!<pattern>' denies every action but those (NotAction); ' (if <condition>)' when conditional |
| <a id="a-ciamdenies"></a>`ciamDenies` | `1.3.6.1.4.1.32473.1.1.336` | `string` | binding | multi | X-PATTERN `^[a-z0-9][a-z0-9-]*$` | What a guardrail prevents, named neutrally (region-escape, public-storage, audit-log-disable, service-account-keys, metadata-v1, root-use, key-deletion) |
| <a id="a-ciamevaluated"></a>`ciamEvaluated` | `1.3.6.1.4.1.32473.1.1.340` | `string` | binding | multi | X-PATTERN `^[a-z-]+ [a-z0-9][a-z0-9-]*: (allowed\|denied\|unknown) \(.+\)$` | A cloud evaluator's verdict on one of an identity's permissions: '<verb> <role>: allowed\|denied\|unknown (<evaluator> <YYYY-MM-DD>)', preferred over evaluating the recorded policies |
| <a id="a-ciamgrant"></a>`ciamGrant` | `1.3.6.1.4.1.32473.1.1.333` | `string` | binding | multi |  | What the cloud grants an identity, in its own terms: '<action or role> on <resource>', with ' (resource policy)' when a resource's policy grants it rather than the identity's |
| <a id="a-ciamguardrailkind"></a>`ciamGuardrailKind` | `1.3.6.1.4.1.32473.1.1.335` | enum: `service-control`, `resource-control`, `policy-assignment`, `deny-assignment`, `org-constraint`, `other` | binding | single |  | What an organization guardrail is: a service or resource control policy, a policy or deny assignment, an organization policy constraint |
| <a id="a-ciamholdsset"></a>`ciamHoldsSet` | `1.3.6.1.4.1.32473.1.1.328` | `dn` | intent | multi |  | A permission set a principal holds |
| <a id="a-ciamidentityclientid"></a>`ciamIdentityClientId` | `1.3.6.1.4.1.32473.1.1.621` | `string` | binding | single |  | The client id of a cloud identity, where the cloud addresses it by one apart from its resource (an Azure user-assigned managed identity: what AKS workload identity and the Key Vault CSI provider name) |
| <a id="a-ciamidentitykind"></a>`ciamIdentityKind` | `1.3.6.1.4.1.32473.1.1.332` | enum: `role`, `managed-identity`, `service-account`, `federated`, `permission-set`, `group`, `user`, `other` | binding | single |  | What realizes a principal in an environment: a role (IAM role, instance profile), a managed identity, a service account, a federated trust, a permission set, a group |
| <a id="a-ciamlasttested"></a>`ciamLastTested` | `1.3.6.1.4.1.32473.1.1.331` | `time` | meta | single |  | When a break-glass procedure was last exercised end to end |
| <a id="a-ciampermits"></a>`ciamPermits` | `1.3.6.1.4.1.32473.1.1.326` | `string` | intent | multi | X-PATTERN `^(read-secret\|write-secret\|use-key\|manage-key\|read-storage\|write-storage\|publish-stream\|consume-stream\|write-logs\|read-logs\|manage) [a-z0-9][a-z0-9-]*$` | What a permission set allows: a verb on a binding role (read-secret pf-admin-password, use-key disk-encryption, write-storage backup-target); each environment's binding of the role is the resource |
| <a id="a-ciamprincipalkind"></a>`ciamPrincipalKind` | `1.3.6.1.4.1.32473.1.1.327` | enum: `workload`, `deployer`, `operator`, `break-glass`, `service` | intent | single |  | What acts: a workload (servers of a role, a compute group, a Kubernetes workload, a job), a deployer (a CI pipeline), an operator role, a break-glass account, a service |
| <a id="a-ciamreviewintervaldays"></a>`ciamReviewIntervalDays` | `1.3.6.1.4.1.32473.1.1.330` | `int` | meta | single |  | How often a principal's access must be reviewed, in days (365 when not stated) |
| <a id="a-ciamtrustedby"></a>`ciamTrustedBy` | `1.3.6.1.4.1.32473.1.1.334` | `string` | binding | multi |  | Who may act as an identity or come in by a path: a service (ec2.amazonaws.com), an OIDC issuer and subject (a CI pipeline), a Kubernetes service account (namespace/name), an identity provider |
