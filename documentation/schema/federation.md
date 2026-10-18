# Federation

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 6 object classes · 35 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

**Branches:** `ou=identity-services,dc=ciam-ops`, `ou=integrations,dc=ciam-ops`

## Object classes

<a id="c-ciamauthextension"></a>
### ciamAuthExtension

A custom authentication extension of a managed identity service (beneath its binding): the event it answers, the application it authenticates as and the claims it returns; its endpoint and the code behind it aren't recorded

OID `1.3.6.1.4.1.32473.1.2.179` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamExtensionEvent`](#a-ciamextensionevent) | yes | `enum` | single | The sign-in event a custom authentication extension answers |
| [`ciamExtensionResource`](#a-ciamextensionresource) |  | `string` | single | The application a custom authentication extension authenticates to its API as (its app ID URI or ID); where the API runs is not recorded |
| [`ciamExtensionClaim`](#a-ciamextensionclaim) |  | `string` | multi | A claim a custom authentication extension returns for tokens |

<a id="c-ciamclaimmap"></a>
### ciamClaimMap

One claim / SAML attribute mapping

OID `1.3.6.1.4.1.32473.1.2.27` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamClaimName`](#a-ciamclaimname) | yes | `string` | single | Claim / SAML attribute name the application receives |
| [`ciamSourceAttribute`](#a-ciamsourceattribute) | yes | `dn` | single | User-directory attribute record the claim comes from |
| [`ciamTransform`](#a-ciamtransform) |  | `string` | single | Transformation applied to the value |

<a id="c-ciamidentityservice"></a>
### ciamIdentityService

The platform's own identity provider / OpenID provider, as partners and applications know it

OID `1.3.6.1.4.1.32473.1.2.35` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamBaseUrl`](#a-ciambaseurl) | yes | `url` | single | Public base URL of an identity service (its endpoints are paths under it) |
| [`ciamEntityId`](#a-ciamentityid) |  | `url` | single | SAML entity ID |
| [`ciamOidcIssuer`](#a-ciamoidcissuer) |  | `url` | single | OIDC issuer identifier |
| [`ciamScope`](#a-ciamscope) |  | `string` | multi | OAuth 2.0 scopes (a client may request / a service supports) |
| [`ciamSigningAlg`](#a-ciamsigningalg) |  | `enum` | multi | Token signing algorithms (JWS) |
| [`ciamNameIdFormat`](#a-ciamnameidformat) |  | `enum` | multi | SAML NameID formats (a partner expects / a service supports) |
| [`ciamUsesCertificate`](#a-ciamusescertificate) |  | `dn` | multi | Certificates this integration depends on |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) |  | `vocab` | single | Server role a service or rule targets |
| [`ciamCriticality`](core.md#a-ciamcriticality) |  | `enum` | single | Business criticality |

<a id="c-ciamintegration"></a>
### ciamIntegration

Application or partner integration

OID `1.3.6.1.4.1.32473.1.2.26` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamProtocolType`](#a-ciamprotocoltype) | yes | `enum` | single | Integration type |
| [`ciamEntityId`](#a-ciamentityid) |  | `url` | single | SAML entity ID |
| [`ciamAcsUrl`](#a-ciamacsurl) |  | `url` | single | SAML assertion consumer service URL |
| [`ciamRedirectUri`](#a-ciamredirecturi) |  | `url` | multi | OIDC redirect URI |
| [`ciamClientId`](#a-ciamclientid) |  | `string` | single | OIDC client id |
| [`ciamGrantType`](#a-ciamgranttype) |  | `enum` | multi | OAuth 2.0 grant types (RFC 6749 and extension grants by URN) |
| [`ciamPkceRequired`](#a-ciampkcerequired) |  | `bool` | single | PKCE required |
| [`ciamDpopBound`](#a-ciamdpopbound) |  | `bool` | single | Whether the client's access tokens are DPoP-bound: it must present DPoP proofs (RFC 9449 dpop_bound_access_tokens) |
| [`ciamPopulation`](core.md#a-ciampopulation) |  | `enum` | multi | Identity populations served |
| [`ciamMfaRequired`](#a-ciammfarequired) |  | `bool` | single | MFA required |
| [`ciamUsesCertificate`](#a-ciamusescertificate) |  | `dn` | multi | Certificates this integration depends on |
| [`ciamJitBaseDn`](#a-ciamjitbasedn) |  | `extdn` | single | Where just-in-time provisioned partner users are created |
| [`ciamCriticality`](core.md#a-ciamcriticality) |  | `enum` | single | Business criticality |
| [`ciamTokenAuthMethod`](#a-ciamtokenauthmethod) |  | `enum` | multi | Token endpoint client authentication methods (a product taking one per client renders the first) |
| [`ciamScope`](#a-ciamscope) |  | `string` | multi | OAuth 2.0 scopes (a client may request / a service supports) |
| [`ciamPostLogoutRedirectUri`](#a-ciampostlogoutredirecturi) |  | `url` | multi | OIDC post-logout redirect URI |
| [`ciamSamlBinding`](#a-ciamsamlbinding) |  | `enum` | single | SAML binding of the assertion consumer service (or single sign-on service) |
| [`ciamNameIdFormat`](#a-ciamnameidformat) |  | `enum` | multi | SAML NameID formats (a partner expects / a service supports) |
| [`ciamSsoUrl`](#a-ciamssourl) |  | `url` | single | Single sign-on service URL of a partner identity provider |
| [`ciamServedBy`](#a-ciamservedby) |  | `dn` | single | The identity service the integration is registered with (none: every identity service serves it) |

<a id="c-ciammanagedidentity"></a>
### ciamManagedIdentity

A cloud-managed identity service an environment uses: the platform's own identity service run on it there (ciamRealizes: the identity service's name; a target), or a neighbour the platform federates with (ciamPartnerOf: the integrations it is the partner side of); its resource (ciamProviderRef), the sign-in host it serves at (ciamFqdn, a custom domain presenting ciamTlsCertificate), where it keeps its users' data (ciamDataGeography) and who keeps it when it isn't the platform team (ciamManagedBy); a target's sign-in flows and custom authentication extensions are entries beneath it

OID `1.3.6.1.4.1.32473.1.2.167` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamManagedService`](#a-ciammanagedservice) | yes | `vocab` | single | The cloud-managed identity service a binding is, as the adapter declaring it names it (a user pool service, an external tenant) |
| [`ciamRealizes`](observability.md#a-ciamrealizes) |  | `string` | single | The alert rule or canary (its name) an alarm or synthetic check a cloud runs realizes |
| [`ciamPartnerOf`](#a-ciampartnerof) |  | `dn` | multi | The integrations a managed identity service is the partner side of (a neighbour the platform federates with): whether it is their relying party or their issuer follows from their protocol type |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamFqdn`](infrastructure.md#a-ciamfqdn) |  | `fqdn` | single | Service DNS name consumers and partners use. Must stay stable across migrations |
| [`ciamTlsCertificate`](infrastructure.md#a-ciamtlscertificate) |  | `dn` | single | Certificate this service name presents in this environment |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamDataGeography`](#a-ciamdatageography) |  | `vocab` | single | Where a managed identity service keeps its users' data, as the adapter declaring it names the geography (a tenant's data residency) |

<a id="c-ciamsigninflow"></a>
### ciamSignInFlow

A sign-in flow of a managed identity service (beneath its binding): the integrations it signs users in to, how (its methods, its upstream identity providers), what it collects at sign-up and the custom authentication extensions it calls

OID `1.3.6.1.4.1.32473.1.2.178` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamFlowApplications`](#a-ciamflowapplications) |  | `dn` | multi | The integrations a sign-in flow signs users in to |
| [`ciamSignInMethod`](#a-ciamsigninmethod) |  | `enum` | multi | How a sign-in flow signs users in (sign-up: it also creates their accounts; federated: through an upstream identity provider) |
| [`ciamUpstreamProvider`](#a-ciamupstreamprovider) |  | `string` | multi | An upstream identity provider a sign-in flow offers, as the managed service names it |
| [`ciamCollectedAttribute`](#a-ciamcollectedattribute) |  | `string` | multi | A user attribute a sign-in flow collects at sign-up, as the managed service names it |
| [`ciamFlowExtension`](#a-ciamflowextension) |  | `dn` | multi | The custom authentication extensions a sign-in flow calls |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamacsurl"></a>`ciamAcsUrl` | `1.3.6.1.4.1.32473.1.1.88` | `url` | contract | single |  | SAML assertion consumer service URL |
| <a id="a-ciambaseurl"></a>`ciamBaseUrl` | `1.3.6.1.4.1.32473.1.1.147` | `url` | contract | single | X-OVERRIDABLE `TRUE` | Public base URL of an identity service (its endpoints are paths under it) |
| <a id="a-ciamclaimname"></a>`ciamClaimName` | `1.3.6.1.4.1.32473.1.1.97` | `string` | contract | single |  | Claim / SAML attribute name the application receives |
| <a id="a-ciamclientid"></a>`ciamClientId` | `1.3.6.1.4.1.32473.1.1.90` | `string` | contract | single |  | OIDC client id |
| <a id="a-ciamcollectedattribute"></a>`ciamCollectedAttribute` | `1.3.6.1.4.1.32473.1.1.811` | `string` | intent | multi |  | A user attribute a sign-in flow collects at sign-up, as the managed service names it |
| <a id="a-ciamdatageography"></a>`ciamDataGeography` | `1.3.6.1.4.1.32473.1.1.816` | vocab: `united-states` (azure), `europe` (azure), `asia-pacific` (azure), `australia` (azure) | binding | single |  | Where a managed identity service keeps its users' data, as the adapter declaring it names the geography (a tenant's data residency) |
| <a id="a-ciamdpopbound"></a>`ciamDpopBound` | `1.3.6.1.4.1.32473.1.1.634` | `bool` | intent | single |  | Whether the client's access tokens are DPoP-bound: it must present DPoP proofs (RFC 9449 dpop_bound_access_tokens) |
| <a id="a-ciamentityid"></a>`ciamEntityId` | `1.3.6.1.4.1.32473.1.1.87` | `url` | contract | single | X-OVERRIDABLE `TRUE` | SAML entity ID |
| <a id="a-ciamextensionclaim"></a>`ciamExtensionClaim` | `1.3.6.1.4.1.32473.1.1.815` | `string` | contract | multi |  | A claim a custom authentication extension returns for tokens |
| <a id="a-ciamextensionevent"></a>`ciamExtensionEvent` | `1.3.6.1.4.1.32473.1.1.813` | enum: `token-issuance-start`, `attribute-collection-start`, `attribute-collection-submit`, `otp-send`, `password-submit` | intent | single |  | The sign-in event a custom authentication extension answers |
| <a id="a-ciamextensionresource"></a>`ciamExtensionResource` | `1.3.6.1.4.1.32473.1.1.814` | `string` | binding | single |  | The application a custom authentication extension authenticates to its API as (its app ID URI or ID); where the API runs is not recorded |
| <a id="a-ciamflowapplications"></a>`ciamFlowApplications` | `1.3.6.1.4.1.32473.1.1.808` | `dn` | intent | multi |  | The integrations a sign-in flow signs users in to |
| <a id="a-ciamflowextension"></a>`ciamFlowExtension` | `1.3.6.1.4.1.32473.1.1.812` | `dn` | intent | multi |  | The custom authentication extensions a sign-in flow calls |
| <a id="a-ciamgranttype"></a>`ciamGrantType` | `1.3.6.1.4.1.32473.1.1.91` | enum: `authorization_code`, `client_credentials`, `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code`, `urn:ietf:params:oauth:grant-type:jwt-bearer`, `urn:ietf:params:oauth:grant-type:saml2-bearer`, `urn:ietf:params:oauth:grant-type:token-exchange` | intent | multi |  | OAuth 2.0 grant types (RFC 6749 and extension grants by URN) |
| <a id="a-ciamjitbasedn"></a>`ciamJitBaseDn` | `1.3.6.1.4.1.32473.1.1.96` | `extdn` | intent | single |  | Where just-in-time provisioned partner users are created |
| <a id="a-ciammanagedservice"></a>`ciamManagedService` | `1.3.6.1.4.1.32473.1.1.770` | vocab: `cognito-user-pool` (aws), `aws-managed-ad` (aws), `entra-external-id` (azure), `entra-domain-services` (azure), `google-managed-ad` (gcp) | binding | single |  | The cloud-managed identity service a binding is, as the adapter declaring it names it (a user pool service, an external tenant) |
| <a id="a-ciammfarequired"></a>`ciamMfaRequired` | `1.3.6.1.4.1.32473.1.1.94` | `bool` | intent | single |  | MFA required |
| <a id="a-ciamnameidformat"></a>`ciamNameIdFormat` | `1.3.6.1.4.1.32473.1.1.144` | enum: `unspecified`, `emailAddress`, `persistent`, `transient` | contract | multi |  | SAML NameID formats (a partner expects / a service supports) |
| <a id="a-ciamoidcissuer"></a>`ciamOidcIssuer` | `1.3.6.1.4.1.32473.1.1.146` | `url` | contract | single | X-OVERRIDABLE `TRUE` | OIDC issuer identifier |
| <a id="a-ciampartnerof"></a>`ciamPartnerOf` | `1.3.6.1.4.1.32473.1.1.771` | `dn` | intent | multi |  | The integrations a managed identity service is the partner side of (a neighbour the platform federates with): whether it is their relying party or their issuer follows from their protocol type |
| <a id="a-ciampkcerequired"></a>`ciamPkceRequired` | `1.3.6.1.4.1.32473.1.1.92` | `bool` | intent | single |  | PKCE required |
| <a id="a-ciampostlogoutredirecturi"></a>`ciamPostLogoutRedirectUri` | `1.3.6.1.4.1.32473.1.1.142` | `url` | contract | multi |  | OIDC post-logout redirect URI |
| <a id="a-ciamprotocoltype"></a>`ciamProtocolType` | `1.3.6.1.4.1.32473.1.1.86` | enum: `saml2-sp`, `oidc-client`, `saml2-idp`, `ldap` | intent | single |  | Integration type |
| <a id="a-ciamredirecturi"></a>`ciamRedirectUri` | `1.3.6.1.4.1.32473.1.1.89` | `url` | contract | multi |  | OIDC redirect URI |
| <a id="a-ciamsamlbinding"></a>`ciamSamlBinding` | `1.3.6.1.4.1.32473.1.1.143` | enum: `HTTP-POST`, `HTTP-Redirect`, `HTTP-Artifact`, `SOAP` | contract | single |  | SAML binding of the assertion consumer service (or single sign-on service) |
| <a id="a-ciamscope"></a>`ciamScope` | `1.3.6.1.4.1.32473.1.1.141` | `string` | contract | multi |  | OAuth 2.0 scopes (a client may request / a service supports) |
| <a id="a-ciamservedby"></a>`ciamServedBy` | `1.3.6.1.4.1.32473.1.1.213` | `dn` | intent | single |  | The identity service the integration is registered with (none: every identity service serves it) |
| <a id="a-ciamsigningalg"></a>`ciamSigningAlg` | `1.3.6.1.4.1.32473.1.1.148` | enum: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512` | intent | multi |  | Token signing algorithms (JWS) |
| <a id="a-ciamsigninmethod"></a>`ciamSignInMethod` | `1.3.6.1.4.1.32473.1.1.809` | enum: `email-password`, `email-otp`, `sign-up`, `federated` | intent | multi |  | How a sign-in flow signs users in (sign-up: it also creates their accounts; federated: through an upstream identity provider) |
| <a id="a-ciamsourceattribute"></a>`ciamSourceAttribute` | `1.3.6.1.4.1.32473.1.1.98` | `dn` | intent | single |  | User-directory attribute record the claim comes from |
| <a id="a-ciamssourl"></a>`ciamSsoUrl` | `1.3.6.1.4.1.32473.1.1.145` | `url` | contract | single |  | Single sign-on service URL of a partner identity provider |
| <a id="a-ciamtokenauthmethod"></a>`ciamTokenAuthMethod` | `1.3.6.1.4.1.32473.1.1.140` | enum: `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` | intent | multi |  | Token endpoint client authentication methods (a product taking one per client renders the first) |
| <a id="a-ciamtransform"></a>`ciamTransform` | `1.3.6.1.4.1.32473.1.1.99` | `string` | intent | single |  | Transformation applied to the value |
| <a id="a-ciamupstreamprovider"></a>`ciamUpstreamProvider` | `1.3.6.1.4.1.32473.1.1.810` | `string` | intent | multi |  | An upstream identity provider a sign-in flow offers, as the managed service names it |
| <a id="a-ciamusescertificate"></a>`ciamUsesCertificate` | `1.3.6.1.4.1.32473.1.1.95` | `dn` | intent | multi |  | Certificates this integration depends on |
