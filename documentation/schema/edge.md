# Edge

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 8 object classes · 45 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Edge domain schema: how traffic reaches the platform and what protects it. Traffic and protection policies and header contracts are intent, the same in every environment: a policy names the binding roles of the service names it applies to, so one policy means each environment's own load balancer, WAF and CDN in front of them. What realizes them is a binding per environment: DNS zones, records and forwarders, the WAF, CDN, DDoS protection, gateways and proxies, and what each actually runs (read back as facts in the policies' terms); and the in-cluster gateway a cluster routes the service names of roles it alone runs through.

**Branches:** `ou=edge-policies,dc=ciam-ops`, `ou=header-contracts,dc=ciam-ops`

## Object classes

<a id="c-ciamclustergateway"></a>
### ciamClusterGateway

A cluster's in-cluster gateway: the service names whose role runs only on Kubernetes there are routed through it, behind each cloud's front (load balancer, WAF, TLS certificate, DNS record) rendered from their policies; its namespace, the private address and subnet the front reaches it at, and, delivered like a workload's, the Secret keys it reads (its internal TLS key pair, the CA its backends' certificates are checked against) with the service account and identity that read them; the CA its internal certificate chains to, which a front re-encrypting to it trusts

OID `1.3.6.1.4.1.32473.1.2.132` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamClusterRole`](compute.md#a-ciamclusterrole) | yes | `string` | single | The binding role of the cluster a workload runs in |
| [`ciamGatewayImplementation`](#a-ciamgatewayimplementation) |  | `vocab` | single | Which Gateway API implementation runs a cluster's in-cluster gateway (the values the installed Kubernetes platform adapter renders); when absent, that adapter's estate setting decides |
| [`ciamNamespace`](compute.md#a-ciamnamespace) |  | `string` | single | The Kubernetes namespace a workload runs in |
| [`ciamFrontendIp`](infrastructure.md#a-ciamfrontendip) |  | `ip` | single | Load balancer frontend IP |
| [`ciamSubnetRole`](network.md#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamWorkloadSecret`](compute.md#a-ciamworkloadsecret) |  | `string` | multi | A Kubernetes Secret key a workload reads and the secret role that fills it: <secret name>/<key> <- <secret role> (each environment binds the role to its secret store's reference; values never. Not key=role: a key named like a password would read as one) |
| [`ciamServiceAccount`](compute.md#a-ciamserviceaccount) |  | `string` | single | The Kubernetes service account a workload runs as |
| [`ciamIdentityRole`](compute.md#a-ciamidentityrole) |  | `string` | single | The binding role whose cloud identity a workload assumes (workload identity): each environment binds it |
| [`ciamTrustsCertificate`](compute.md#a-ciamtrustscertificate) |  | `dn` | multi | A certificate the role's Java truststore (cacerts) adds to the runtime's own: lost silently when a server is rebuilt from a stock image |

<a id="c-ciamdnsforwarder"></a>
### ciamDnsForwarder

A conditional forwarder or resolver rule: the domains it forwards and the resolvers it forwards to

OID `1.3.6.1.4.1.32473.1.2.79` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamForwardDomain`](#a-ciamforwarddomain) | yes | `fqdn` | multi | A domain whose queries are forwarded to other resolvers (a conditional forwarder) |
| [`ciamForwardTarget`](#a-ciamforwardtarget) | yes | `ip` | multi | A resolver queries are forwarded to |
| [`ciamForwardDirection`](#a-ciamforwarddirection) |  | `enum` | single | outbound: the environment's queries for the domains go to the targets; inbound: other networks' queries come in to the environment |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamResolverHost`](#a-ciamresolverhost) |  | `ip` | multi | A DNS server on the environment's own machines that does the forwarding, instead of the platform's managed resolver; the network's DNS settings point at it |

<a id="c-ciamdnsrecord"></a>
### ciamDnsRecord

A DNS record beyond the service names (verification, mail, delegation), with its TTL and routing

OID `1.3.6.1.4.1.32473.1.2.78` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRecordName`](#a-ciamrecordname) | yes | `fqdn` | single | Name of a DNS record |
| [`ciamRecordType`](#a-ciamrecordtype) | yes | `enum` | single | Type of a DNS record |
| [`ciamRecordValue`](#a-ciamrecordvalue) |  | `string` | multi | A value a DNS record answers with |
| [`ciamTtlSeconds`](#a-ciamttlseconds) |  | `int` | single | How long resolvers may cache a DNS answer, in seconds (lowered before a cutover) |
| [`ciamRoutingPolicy`](#a-ciamroutingpolicy) |  | `enum` | single | How a DNS name chooses among answers: one answer, the primary or secondary of a health-checked failover pair, or a weighted share |
| [`ciamRoutingWeight`](#a-ciamroutingweight) |  | `int` | single | Share of answers a weighted record gets |
| [`ciamDnsZone`](infrastructure.md#a-ciamdnszone) |  | `fqdn` | single | DNS zone the service name is published in |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |

<a id="c-ciamdnszonebinding"></a>
### ciamDnsZoneBinding

A DNS zone the environment publishes in, and who runs it when not the platform

OID `1.3.6.1.4.1.32473.1.2.77` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamDnsZone`](infrastructure.md#a-ciamdnszone) | yes | `fqdn` | single | DNS zone the service name is published in |
| [`ciamZoneVisibility`](#a-ciamzonevisibility) | yes | `enum` | single | Whether a DNS zone answers the internet or only the networks linked to it |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamedgeservice"></a>
### ciamEdgeService

A web application firewall, CDN, DDoS protection, API gateway or reverse proxy in front of service names, and what it runs

OID `1.3.6.1.4.1.32473.1.2.80` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamEdgeKind`](#a-ciamedgekind) | yes | `enum` | single | What an edge service is: a web application firewall, a CDN, DDoS protection, an API gateway, a reverse proxy |
| [`ciamServiceRole`](#a-ciamservicerole) |  | `string` | multi | Binding role of a service name this applies to (each environment binds its own) |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamEdgeFact`](#a-ciamedgefact) |  | `string` | multi | What the edge runs, read back in the policies' terms: '<key> <value>' (tls-min 1.2, waf-category core-rules, rate-limit token 100/300s per ip, health https /pf/heartbeat.ping) |
| [`ciamEdgeSetting`](#a-ciamedgesetting) |  | `string` | multi | A setting the edge runs that the policies' terms can't express, in the provider's own terms |

<a id="c-ciamheadercontract"></a>
### ciamHeaderContract

A header someone sets and applications or products trust: header-based sign-on, the client address behind a proxy

OID `1.3.6.1.4.1.32473.1.2.76` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamHeaderName`](#a-ciamheadername) | yes | `string` | single | HTTP header an application or product trusts. Must stay the same across migrations |
| [`ciamHeaderKind`](#a-ciamheaderkind) | yes | `enum` | single | What a header carries: who the user is (header-based sign-on), the client's address, the scheme or host the client used |
| [`ciamSetByRole`](#a-ciamsetbyrole) | yes | `string` | single | Who sets a header: a server role (a gateway, a proxy) or a service name's binding role (its load balancer); an environment overrides it when another product sets the header there |
| [`ciamTrustedByRole`](#a-ciamtrustedbyrole) |  | `string` | multi | A server role that trusts a header |
| [`ciamTrustedByConsumer`](#a-ciamtrustedbyconsumer) |  | `dn` | multi | A consumer that trusts a header |
| [`ciamHeaderValue`](#a-ciamheadervalue) |  | `string` | single | What a header's value comes from (claim sub, attribute uid, the client's address) |
| [`ciamStripsInbound`](#a-ciamstripsinbound) |  | `bool` | single | Whether the setter removes the header from incoming requests, so a client cannot supply it |

<a id="c-ciamprotectionpolicy"></a>
### ciamProtectionPolicy

What protects service names: web application firewall rules and rate limits, address and country rules, DDoS protection, a CDN

OID `1.3.6.1.4.1.32473.1.2.75` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamServiceRole`](#a-ciamservicerole) | yes | `string` | multi | Binding role of a service name this applies to (each environment binds its own) |
| [`ciamWafMode`](#a-ciamwafmode) |  | `enum` | single | Whether the web application firewall only counts what its rules match (detect) or blocks it |
| [`ciamWafCategory`](#a-ciamwafcategory) |  | `enum` | multi | A category of managed rules the web application firewall applies |
| [`ciamRateLimit`](#a-ciamratelimit) |  | `string` | multi | A rate limit on an endpoint kind: '<kind> <requests>/<seconds>s per <ip\|header:Name>' (token 100/300s per ip) |
| [`ciamIpRule`](#a-ciamiprule) |  | `string` | multi | Addresses always allowed or refused: 'allow\|deny <cidr>' |
| [`ciamGeoRule`](#a-ciamgeorule) |  | `string` | multi | Countries allowed or refused: 'allow\|deny <ISO 3166 codes>' |
| [`ciamWafExclusion`](#a-ciamwafexclusion) |  | `string` | multi | A field a managed rule category must not inspect on an endpoint kind (SAML posts, token requests trip generic rules): '<category> on <kind> <body\|query\|header\|cookie>:<name>' |
| [`ciamDdosTier`](#a-ciamddostier) |  | `enum` | single | DDoS protection beyond the provider's standard: network-advanced (the addresses), application-advanced (layer 7 too) |
| [`ciamCdn`](#a-ciamcdn) |  | `bool` | single | Whether a CDN serves these service names (sign-in, token and password endpoints are never cached) |
| [`ciamEndpointPath`](#a-ciamendpointpath) |  | `string` | multi | Where an endpoint lives on these services when not where its product declares it: '<kind> <path>' (token /oauth/token) |

<a id="c-ciamtrafficpolicy"></a>
### ciamTrafficPolicy

How traffic reaches the servers behind service names: TLS handling and level, health checks, stickiness, timeouts

OID `1.3.6.1.4.1.32473.1.2.74` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamServiceRole`](#a-ciamservicerole) | yes | `string` | multi | Binding role of a service name this applies to (each environment binds its own) |
| [`ciamTlsMode`](#a-ciamtlsmode) | yes | `enum` | single | How the load balancer handles TLS: passthrough to the servers (layer 4), or terminate at the edge and send on in clear (terminate) or encrypted again (reencrypt); only layer 7 can inspect requests |
| [`ciamTlsMinVersion`](#a-ciamtlsminversion) |  | `enum` | single | Lowest TLS version the edge accepts from clients |
| [`ciamTlsProfile`](#a-ciamtlsprofile) |  | `enum` | single | Cipher profile the edge offers (modern, intermediate, compatible); each cloud renders its nearest named policy |
| [`ciamBackendValidation`](#a-ciambackendvalidation) |  | `enum` | single | What the edge checks of the servers' certificates when it re-encrypts: nothing, a trusted root, or a trusted root and the name |
| [`ciamHealthProtocol`](#a-ciamhealthprotocol) |  | `enum` | single | How the load balancer checks a server is healthy |
| [`ciamHealthPath`](#a-ciamhealthpath) |  | `string` | single | Path of an HTTP health check, when not the product's declared health endpoint |
| [`ciamHealthIntervalSeconds`](#a-ciamhealthintervalseconds) |  | `int` | single | Seconds between health checks |
| [`ciamHealthyThreshold`](#a-ciamhealthythreshold) |  | `int` | single | Consecutive passed checks before a server takes traffic |
| [`ciamUnhealthyThreshold`](#a-ciamunhealthythreshold) |  | `int` | single | Consecutive failed checks before a server stops taking traffic |
| [`ciamStickiness`](#a-ciamstickiness) |  | `enum` | single | Whether a client keeps reaching the same server: no, by source address, or by a cookie |
| [`ciamStickinessSeconds`](#a-ciamstickinessseconds) |  | `int` | single | How long stickiness lasts |
| [`ciamIdleTimeoutSeconds`](#a-ciamidletimeoutseconds) |  | `int` | single | Seconds an idle connection is kept open |
| [`ciamDrainSeconds`](#a-ciamdrainseconds) |  | `int` | single | Seconds a server leaving the pool keeps its open connections |
| [`ciamEndpointPath`](#a-ciamendpointpath) |  | `string` | multi | Where an endpoint lives on these services when not where its product declares it: '<kind> <path>' (token /oauth/token) |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciambackendvalidation"></a>`ciamBackendValidation` | `1.3.6.1.4.1.32473.1.1.346` | enum: `none`, `trusted-roots`, `san-match` | intent | single |  | What the edge checks of the servers' certificates when it re-encrypts: nothing, a trusted root, or a trusted root and the name |
| <a id="a-ciamcdn"></a>`ciamCdn` | `1.3.6.1.4.1.32473.1.1.363` | `bool` | intent | single |  | Whether a CDN serves these service names (sign-in, token and password endpoints are never cached) |
| <a id="a-ciamddostier"></a>`ciamDdosTier` | `1.3.6.1.4.1.32473.1.1.362` | enum: `standard`, `network-advanced`, `application-advanced` | intent | single |  | DDoS protection beyond the provider's standard: network-advanced (the addresses), application-advanced (layer 7 too) |
| <a id="a-ciamdrainseconds"></a>`ciamDrainSeconds` | `1.3.6.1.4.1.32473.1.1.355` | `int` | intent | single |  | Seconds a server leaving the pool keeps its open connections |
| <a id="a-ciamedgefact"></a>`ciamEdgeFact` | `1.3.6.1.4.1.32473.1.1.383` | `string` | observed | multi | X-PATTERN `^(tls-mode\|tls-min\|tls-profile\|backend-validation\|health\|stickiness\|idle-timeout\|drain\|waf-mode\|waf-category\|rate-limit\|ip-rule\|geo-rule\|ddos\|cdn) [^ ].*$` | What the edge runs, read back in the policies' terms: '<key> <value>' (tls-min 1.2, waf-category core-rules, rate-limit token 100/300s per ip, health https /pf/heartbeat.ping) |
| <a id="a-ciamedgekind"></a>`ciamEdgeKind` | `1.3.6.1.4.1.32473.1.1.382` | enum: `waf`, `cdn`, `ddos`, `api-gateway`, `reverse-proxy` | binding | single |  | What an edge service is: a web application firewall, a CDN, DDoS protection, an API gateway, a reverse proxy |
| <a id="a-ciamedgesetting"></a>`ciamEdgeSetting` | `1.3.6.1.4.1.32473.1.1.384` | `string` | observed | multi |  | A setting the edge runs that the policies' terms can't express, in the provider's own terms |
| <a id="a-ciamendpointpath"></a>`ciamEndpointPath` | `1.3.6.1.4.1.32473.1.1.364` | `string` | intent | multi | X-PATTERN `^(login\|token\|password-reset\|registration\|saml-post\|saml-start\|health) /[^ ]*$` | Where an endpoint lives on these services when not where its product declares it: '<kind> <path>' (token /oauth/token) |
| <a id="a-ciamforwarddirection"></a>`ciamForwardDirection` | `1.3.6.1.4.1.32473.1.1.381` | enum: `outbound`, `inbound` | binding | single |  | outbound: the environment's queries for the domains go to the targets; inbound: other networks' queries come in to the environment |
| <a id="a-ciamforwarddomain"></a>`ciamForwardDomain` | `1.3.6.1.4.1.32473.1.1.379` | `fqdn` | binding | multi |  | A domain whose queries are forwarded to other resolvers (a conditional forwarder) |
| <a id="a-ciamforwardtarget"></a>`ciamForwardTarget` | `1.3.6.1.4.1.32473.1.1.380` | `ip` | binding | multi |  | A resolver queries are forwarded to |
| <a id="a-ciamgatewayimplementation"></a>`ciamGatewayImplementation` | `1.3.6.1.4.1.32473.1.1.622` | vocab: `istio` (kubernetes), `envoy-gateway` (kubernetes) | binding | single |  | Which Gateway API implementation runs a cluster's in-cluster gateway (the values the installed Kubernetes platform adapter renders); when absent, that adapter's estate setting decides |
| <a id="a-ciamgeorule"></a>`ciamGeoRule` | `1.3.6.1.4.1.32473.1.1.360` | `string` | intent | multi | X-PATTERN `^(allow\|deny) [A-Z]{2}( [A-Z]{2})*$` | Countries allowed or refused: 'allow\|deny <ISO 3166 codes>' |
| <a id="a-ciamheaderkind"></a>`ciamHeaderKind` | `1.3.6.1.4.1.32473.1.1.366` | enum: `identity`, `client-ip`, `forwarded-proto`, `forwarded-host`, `other` | intent | single |  | What a header carries: who the user is (header-based sign-on), the client's address, the scheme or host the client used |
| <a id="a-ciamheadername"></a>`ciamHeaderName` | `1.3.6.1.4.1.32473.1.1.365` | `string` | contract | single | X-PATTERN `^[A-Za-z0-9][A-Za-z0-9_-]*$` | HTTP header an application or product trusts. Must stay the same across migrations |
| <a id="a-ciamheadervalue"></a>`ciamHeaderValue` | `1.3.6.1.4.1.32473.1.1.370` | `string` | intent | single |  | What a header's value comes from (claim sub, attribute uid, the client's address) |
| <a id="a-ciamhealthintervalseconds"></a>`ciamHealthIntervalSeconds` | `1.3.6.1.4.1.32473.1.1.349` | `int` | intent | single | X-MIN `1` | Seconds between health checks |
| <a id="a-ciamhealthpath"></a>`ciamHealthPath` | `1.3.6.1.4.1.32473.1.1.348` | `string` | intent | single | X-PATTERN `^/[^ ]*$` | Path of an HTTP health check, when not the product's declared health endpoint |
| <a id="a-ciamhealthprotocol"></a>`ciamHealthProtocol` | `1.3.6.1.4.1.32473.1.1.347` | enum: `tcp`, `http`, `https` | intent | single |  | How the load balancer checks a server is healthy |
| <a id="a-ciamhealthythreshold"></a>`ciamHealthyThreshold` | `1.3.6.1.4.1.32473.1.1.350` | `int` | intent | single | X-MIN `1` | Consecutive passed checks before a server takes traffic |
| <a id="a-ciamidletimeoutseconds"></a>`ciamIdleTimeoutSeconds` | `1.3.6.1.4.1.32473.1.1.354` | `int` | intent | single | X-MIN `1` | Seconds an idle connection is kept open |
| <a id="a-ciamiprule"></a>`ciamIpRule` | `1.3.6.1.4.1.32473.1.1.359` | `string` | intent | multi | X-PATTERN `^(allow\|deny) [0-9A-Fa-f:.]+/[0-9]+$` | Addresses always allowed or refused: 'allow\|deny <cidr>' |
| <a id="a-ciamratelimit"></a>`ciamRateLimit` | `1.3.6.1.4.1.32473.1.1.358` | `string` | intent | multi | X-PATTERN `^(login\|token\|password-reset\|registration\|saml-post\|saml-start\|health) [0-9]+/[0-9]+s per (ip\|header:[A-Za-z0-9-]+)$` | A rate limit on an endpoint kind: '<kind> <requests>/<seconds>s per <ip\|header:Name>' (token 100/300s per ip) |
| <a id="a-ciamrecordname"></a>`ciamRecordName` | `1.3.6.1.4.1.32473.1.1.373` | `fqdn` | binding | single |  | Name of a DNS record |
| <a id="a-ciamrecordtype"></a>`ciamRecordType` | `1.3.6.1.4.1.32473.1.1.374` | enum: `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `SRV`, `CAA`, `NS` | binding | single |  | Type of a DNS record |
| <a id="a-ciamrecordvalue"></a>`ciamRecordValue` | `1.3.6.1.4.1.32473.1.1.375` | `string` | binding | multi |  | A value a DNS record answers with |
| <a id="a-ciamresolverhost"></a>`ciamResolverHost` | `1.3.6.1.4.1.32473.1.1.592` | `ip` | binding | multi |  | A DNS server on the environment's own machines that does the forwarding, instead of the platform's managed resolver; the network's DNS settings point at it |
| <a id="a-ciamroutingpolicy"></a>`ciamRoutingPolicy` | `1.3.6.1.4.1.32473.1.1.377` | enum: `simple`, `failover-primary`, `failover-secondary`, `weighted` | binding | single |  | How a DNS name chooses among answers: one answer, the primary or secondary of a health-checked failover pair, or a weighted share |
| <a id="a-ciamroutingweight"></a>`ciamRoutingWeight` | `1.3.6.1.4.1.32473.1.1.378` | `int` | binding | single | X-MIN `0` | Share of answers a weighted record gets |
| <a id="a-ciamservicerole"></a>`ciamServiceRole` | `1.3.6.1.4.1.32473.1.1.342` | `string` | intent | multi |  | Binding role of a service name this applies to (each environment binds its own) |
| <a id="a-ciamsetbyrole"></a>`ciamSetByRole` | `1.3.6.1.4.1.32473.1.1.367` | `string` | intent | single | X-OVERRIDABLE `TRUE` | Who sets a header: a server role (a gateway, a proxy) or a service name's binding role (its load balancer); an environment overrides it when another product sets the header there |
| <a id="a-ciamstickiness"></a>`ciamStickiness` | `1.3.6.1.4.1.32473.1.1.352` | enum: `none`, `source-ip`, `cookie` | intent | single |  | Whether a client keeps reaching the same server: no, by source address, or by a cookie |
| <a id="a-ciamstickinessseconds"></a>`ciamStickinessSeconds` | `1.3.6.1.4.1.32473.1.1.353` | `int` | intent | single | X-MIN `1` | How long stickiness lasts |
| <a id="a-ciamstripsinbound"></a>`ciamStripsInbound` | `1.3.6.1.4.1.32473.1.1.371` | `bool` | intent | single |  | Whether the setter removes the header from incoming requests, so a client cannot supply it |
| <a id="a-ciamtlsminversion"></a>`ciamTlsMinVersion` | `1.3.6.1.4.1.32473.1.1.344` | enum: `1.2`, `1.3` | intent | single |  | Lowest TLS version the edge accepts from clients |
| <a id="a-ciamtlsmode"></a>`ciamTlsMode` | `1.3.6.1.4.1.32473.1.1.343` | enum: `passthrough`, `terminate`, `reencrypt` | intent | single |  | How the load balancer handles TLS: passthrough to the servers (layer 4), or terminate at the edge and send on in clear (terminate) or encrypted again (reencrypt); only layer 7 can inspect requests |
| <a id="a-ciamtlsprofile"></a>`ciamTlsProfile` | `1.3.6.1.4.1.32473.1.1.345` | enum: `modern`, `intermediate`, `compatible` | intent | single |  | Cipher profile the edge offers (modern, intermediate, compatible); each cloud renders its nearest named policy |
| <a id="a-ciamtrustedbyconsumer"></a>`ciamTrustedByConsumer` | `1.3.6.1.4.1.32473.1.1.369` | `dn` | intent | multi |  | A consumer that trusts a header |
| <a id="a-ciamtrustedbyrole"></a>`ciamTrustedByRole` | `1.3.6.1.4.1.32473.1.1.368` | `string` | intent | multi |  | A server role that trusts a header |
| <a id="a-ciamttlseconds"></a>`ciamTtlSeconds` | `1.3.6.1.4.1.32473.1.1.376` | `int` | binding | single | X-MIN `0` | How long resolvers may cache a DNS answer, in seconds (lowered before a cutover) |
| <a id="a-ciamunhealthythreshold"></a>`ciamUnhealthyThreshold` | `1.3.6.1.4.1.32473.1.1.351` | `int` | intent | single | X-MIN `1` | Consecutive failed checks before a server stops taking traffic |
| <a id="a-ciamwafcategory"></a>`ciamWafCategory` | `1.3.6.1.4.1.32473.1.1.357` | enum: `core-rules`, `known-bad-inputs`, `ip-reputation`, `bot-control`, `account-takeover`, `account-creation-fraud` | intent | multi |  | A category of managed rules the web application firewall applies |
| <a id="a-ciamwafexclusion"></a>`ciamWafExclusion` | `1.3.6.1.4.1.32473.1.1.361` | `string` | intent | multi | X-PATTERN `^(core-rules\|known-bad-inputs\|ip-reputation\|bot-control\|account-takeover\|account-creation-fraud) on (login\|token\|password-reset\|registration\|saml-post\|saml-start\|health) (body\|query\|header\|cookie):[A-Za-z0-9_.-]+$` | A field a managed rule category must not inspect on an endpoint kind (SAML posts, token requests trip generic rules): '<category> on <kind> <body\|query\|header\|cookie>:<name>' |
| <a id="a-ciamwafmode"></a>`ciamWafMode` | `1.3.6.1.4.1.32473.1.1.356` | enum: `detect`, `block` | intent | single |  | Whether the web application firewall only counts what its rules match (detect) or blocks it |
| <a id="a-ciamzonevisibility"></a>`ciamZoneVisibility` | `1.3.6.1.4.1.32473.1.1.372` | enum: `public`, `private` | binding | single |  | Whether a DNS zone answers the internet or only the networks linked to it |
