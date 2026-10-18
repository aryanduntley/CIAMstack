# Network

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 9 object classes · 37 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Network domain schema: how the platform's networks carry its traffic beyond the basics (networks, subnets, inbound firewall rules, egress addresses, interconnects, which stay in infrastructure). The outside sites the platform must reach are intent, the same in every environment. How each environment gets there is a binding: route tables, stateless network ACLs, private endpoints to the services it uses, endpoint services that expose its services to other networks, the proxy or firewall its egress passes, its time source, its flow logs and its firewall policies; and the depth of its interconnects and egress (added to the infrastructure classes).

**Branches:** `ou=egress-destinations,dc=ciam-ops`

## Object classes

<a id="c-ciamegressdestination"></a>
### ciamEgressDestination

An outside site the platform must reach (partner metadata, signing keys, certificate status, vendors)

OID `1.3.6.1.4.1.32473.1.2.82` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamDestination`](#a-ciamdestination) | yes | `string` | single | An outside site the platform must reach: a host name or '*.' and a domain, with a port when not 443 |
| [`ciamSiteKind`](#a-ciamsitekind) | yes | `enum` | single | What the site serves: a partner's metadata, signing keys (JWKS), certificate status (OCSP, CRL), an MFA or messaging vendor, vendor updates, a directory |
| [`ciamNeededByRole`](#a-ciamneededbyrole) |  | `string` | multi | A server role that must reach it |
| [`ciamPort`](infrastructure.md#a-ciamport) |  | `port` | multi | TCP/UDP port |

<a id="c-ciamendpointservice"></a>
### ciamEndpointService

A service name exposed privately to other networks or accounts, and who may connect

OID `1.3.6.1.4.1.32473.1.2.86` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamServiceRole`](edge.md#a-ciamservicerole) | yes | `string` | multi | Binding role of a service name this applies to (each environment binds its own) |
| [`ciamServiceAlias`](#a-ciamservicealias) |  | `string` | single | The name other networks connect to an endpoint service by (service name, alias, attachment); it changes with the environment, so every consumer reconnects |
| [`ciamAllowedPrincipal`](#a-ciamallowedprincipal) |  | `string` | multi | An account, subscription or project allowed to connect (or approved automatically) |
| [`ciamAllowsConsumer`](infrastructure.md#a-ciamallowsconsumer) |  | `dn` | multi | Consumer this firewall rule exists for |
| [`ciamAcceptanceRequired`](#a-ciamacceptancerequired) |  | `bool` | single | Whether each new connection waits for the operators to accept it |
| [`ciamVisibleTo`](#a-ciamvisibleto) |  | `string` | multi | An account, subscription or project that may discover the service (none recorded: anyone who knows its name) |
| [`ciamSubnetRole`](#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |

<a id="c-ciamfirewallpolicy"></a>
### ciamFirewallPolicy

A firewall policy attached to the network or above it; rules name it by its role

OID `1.3.6.1.4.1.32473.1.2.90` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamPolicyScope`](#a-ciampolicyscope) | yes | `enum` | single | Whether a firewall policy is attached to the network or above it (an organization or folder; read, never rendered) |
| [`ciamPolicyOrder`](#a-ciampolicyorder) |  | `enum` | single | Which the network evaluates first: its rules or its policy |
| [`ciamTagKeyRef`](#a-ciamtagkeyref) |  | `string` | single | Provider reference of the tag key a firewall policy targets servers by |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamflowlog"></a>
### ciamFlowLog

A flow log: what it records, where it goes, how long it is kept

OID `1.3.6.1.4.1.32473.1.2.89` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamFlowScope`](#a-ciamflowscope) | yes | `enum` | single | What a flow log records: a whole network, subnets, interfaces, a transit attachment, a security group |
| [`ciamSubnetRole`](#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamLogDestinationRole`](observability.md#a-ciamlogdestinationrole) |  | `string` | single | The binding role of what keeps a route's logs in each environment (a log group, a workspace, a SIEM index) |
| [`ciamRetentionDays`](infrastructure.md#a-ciamretentiondays) |  | `int` | single | Retention period in days |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamnetworkacl"></a>
### ciamNetworkAcl

A stateless network ACL on subnets: rules both ways, in number order

OID `1.3.6.1.4.1.32473.1.2.84` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamAclRule`](#a-ciamaclrule) | yes | `string` | multi | A stateless network ACL rule, evaluated in number order: '<number> <allow\|deny> <in\|out> <protocol> <port\|from-to\|all> <cidr>' (100 allow in tcp 636 10.20.0.0/16) |
| [`ciamSubnetRole`](#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamEphemeralPorts`](#a-ciamephemeralports) |  | `string` | single | Port range the clients' return traffic uses (from-to; 1024-65535 when not stated) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamprivateendpoint"></a>
### ciamPrivateEndpoint

A private way to a service the platform uses, so its traffic stays off the internet

OID `1.3.6.1.4.1.32473.1.2.85` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamPrivateService`](#a-ciamprivateservice) | yes | `enum` | single | What a private endpoint reaches: the secret store, keys, object storage, a database, logs, messaging, a registry, the provider's APIs |
| [`ciamPrivateEndpointKind`](#a-ciamprivateendpointkind) |  | `enum` | single | How: an endpoint the routes point at (gateway), an address in a subnet (interface), one address for all of the provider's APIs, the provider's service networks reached by peering, or a subnet setting |
| [`ciamReachesRole`](#a-ciamreachesrole) |  | `string` | multi | Binding role of what it reaches (a secret, key or object store binding) |
| [`ciamSubnetRole`](#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamFrontendIp`](infrastructure.md#a-ciamfrontendip) |  | `ip` | single | Load balancer frontend IP |
| [`ciamCidr`](infrastructure.md#a-ciamcidr) |  | `cidr` | multi | Address range |
| [`ciamDnsZone`](infrastructure.md#a-ciamdnszone) |  | `fqdn` | single | DNS zone the service name is published in |
| [`ciamDnsZoneRef`](infrastructure.md#a-ciamdnszoneref) |  | `string` | single | Provider id of the DNS zone |
| [`ciamPrivateDns`](#a-ciamprivatedns) |  | `bool` | single | Whether the service's usual name resolves to the private endpoint inside the network |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamproxy"></a>
### ciamProxy

What egress to named sites passes, and the sites it allows

OID `1.3.6.1.4.1.32473.1.2.87` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProxyKind`](#a-ciamproxykind) | yes | `enum` | single | What controls egress to named sites: a cloud firewall with domain rules, a managed web proxy, a forward proxy the platform runs, a proxy service run by someone else |
| [`ciamProxyAddress`](#a-ciamproxyaddress) |  | `string` | single | Where clients send traffic to an explicit proxy (host:port) |
| [`ciamAllowedDestination`](#a-ciamalloweddestination) |  | `string` | multi | A site the proxy or firewall lets traffic out to (host, or * and a domain) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamroutetable"></a>
### ciamRouteTable

Routes, and the subnets that use them

OID `1.3.6.1.4.1.32473.1.2.83` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRoute`](#a-ciamroute) | yes | `string` | multi | A route: '<destination> <target kind> [<target>] [for <server roles>]', the target the binding role of what realizes it (0.0.0.0/0 nat pf-egress; 10.20.0.0/16 vpn link-source) |
| [`ciamSubnetRole`](#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamMainTable`](#a-ciammaintable) |  | `bool` | single | Whether this is the network's main route table: subnets no other table names use it |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamtimesource"></a>
### ciamTimeSource

Where the servers get their time (clock skew breaks SAML and replication)

OID `1.3.6.1.4.1.32473.1.2.88` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamTimeServer`](#a-ciamtimeserver) | yes | `string` | multi | A time server the servers synchronize with (host or address; 'ptp:<device>' for a host clock) |
| [`ciamTimeKind`](#a-ciamtimekind) |  | `enum` | single | Where time comes from: the provider's own service, NTP servers, the host's clock (PTP), servers the organization runs |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamacceptancerequired"></a>`ciamAcceptanceRequired` | `1.3.6.1.4.1.32473.1.1.396` | `bool` | binding | single |  | Whether each new connection waits for the operators to accept it |
| <a id="a-ciamacceptedcidr"></a>`ciamAcceptedCidr` | `1.3.6.1.4.1.32473.1.1.403` | `cidr` | binding | multi |  | A range this side accepts from the peer |
| <a id="a-ciamaclrule"></a>`ciamAclRule` | `1.3.6.1.4.1.32473.1.1.388` | `string` | binding | multi | X-PATTERN `^[0-9]+ (allow\|deny) (in\|out) (tcp\|udp\|icmp\|all) ([0-9]+(-[0-9]+)?\|all) [0-9A-Fa-f:.]+/[0-9]+$` | A stateless network ACL rule, evaluated in number order: '<number> <allow\|deny> <in\|out> <protocol> <port\|from-to\|all> <cidr>' (100 allow in tcp 636 10.20.0.0/16) |
| <a id="a-ciamadvertisedcidr"></a>`ciamAdvertisedCidr` | `1.3.6.1.4.1.32473.1.1.402` | `cidr` | binding | multi |  | A range this side advertises over the link |
| <a id="a-ciamalloweddestination"></a>`ciamAllowedDestination` | `1.3.6.1.4.1.32473.1.1.407` | `string` | binding | multi | X-PATTERN `^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+(:[0-9]+)?$` | A site the proxy or firewall lets traffic out to (host, or * and a domain) |
| <a id="a-ciamallowedprincipal"></a>`ciamAllowedPrincipal` | `1.3.6.1.4.1.32473.1.1.395` | `string` | binding | multi |  | An account, subscription or project allowed to connect (or approved automatically) |
| <a id="a-ciamdestination"></a>`ciamDestination` | `1.3.6.1.4.1.32473.1.1.408` | `string` | intent | single | X-PATTERN `^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+(:[0-9]+)?$` | An outside site the platform must reach: a host name or '*.' and a domain, with a port when not 443 |
| <a id="a-ciamephemeralports"></a>`ciamEphemeralPorts` | `1.3.6.1.4.1.32473.1.1.389` | `string` | binding | single | X-PATTERN `^[0-9]+-[0-9]+$` | Port range the clients' return traffic uses (from-to; 1024-65535 when not stated) |
| <a id="a-ciamfirewallmodel"></a>`ciamFirewallModel` | `1.3.6.1.4.1.32473.1.1.414` | enum: `rules`, `policy` | binding | single |  | How the network's firewall rules are kept: as rules on the network (the default) or in a policy attached to it, targeting servers by governed tags |
| <a id="a-ciamflowscope"></a>`ciamFlowScope` | `1.3.6.1.4.1.32473.1.1.413` | enum: `network`, `subnet`, `interface`, `transit`, `security-group` | binding | single |  | What a flow log records: a whole network, subnets, interfaces, a transit attachment, a security group |
| <a id="a-ciamlinkkind"></a>`ciamLinkKind` | `1.3.6.1.4.1.32473.1.1.398` | enum: `peering`, `transit`, `vpn`, `dedicated`, `hub` | binding | single |  | What an interconnect is: network peering, a transit hub attachment, a site-to-site VPN, a dedicated circuit, a managed hub connection |
| <a id="a-ciamlocalasn"></a>`ciamLocalAsn` | `1.3.6.1.4.1.32473.1.1.400` | `int` | binding | single |  | BGP autonomous system number on this side |
| <a id="a-ciammaintable"></a>`ciamMainTable` | `1.3.6.1.4.1.32473.1.1.387` | `bool` | binding | single |  | Whether this is the network's main route table: subnets no other table names use it |
| <a id="a-ciamnatallocation"></a>`ciamNatAllocation` | `1.3.6.1.4.1.32473.1.1.418` | enum: `static`, `automatic` | binding | single |  | Whether egress addresses are fixed (static) or picked by the provider (automatic: nothing a partner can allowlist) |
| <a id="a-ciamneededbyrole"></a>`ciamNeededByRole` | `1.3.6.1.4.1.32473.1.1.410` | `string` | intent | multi |  | A server role that must reach it |
| <a id="a-ciamopenwithinnetwork"></a>`ciamOpenWithinNetwork` | `1.3.6.1.4.1.32473.1.1.420` | `bool` | binding | single |  | Whether the network admits traffic between its own addresses unless a rule denies it (some providers' default rules do) |
| <a id="a-ciampeeraccepted"></a>`ciamPeerAccepted` | `1.3.6.1.4.1.32473.1.1.404` | `bool` | binding | single |  | Whether the other side has accepted or configured its half (peering is two-sided) |
| <a id="a-ciampeerasn"></a>`ciamPeerAsn` | `1.3.6.1.4.1.32473.1.1.401` | `int` | binding | single |  | BGP autonomous system number of the peer |
| <a id="a-ciampeergateway"></a>`ciamPeerGateway` | `1.3.6.1.4.1.32473.1.1.399` | `ip` | binding | multi |  | Address of the other end (a VPN peer's gateway, a tunnel's outside address) |
| <a id="a-ciampolicyorder"></a>`ciamPolicyOrder` | `1.3.6.1.4.1.32473.1.1.416` | enum: `rules-first`, `policy-first` | binding | single |  | Which the network evaluates first: its rules or its policy |
| <a id="a-ciampolicyrole"></a>`ciamPolicyRole` | `1.3.6.1.4.1.32473.1.1.417` | `string` | binding | single |  | Binding role of the firewall policy a rule belongs to |
| <a id="a-ciampolicyscope"></a>`ciamPolicyScope` | `1.3.6.1.4.1.32473.1.1.415` | enum: `network`, `hierarchical` | binding | single |  | Whether a firewall policy is attached to the network or above it (an organization or folder; read, never rendered) |
| <a id="a-ciamprivatedns"></a>`ciamPrivateDns` | `1.3.6.1.4.1.32473.1.1.393` | `bool` | binding | single |  | Whether the service's usual name resolves to the private endpoint inside the network |
| <a id="a-ciamprivateendpointkind"></a>`ciamPrivateEndpointKind` | `1.3.6.1.4.1.32473.1.1.391` | enum: `gateway`, `interface`, `all-apis`, `peered-service`, `subnet-access` | binding | single |  | How: an endpoint the routes point at (gateway), an address in a subnet (interface), one address for all of the provider's APIs, the provider's service networks reached by peering, or a subnet setting |
| <a id="a-ciamprivateservice"></a>`ciamPrivateService` | `1.3.6.1.4.1.32473.1.1.390` | enum: `secrets`, `keys`, `object-storage`, `database`, `logs`, `messaging`, `registry`, `apis`, `other` | binding | single |  | What a private endpoint reaches: the secret store, keys, object storage, a database, logs, messaging, a registry, the provider's APIs |
| <a id="a-ciamproxyaddress"></a>`ciamProxyAddress` | `1.3.6.1.4.1.32473.1.1.406` | `string` | binding | single | X-PATTERN `^[A-Za-z0-9.-]+:[0-9]+$` | Where clients send traffic to an explicit proxy (host:port) |
| <a id="a-ciamproxykind"></a>`ciamProxyKind` | `1.3.6.1.4.1.32473.1.1.405` | enum: `firewall`, `web-proxy`, `forward-proxy`, `service` | binding | single |  | What controls egress to named sites: a cloud firewall with domain rules, a managed web proxy, a forward proxy the platform runs, a proxy service run by someone else |
| <a id="a-ciamreachesrole"></a>`ciamReachesRole` | `1.3.6.1.4.1.32473.1.1.392` | `string` | binding | multi |  | Binding role of what it reaches (a secret, key or object store binding) |
| <a id="a-ciamroute"></a>`ciamRoute` | `1.3.6.1.4.1.32473.1.1.386` | `string` | binding | multi | X-PATTERN `^([0-9A-Fa-f:.]+/[0-9]+\|[A-Za-z][A-Za-z0-9._-]*) (local\|internet\|egress-only\|nat\|transit\|peering\|vpn\|endpoint\|firewall\|appliance\|gateway-lb\|none)( [^ ]+)?( for [a-z0-9][a-z0-9-]*(,[a-z0-9][a-z0-9-]*)*)?$` | A route: '<destination> <target kind> [<target>] [for <server roles>]', the target the binding role of what realizes it (0.0.0.0/0 nat pf-egress; 10.20.0.0/16 vpn link-source) |
| <a id="a-ciamservicealias"></a>`ciamServiceAlias` | `1.3.6.1.4.1.32473.1.1.394` | `string` | binding | single |  | The name other networks connect to an endpoint service by (service name, alias, attachment); it changes with the environment, so every consumer reconnects |
| <a id="a-ciamsharedkeyrole"></a>`ciamSharedKeyRole` | `1.3.6.1.4.1.32473.1.1.967` | `string` | binding | single |  | The binding role of the secret reference (ciamSecretRef) holding the link's pre-shared key (a VPN's IPsec key), read when applied: a reference, never the value |
| <a id="a-ciamsitekind"></a>`ciamSiteKind` | `1.3.6.1.4.1.32473.1.1.409` | enum: `partner-metadata`, `jwks`, `ocsp-crl`, `mfa`, `messaging`, `vendor-update`, `directory`, `other` | intent | single |  | What the site serves: a partner's metadata, signing keys (JWKS), certificate status (OCSP, CRL), an MFA or messaging vendor, vendor updates, a directory |
| <a id="a-ciamsubnetrole"></a>`ciamSubnetRole` | `1.3.6.1.4.1.32473.1.1.385` | `string` | binding | multi |  | Binding role of a subnet this applies to |
| <a id="a-ciamtagkeyref"></a>`ciamTagKeyRef` | `1.3.6.1.4.1.32473.1.1.419` | `string` | binding | single |  | Provider reference of the tag key a firewall policy targets servers by |
| <a id="a-ciamtimekind"></a>`ciamTimeKind` | `1.3.6.1.4.1.32473.1.1.412` | enum: `provider`, `ntp`, `ptp`, `internal` | binding | single |  | Where time comes from: the provider's own service, NTP servers, the host's clock (PTP), servers the organization runs |
| <a id="a-ciamtimeserver"></a>`ciamTimeServer` | `1.3.6.1.4.1.32473.1.1.411` | `string` | binding | multi |  | A time server the servers synchronize with (host or address; 'ptp:<device>' for a host clock) |
| <a id="a-ciamvisibleto"></a>`ciamVisibleTo` | `1.3.6.1.4.1.32473.1.1.397` | `string` | binding | multi |  | An account, subscription or project that may discover the service (none recorded: anyone who knows its name) |
