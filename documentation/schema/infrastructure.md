# Infrastructure

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 20 object classes · 76 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

**Branches:** `ou=environments,dc=ciam-ops`, `ou=external-allowlists,dc=ciam-ops`

## Object classes

<a id="c-ciamappliance"></a>
### ciamAppliance

An appliance the platform's configuration is pushed to (a load balancer, a DNS server, a network firewall), filling a stack role: where its management API answers and how the push signs in

OID `1.3.6.1.4.1.32473.1.2.133` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamStackRole`](#a-ciamstackrole) | yes | `string` | single | Role a stack component fills in its environment (e.g. provider, directory, federation) |
| [`ciamManagementAddress`](#a-ciammanagementaddress) | yes | `string` | single | Where an appliance's management API answers: a host name or address (and port when not the default) |
| [`ciamApplianceScope`](#a-ciamappliancescope) |  | `string` | single | Where on an appliance the platform's objects go, in the appliance's own terms (a tenant, a partition, a device group or virtual system, a DNS view or server): the adapter that renders for it says which |
| [`ciamLoginName`](governance.md#a-ciamloginname) |  | `string` | single | The account a collection source's credential signs in as (a read-only service account) |
| [`ciamLoginSecretRole`](#a-ciamloginsecretrole) |  | `string` | single | Binding role of the secret holding the password or API key an appliance's login signs in with, read at run time |
| [`ciamManagedBy`](#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamProviderRef`](#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamApplianceSource`](#a-ciamappliancesource) |  | `cidr` | multi | A range an appliance's own traffic to the servers comes from (a load balancer's source NAT pool and self addresses, its health monitors too): the servers' firewall rules must admit it |
| [`ciamUnrecordedRule`](#a-ciamunrecordedrule) |  | `string` | multi | A rule a network firewall's running configuration, read back, holds that the record doesn't: one carrying the environment's marker for a rule the record lacks, or an allow to the environment's servers nobody recorded; '<rulebase> <rule>: <sources> -> <destinations> <services>' |

<a id="c-ciambackuptarget"></a>
### ciamBackupTarget

An object store backups are written to, with their retention

OID `1.3.6.1.4.1.32473.1.2.14` · structural · inherits [`ciamObjectStore`](#c-ciamobjectstore)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRetentionDays`](#a-ciamretentiondays) |  | `int` | single | Retention period in days |

<a id="c-ciambinding"></a>
### ciamBinding

Environment-specific binding of an abstract role

OID `1.3.6.1.4.1.32473.1.2.5` · abstract · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamBindingRole`](#a-ciambindingrole) | yes | `string` | single | Abstract role a binding fulfils (for a credential, the role of the bindings that hold it); migrations match roles across environments |
| [`ciamProviderRef`](#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |

<a id="c-ciamcloud"></a>
### ciamCloud

A cloud hosting environment

OID `1.3.6.1.4.1.32473.1.2.2` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cloud`](#a-cloud) | yes | `string` | single | RDN of a cloud hosting environment |
| [`ciamCloudProvider`](#a-ciamcloudprovider) | yes | `vocab` | single | Cloud or hosting provider; the adapters that apply are chosen from it |
| [`ciamRegion`](#a-ciamregion) | yes | `string` | single | Provider region |
| [`ciamCloudEnvironment`](#a-ciamcloudenvironment) |  | `vocab` | single | Partition of the provider (e.g. commercial vs government cloud) |
| [`ciamLifecycle`](#a-ciamlifecycle) |  | `enum` | single | Lifecycle state |

<a id="c-ciamegress"></a>
### ciamEgress

Outbound (NAT) addresses our services send from

OID `1.3.6.1.4.1.32473.1.2.12` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamCidr`](#a-ciamcidr) | yes | `cidr` | multi | Address range |
| [`ciamNatAllocation`](network.md#a-ciamnatallocation) |  | `enum` | single | Whether egress addresses are fixed (static) or picked by the provider (automatic: nothing a partner can allowlist) |
| [`ciamZone`](#a-ciamzone) |  | `string` | single | Availability zone |
| [`ciamManagedBy`](#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamenvironment"></a>
### ciamEnvironment

A deployment stage within a cloud

OID `1.3.6.1.4.1.32473.1.2.3` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`env`](#a-env) | yes | `string` | single | RDN of a deployment stage within a cloud (prod/stage) |
| [`ciamLifecycle`](#a-ciamlifecycle) |  | `enum` | single | Lifecycle state |
| [`ciamPlannedCutover`](#a-ciamplannedcutover) |  | `time` | single | Planned cutover date for an environment being built |
| [`ciamJoinsDeploymentOf`](#a-ciamjoinsdeploymentof) |  | `dn` | single | DS replicas here join the replication deployment of that environment |
| [`ciamOverlayOf`](#a-ciamoverlayof) |  | `dn` | single | The environment this one is an overlay of: it inherits that environment's bindings, stack, required roles and overrides, except the roles it binds, drops, declares or overrides itself (never servers) |
| [`ciamDropsRole`](#a-ciamdropsrole) |  | `string` | multi | A role of the base environment this overlay does not inherit |

<a id="c-ciamexternalallowlist"></a>
### ciamExternalAllowlist

An allowlist in someone else's system that contains our addresses

OID `1.3.6.1.4.1.32473.1.2.13` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamManagedBy`](#a-ciammanagedby) | yes | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamRefersToRole`](#a-ciamreferstorole) | yes | `string` | single | Binding role of OUR address this allowlist contains (resolved per environment) |
| [`ciamRecordedCidr`](#a-ciamrecordedcidr) | yes | `cidr` | multi | Addresses the external allowlist contains today |
| [`ciamAllowlistDirection`](#a-ciamallowlistdirection) | yes | `enum` | single | consumer-egress: their outbound rule to our service; partner-ingress: they allow our egress in; partner-egress: they send to us |
| [`ciamExternalSystem`](#a-ciamexternalsystem) |  | `string` | single | Where the allowlist lives (partner firewall, app egress policy, SaaS IP list) |
| [`ciamLeadTimeDays`](#a-ciamleadtimedays) |  | `int` | single | Typical lead time for the owner to change it |
| [`ciamRequestStatus`](#a-ciamrequeststatus) |  | `enum` | single | Status of the change request to the owner |
| [`ciamAllowsConsumer`](#a-ciamallowsconsumer) |  | `dn` | multi | Consumer this firewall rule exists for |
| [`ciamAllowlistRef`](#a-ciamallowlistref) |  | `string` | single | Where in the system holding it the allowlist is, as the adapter reading that system names it ('<adapter>:<path>', e.g. panos:panorama.example.internal/shared/address-group/partner-in): an import of that system's running configuration records the addresses it holds (ciamRecordedCidr) |

<a id="c-ciamexternalhost"></a>
### ciamExternalHost

A system the platform reaches but doesn't run (a database, a corporate directory), as this environment reaches it: its host name (and port); products name its role, so each environment renders its own host. One host is the usual case; a system reached at several (two domain controllers) is several bindings of the role, in host order

OID `1.3.6.1.4.1.32473.1.2.92` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamFqdn`](#a-ciamfqdn) | yes | `fqdn` | single | Service DNS name consumers and partners use. Must stay stable across migrations |
| [`ciamPort`](#a-ciamport) |  | `port` | multi | TCP/UDP port |
| [`ciamManagedBy`](#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamHostOrder`](#a-ciamhostorder) |  | `int` | single | This host's place among an environment's bindings of one role when a product setting lists several (failover order, lowest first) |

<a id="c-ciamfirewallrule"></a>
### ciamFirewallRule

Inbound allow rule

OID `1.3.6.1.4.1.32473.1.2.9` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamSourceCidr`](#a-ciamsourcecidr) | yes | `cidr` | multi | Allowed source range |
| [`ciamPort`](#a-ciamport) | yes | `port` | multi | TCP/UDP port |
| [`ciamTargetRole`](#a-ciamtargetrole) | yes | `vocab` | single | Server role a service or rule targets |
| [`ciamProtocol`](#a-ciamprotocol) |  | `enum` | single | Transport protocol |
| [`ciamAllowsConsumer`](#a-ciamallowsconsumer) |  | `dn` | multi | Consumer this firewall rule exists for |
| [`ciamRulePriority`](#a-ciamrulepriority) |  | `int` | single | Provider firewall rule priority. Pinned so adding a rule never renumbers others |
| [`ciamPolicyRole`](network.md#a-ciampolicyrole) |  | `string` | single | Binding role of the firewall policy a rule belongs to |
| [`ciamManagedBy`](#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| [`ciamRunningState`](#a-ciamrunningstate) |  | `enum` | single | Where a firewall manager's running configuration, read back, holds this rule: committed (a manager's, such as Panorama: its delivery to the firewalls unconfirmed), deployed (a firewall's own; on a manager whose firewalls were read, every firewall it pushes to runs it), partial (some of them don't), disabled (there, but switched off), missing (the record holds it, the running configuration doesn't); on a rule observation, what one managed firewall runs |
| [`ciamRunningFact`](#a-ciamrunningfact) |  | `string` | multi | What a firewall rule, read back running, does that the rule's own attributes can't hold: '<key> <value>'; record-owned drift (action deny, log-end no, destination 10.0.1.9/32, description <text>, source or service it can't resolve) and the network team's settings that limit what it admits (negate-source yes, schedule <name>, rulebase <where>) |

<a id="c-ciaminterconnect"></a>
### ciamInterconnect

Link to another environment

OID `1.3.6.1.4.1.32473.1.2.15` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamInterconnectKind`](#a-ciaminterconnectkind) | yes | `string` | single | Cross-environment link, in words (site-to-site VPN run by the landing zone); ciamLinkKind says which kind it is |
| [`ciamPeerEnvironment`](#a-ciampeerenvironment) | yes | `dn` | single | Environment at the other end of an interconnect |
| [`ciamSourceCidr`](#a-ciamsourcecidr) | yes | `cidr` | multi | Allowed source range |
| [`ciamPort`](#a-ciamport) |  | `port` | multi | TCP/UDP port |
| [`ciamLinkKind`](network.md#a-ciamlinkkind) |  | `enum` | single | What an interconnect is: network peering, a transit hub attachment, a site-to-site VPN, a dedicated circuit, a managed hub connection |
| [`ciamPeerGateway`](network.md#a-ciampeergateway) |  | `ip` | multi | Address of the other end (a VPN peer's gateway, a tunnel's outside address) |
| [`ciamLocalAsn`](network.md#a-ciamlocalasn) |  | `int` | single | BGP autonomous system number on this side |
| [`ciamPeerAsn`](network.md#a-ciampeerasn) |  | `int` | single | BGP autonomous system number of the peer |
| [`ciamAdvertisedCidr`](network.md#a-ciamadvertisedcidr) |  | `cidr` | multi | A range this side advertises over the link |
| [`ciamAcceptedCidr`](network.md#a-ciamacceptedcidr) |  | `cidr` | multi | A range this side accepts from the peer |
| [`ciamPeerAccepted`](network.md#a-ciampeeraccepted) |  | `bool` | single | Whether the other side has accepted or configured its half (peering is two-sided) |
| [`ciamSharedKeyRole`](network.md#a-ciamsharedkeyrole) |  | `string` | single | The binding role of the secret reference (ciamSecretRef) holding the link's pre-shared key (a VPN's IPsec key), read when applied: a reference, never the value |
| [`ciamManagedBy`](#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciammanagedfirewall"></a>
### ciamManagedFirewall

A firewall a manager appliance pushes the environment's rules to (cn: its serial number; a child of the manager's ciamAppliance), observed: its name, the virtual contexts and device group it gets, whether it is connected and in sync, its software version and high-availability peer

OID `1.3.6.1.4.1.32473.1.2.204` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamDeviceName`](#a-ciamdevicename) |  | `string` | single | A managed firewall's host name, as its manager lists it |
| [`ciamDeviceContext`](#a-ciamdevicecontext) |  | `string` | multi | A virtual firewall context of a managed firewall its manager pushes policy to, in the vendor's naming (a PAN-OS virtual system vsys1, a FortiGate VDOM) |
| [`ciamApplianceScope`](#a-ciamappliancescope) |  | `string` | single | Where on an appliance the platform's objects go, in the appliance's own terms (a tenant, a partition, a device group or virtual system, a DNS view or server): the adapter that renders for it says which |
| [`ciamDeviceConnected`](#a-ciamdeviceconnected) |  | `bool` | single | Whether a managed firewall is connected to its manager, as the manager says |
| [`ciamSoftwareVersion`](#a-ciamsoftwareversion) |  | `string` | single | The software version a managed firewall runs, as its manager lists it |
| [`ciamHaState`](#a-ciamhastate) |  | `string` | single | A managed firewall's high-availability state as its manager lists it, with its peer: 'active, peer <serial>' |
| [`ciamPolicySync`](#a-ciampolicysync) |  | `string` | single | Whether the policy a manager pushed is what a managed firewall runs, in the manager's words (in sync, out of sync) |

<a id="c-ciamnetwork"></a>
### ciamNetwork

Virtual network

OID `1.3.6.1.4.1.32473.1.2.6` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamCidr`](#a-ciamcidr) | yes | `cidr` | multi | Address range |
| [`ciamResourceGroup`](#a-ciamresourcegroup) |  | `string` | single | Provider resource group or container the resources are placed in |
| [`ciamFirewallModel`](network.md#a-ciamfirewallmodel) |  | `enum` | single | How the network's firewall rules are kept: as rules on the network (the default) or in a policy attached to it, targeting servers by governed tags |
| [`ciamOpenWithinNetwork`](network.md#a-ciamopenwithinnetwork) |  | `bool` | single | Whether the network admits traffic between its own addresses unless a rule denies it (some providers' default rules do) |

<a id="c-ciamobjectstore"></a>
### ciamObjectStore

An object storage location (bucket or container) the stack uses; a backup target is one with a retention

OID `1.3.6.1.4.1.32473.1.2.81` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamStorageRef`](#a-ciamstorageref) | yes | `string` | single | Object storage location (bucket or container URI, e.g. s3://bucket, azblob://account/container, gs://bucket) |
| [`ciamStorageVersioning`](data.md#a-ciamstorageversioning) |  | `bool` | single | Whether an object store keeps every version of an object, so an overwrite or delete can be undone |
| [`ciamStorageImmutability`](data.md#a-ciamstorageimmutability) |  | `enum` | single | Whether an object store's objects, or a backup vault's recovery points, are locked against change and deletion for ciamStorageLockDays: governance (a privileged user may lift it) or compliance (nobody may, the account root included) |
| [`ciamStorageLockDays`](data.md#a-ciamstoragelockdays) |  | `int` | single | How long each object or recovery point stays locked at least (ciamStorageImmutability) |
| [`ciamStorageLifecycle`](data.md#a-ciamstoragelifecycle) |  | `string` | multi | A lifecycle rule: '[noncurrent ]<days> <cool\|cold\|archive\|delete>', after days move objects (or their noncurrent versions) to a cheaper tier or delete them (30 cool; 365 delete; noncurrent 90 delete) |
| [`ciamStoragePublicBlocked`](data.md#a-ciamstoragepublicblocked) |  | `bool` | single | Whether public access to the object store is blocked whatever its policies and ACLs say |
| [`ciamStorageReplicaRef`](data.md#a-ciamstoragereplicaref) |  | `string` | single | The object store its objects are copied to, usually in another region (a bucket or container URI): each environment's own |
| [`ciamEncryptedByRole`](pki.md#a-ciamencryptedbyrole) |  | `string` | single | The binding role of the key that encrypts a secret in its store (a customer managed key): who reads or writes the secret may also need to use that key |
| [`ciamManagedBy`](#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamoverride"></a>
### ciamOverride

An environment's own value for one overridable attribute of a shared entry; the description says why

OID `1.3.6.1.4.1.32473.1.2.45` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamOverrides`](#a-ciamoverrides) | yes | `dn` | single | The entry whose value this environment overrides |
| [`ciamOverrideAttribute`](#a-ciamoverrideattribute) | yes | `string` | single | The attribute overridden: one whose definition allows it (X-OVERRIDABLE) |
| [`ciamOverrideValue`](#a-ciamoverridevalue) | yes | `string` | multi | The value(s) this environment uses instead of the shared one |

<a id="c-ciamrequiredrole"></a>
### ciamRequiredRole

A role the environment must bind, declared as data (beyond what its domains and adapters require); the description says why

OID `1.3.6.1.4.1.32473.1.2.44` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamBindingRole`](#a-ciambindingrole) | yes | `string` | single | Abstract role a binding fulfils (for a credential, the role of the bindings that hold it); migrations match roles across environments |

<a id="c-ciamruleobservation"></a>
### ciamRuleObservation

What one managed firewall runs of one of the environment's firewall rules (cn: '<rule>/<context>'; a child of the ciamManagedFirewall), observed: deployed, disabled or missing in the policy pushed to it, and its hit counts

OID `1.3.6.1.4.1.32473.1.2.205` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamRunningState`](#a-ciamrunningstate) | yes | `enum` | single | Where a firewall manager's running configuration, read back, holds this rule: committed (a manager's, such as Panorama: its delivery to the firewalls unconfirmed), deployed (a firewall's own; on a manager whose firewalls were read, every firewall it pushes to runs it), partial (some of them don't), disabled (there, but switched off), missing (the record holds it, the running configuration doesn't); on a rule observation, what one managed firewall runs |
| [`ciamDeviceContext`](#a-ciamdevicecontext) |  | `string` | multi | A virtual firewall context of a managed firewall its manager pushes policy to, in the vendor's naming (a PAN-OS virtual system vsys1, a FortiGate VDOM) |
| [`ciamHitCount`](#a-ciamhitcount) |  | `int` | single | How many sessions a rule has matched on a firewall since counting began (ciamCountedSince) |
| [`ciamFirstHit`](#a-ciamfirsthit) |  | `time` | single | When a rule first matched a session on a firewall |
| [`ciamLastHit`](#a-ciamlasthit) |  | `time` | single | When a rule last matched a session on a firewall |
| [`ciamCountedSince`](#a-ciamcountedsince) |  | `time` | single | When a firewall began counting a rule's hits: the later of its counters' last reset and the rule's creation |

<a id="c-ciamserver"></a>
### ciamServer

A server instance

OID `1.3.6.1.4.1.32473.1.2.4` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamServerRole`](#a-ciamserverrole) | yes | `vocab` | single | What the server runs (a role the product adapters define) |
| [`ciamHostname`](#a-ciamhostname) | yes | `fqdn` | single | Server hostname (never used by consumers) |
| [`ciamSubnet`](#a-ciamsubnet) | yes | `dn` | single | Subnet binding the server is placed in |
| [`ciamProductVersion`](#a-ciamproductversion) |  | `string` | single | Product and version |
| [`ciamPrivateIp`](#a-ciamprivateip) |  | `ip` | single | Private IP address |
| [`ciamZone`](#a-ciamzone) |  | `string` | single | Availability zone |
| [`ciamInstanceSize`](#a-ciaminstancesize) |  | `string` | single | Instance / VM size |
| [`ciamImageRef`](#a-ciamimageref) |  | `string` | single | Machine image reference |
| [`ciamInstallRoot`](#a-ciaminstallroot) |  | `string` | single | Where the server's product is installed (an absolute path: the opendj directory, AM's base directory, <pf_install>): the base its log files are found under; none recorded, none guessed |

<a id="c-ciamservicename"></a>
### ciamServiceName

Stable service name + load balancer (its DNS answer, and what the load balancer runs)

OID `1.3.6.1.4.1.32473.1.2.8` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamFqdn`](#a-ciamfqdn) | yes | `fqdn` | single | Service DNS name consumers and partners use. Must stay stable across migrations |
| [`ciamTargetRole`](#a-ciamtargetrole) | yes | `vocab` | single | Server role a service or rule targets |
| [`ciamPort`](#a-ciamport) | yes | `port` | multi | TCP/UDP port |
| [`ciamDnsZone`](#a-ciamdnszone) |  | `fqdn` | single | DNS zone the service name is published in |
| [`ciamDnsZoneRef`](#a-ciamdnszoneref) |  | `string` | single | Provider id of the DNS zone |
| [`ciamFrontendIp`](#a-ciamfrontendip) |  | `ip` | single | Load balancer frontend IP |
| [`ciamExposure`](#a-ciamexposure) |  | `enum` | single | Whether a service name's load balancer is internal or internet-facing, recorded when no frontend address says so (the provider assigns the address) |
| [`ciamTlsCertificate`](#a-ciamtlscertificate) |  | `dn` | single | Certificate this service name presents in this environment |
| [`ciamTtlSeconds`](edge.md#a-ciamttlseconds) |  | `int` | single | How long resolvers may cache a DNS answer, in seconds (lowered before a cutover) |
| [`ciamRoutingPolicy`](edge.md#a-ciamroutingpolicy) |  | `enum` | single | How a DNS name chooses among answers: one answer, the primary or secondary of a health-checked failover pair, or a weighted share |
| [`ciamRoutingWeight`](edge.md#a-ciamroutingweight) |  | `int` | single | Share of answers a weighted record gets |
| [`ciamEdgeFact`](edge.md#a-ciamedgefact) |  | `string` | multi | What the edge runs, read back in the policies' terms: '<key> <value>' (tls-min 1.2, waf-category core-rules, rate-limit token 100/300s per ip, health https /pf/heartbeat.ping) |
| [`ciamEdgeSetting`](edge.md#a-ciamedgesetting) |  | `string` | multi | A setting the edge runs that the policies' terms can't express, in the provider's own terms |
| [`ciamManagedBy`](#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamstackcomponent"></a>
### ciamStackComponent

One component of an environment stack: the adapter that fills a role, and the offering of its product when it has several (ciamOffering)

OID `1.3.6.1.4.1.32473.1.2.33` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamStackRole`](#a-ciamstackrole) | yes | `string` | single | Role a stack component fills in its environment (e.g. provider, directory, federation) |
| [`ciamAdapter`](#a-ciamadapter) | yes | `string` | single | Name of the adapter that fills the role, as its package registers it |
| [`ciamAdapterVersion`](#a-ciamadapterversion) |  | `string` | single | Adapter versions the environment accepts (a PEP 440 range, e.g. >=0.1,<1) |
| [`ciamAdapterSource`](#a-ciamadaptersource) |  | `string` | single | Where to get the adapter package (URL or package name) |
| [`ciamRenderTarget`](#a-ciamrendertarget) |  | `string` | multi | A render target the environment holds for the component's adapter (one the adapter declares, such as the infrastructure-as-code language a cloud adapter writes), set only when the environment requires that form: renders then write only the forms it holds. None: the user chooses for each render (`opsdir render --target`), else the adapter's defaults |
| [`ciamOffering`](#a-ciamoffering) |  | `vocab` | single | Which offering of its product fills a stack component's role, from the vocabulary its adapter declares (e.g. a managed service's serverless form). Not recorded: the adapter's default |

<a id="c-ciamsubnetbinding"></a>
### ciamSubnetBinding

Subnet

OID `1.3.6.1.4.1.32473.1.2.7` · structural · inherits [`ciamBinding`](#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamCidr`](#a-ciamcidr) | yes | `cidr` | multi | Address range |
| [`ciamZone`](#a-ciamzone) |  | `string` | single | Availability zone |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamadapter"></a>`ciamAdapter` | `1.3.6.1.4.1.32473.1.1.127` | `string` | binding | single |  | Name of the adapter that fills the role, as its package registers it |
| <a id="a-ciamadaptersource"></a>`ciamAdapterSource` | `1.3.6.1.4.1.32473.1.1.129` | `string` | binding | single |  | Where to get the adapter package (URL or package name) |
| <a id="a-ciamadapterversion"></a>`ciamAdapterVersion` | `1.3.6.1.4.1.32473.1.1.128` | `string` | binding | single |  | Adapter versions the environment accepts (a PEP 440 range, e.g. >=0.1,<1) |
| <a id="a-ciamallowlistdirection"></a>`ciamAllowlistDirection` | `1.3.6.1.4.1.32473.1.1.42` | enum: `consumer-egress`, `partner-ingress`, `partner-egress` | meta | single |  | consumer-egress: their outbound rule to our service; partner-ingress: they allow our egress in; partner-egress: they send to us |
| <a id="a-ciamallowlistref"></a>`ciamAllowlistRef` | `1.3.6.1.4.1.32473.1.1.703` | `string` | meta | single | X-PATTERN `^[a-z0-9][a-z0-9-]*:[^ ].*$` | Where in the system holding it the allowlist is, as the adapter reading that system names it ('<adapter>:<path>', e.g. panos:panorama.example.internal/shared/address-group/partner-in): an import of that system's running configuration records the addresses it holds (ciamRecordedCidr) |
| <a id="a-ciamallowsconsumer"></a>`ciamAllowsConsumer` | `1.3.6.1.4.1.32473.1.1.33` | `dn` | binding | multi |  | Consumer this firewall rule exists for |
| <a id="a-ciamappliancescope"></a>`ciamApplianceScope` | `1.3.6.1.4.1.32473.1.1.627` | `string` | binding | single |  | Where on an appliance the platform's objects go, in the appliance's own terms (a tenant, a partition, a device group or virtual system, a DNS view or server): the adapter that renders for it says which |
| <a id="a-ciamappliancesource"></a>`ciamApplianceSource` | `1.3.6.1.4.1.32473.1.1.631` | `cidr` | binding | multi |  | A range an appliance's own traffic to the servers comes from (a load balancer's source NAT pool and self addresses, its health monitors too): the servers' firewall rules must admit it |
| <a id="a-ciambindingrole"></a>`ciamBindingRole` | `1.3.6.1.4.1.32473.1.1.21` | `string` | meta | single |  | Abstract role a binding fulfils (for a credential, the role of the bindings that hold it); migrations match roles across environments |
| <a id="a-ciamcidr"></a>`ciamCidr` | `1.3.6.1.4.1.32473.1.1.24` | `cidr` | binding | multi |  | Address range |
| <a id="a-ciamcloudenvironment"></a>`ciamCloudEnvironment` | `1.3.6.1.4.1.32473.1.1.9` | vocab: `public` (aws), `public` (azure), `usgovernment` (azure), `public` (gcp), `on-premises` (onprem) | binding | single |  | Partition of the provider (e.g. commercial vs government cloud) |
| <a id="a-ciamcloudprovider"></a>`ciamCloudProvider` | `1.3.6.1.4.1.32473.1.1.7` | vocab: `aws` (aws), `azure` (azure), `gcp` (gcp), `onprem` (onprem) | binding | single |  | Cloud or hosting provider; the adapters that apply are chosen from it |
| <a id="a-ciamcountedsince"></a>`ciamCountedSince` | `1.3.6.1.4.1.32473.1.1.957` | `time` | observed | single |  | When a firewall began counting a rule's hits: the later of its counters' last reset and the rule's creation |
| <a id="a-ciamdeviceconnected"></a>`ciamDeviceConnected` | `1.3.6.1.4.1.32473.1.1.950` | `bool` | observed | single |  | Whether a managed firewall is connected to its manager, as the manager says |
| <a id="a-ciamdevicecontext"></a>`ciamDeviceContext` | `1.3.6.1.4.1.32473.1.1.949` | `string` | observed | multi |  | A virtual firewall context of a managed firewall its manager pushes policy to, in the vendor's naming (a PAN-OS virtual system vsys1, a FortiGate VDOM) |
| <a id="a-ciamdevicename"></a>`ciamDeviceName` | `1.3.6.1.4.1.32473.1.1.948` | `string` | observed | single |  | A managed firewall's host name, as its manager lists it |
| <a id="a-ciamdnszone"></a>`ciamDnsZone` | `1.3.6.1.4.1.32473.1.1.26` | `fqdn` | binding | single |  | DNS zone the service name is published in |
| <a id="a-ciamdnszoneref"></a>`ciamDnsZoneRef` | `1.3.6.1.4.1.32473.1.1.27` | `string` | binding | single |  | Provider id of the DNS zone |
| <a id="a-ciamdropsrole"></a>`ciamDropsRole` | `1.3.6.1.4.1.32473.1.1.209` | `string` | binding | multi |  | A role of the base environment this overlay does not inherit |
| <a id="a-ciamexposure"></a>`ciamExposure` | `1.3.6.1.4.1.32473.1.1.623` | enum: `internal`, `internet` | binding | single |  | Whether a service name's load balancer is internal or internet-facing, recorded when no frontend address says so (the provider assigns the address) |
| <a id="a-ciamexternalsystem"></a>`ciamExternalSystem` | `1.3.6.1.4.1.32473.1.1.41` | `string` | meta | single |  | Where the allowlist lives (partner firewall, app egress policy, SaaS IP list) |
| <a id="a-ciamfirsthit"></a>`ciamFirstHit` | `1.3.6.1.4.1.32473.1.1.955` | `time` | observed | single |  | When a rule first matched a session on a firewall |
| <a id="a-ciamfqdn"></a>`ciamFqdn` | `1.3.6.1.4.1.32473.1.1.25` | `fqdn` | contract | single |  | Service DNS name consumers and partners use. Must stay stable across migrations |
| <a id="a-ciamfrontendip"></a>`ciamFrontendIp` | `1.3.6.1.4.1.32473.1.1.30` | `ip` | binding | single |  | Load balancer frontend IP |
| <a id="a-ciamhastate"></a>`ciamHaState` | `1.3.6.1.4.1.32473.1.1.952` | `string` | observed | single |  | A managed firewall's high-availability state as its manager lists it, with its peer: 'active, peer <serial>' |
| <a id="a-ciamhitcount"></a>`ciamHitCount` | `1.3.6.1.4.1.32473.1.1.954` | `int` | observed | single |  | How many sessions a rule has matched on a firewall since counting began (ciamCountedSince) |
| <a id="a-ciamhostname"></a>`ciamHostname` | `1.3.6.1.4.1.32473.1.1.15` | `fqdn` | binding | single |  | Server hostname (never used by consumers) |
| <a id="a-ciamhostorder"></a>`ciamHostOrder` | `1.3.6.1.4.1.32473.1.1.426` | `int` | binding | single |  | This host's place among an environment's bindings of one role when a product setting lists several (failover order, lowest first) |
| <a id="a-ciamimageref"></a>`ciamImageRef` | `1.3.6.1.4.1.32473.1.1.19` | `string` | binding | single |  | Machine image reference |
| <a id="a-ciaminenvironment"></a>`ciamInEnvironment` | `1.3.6.1.4.1.32473.1.1.629` | `dn` | intent | multi |  | An environment a shared entry (a host baseline, a job) applies in; an overlay of it too. With neither this nor ciamOnProvider, the entry applies in every environment |
| <a id="a-ciaminstallroot"></a>`ciamInstallRoot` | `1.3.6.1.4.1.32473.1.1.632` | `string` | binding | single | X-PATTERN `^(/\|[A-Za-z]:[\\/]).*$` | Where the server's product is installed (an absolute path: the opendj directory, AM's base directory, <pf_install>): the base its log files are found under; none recorded, none guessed |
| <a id="a-ciaminstancesize"></a>`ciamInstanceSize` | `1.3.6.1.4.1.32473.1.1.18` | `string` | binding | single |  | Instance / VM size |
| <a id="a-ciaminterconnectkind"></a>`ciamInterconnectKind` | `1.3.6.1.4.1.32473.1.1.36` | `string` | binding | single |  | Cross-environment link, in words (site-to-site VPN run by the landing zone); ciamLinkKind says which kind it is |
| <a id="a-ciamjoinsdeploymentof"></a>`ciamJoinsDeploymentOf` | `1.3.6.1.4.1.32473.1.1.12` | `dn` | intent | single |  | DS replicas here join the replication deployment of that environment |
| <a id="a-ciamlasthit"></a>`ciamLastHit` | `1.3.6.1.4.1.32473.1.1.956` | `time` | observed | single |  | When a rule last matched a session on a firewall |
| <a id="a-ciamleadtimedays"></a>`ciamLeadTimeDays` | `1.3.6.1.4.1.32473.1.1.45` | `int` | meta | single |  | Typical lead time for the owner to change it |
| <a id="a-ciamlifecycle"></a>`ciamLifecycle` | `1.3.6.1.4.1.32473.1.1.10` | enum: `active`, `building`, `retiring`, `retired` | meta | single |  | Lifecycle state |
| <a id="a-ciamloginsecretrole"></a>`ciamLoginSecretRole` | `1.3.6.1.4.1.32473.1.1.628` | `string` | binding | single |  | Binding role of the secret holding the password or API key an appliance's login signs in with, read at run time |
| <a id="a-ciammanagedby"></a>`ciamManagedBy` | `1.3.6.1.4.1.32473.1.1.40` | `dn` | meta | single |  | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |
| <a id="a-ciammanagementaddress"></a>`ciamManagementAddress` | `1.3.6.1.4.1.32473.1.1.626` | `string` | binding | single |  | Where an appliance's management API answers: a host name or address (and port when not the default) |
| <a id="a-ciamoffering"></a>`ciamOffering` | `1.3.6.1.4.1.32473.1.1.850` | vocab: `stateful` (elastic), `serverless` (elastic), `platform` (splunk), `enterprise-security` (splunk) | binding | single |  | Which offering of its product fills a stack component's role, from the vocabulary its adapter declares (e.g. a managed service's serverless form). Not recorded: the adapter's default |
| <a id="a-ciamonprovider"></a>`ciamOnProvider` | `1.3.6.1.4.1.32473.1.1.630` | vocab: `aws` (aws), `azure` (azure), `gcp` (gcp), `onprem` (onprem) | intent | multi |  | A provider (a ciamCloudProvider value) in whose environments a shared entry (a host baseline, a job) applies |
| <a id="a-ciamoverlayof"></a>`ciamOverlayOf` | `1.3.6.1.4.1.32473.1.1.208` | `dn` | binding | single |  | The environment this one is an overlay of: it inherits that environment's bindings, stack, required roles and overrides, except the roles it binds, drops, declares or overrides itself (never servers) |
| <a id="a-ciamoverrideattribute"></a>`ciamOverrideAttribute` | `1.3.6.1.4.1.32473.1.1.211` | `string` | binding | single |  | The attribute overridden: one whose definition allows it (X-OVERRIDABLE) |
| <a id="a-ciamoverrides"></a>`ciamOverrides` | `1.3.6.1.4.1.32473.1.1.210` | `dn` | binding | single |  | The entry whose value this environment overrides |
| <a id="a-ciamoverridevalue"></a>`ciamOverrideValue` | `1.3.6.1.4.1.32473.1.1.212` | `string` | binding | multi |  | The value(s) this environment uses instead of the shared one |
| <a id="a-ciampeerenvironment"></a>`ciamPeerEnvironment` | `1.3.6.1.4.1.32473.1.1.37` | `dn` | binding | single |  | Environment at the other end of an interconnect |
| <a id="a-ciamplannedcutover"></a>`ciamPlannedCutover` | `1.3.6.1.4.1.32473.1.1.11` | `time` | meta | single |  | Planned cutover date for an environment being built |
| <a id="a-ciampolicysync"></a>`ciamPolicySync` | `1.3.6.1.4.1.32473.1.1.953` | `string` | observed | single |  | Whether the policy a manager pushed is what a managed firewall runs, in the manager's words (in sync, out of sync) |
| <a id="a-ciamport"></a>`ciamPort` | `1.3.6.1.4.1.32473.1.1.29` | `port` | intent | multi |  | TCP/UDP port |
| <a id="a-ciamprivateip"></a>`ciamPrivateIp` | `1.3.6.1.4.1.32473.1.1.16` | `ip` | binding | single |  | Private IP address |
| <a id="a-ciamproductversion"></a>`ciamProductVersion` | `1.3.6.1.4.1.32473.1.1.14` | `string` | intent | single |  | Product and version |
| <a id="a-ciamprotocol"></a>`ciamProtocol` | `1.3.6.1.4.1.32473.1.1.32` | enum: `tcp`, `udp` | intent | single |  | Transport protocol |
| <a id="a-ciamproviderref"></a>`ciamProviderRef` | `1.3.6.1.4.1.32473.1.1.22` | `string` | binding | single |  | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| <a id="a-ciamrecordedcidr"></a>`ciamRecordedCidr` | `1.3.6.1.4.1.32473.1.1.44` | `cidr` | observed | multi |  | Addresses the external allowlist contains today |
| <a id="a-ciamreferstorole"></a>`ciamRefersToRole` | `1.3.6.1.4.1.32473.1.1.43` | `string` | meta | single |  | Binding role of OUR address this allowlist contains (resolved per environment) |
| <a id="a-ciamregion"></a>`ciamRegion` | `1.3.6.1.4.1.32473.1.1.8` | `string` | binding | single |  | Provider region |
| <a id="a-ciamrendertarget"></a>`ciamRenderTarget` | `1.3.6.1.4.1.32473.1.1.645` | `string` | binding | multi |  | A render target the environment holds for the component's adapter (one the adapter declares, such as the infrastructure-as-code language a cloud adapter writes), set only when the environment requires that form: renders then write only the forms it holds. None: the user chooses for each render (`opsdir render --target`), else the adapter's defaults |
| <a id="a-ciamrequeststatus"></a>`ciamRequestStatus` | `1.3.6.1.4.1.32473.1.1.46` | enum: `not-needed`, `to-request`, `requested`, `done` | meta | single |  | Status of the change request to the owner |
| <a id="a-ciamresourcegroup"></a>`ciamResourceGroup` | `1.3.6.1.4.1.32473.1.1.23` | `string` | binding | single |  | Provider resource group or container the resources are placed in |
| <a id="a-ciamretentiondays"></a>`ciamRetentionDays` | `1.3.6.1.4.1.32473.1.1.39` | `int` | intent | single |  | Retention period in days |
| <a id="a-ciamrulepriority"></a>`ciamRulePriority` | `1.3.6.1.4.1.32473.1.1.34` | `int` | binding | single |  | Provider firewall rule priority. Pinned so adding a rule never renumbers others |
| <a id="a-ciamrunningfact"></a>`ciamRunningFact` | `1.3.6.1.4.1.32473.1.1.701` | `string` | observed | multi | X-PATTERN `^(action\|log-end\|destination\|description\|source\|service\|negate-source\|negate-destination\|schedule\|rulebase) [^ ].*$` | What a firewall rule, read back running, does that the rule's own attributes can't hold: '<key> <value>'; record-owned drift (action deny, log-end no, destination 10.0.1.9/32, description <text>, source or service it can't resolve) and the network team's settings that limit what it admits (negate-source yes, schedule <name>, rulebase <where>) |
| <a id="a-ciamrunningstate"></a>`ciamRunningState` | `1.3.6.1.4.1.32473.1.1.700` | enum: `committed`, `deployed`, `partial`, `disabled`, `missing` | observed | single |  | Where a firewall manager's running configuration, read back, holds this rule: committed (a manager's, such as Panorama: its delivery to the firewalls unconfirmed), deployed (a firewall's own; on a manager whose firewalls were read, every firewall it pushes to runs it), partial (some of them don't), disabled (there, but switched off), missing (the record holds it, the running configuration doesn't); on a rule observation, what one managed firewall runs |
| <a id="a-ciamserverrole"></a>`ciamServerRole` | `1.3.6.1.4.1.32473.1.1.13` | vocab: `ds` (directory), `monitoring` (prometheus), `pa-admin` (pingaccess), `pa-engine` (pingaccess), `am` (pingam), `pf-engine` (pingfederate), `pf-admin` (pingfederate), `ig` (pinggateway), `idm` (pingidm), `sm-policy-server` (siteminder), `sm-agent` (siteminder), `sm-access-gateway` (siteminder) | intent | single |  | What the server runs (a role the product adapters define) |
| <a id="a-ciamsoftwareversion"></a>`ciamSoftwareVersion` | `1.3.6.1.4.1.32473.1.1.951` | `string` | observed | single |  | The software version a managed firewall runs, as its manager lists it |
| <a id="a-ciamsourcecidr"></a>`ciamSourceCidr` | `1.3.6.1.4.1.32473.1.1.31` | `cidr` | binding | multi |  | Allowed source range |
| <a id="a-ciamstackrole"></a>`ciamStackRole` | `1.3.6.1.4.1.32473.1.1.126` | `string` | binding | single |  | Role a stack component fills in its environment (e.g. provider, directory, federation) |
| <a id="a-ciamstorageref"></a>`ciamStorageRef` | `1.3.6.1.4.1.32473.1.1.38` | `string` | binding | single |  | Object storage location (bucket or container URI, e.g. s3://bucket, azblob://account/container, gs://bucket) |
| <a id="a-ciamsubnet"></a>`ciamSubnet` | `1.3.6.1.4.1.32473.1.1.20` | `dn` | binding | single |  | Subnet binding the server is placed in |
| <a id="a-ciamtargetrole"></a>`ciamTargetRole` | `1.3.6.1.4.1.32473.1.1.28` | vocab: `ds` (directory), `monitoring` (prometheus), `pa-admin` (pingaccess), `pa-engine` (pingaccess), `am` (pingam), `pf-engine` (pingfederate), `pf-admin` (pingfederate), `ig` (pinggateway), `idm` (pingidm), `sm-policy-server` (siteminder), `sm-agent` (siteminder), `sm-access-gateway` (siteminder) | intent | single |  | Server role a service or rule targets |
| <a id="a-ciamtlscertificate"></a>`ciamTlsCertificate` | `1.3.6.1.4.1.32473.1.1.125` | `dn` | binding | single |  | Certificate this service name presents in this environment |
| <a id="a-ciamunrecordedrule"></a>`ciamUnrecordedRule` | `1.3.6.1.4.1.32473.1.1.702` | `string` | observed | multi |  | A rule a network firewall's running configuration, read back, holds that the record doesn't: one carrying the environment's marker for a rule the record lacks, or an allow to the environment's servers nobody recorded; '<rulebase> <rule>: <sources> -> <destinations> <services>' |
| <a id="a-ciamzone"></a>`ciamZone` | `1.3.6.1.4.1.32473.1.1.17` | `string` | binding | single |  | Availability zone |
| <a id="a-cloud"></a>`cloud` | `1.3.6.1.4.1.32473.1.1.1` | `string` | meta | single |  | RDN of a cloud hosting environment |
| <a id="a-env"></a>`env` | `1.3.6.1.4.1.32473.1.1.2` | `string` | meta | single |  | RDN of a deployment stage within a cloud (prod/stage) |
