# Directory

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 16 object classes · 76 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

**Branches:** `ou=acis,dc=ciam-ops`, `ou=config,dc=ciam-ops`, `ou=declared,ou=config,dc=ciam-ops`, `ou=observed,ou=config,dc=ciam-ops`, `ou=consumers,dc=ciam-ops`, `ou=data-profile,dc=ciam-ops`, `ou=user-schema,dc=ciam-ops`

## Object classes

<a id="c-ciamaci"></a>
### ciamAci

Access control instruction

OID `1.3.6.1.4.1.32473.1.2.25` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamAciTargetDn`](#a-ciamacitargetdn) | yes | `extdn` | single | Subtree the ACI is placed on |
| [`ciamAciRight`](#a-ciamaciright) | yes | `enum` | multi | Granted rights |
| [`ciamAciGrantee`](#a-ciamacigrantee) | yes | `dn` | multi | Consumer(s) the ACI grants to |
| [`ciamAciTargetAttr`](#a-ciamacitargetattr) |  | `dn` | multi | User-directory attribute records the ACI covers |
| [`ciamAciAllAttributes`](#a-ciamaciallattributes) |  | `bool` | single | ACI covers all attributes (targetattr=*) |
| [`ciamJustification`](#a-ciamjustification) |  | `string` | single | Why the access exists |
| [`ciamReviewedOn`](#a-ciamreviewedon) |  | `time` | single | Last review (of the access an ACI grants, of a consumer record) |

<a id="c-ciamattributeprofile"></a>
### ciamAttributeProfile

How one attribute is used in the user data: holders, most values, largest value

OID `1.3.6.1.4.1.32473.1.2.61` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamLdapName`](#a-ciamldapname) | yes | `string` | single | Attribute or object class name in the user directory |
| [`ciamHolderCount`](#a-ciamholdercount) | yes | `int` | single | Entries holding an attribute |
| [`ciamMostValues`](#a-ciammostvalues) |  | `int` | single | The most values one entry holds of an attribute |
| [`ciamLargestValueBytes`](#a-ciamlargestvaluebytes) |  | `int` | single | Size of the largest value of an attribute |
| [`ciamProfiledAttribute`](#a-ciamprofiledattribute) |  | `dn` | single | The ou=user-schema record describing a profiled attribute (absent: the record describes none) |

<a id="c-ciambackend"></a>
### ciamBackend

DS backend

OID `1.3.6.1.4.1.32473.1.2.16` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamBackendType`](#a-ciambackendtype) | yes | `string` | single | DS backend type |
| [`ciamBaseDn`](#a-ciambasedn) | yes | `extdn` | single | Base DN in the user directory |

<a id="c-ciambranchprofile"></a>
### ciamBranchProfile

Entries directly under one container of the user directory, by object class

OID `1.3.6.1.4.1.32473.1.2.60` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamProfiledBranch`](#a-ciamprofiledbranch) | yes | `string` | single | The container a branch profile counts the entries of: its DN with every RDN that is not a container's masked (uid=*,ou=people,...); a pattern, not a reference to an entry |
| [`ciamEntryCount`](#a-ciamentrycount) | yes | `int` | single | Entries counted: all the profiled entries, or those directly under a branch |
| [`ciamClassCount`](#a-ciamclasscount) |  | `string` | multi | Entries of one object class, as name=count (inetOrgPerson=812000) |

<a id="c-ciamconnectionhandler"></a>
### ciamConnectionHandler

DS connection handler

OID `1.3.6.1.4.1.32473.1.2.19` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamEnabled`](#a-ciamenabled) | yes | `bool` | single | Enabled flag |
| [`ciamListenPort`](#a-ciamlistenport) |  | `port` | single | Listener port |

<a id="c-ciamconsumer"></a>
### ciamConsumer

A client of the user directory

OID `1.3.6.1.4.1.32473.1.2.24` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamBindDn`](#a-ciambinddn) | yes | `extdn` | single | Bind DN in the user directory |
| [`ciamObservedSource`](#a-ciamobservedsource) |  | `cidr` | multi | Source addresses seen in access logs |
| [`ciamOperationMix`](#a-ciamoperationmix) |  | `string` | single | Operation mix seen in access logs |
| [`ciamSubtreeRead`](#a-ciamsubtreeread) |  | `extdn` | multi | Subtrees searched |
| [`ciamAttrRead`](#a-ciamattrread) |  | `dn` | multi | User-directory attribute records read |
| [`ciamUnindexedSearchesPerDay`](#a-ciamunindexedsearchesperday) |  | `int` | single | Unindexed searches per day |
| [`ciamTlsOnly`](#a-ciamtlsonly) |  | `bool` | single | Only TLS connections seen |
| [`ciamPeakOpsPerSec`](#a-ciampeakopspersec) |  | `int` | single | Peak operations per second |
| [`ciamFirstSeen`](#a-ciamfirstseen) |  | `time` | single | First seen in logs |
| [`ciamLastSeen`](#a-ciamlastseen) |  | `time` | single | Last seen in logs |
| [`ciamCriticality`](core.md#a-ciamcriticality) |  | `enum` | single | Business criticality |
| [`ciamMigrationStatus`](#a-ciammigrationstatus) |  | `enum` | single | Migration readiness of a consumer |
| [`ciamReviewedOn`](#a-ciamreviewedon) |  | `time` | single | Last review (of the access an ACI grants, of a consumer record) |

<a id="c-ciamdataprofile"></a>
### ciamDataProfile

The shape of an environment's user data, values-free: counts and distributions

OID `1.3.6.1.4.1.32473.1.2.59` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamProfiledEnvironment`](#a-ciamprofiledenvironment) | yes | `dn` | single | The environment whose user directory a data profile describes |
| [`ciamCapturedAt`](#a-ciamcapturedat) | yes | `time` | single | Snapshot capture time |
| [`ciamEntryCount`](#a-ciamentrycount) | yes | `int` | single | Entries counted: all the profiled entries, or those directly under a branch |
| [`ciamHashSchemeCount`](#a-ciamhashschemecount) |  | `string` | multi | Password values hashed with one scheme, as SCHEME=count ({SSHA512} -> SSHA512; none: no scheme prefix, possibly clear text) |
| [`ciamLastLoginAge`](#a-ciamlastloginage) |  | `string` | multi | Entries by time since their last login, as bucket=count (<30d, 30-90d, 90-365d, 1-2y, >2y, never, unreadable) |
| [`ciamPasswordAge`](#a-ciampasswordage) |  | `string` | multi | Entries by time since their password last changed, as bucket=count (the same buckets) |
| [`ciamLockedCount`](#a-ciamlockedcount) |  | `int` | single | Entries locked out (pwdAccountLockedTime, ...) |
| [`ciamDisabledCount`](#a-ciamdisabledcount) |  | `int` | single | Entries disabled by an administrator |
| [`ciamPendingCount`](#a-ciampendingcount) |  | `int` | single | Entries pending registration or activation |
| [`ciamKbaCount`](#a-ciamkbacount) |  | `int` | single | Entries holding knowledge-based authentication (challenge questions) |
| [`ciamGroupCount`](#a-ciamgroupcount) |  | `int` | single | Static groups (groupOfNames, groupOfUniqueNames, ...) |
| [`ciamEmptyGroupCount`](#a-ciamemptygroupcount) |  | `int` | single | Static groups without members |
| [`ciamDanglingMemberCount`](#a-ciamdanglingmembercount) |  | `int` | single | Distinct member DNs groups name that are not among the profiled entries |
| [`ciamLargestGroup`](#a-ciamlargestgroup) |  | `int` | single | Members of the largest static group |
| [`ciamLargestEntryBytes`](#a-ciamlargestentrybytes) |  | `int` | single | Size of the largest entry (names and values) |

<a id="c-ciamdirectorytrust"></a>
### ciamDirectoryTrust

A trust of a managed directory (beneath its binding) with another domain (ciamFqdn), its DNS servers (ciamForwardTarget) and who keeps the other side (ciamManagedBy)

OID `1.3.6.1.4.1.32473.1.2.190` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamFqdn`](infrastructure.md#a-ciamfqdn) | yes | `fqdn` | single | Service DNS name consumers and partners use. Must stay stable across migrations |
| [`ciamTrustType`](#a-ciamtrusttype) | yes | `enum` | single | Kind of a directory trust: a forest trust, or an external trust with one domain |
| [`ciamTrustDirection`](#a-ciamtrustdirection) | yes | `enum` | single | Direction of a directory trust, from the managed domain's side (outgoing: it trusts the other domain, whose users reach its resources) |
| [`ciamForwardTarget`](edge.md#a-ciamforwardtarget) |  | `ip` | multi | A resolver queries are forwarded to |
| [`ciamSelectiveAuth`](#a-ciamselectiveauth) |  | `bool` | single | A directory trust uses selective authentication (only the users granted reach the trusting side) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamindex"></a>
### ciamIndex

DS backend index

OID `1.3.6.1.4.1.32473.1.2.17` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamIndexedAttribute`](#a-ciamindexedattribute) | yes | `dn` | single | User-directory attribute record being indexed |
| [`ciamIndexType`](#a-ciamindextype) | yes | `enum` | multi | DS index type |

<a id="c-ciamlogpublisher"></a>
### ciamLogPublisher

DS log publisher

OID `1.3.6.1.4.1.32473.1.2.20` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamEnabled`](#a-ciamenabled) | yes | `bool` | single | Enabled flag |

<a id="c-ciammanageddirectory"></a>
### ciamManagedDirectory

A cloud-managed directory service an environment uses (managed Active Directory): the platform's user directory held on it there (ciamRealizes ds: a target), or a directory the platform binds to or syncs from (ciamPartnerOf: the ldap integrations it is the partner side of; a neighbour). Its domain (ciamFqdn, ciamNetbiosName), edition, regions and domain controllers per region (ciamReplicaCount), the OU the platform writes in (ciamWritableBase), secure LDAP (ciamLdapsMode, presenting ciamTlsCertificate), where it is placed (subnet roles; a reserved range, ciamCidr), the secret role of its administrator's password (ciamCredentialRole) and who keeps it when it isn't the platform team (ciamManagedBy); its trusts are entries beneath it

OID `1.3.6.1.4.1.32473.1.2.189` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamManagedService`](federation.md#a-ciammanagedservice) | yes | `vocab` | single | The cloud-managed identity service a binding is, as the adapter declaring it names it (a user pool service, an external tenant) |
| [`ciamRealizes`](observability.md#a-ciamrealizes) |  | `string` | single | The alert rule or canary (its name) an alarm or synthetic check a cloud runs realizes |
| [`ciamPartnerOf`](federation.md#a-ciampartnerof) |  | `dn` | multi | The integrations a managed identity service is the partner side of (a neighbour the platform federates with): whether it is their relying party or their issuer follows from their protocol type |
| [`ciamFqdn`](infrastructure.md#a-ciamfqdn) |  | `fqdn` | single | Service DNS name consumers and partners use. Must stay stable across migrations |
| [`ciamNetbiosName`](#a-ciamnetbiosname) |  | `string` | single | NetBIOS name of a managed Active Directory domain |
| [`ciamDirectoryEdition`](#a-ciamdirectoryedition) |  | `vocab` | single | Edition (SKU) of a managed directory service, as the adapter declaring the service names it |
| [`ciamRegion`](infrastructure.md#a-ciamregion) |  | `string` | single | Provider region |
| [`ciamReplicaRegion`](pki.md#a-ciamreplicaregion) |  | `string` | multi | Regions the key, secret or managed directory is replicated to (multi-region keys, replicated secrets, a managed directory's further regions) |
| [`ciamReplicaCount`](#a-ciamreplicacount) |  | `int` | single | DS replicas per environment |
| [`ciamWritableBase`](#a-ciamwritablebase) |  | `extdn` | single | The OU of a managed directory the platform writes in: where the record's directory entries land |
| [`ciamLdapsMode`](#a-ciamldapsmode) |  | `enum` | single | Secure LDAP of a managed directory: off, on private networks only, or reachable from the internet |
| [`ciamTlsCertificate`](infrastructure.md#a-ciamtlscertificate) |  | `dn` | single | Certificate this service name presents in this environment |
| [`ciamSubnetRole`](network.md#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamCidr`](infrastructure.md#a-ciamcidr) |  | `cidr` | multi | Address range |
| [`ciamCredentialRole`](governance.md#a-ciamcredentialrole) |  | `string` | single | The role of the binding holding the reference to the credential a collection source is read with (resolved when collecting, held in memory for the call, never stored) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciampasswordpolicy"></a>
### ciamPasswordPolicy

Password policy

OID `1.3.6.1.4.1.32473.1.2.18` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamStorageScheme`](#a-ciamstoragescheme) | yes | `string` | single | Password storage scheme |
| [`ciamLockoutFailureCount`](#a-ciamlockoutfailurecount) |  | `int` | single | Failed binds before lockout |
| [`ciamLockoutDuration`](#a-ciamlockoutduration) |  | `string` | single | Lockout duration (DS duration syntax) |
| [`ciamPasswordHistoryCount`](#a-ciampasswordhistorycount) |  | `int` | single | Passwords remembered |
| [`ciamMaxPasswordAge`](#a-ciammaxpasswordage) |  | `string` | single | Maximum password age (DS duration syntax) |
| [`ciamPopulation`](core.md#a-ciampopulation) |  | `enum` | multi | Identity populations served |

<a id="c-ciamreplicationtopology"></a>
### ciamReplicationTopology

Replication topology shape

OID `1.3.6.1.4.1.32473.1.2.21` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamReplicaCount`](#a-ciamreplicacount) | yes | `int` | single | DS replicas per environment |
| [`ciamReplicationPurgeDelay`](#a-ciamreplicationpurgedelay) |  | `string` | single | Replication changelog purge delay |

<a id="c-ciamsnapshot"></a>
### ciamSnapshot

Observed config snapshot of one server

OID `1.3.6.1.4.1.32473.1.2.22` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`snap`](#a-snap) | yes | `string` | single | RDN of an observed configuration snapshot |
| [`ciamServerRef`](#a-ciamserverref) | yes | `dn` | single | Server a snapshot was captured from |
| [`ciamCapturedAt`](#a-ciamcapturedat) | yes | `time` | single | Snapshot capture time |

<a id="c-ciamuserattribute"></a>
### ciamUserAttribute

Record describing a user-directory attribute

OID `1.3.6.1.4.1.32473.1.2.23` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamLdapName`](#a-ciamldapname) | yes | `string` | single | Attribute or object class name in the user directory |
| [`ciamPiiClass`](#a-ciampiiclass) | yes | `enum` | single | Privacy classification |
| [`ciamExportControlled`](#a-ciamexportcontrolled) |  | `bool` | single | Export-control relevant |
| [`ciamPurpose`](#a-ciampurpose) |  | `string` | single | Why the attribute is stored |
| [`ciamRetentionRule`](#a-ciamretentionrule) |  | `string` | single | Retention rule |
| [`ciamLdapOid`](#a-ciamldapoid) |  | `string` | single | OID of a non-standard user-directory attribute type or object class |
| [`ciamLdapSyntax`](#a-ciamldapsyntax) |  | `string` | single | LDAP syntax OID of a non-standard user-directory attribute |
| [`ciamLdapEquality`](#a-ciamldapequality) |  | `string` | single | Equality matching rule of a non-standard user-directory attribute |
| [`ciamLdapSubstring`](#a-ciamldapsubstring) |  | `string` | single | Substring matching rule of a non-standard user-directory attribute |
| [`ciamLdapOrdering`](#a-ciamldapordering) |  | `string` | single | Ordering matching rule of a non-standard user-directory attribute |
| [`ciamLdapSingleValue`](#a-ciamldapsinglevalue) |  | `bool` | single | A non-standard user-directory attribute holds one value |

<a id="c-ciamuserobjectclass"></a>
### ciamUserObjectClass

Record describing a user-directory object class

OID `1.3.6.1.4.1.32473.1.2.34` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamLdapName`](#a-ciamldapname) | yes | `string` | single | Attribute or object class name in the user directory |
| [`ciamLdapClassKind`](#a-ciamldapclasskind) | yes | `enum` | single | Kind of a user-directory object class |
| [`ciamLdapOid`](#a-ciamldapoid) |  | `string` | single | OID of a non-standard user-directory attribute type or object class |
| [`ciamLdapSuperior`](#a-ciamldapsuperior) |  | `string` | single | Superclass (by name: standard, or another recorded class) of a user-directory object class |
| [`ciamLdapMust`](#a-ciamldapmust) |  | `dn` | multi | User-directory attribute records a user-directory object class requires |
| [`ciamLdapMay`](#a-ciamldapmay) |  | `dn` | multi | User-directory attribute records a user-directory object class allows |
| [`ciamPurpose`](#a-ciampurpose) |  | `string` | single | Why the attribute is stored |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamaciallattributes"></a>`ciamAciAllAttributes` | `1.3.6.1.4.1.32473.1.1.81` | `bool` | intent | single |  | ACI covers all attributes (targetattr=*) |
| <a id="a-ciamacigrantee"></a>`ciamAciGrantee` | `1.3.6.1.4.1.32473.1.1.83` | `dn` | intent | multi |  | Consumer(s) the ACI grants to |
| <a id="a-ciamaciright"></a>`ciamAciRight` | `1.3.6.1.4.1.32473.1.1.82` | enum: `read`, `search`, `compare`, `write`, `add`, `delete`, `selfwrite`, `all` | intent | multi |  | Granted rights |
| <a id="a-ciamacitargetattr"></a>`ciamAciTargetAttr` | `1.3.6.1.4.1.32473.1.1.80` | `dn` | intent | multi |  | User-directory attribute records the ACI covers |
| <a id="a-ciamacitargetdn"></a>`ciamAciTargetDn` | `1.3.6.1.4.1.32473.1.1.79` | `extdn` | intent | single |  | Subtree the ACI is placed on |
| <a id="a-ciamattrread"></a>`ciamAttrRead` | `1.3.6.1.4.1.32473.1.1.71` | `dn` | observed | multi |  | User-directory attribute records read |
| <a id="a-ciambackendtype"></a>`ciamBackendType` | `1.3.6.1.4.1.32473.1.1.47` | `string` | intent | single |  | DS backend type |
| <a id="a-ciambasedn"></a>`ciamBaseDn` | `1.3.6.1.4.1.32473.1.1.48` | `extdn` | intent | single |  | Base DN in the user directory |
| <a id="a-ciambinddn"></a>`ciamBindDn` | `1.3.6.1.4.1.32473.1.1.67` | `extdn` | intent | single |  | Bind DN in the user directory |
| <a id="a-ciamcapturedat"></a>`ciamCapturedAt` | `1.3.6.1.4.1.32473.1.1.61` | `time` | observed | single |  | Snapshot capture time |
| <a id="a-ciamclasscount"></a>`ciamClassCount` | `1.3.6.1.4.1.32473.1.1.291` | `string` | observed | multi | X-PATTERN `^[^=]+=[0-9]+$` | Entries of one object class, as name=count (inetOrgPerson=812000) |
| <a id="a-ciamdanglingmembercount"></a>`ciamDanglingMemberCount` | `1.3.6.1.4.1.32473.1.1.301` | `int` | observed | single |  | Distinct member DNs groups name that are not among the profiled entries |
| <a id="a-ciamdirectoryedition"></a>`ciamDirectoryEdition` | `1.3.6.1.4.1.32473.1.1.871` | vocab: `standard` (aws), `enterprise` (aws), `standard` (azure), `enterprise` (azure), `premium` (azure) | binding | single |  | Edition (SKU) of a managed directory service, as the adapter declaring the service names it |
| <a id="a-ciamdisabledcount"></a>`ciamDisabledCount` | `1.3.6.1.4.1.32473.1.1.296` | `int` | observed | single |  | Entries disabled by an administrator |
| <a id="a-ciamemptygroupcount"></a>`ciamEmptyGroupCount` | `1.3.6.1.4.1.32473.1.1.300` | `int` | observed | single |  | Static groups without members |
| <a id="a-ciamenabled"></a>`ciamEnabled` | `1.3.6.1.4.1.32473.1.1.56` | `bool` | intent | single |  | Enabled flag |
| <a id="a-ciamentrycount"></a>`ciamEntryCount` | `1.3.6.1.4.1.32473.1.1.290` | `int` | observed | single |  | Entries counted: all the profiled entries, or those directly under a branch |
| <a id="a-ciamexportcontrolled"></a>`ciamExportControlled` | `1.3.6.1.4.1.32473.1.1.64` | `bool` | intent | single |  | Export-control relevant |
| <a id="a-ciamfirstseen"></a>`ciamFirstSeen` | `1.3.6.1.4.1.32473.1.1.75` | `time` | observed | single |  | First seen in logs |
| <a id="a-ciamgroupcount"></a>`ciamGroupCount` | `1.3.6.1.4.1.32473.1.1.299` | `int` | observed | single |  | Static groups (groupOfNames, groupOfUniqueNames, ...) |
| <a id="a-ciamhashschemecount"></a>`ciamHashSchemeCount` | `1.3.6.1.4.1.32473.1.1.292` | `string` | observed | multi | X-PATTERN `^[^=]+=[0-9]+$` | Password values hashed with one scheme, as SCHEME=count ({SSHA512} -> SSHA512; none: no scheme prefix, possibly clear text) |
| <a id="a-ciamholdercount"></a>`ciamHolderCount` | `1.3.6.1.4.1.32473.1.1.304` | `int` | observed | single |  | Entries holding an attribute |
| <a id="a-ciamindexedattribute"></a>`ciamIndexedAttribute` | `1.3.6.1.4.1.32473.1.1.49` | `dn` | intent | single |  | User-directory attribute record being indexed |
| <a id="a-ciamindextype"></a>`ciamIndexType` | `1.3.6.1.4.1.32473.1.1.50` | enum: `equality`, `presence`, `substring`, `ordering`, `approximate` | intent | multi |  | DS index type |
| <a id="a-ciamjustification"></a>`ciamJustification` | `1.3.6.1.4.1.32473.1.1.84` | `string` | meta | single |  | Why the access exists |
| <a id="a-ciamkbacount"></a>`ciamKbaCount` | `1.3.6.1.4.1.32473.1.1.298` | `int` | observed | single |  | Entries holding knowledge-based authentication (challenge questions) |
| <a id="a-ciamlargestentrybytes"></a>`ciamLargestEntryBytes` | `1.3.6.1.4.1.32473.1.1.303` | `int` | observed | single |  | Size of the largest entry (names and values) |
| <a id="a-ciamlargestgroup"></a>`ciamLargestGroup` | `1.3.6.1.4.1.32473.1.1.302` | `int` | observed | single |  | Members of the largest static group |
| <a id="a-ciamlargestvaluebytes"></a>`ciamLargestValueBytes` | `1.3.6.1.4.1.32473.1.1.306` | `int` | observed | single |  | Size of the largest value of an attribute |
| <a id="a-ciamlastloginage"></a>`ciamLastLoginAge` | `1.3.6.1.4.1.32473.1.1.293` | `string` | observed | multi | X-PATTERN `^[^=]+=[0-9]+$` | Entries by time since their last login, as bucket=count (<30d, 30-90d, 90-365d, 1-2y, >2y, never, unreadable) |
| <a id="a-ciamlastseen"></a>`ciamLastSeen` | `1.3.6.1.4.1.32473.1.1.76` | `time` | observed | single |  | Last seen in logs |
| <a id="a-ciamldapclasskind"></a>`ciamLdapClassKind` | `1.3.6.1.4.1.32473.1.1.136` | enum: `structural`, `auxiliary`, `abstract` | intent | single |  | Kind of a user-directory object class |
| <a id="a-ciamldapequality"></a>`ciamLdapEquality` | `1.3.6.1.4.1.32473.1.1.132` | `string` | intent | single |  | Equality matching rule of a non-standard user-directory attribute |
| <a id="a-ciamldapmay"></a>`ciamLdapMay` | `1.3.6.1.4.1.32473.1.1.139` | `dn` | intent | multi |  | User-directory attribute records a user-directory object class allows |
| <a id="a-ciamldapmust"></a>`ciamLdapMust` | `1.3.6.1.4.1.32473.1.1.138` | `dn` | intent | multi |  | User-directory attribute records a user-directory object class requires |
| <a id="a-ciamldapname"></a>`ciamLdapName` | `1.3.6.1.4.1.32473.1.1.62` | `string` | intent | single |  | Attribute or object class name in the user directory |
| <a id="a-ciamldapoid"></a>`ciamLdapOid` | `1.3.6.1.4.1.32473.1.1.130` | `string` | intent | single |  | OID of a non-standard user-directory attribute type or object class |
| <a id="a-ciamldapordering"></a>`ciamLdapOrdering` | `1.3.6.1.4.1.32473.1.1.134` | `string` | intent | single |  | Ordering matching rule of a non-standard user-directory attribute |
| <a id="a-ciamldapsinglevalue"></a>`ciamLdapSingleValue` | `1.3.6.1.4.1.32473.1.1.135` | `bool` | intent | single |  | A non-standard user-directory attribute holds one value |
| <a id="a-ciamldapsmode"></a>`ciamLdapsMode` | `1.3.6.1.4.1.32473.1.1.874` | enum: `off`, `private`, `internet` | binding | single |  | Secure LDAP of a managed directory: off, on private networks only, or reachable from the internet |
| <a id="a-ciamldapsubstring"></a>`ciamLdapSubstring` | `1.3.6.1.4.1.32473.1.1.133` | `string` | intent | single |  | Substring matching rule of a non-standard user-directory attribute |
| <a id="a-ciamldapsuperior"></a>`ciamLdapSuperior` | `1.3.6.1.4.1.32473.1.1.137` | `string` | intent | single |  | Superclass (by name: standard, or another recorded class) of a user-directory object class |
| <a id="a-ciamldapsyntax"></a>`ciamLdapSyntax` | `1.3.6.1.4.1.32473.1.1.131` | `string` | intent | single |  | LDAP syntax OID of a non-standard user-directory attribute |
| <a id="a-ciamlistenport"></a>`ciamListenPort` | `1.3.6.1.4.1.32473.1.1.57` | `port` | intent | single |  | Listener port |
| <a id="a-ciamlockedcount"></a>`ciamLockedCount` | `1.3.6.1.4.1.32473.1.1.295` | `int` | observed | single |  | Entries locked out (pwdAccountLockedTime, ...) |
| <a id="a-ciamlockoutduration"></a>`ciamLockoutDuration` | `1.3.6.1.4.1.32473.1.1.53` | `string` | intent | single | X-OVERRIDABLE `TRUE` | Lockout duration (DS duration syntax) |
| <a id="a-ciamlockoutfailurecount"></a>`ciamLockoutFailureCount` | `1.3.6.1.4.1.32473.1.1.52` | `int` | intent | single | X-OVERRIDABLE `TRUE` | Failed binds before lockout |
| <a id="a-ciammaxpasswordage"></a>`ciamMaxPasswordAge` | `1.3.6.1.4.1.32473.1.1.55` | `string` | intent | single | X-OVERRIDABLE `TRUE` | Maximum password age (DS duration syntax) |
| <a id="a-ciammigrationstatus"></a>`ciamMigrationStatus` | `1.3.6.1.4.1.32473.1.1.78` | enum: `unknown`, `identified`, `contacted`, `tested`, `cutover` | meta | single |  | Migration readiness of a consumer |
| <a id="a-ciammostvalues"></a>`ciamMostValues` | `1.3.6.1.4.1.32473.1.1.305` | `int` | observed | single |  | The most values one entry holds of an attribute |
| <a id="a-ciamnetbiosname"></a>`ciamNetbiosName` | `1.3.6.1.4.1.32473.1.1.870` | `string` | binding | single |  | NetBIOS name of a managed Active Directory domain |
| <a id="a-ciamobservedsource"></a>`ciamObservedSource` | `1.3.6.1.4.1.32473.1.1.68` | `cidr` | observed | multi |  | Source addresses seen in access logs |
| <a id="a-ciamoperationmix"></a>`ciamOperationMix` | `1.3.6.1.4.1.32473.1.1.69` | `string` | observed | single |  | Operation mix seen in access logs |
| <a id="a-ciampasswordage"></a>`ciamPasswordAge` | `1.3.6.1.4.1.32473.1.1.294` | `string` | observed | multi | X-PATTERN `^[^=]+=[0-9]+$` | Entries by time since their password last changed, as bucket=count (the same buckets) |
| <a id="a-ciampasswordhistorycount"></a>`ciamPasswordHistoryCount` | `1.3.6.1.4.1.32473.1.1.54` | `int` | intent | single | X-OVERRIDABLE `TRUE` | Passwords remembered |
| <a id="a-ciampeakopspersec"></a>`ciamPeakOpsPerSec` | `1.3.6.1.4.1.32473.1.1.74` | `int` | observed | single |  | Peak operations per second |
| <a id="a-ciampendingcount"></a>`ciamPendingCount` | `1.3.6.1.4.1.32473.1.1.297` | `int` | observed | single |  | Entries pending registration or activation |
| <a id="a-ciampiiclass"></a>`ciamPiiClass` | `1.3.6.1.4.1.32473.1.1.63` | enum: `none`, `low`, `moderate`, `high` | intent | single |  | Privacy classification |
| <a id="a-ciamprofiledattribute"></a>`ciamProfiledAttribute` | `1.3.6.1.4.1.32473.1.1.307` | `dn` | observed | single |  | The ou=user-schema record describing a profiled attribute (absent: the record describes none) |
| <a id="a-ciamprofiledbranch"></a>`ciamProfiledBranch` | `1.3.6.1.4.1.32473.1.1.308` | `string` | observed | single |  | The container a branch profile counts the entries of: its DN with every RDN that is not a container's masked (uid=*,ou=people,...); a pattern, not a reference to an entry |
| <a id="a-ciamprofiledenvironment"></a>`ciamProfiledEnvironment` | `1.3.6.1.4.1.32473.1.1.289` | `dn` | observed | single |  | The environment whose user directory a data profile describes |
| <a id="a-ciampurpose"></a>`ciamPurpose` | `1.3.6.1.4.1.32473.1.1.65` | `string` | intent | single |  | Why the attribute is stored |
| <a id="a-ciamreplicacount"></a>`ciamReplicaCount` | `1.3.6.1.4.1.32473.1.1.58` | `int` | intent | single | X-OVERRIDABLE `TRUE` | DS replicas per environment |
| <a id="a-ciamreplicationpurgedelay"></a>`ciamReplicationPurgeDelay` | `1.3.6.1.4.1.32473.1.1.59` | `string` | intent | single | X-OVERRIDABLE `TRUE` | Replication changelog purge delay |
| <a id="a-ciamretentionrule"></a>`ciamRetentionRule` | `1.3.6.1.4.1.32473.1.1.66` | `string` | intent | single |  | Retention rule |
| <a id="a-ciamreviewedon"></a>`ciamReviewedOn` | `1.3.6.1.4.1.32473.1.1.85` | `time` | meta | single |  | Last review (of the access an ACI grants, of a consumer record) |
| <a id="a-ciamselectiveauth"></a>`ciamSelectiveAuth` | `1.3.6.1.4.1.32473.1.1.877` | `bool` | binding | single |  | A directory trust uses selective authentication (only the users granted reach the trusting side) |
| <a id="a-ciamserverref"></a>`ciamServerRef` | `1.3.6.1.4.1.32473.1.1.60` | `dn` | observed | single |  | Server a snapshot was captured from |
| <a id="a-ciamstoragescheme"></a>`ciamStorageScheme` | `1.3.6.1.4.1.32473.1.1.51` | `string` | intent | single |  | Password storage scheme |
| <a id="a-ciamsubtreeread"></a>`ciamSubtreeRead` | `1.3.6.1.4.1.32473.1.1.70` | `extdn` | observed | multi |  | Subtrees searched |
| <a id="a-ciamtlsonly"></a>`ciamTlsOnly` | `1.3.6.1.4.1.32473.1.1.73` | `bool` | observed | single |  | Only TLS connections seen |
| <a id="a-ciamtrustdirection"></a>`ciamTrustDirection` | `1.3.6.1.4.1.32473.1.1.875` | enum: `one-way-incoming`, `one-way-outgoing`, `two-way` | binding | single |  | Direction of a directory trust, from the managed domain's side (outgoing: it trusts the other domain, whose users reach its resources) |
| <a id="a-ciamtrusttype"></a>`ciamTrustType` | `1.3.6.1.4.1.32473.1.1.876` | enum: `forest`, `external` | binding | single |  | Kind of a directory trust: a forest trust, or an external trust with one domain |
| <a id="a-ciamunindexedsearchesperday"></a>`ciamUnindexedSearchesPerDay` | `1.3.6.1.4.1.32473.1.1.72` | `int` | observed | single |  | Unindexed searches per day |
| <a id="a-ciamwritablebase"></a>`ciamWritableBase` | `1.3.6.1.4.1.32473.1.1.873` | `extdn` | binding | single |  | The OU of a managed directory the platform writes in: where the record's directory entries land |
| <a id="a-snap"></a>`snap` | `1.3.6.1.4.1.32473.1.1.3` | `string` | observed | single |  | RDN of an observed configuration snapshot |
