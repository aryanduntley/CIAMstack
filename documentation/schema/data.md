# Data

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 6 object classes · 43 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Data domain schema: the managed databases an environment runs for the stack (PingFederate's, AM's and IDM's repositories, session and token stores). A database is a binding: each environment runs its own, its products name it by role (its endpoint is a ciamFqdn, so an importer turns the host into the role), and what must carry over unchanged in a move (the engine and its version, how available, encrypted and backed up it is, the parameters set on it) is intent the planner compares; its size, the provider's offering and the secret holding its credentials are each environment's own. How an object store (infrastructure's ciamObjectStore, backup targets among them) keeps what it holds is defined here too: versioning, immutability, lifecycle, public access and replication, allowed on the object store's class. A server role's disks (its boot disk and the volumes it keeps data on, each environment's own) and the snapshot policies that copy them are bindings too: what a move keeps of them (no smaller, encrypted, snapshotted as often and kept as long, copied to another region) is checked. So are backups by a backup service: the vault it keeps recovery points in (locked, encrypted, restorable in another region) and the plan saying what it backs up, how often, how long it keeps them and where it copies them (a different thing from infrastructure's ciamBackupTarget, the object store a product writes its own backup files to), and the record of each restore test, which the planner holds to a schedule (the estate setting restore-test-interval-days).

**Branches:** `ou=restore-tests,dc=ciam-ops`

## Object classes

<a id="c-ciambackupplan"></a>
### ciamBackupPlan

What a backup service backs up in an environment (the roles it protects), into which vault, how often and from when, how long it keeps each recovery point (ciamRetentionDays) and the regions it copies them to

OID `1.3.6.1.4.1.32473.1.2.98` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProtectsRole`](#a-ciamprotectsrole) | yes | `string` | multi | A role a backup plan backs up: a volume, a database, or the servers of a role |
| [`ciamBackupVaultRole`](#a-ciambackupvaultrole) | yes | `string` | single | The binding role of the backup vault a backup plan keeps its recovery points in |
| [`ciamRetentionDays`](infrastructure.md#a-ciamretentiondays) | yes | `int` | single | Retention period in days |
| [`ciamBackupEveryHours`](#a-ciambackupeveryhours) |  | `int` | single | How often a backup plan backs up, in hours (24 when absent) |
| [`ciamBackupAt`](#a-ciambackupat) |  | `string` | single | When a backup plan starts its first backup of the day, HH:MM in UTC |
| [`ciamBackupWindowHours`](#a-ciambackupwindowhours) |  | `int` | single | How long after its start time a backup may begin, in hours (the service decides when absent) |
| [`ciamCopyRegion`](#a-ciamcopyregion) |  | `string` | multi | A region a snapshot policy or backup plan copies each snapshot or recovery point to, or a managed database its automated backups (and the logs its point-in-time restore replays) are copied to (each environment's own) |
| [`ciamRestoreTestDays`](#a-ciamrestoretestdays) |  | `int` | single | How often what a backup plan protects must be restore-tested, in days: its own, in place of the estate setting restore-test-interval-days |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciambackupvault"></a>
### ciamBackupVault

Where a backup service keeps an environment's recovery points (an AWS Backup vault, an Azure Backup vault, a Backup and DR vault): its key, its lock and whether it can restore in another region. Not infrastructure's ciamBackupTarget, the object store a product writes its own backup files to

OID `1.3.6.1.4.1.32473.1.2.97` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamEncryptedByRole`](pki.md#a-ciamencryptedbyrole) |  | `string` | single | The binding role of the key that encrypts a secret in its store (a customer managed key): who reads or writes the secret may also need to use that key |
| [`ciamStorageImmutability`](#a-ciamstorageimmutability) |  | `enum` | single | Whether an object store's objects, or a backup vault's recovery points, are locked against change and deletion for ciamStorageLockDays: governance (a privileged user may lift it) or compliance (nobody may, the account root included) |
| [`ciamStorageLockDays`](#a-ciamstoragelockdays) |  | `int` | single | How long each object or recovery point stays locked at least (ciamStorageImmutability) |
| [`ciamCrossRegionRestore`](#a-ciamcrossregionrestore) |  | `bool` | single | Whether a backup vault's recovery points can be restored in another region (its geo-redundancy or location) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamdatabase"></a>
### ciamDatabase

A managed database an environment runs for the stack (a repository, a session or token store): its engine and version, endpoint, availability, encryption and backups (ciamRetentionDays: automated backups kept), parameters, the ranges admitted to its port (ciamSourceCidr) and the secret role of its credentials

OID `1.3.6.1.4.1.32473.1.2.93` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamDbEngine`](#a-ciamdbengine) | yes | `enum` | single | The database engine a managed database runs |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamFqdn`](infrastructure.md#a-ciamfqdn) |  | `fqdn` | single | Service DNS name consumers and partners use. Must stay stable across migrations |
| [`ciamPort`](infrastructure.md#a-ciamport) |  | `port` | multi | TCP/UDP port |
| [`ciamDbEngineVersion`](#a-ciamdbengineversion) |  | `string` | single | The engine version it runs (16.4): a move carries it unchanged; an upgrade is its own change |
| [`ciamDbEdition`](#a-ciamdbedition) |  | `enum` | single | The engine's edition where it comes in several (SQL Server, Oracle): what it is licensed and able to do, so a move keeps it |
| [`ciamDbService`](#a-ciamdbservice) |  | `string` | single | The provider's managed offering it runs on (rds, aurora, flexible-server, cloud-sql); the cloud's usual one when absent |
| [`ciamInstanceSize`](infrastructure.md#a-ciaminstancesize) |  | `string` | single | Instance / VM size |
| [`ciamDbStorageGb`](#a-ciamdbstoragegb) |  | `int` | single | The storage it is given, in GB |
| [`ciamZone`](infrastructure.md#a-ciamzone) |  | `string` | single | Availability zone |
| [`ciamDbHighAvailability`](#a-ciamdbhighavailability) |  | `enum` | single | How available it is kept: a standby in another zone it fails over to (zone-redundant), or none |
| [`ciamEncryptedByRole`](pki.md#a-ciamencryptedbyrole) |  | `string` | single | The binding role of the key that encrypts a secret in its store (a customer managed key): who reads or writes the secret may also need to use that key |
| [`ciamDbTlsRequired`](#a-ciamdbtlsrequired) |  | `bool` | single | Whether it refuses connections without TLS |
| [`ciamRetentionDays`](infrastructure.md#a-ciamretentiondays) |  | `int` | single | Retention period in days |
| [`ciamDbPointInTime`](#a-ciamdbpointintime) |  | `bool` | single | Whether it can be restored to any point within its backup retention |
| [`ciamDbDeletionProtection`](#a-ciamdbdeletionprotection) |  | `bool` | single | Whether the provider refuses to delete it until protection is turned off |
| [`ciamDbParameter`](#a-ciamdbparameter) |  | `string` | multi | An engine parameter set on it, name=value (the engine's defaults are not recorded) |
| [`ciamSubnetRole`](network.md#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamSourceCidr`](infrastructure.md#a-ciamsourcecidr) |  | `cidr` | multi | Allowed source range |
| [`ciamDbCredentialRole`](#a-ciamdbcredentialrole) |  | `string` | single | The binding role of the secret holding its administrator credentials (never a value) |
| [`ciamCopyRegion`](#a-ciamcopyregion) |  | `string` | multi | A region a snapshot policy or backup plan copies each snapshot or recovery point to, or a managed database its automated backups (and the logs its point-in-time restore replays) are copied to (each environment's own) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamrestoretest"></a>
### ciamRestoreTest

One restore test (under ou=restore-tests): when, in which environment, whose data it restored and from what, what it proved (disk or application), how it went and how long it took

OID `1.3.6.1.4.1.32473.1.2.99` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamTestedOn`](#a-ciamtestedon) | yes | `time` | single | When a restore test was done |
| [`ciamTestEnvironment`](#a-ciamtestenvironment) | yes | `dn` | single | The environment a restore test restored in |
| [`ciamRestoredRole`](#a-ciamrestoredrole) | yes | `string` | single | The role whose data a restore test restored: a volume, a database, the servers of a role |
| [`ciamRestoreLevel`](#a-ciamrestorelevel) | yes | `enum` | single | What a restore test proved: the disk restored and mounted (disk: as far as a crash-consistent snapshot goes), or the application's data restored and verified to work (application) |
| [`ciamTestResult`](#a-ciamtestresult) | yes | `enum` | single | How a restore test went: passed, partial (restored, but something was missing or wrong), failed |
| [`ciamRestoredFromRole`](#a-ciamrestoredfromrole) |  | `string` | single | The binding role of what it was restored from: a backup plan, a snapshot policy, a backup target |
| [`ciamRestoreMinutes`](#a-ciamrestoreminutes) |  | `int` | single | How long the restore took, in minutes, until the data was usable |
| [`ciamRunbookRef`](custom.md#a-ciamrunbookref) |  | `dn` | multi | Runbooks about it |

<a id="c-ciamsnapshotpolicy"></a>
### ciamSnapshotPolicy

How an environment snapshots its disks: how often, when, how long each snapshot is kept (ciamRetentionDays) and the regions it is copied to

OID `1.3.6.1.4.1.32473.1.2.95` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamRetentionDays`](infrastructure.md#a-ciamretentiondays) | yes | `int` | single | Retention period in days |
| [`ciamSnapshotEveryHours`](#a-ciamsnapshoteveryhours) |  | `int` | single | How often a snapshot policy takes a snapshot, in hours (24 when absent) |
| [`ciamSnapshotAt`](#a-ciamsnapshotat) |  | `string` | single | When a snapshot policy takes its first snapshot of the day, HH:MM in UTC |
| [`ciamCopyRegion`](#a-ciamcopyregion) |  | `string` | multi | A region a snapshot policy or backup plan copies each snapshot or recovery point to, or a managed database its automated backups (and the logs its point-in-time restore replays) are copied to (each environment's own) |
| [`ciamSnapshotConsistency`](#a-ciamsnapshotconsistency) |  | `enum` | single | What a snapshot holds of a running server: the disk as a power cut would leave it (crash), or what the application was asked to flush first (application). Neither is a backup of a database or directory the server runs |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

<a id="c-ciamvolume"></a>
### ciamVolume

A disk every server of a role (ciamTargetRole) has in an environment, its compute groups' included: its boot disk or a data volume, how big and fast it is, its encryption and the snapshot policy that copies it

OID `1.3.6.1.4.1.32473.1.2.94` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) | yes | `vocab` | single | Server role a service or rule targets |
| [`ciamVolumeKind`](#a-ciamvolumekind) | yes | `enum` | single | Which disk of a server it is: the one it starts from (boot), or one it keeps data on (data) |
| [`ciamMountPath`](#a-ciammountpath) |  | `string` | single | Where a server mounts a data volume (/opt/ds/db): what its products keep there |
| [`ciamVolumeSizeGb`](#a-ciamvolumesizegb) |  | `int` | single | The disk's size in GB: each environment's own, but a move must not make it smaller |
| [`ciamVolumeClass`](#a-ciamvolumeclass) |  | `enum` | single | What kind of disk it is: magnetic (standard), general-purpose SSD (ssd), or SSD with provisioned IOPS (provisioned); each cloud's own type for it is the adapter's |
| [`ciamIops`](#a-ciamiops) |  | `int` | single | The I/O operations per second the disk is provisioned for, where its type takes them |
| [`ciamThroughputMb`](#a-ciamthroughputmb) |  | `int` | single | The throughput the disk is provisioned for, in MB/s, where its type takes it |
| [`ciamVolumeEncrypted`](#a-ciamvolumeencrypted) |  | `bool` | single | Whether the disk is encrypted at rest (with ciamEncryptedByRole, else the environment's disk-encryption key) |
| [`ciamEncryptedByRole`](pki.md#a-ciamencryptedbyrole) |  | `string` | single | The binding role of the key that encrypts a secret in its store (a customer managed key): who reads or writes the secret may also need to use that key |
| [`ciamSnapshotPolicyRole`](#a-ciamsnapshotpolicyrole) |  | `string` | single | The binding role of what copies the disk on a schedule: a snapshot policy, or a backup plan where the environment does that with a backup service |
| [`ciamManagedBy`](infrastructure.md#a-ciammanagedby) |  | `dn` | single | Party that keeps it outside the platform's own stack (an external allowlist, a DNS zone, network plumbing, a database, any binding another team runs): its keeper, whose root renders it or who is asked for it |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciambackupat"></a>`ciamBackupAt` | `1.3.6.1.4.1.32473.1.1.460` | `string` | intent | single | X-PATTERN `([01][0-9]\|2[0-3]):[0-5][0-9]` | When a backup plan starts its first backup of the day, HH:MM in UTC |
| <a id="a-ciambackupeveryhours"></a>`ciamBackupEveryHours` | `1.3.6.1.4.1.32473.1.1.459` | `int` | intent | single | X-MIN `1` | How often a backup plan backs up, in hours (24 when absent) |
| <a id="a-ciambackupvaultrole"></a>`ciamBackupVaultRole` | `1.3.6.1.4.1.32473.1.1.457` | `string` | binding | single |  | The binding role of the backup vault a backup plan keeps its recovery points in |
| <a id="a-ciambackupwindowhours"></a>`ciamBackupWindowHours` | `1.3.6.1.4.1.32473.1.1.461` | `int` | intent | single | X-MIN `1` | How long after its start time a backup may begin, in hours (the service decides when absent) |
| <a id="a-ciamcopyregion"></a>`ciamCopyRegion` | `1.3.6.1.4.1.32473.1.1.454` | `string` | binding | multi |  | A region a snapshot policy or backup plan copies each snapshot or recovery point to, or a managed database its automated backups (and the logs its point-in-time restore replays) are copied to (each environment's own) |
| <a id="a-ciamcrossregionrestore"></a>`ciamCrossRegionRestore` | `1.3.6.1.4.1.32473.1.1.462` | `bool` | intent | single |  | Whether a backup vault's recovery points can be restored in another region (its geo-redundancy or location) |
| <a id="a-ciamdbcredentialrole"></a>`ciamDbCredentialRole` | `1.3.6.1.4.1.32473.1.1.435` | `string` | binding | single |  | The binding role of the secret holding its administrator credentials (never a value) |
| <a id="a-ciamdbdeletionprotection"></a>`ciamDbDeletionProtection` | `1.3.6.1.4.1.32473.1.1.433` | `bool` | intent | single |  | Whether the provider refuses to delete it until protection is turned off |
| <a id="a-ciamdbedition"></a>`ciamDbEdition` | `1.3.6.1.4.1.32473.1.1.437` | enum: `enterprise`, `standard`, `standard2`, `web`, `express` | intent | single |  | The engine's edition where it comes in several (SQL Server, Oracle): what it is licensed and able to do, so a move keeps it |
| <a id="a-ciamdbengine"></a>`ciamDbEngine` | `1.3.6.1.4.1.32473.1.1.427` | enum: `postgresql`, `mysql`, `mariadb`, `sqlserver`, `oracle` | intent | single |  | The database engine a managed database runs |
| <a id="a-ciamdbengineversion"></a>`ciamDbEngineVersion` | `1.3.6.1.4.1.32473.1.1.428` | `string` | intent | single |  | The engine version it runs (16.4): a move carries it unchanged; an upgrade is its own change |
| <a id="a-ciamdbhighavailability"></a>`ciamDbHighAvailability` | `1.3.6.1.4.1.32473.1.1.430` | enum: `none`, `zone-redundant` | intent | single |  | How available it is kept: a standby in another zone it fails over to (zone-redundant), or none |
| <a id="a-ciamdbparameter"></a>`ciamDbParameter` | `1.3.6.1.4.1.32473.1.1.434` | `string` | intent | multi |  | An engine parameter set on it, name=value (the engine's defaults are not recorded) |
| <a id="a-ciamdbpointintime"></a>`ciamDbPointInTime` | `1.3.6.1.4.1.32473.1.1.432` | `bool` | intent | single |  | Whether it can be restored to any point within its backup retention |
| <a id="a-ciamdbservice"></a>`ciamDbService` | `1.3.6.1.4.1.32473.1.1.429` | `string` | binding | single |  | The provider's managed offering it runs on (rds, aurora, flexible-server, cloud-sql); the cloud's usual one when absent |
| <a id="a-ciamdbstoragegb"></a>`ciamDbStorageGb` | `1.3.6.1.4.1.32473.1.1.436` | `int` | binding | single | X-MIN `1` | The storage it is given, in GB |
| <a id="a-ciamdbtlsrequired"></a>`ciamDbTlsRequired` | `1.3.6.1.4.1.32473.1.1.431` | `bool` | intent | single |  | Whether it refuses connections without TLS |
| <a id="a-ciamiops"></a>`ciamIops` | `1.3.6.1.4.1.32473.1.1.448` | `int` | intent | single | X-MIN `1` | The I/O operations per second the disk is provisioned for, where its type takes them |
| <a id="a-ciammountpath"></a>`ciamMountPath` | `1.3.6.1.4.1.32473.1.1.445` | `string` | intent | single |  | Where a server mounts a data volume (/opt/ds/db): what its products keep there |
| <a id="a-ciamprotectsrole"></a>`ciamProtectsRole` | `1.3.6.1.4.1.32473.1.1.458` | `string` | binding | multi |  | A role a backup plan backs up: a volume, a database, or the servers of a role |
| <a id="a-ciamrestoredfromrole"></a>`ciamRestoredFromRole` | `1.3.6.1.4.1.32473.1.1.467` | `string` | meta | single |  | The binding role of what it was restored from: a backup plan, a snapshot policy, a backup target |
| <a id="a-ciamrestoredrole"></a>`ciamRestoredRole` | `1.3.6.1.4.1.32473.1.1.466` | `string` | meta | single |  | The role whose data a restore test restored: a volume, a database, the servers of a role |
| <a id="a-ciamrestorelevel"></a>`ciamRestoreLevel` | `1.3.6.1.4.1.32473.1.1.468` | enum: `disk`, `application` | meta | single |  | What a restore test proved: the disk restored and mounted (disk: as far as a crash-consistent snapshot goes), or the application's data restored and verified to work (application) |
| <a id="a-ciamrestoreminutes"></a>`ciamRestoreMinutes` | `1.3.6.1.4.1.32473.1.1.470` | `int` | meta | single | X-MIN `0` | How long the restore took, in minutes, until the data was usable |
| <a id="a-ciamrestoretestdays"></a>`ciamRestoreTestDays` | `1.3.6.1.4.1.32473.1.1.463` | `int` | meta | single | X-MIN `1` | How often what a backup plan protects must be restore-tested, in days: its own, in place of the estate setting restore-test-interval-days |
| <a id="a-ciamsnapshotat"></a>`ciamSnapshotAt` | `1.3.6.1.4.1.32473.1.1.453` | `string` | intent | single | X-PATTERN `([01][0-9]\|2[0-3]):[0-5][0-9]` | When a snapshot policy takes its first snapshot of the day, HH:MM in UTC |
| <a id="a-ciamsnapshotconsistency"></a>`ciamSnapshotConsistency` | `1.3.6.1.4.1.32473.1.1.455` | enum: `crash`, `application` | intent | single |  | What a snapshot holds of a running server: the disk as a power cut would leave it (crash), or what the application was asked to flush first (application). Neither is a backup of a database or directory the server runs |
| <a id="a-ciamsnapshoteveryhours"></a>`ciamSnapshotEveryHours` | `1.3.6.1.4.1.32473.1.1.452` | `int` | intent | single | X-MIN `1` | How often a snapshot policy takes a snapshot, in hours (24 when absent) |
| <a id="a-ciamsnapshotpolicyrole"></a>`ciamSnapshotPolicyRole` | `1.3.6.1.4.1.32473.1.1.451` | `string` | binding | single |  | The binding role of what copies the disk on a schedule: a snapshot policy, or a backup plan where the environment does that with a backup service |
| <a id="a-ciamstorageimmutability"></a>`ciamStorageImmutability` | `1.3.6.1.4.1.32473.1.1.439` | enum: `none`, `governance`, `compliance` | intent | single |  | Whether an object store's objects, or a backup vault's recovery points, are locked against change and deletion for ciamStorageLockDays: governance (a privileged user may lift it) or compliance (nobody may, the account root included) |
| <a id="a-ciamstoragelifecycle"></a>`ciamStorageLifecycle` | `1.3.6.1.4.1.32473.1.1.441` | `string` | intent | multi | X-PATTERN `(noncurrent )?[1-9][0-9]{0,4} (cool\|cold\|archive\|delete)` | A lifecycle rule: '[noncurrent ]<days> <cool\|cold\|archive\|delete>', after days move objects (or their noncurrent versions) to a cheaper tier or delete them (30 cool; 365 delete; noncurrent 90 delete) |
| <a id="a-ciamstoragelockdays"></a>`ciamStorageLockDays` | `1.3.6.1.4.1.32473.1.1.440` | `int` | intent | single | X-MIN `1` | How long each object or recovery point stays locked at least (ciamStorageImmutability) |
| <a id="a-ciamstoragepublicblocked"></a>`ciamStoragePublicBlocked` | `1.3.6.1.4.1.32473.1.1.442` | `bool` | intent | single |  | Whether public access to the object store is blocked whatever its policies and ACLs say |
| <a id="a-ciamstoragereplicaref"></a>`ciamStorageReplicaRef` | `1.3.6.1.4.1.32473.1.1.443` | `string` | binding | single |  | The object store its objects are copied to, usually in another region (a bucket or container URI): each environment's own |
| <a id="a-ciamstorageversioning"></a>`ciamStorageVersioning` | `1.3.6.1.4.1.32473.1.1.438` | `bool` | intent | single |  | Whether an object store keeps every version of an object, so an overwrite or delete can be undone |
| <a id="a-ciamtestedon"></a>`ciamTestedOn` | `1.3.6.1.4.1.32473.1.1.464` | `time` | meta | single |  | When a restore test was done |
| <a id="a-ciamtestenvironment"></a>`ciamTestEnvironment` | `1.3.6.1.4.1.32473.1.1.465` | `dn` | meta | single |  | The environment a restore test restored in |
| <a id="a-ciamtestresult"></a>`ciamTestResult` | `1.3.6.1.4.1.32473.1.1.469` | enum: `passed`, `partial`, `failed` | meta | single |  | How a restore test went: passed, partial (restored, but something was missing or wrong), failed |
| <a id="a-ciamthroughputmb"></a>`ciamThroughputMb` | `1.3.6.1.4.1.32473.1.1.449` | `int` | intent | single | X-MIN `1` | The throughput the disk is provisioned for, in MB/s, where its type takes it |
| <a id="a-ciamvolumeclass"></a>`ciamVolumeClass` | `1.3.6.1.4.1.32473.1.1.447` | enum: `standard`, `ssd`, `provisioned` | intent | single |  | What kind of disk it is: magnetic (standard), general-purpose SSD (ssd), or SSD with provisioned IOPS (provisioned); each cloud's own type for it is the adapter's |
| <a id="a-ciamvolumeencrypted"></a>`ciamVolumeEncrypted` | `1.3.6.1.4.1.32473.1.1.450` | `bool` | intent | single |  | Whether the disk is encrypted at rest (with ciamEncryptedByRole, else the environment's disk-encryption key) |
| <a id="a-ciamvolumekind"></a>`ciamVolumeKind` | `1.3.6.1.4.1.32473.1.1.444` | enum: `boot`, `data` | intent | single |  | Which disk of a server it is: the one it starts from (boot), or one it keeps data on (data) |
| <a id="a-ciamvolumesizegb"></a>`ciamVolumeSizeGb` | `1.3.6.1.4.1.32473.1.1.446` | `int` | binding | single | X-MIN `1` | The disk's size in GB: each environment's own, but a move must not make it smaller |
