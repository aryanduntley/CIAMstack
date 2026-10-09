"""Data domain schema: the managed databases an environment runs for the stack (PingFederate's, AM's and IDM's
repositories, session and token stores). A database is a binding: each environment runs its own, its products name it
by role (its endpoint is a ciamFqdn, so an importer turns the host into the role), and what must carry over unchanged
in a move (the engine and its version, how available, encrypted and backed up it is, the parameters set on it) is
intent the planner compares; its size, the provider's offering and the secret holding its credentials are each
environment's own. How an object store (infrastructure's ciamObjectStore, backup targets among them) keeps what it
holds is defined here too: versioning, immutability, lifecycle, public access and replication, allowed on the object
store's class. A server role's disks (its boot disk and the volumes it keeps data on, each environment's own) and
the snapshot policies that copy them are bindings too: what a move keeps of them (no smaller, encrypted, snapshotted
as often and kept as long, copied to another region) is checked. So are backups by a backup service: the vault it
keeps recovery points in (locked, encrypted, restorable in another region) and the plan saying what it backs up, how
often, how long it keeps them and where it copies them (a different thing from infrastructure's ciamBackupTarget, the
object store a product writes its own backup files to), and the record of each restore test, which the planner holds
to a schedule (the estate setting restore-test-interval-days)."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import (CONSISTENCY, EDITIONS, ENGINES, HIGH_AVAILABILITY, IMMUTABILITY, LIFECYCLE, RESTORE_LEVELS,
                     SNAPSHOT_AT, TEST_RESULTS, VOLUME_CLASSES, VOLUME_KINDS)

ATTRIBUTES = (
    AttributeDef(427, 'ciamDbEngine', enum_type(ENGINES), 'intent', True,
                 'The database engine a managed database runs'),
    AttributeDef(428, 'ciamDbEngineVersion', 'string', 'intent', True,
                 'The engine version it runs (16.4): a move carries it unchanged; an upgrade is its own change'),
    AttributeDef(429, 'ciamDbService', 'string', 'binding', True,
                 "The provider's managed offering it runs on (rds, aurora, flexible-server, cloud-sql); the cloud's "
                 'usual one when absent'),
    AttributeDef(430, 'ciamDbHighAvailability', enum_type(HIGH_AVAILABILITY), 'intent', True,
                 'How available it is kept: a standby in another zone it fails over to (zone-redundant), or none'),
    AttributeDef(431, 'ciamDbTlsRequired', 'bool', 'intent', True,
                 'Whether it refuses connections without TLS'),
    AttributeDef(432, 'ciamDbPointInTime', 'bool', 'intent', True,
                 'Whether it can be restored to any point within its backup retention'),
    AttributeDef(433, 'ciamDbDeletionProtection', 'bool', 'intent', True,
                 'Whether the provider refuses to delete it until protection is turned off'),
    AttributeDef(434, 'ciamDbParameter', 'string', 'intent', False,
                 "An engine parameter set on it, name=value (the engine's defaults are not recorded)"),
    AttributeDef(435, 'ciamDbCredentialRole', 'string', 'binding', True,
                 'The binding role of the secret holding its administrator credentials (never a value)'),
    AttributeDef(436, 'ciamDbStorageGb', 'int', 'binding', True,
                 'The storage it is given, in GB', (("X-MIN", "1"),)),
    AttributeDef(437, 'ciamDbEdition', enum_type(EDITIONS), 'intent', True,
                 "The engine's edition where it comes in several (SQL Server, Oracle): what it is licensed and able to "
                 "do, so a move keeps it"),
    AttributeDef(438, 'ciamStorageVersioning', 'bool', 'intent', True,
                 'Whether an object store keeps every version of an object, so an overwrite or delete can be undone'),
    AttributeDef(439, 'ciamStorageImmutability', enum_type(IMMUTABILITY), 'intent', True,
                 "Whether an object store's objects, or a backup vault's recovery points, are locked against "
                 "change and deletion for ciamStorageLockDays: governance (a privileged user may lift it) or "
                 "compliance (nobody may, the account root included)"),
    AttributeDef(440, 'ciamStorageLockDays', 'int', 'intent', True,
                 'How long each object or recovery point stays locked at least (ciamStorageImmutability)',
                 (("X-MIN", "1"),)),
    AttributeDef(441, 'ciamStorageLifecycle', 'string', 'intent', False,
                 "A lifecycle rule: '[noncurrent ]<days> <cool|cold|archive|delete>', after days move objects "
                 "(or their noncurrent versions) to a cheaper tier or delete them "
                 "(30 cool; 365 delete; noncurrent 90 delete)",
                 (("X-PATTERN", LIFECYCLE),)),
    AttributeDef(442, 'ciamStoragePublicBlocked', 'bool', 'intent', True,
                 'Whether public access to the object store is blocked whatever its policies and ACLs say'),
    AttributeDef(443, 'ciamStorageReplicaRef', 'string', 'binding', True,
                 "The object store its objects are copied to, usually in another region (a bucket or container URI): "
                 "each environment's own"),
    AttributeDef(444, 'ciamVolumeKind', enum_type(VOLUME_KINDS), 'intent', True,
                 'Which disk of a server it is: the one it starts from (boot), or one it keeps data on (data)'),
    AttributeDef(445, 'ciamMountPath', 'string', 'intent', True,
                 "Where a server mounts a data volume (/opt/ds/db): what its products keep there"),
    AttributeDef(446, 'ciamVolumeSizeGb', 'int', 'binding', True,
                 "The disk's size in GB: each environment's own, but a move must not make it smaller",
                 (("X-MIN", "1"),)),
    AttributeDef(447, 'ciamVolumeClass', enum_type(VOLUME_CLASSES), 'intent', True,
                 "What kind of disk it is: magnetic (standard), general-purpose SSD (ssd), or SSD with provisioned "
                 "IOPS (provisioned); each cloud's own type for it is the adapter's"),
    AttributeDef(448, 'ciamIops', 'int', 'intent', True,
                 'The I/O operations per second the disk is provisioned for, where its type takes them',
                 (("X-MIN", "1"),)),
    AttributeDef(449, 'ciamThroughputMb', 'int', 'intent', True,
                 'The throughput the disk is provisioned for, in MB/s, where its type takes it', (("X-MIN", "1"),)),
    AttributeDef(450, 'ciamVolumeEncrypted', 'bool', 'intent', True,
                 'Whether the disk is encrypted at rest (with ciamEncryptedByRole, else the environment\'s '
                 'disk-encryption key)'),
    AttributeDef(451, 'ciamSnapshotPolicyRole', 'string', 'binding', True,
                 'The binding role of what copies the disk on a schedule: a snapshot policy, or a backup plan where '
                 'the environment does that with a backup service'),
    AttributeDef(452, 'ciamSnapshotEveryHours', 'int', 'intent', True,
                 'How often a snapshot policy takes a snapshot, in hours (24 when absent)', (("X-MIN", "1"),)),
    AttributeDef(453, 'ciamSnapshotAt', 'string', 'intent', True,
                 'When a snapshot policy takes its first snapshot of the day, HH:MM in UTC',
                 (("X-PATTERN", SNAPSHOT_AT),)),
    AttributeDef(454, 'ciamCopyRegion', 'string', 'binding', False,
                 "A region a snapshot policy or backup plan copies each snapshot or recovery point to, or a managed "
                 "database its automated backups (and the logs its point-in-time restore replays) are copied to "
                 "(each environment's own)"),
    AttributeDef(455, 'ciamSnapshotConsistency', enum_type(CONSISTENCY), 'intent', True,
                 "What a snapshot holds of a running server: the disk as a power cut would leave it (crash), or what "
                 "the application was asked to flush first (application). Neither is a backup of a database or "
                 "directory the server runs"),
    AttributeDef(457, 'ciamBackupVaultRole', 'string', 'binding', True,
                 'The binding role of the backup vault a backup plan keeps its recovery points in'),
    AttributeDef(458, 'ciamProtectsRole', 'string', 'binding', False,
                 'A role a backup plan backs up: a volume, a database, or the servers of a role'),
    AttributeDef(459, 'ciamBackupEveryHours', 'int', 'intent', True,
                 'How often a backup plan backs up, in hours (24 when absent)', (("X-MIN", "1"),)),
    AttributeDef(460, 'ciamBackupAt', 'string', 'intent', True,
                 'When a backup plan starts its first backup of the day, HH:MM in UTC', (("X-PATTERN", SNAPSHOT_AT),)),
    AttributeDef(461, 'ciamBackupWindowHours', 'int', 'intent', True,
                 'How long after its start time a backup may begin, in hours (the service decides when absent)',
                 (("X-MIN", "1"),)),
    AttributeDef(462, 'ciamCrossRegionRestore', 'bool', 'intent', True,
                 "Whether a backup vault's recovery points can be restored in another region (its geo-redundancy or "
                 "location)"),
    AttributeDef(463, 'ciamRestoreTestDays', 'int', 'meta', True,
                 "How often what a backup plan protects must be restore-tested, in days: its own, in place of the "
                 "estate setting restore-test-interval-days", (("X-MIN", "1"),)),
    AttributeDef(464, 'ciamTestedOn', 'time', 'meta', True,
                 'When a restore test was done'),
    AttributeDef(465, 'ciamTestEnvironment', 'dn', 'meta', True,
                 'The environment a restore test restored in'),
    AttributeDef(466, 'ciamRestoredRole', 'string', 'meta', True,
                 'The role whose data a restore test restored: a volume, a database, the servers of a role'),
    AttributeDef(467, 'ciamRestoredFromRole', 'string', 'meta', True,
                 'The binding role of what it was restored from: a backup plan, a snapshot policy, a backup target'),
    AttributeDef(468, 'ciamRestoreLevel', enum_type(RESTORE_LEVELS), 'meta', True,
                 "What a restore test proved: the disk restored and mounted (disk: as far as a crash-consistent "
                 "snapshot goes), or the application's data restored and verified to work (application)"),
    AttributeDef(469, 'ciamTestResult', enum_type(TEST_RESULTS), 'meta', True,
                 'How a restore test went: passed, partial (restored, but something was missing or wrong), failed'),
    AttributeDef(470, 'ciamRestoreMinutes', 'int', 'meta', True,
                 'How long the restore took, in minutes, until the data was usable', (("X-MIN", "0"),)),
)
# what an object store may record of how it keeps what it holds (allowed on infrastructure's ciamObjectStore)
STORAGE_DEPTH = ('ciamStorageVersioning', 'ciamStorageImmutability', 'ciamStorageLockDays', 'ciamStorageLifecycle',
                 'ciamStoragePublicBlocked', 'ciamStorageReplicaRef', 'ciamEncryptedByRole', 'ciamManagedBy')
CLASSES = (
    ClassDef(93, 'ciamDatabase', 'ciamBinding', 'STRUCTURAL', ('ciamDbEngine',),
             ('ciamProviderRef', 'ciamFqdn', 'ciamPort', 'ciamDbEngineVersion', 'ciamDbEdition', 'ciamDbService',
              'ciamInstanceSize', 'ciamDbStorageGb', 'ciamZone', 'ciamDbHighAvailability', 'ciamEncryptedByRole',
              'ciamDbTlsRequired', 'ciamRetentionDays', 'ciamDbPointInTime', 'ciamDbDeletionProtection',
              'ciamDbParameter', 'ciamSubnetRole', 'ciamSourceCidr', 'ciamDbCredentialRole', 'ciamCopyRegion',
              'ciamManagedBy'),
             'A managed database an environment runs for the stack (a repository, a session or token store): its '
             'engine and version, endpoint, availability, encryption and backups (ciamRetentionDays: automated '
             'backups kept), parameters, the ranges admitted to its port (ciamSourceCidr) and the secret role of '
             'its credentials'),
    ClassDef(94, 'ciamVolume', 'ciamBinding', 'STRUCTURAL', ('ciamTargetRole', 'ciamVolumeKind'),
             ('ciamMountPath', 'ciamVolumeSizeGb', 'ciamVolumeClass', 'ciamIops', 'ciamThroughputMb',
              'ciamVolumeEncrypted', 'ciamEncryptedByRole', 'ciamSnapshotPolicyRole', 'ciamManagedBy'),
             "A disk every server of a role (ciamTargetRole) has in an environment, its compute groups' included: "
             "its boot disk or a data volume, how big and fast it is, its encryption and the snapshot policy that "
             "copies it"),
    ClassDef(95, 'ciamSnapshotPolicy', 'ciamBinding', 'STRUCTURAL', ('ciamRetentionDays',),
             ('ciamSnapshotEveryHours', 'ciamSnapshotAt', 'ciamCopyRegion', 'ciamSnapshotConsistency',
              'ciamProviderRef', 'ciamManagedBy'),
             "How an environment snapshots its disks: how often, when, how long each snapshot is kept "
             "(ciamRetentionDays) and the regions it is copied to"),
    ClassDef(97, 'ciamBackupVault', 'ciamBinding', 'STRUCTURAL', (),
             ('ciamProviderRef', 'ciamEncryptedByRole', 'ciamStorageImmutability', 'ciamStorageLockDays',
              'ciamCrossRegionRestore', 'ciamManagedBy'),
             "Where a backup service keeps an environment's recovery points (an AWS Backup vault, an Azure Backup "
             "vault, a Backup and DR vault): its key, its lock and whether it can restore in another region. Not "
             "infrastructure's ciamBackupTarget, the object store a product writes its own backup files to"),
    ClassDef(98, 'ciamBackupPlan', 'ciamBinding', 'STRUCTURAL', ('ciamProtectsRole', 'ciamBackupVaultRole',
                                                                  'ciamRetentionDays'),
             ('ciamBackupEveryHours', 'ciamBackupAt', 'ciamBackupWindowHours', 'ciamCopyRegion',
              'ciamRestoreTestDays', 'ciamProviderRef', 'ciamManagedBy'),
             "What a backup service backs up in an environment (the roles it protects), into which vault, how often "
             "and from when, how long it keeps each recovery point (ciamRetentionDays) and the regions it copies them "
             "to"),
    ClassDef(99, 'ciamRestoreTest', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTestedOn', 'ciamTestEnvironment',
                                                                  'ciamRestoredRole', 'ciamRestoreLevel',
                                                                  'ciamTestResult'),
             ('ciamRestoredFromRole', 'ciamRestoreMinutes', 'ciamRunbookRef'),
             "One restore test (under ou=restore-tests): when, in which environment, whose data it restored and from "
             "what, what it proved (disk or application), how it went and how long it took"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
