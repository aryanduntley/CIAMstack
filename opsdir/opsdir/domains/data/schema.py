"""Data domain schema: the managed databases an environment runs for the stack (PingFederate's, AM's and IDM's
repositories, session and token stores). A database is a binding: each environment runs its own, its products name it
by role (its endpoint is a ciamFqdn, so an importer turns the host into the role), and what must carry over unchanged
in a move (the engine and its version, how available, encrypted and backed up it is, the parameters set on it) is
intent the planner compares; its size, the provider's offering and the secret holding its credentials are each
environment's own."""
from ...core.standard import AttributeDef, ClassDef, enum_type, fragment
from .naming import EDITIONS, ENGINES, HIGH_AVAILABILITY

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
)
CLASSES = (
    ClassDef(93, 'ciamDatabase', 'ciamBinding', 'STRUCTURAL', ('ciamDbEngine',),
             ('ciamProviderRef', 'ciamFqdn', 'ciamPort', 'ciamDbEngineVersion', 'ciamDbEdition', 'ciamDbService',
              'ciamInstanceSize', 'ciamDbStorageGb', 'ciamZone', 'ciamDbHighAvailability', 'ciamEncryptedByRole',
              'ciamDbTlsRequired', 'ciamRetentionDays', 'ciamDbPointInTime', 'ciamDbDeletionProtection',
              'ciamDbParameter', 'ciamSubnetRole', 'ciamDbCredentialRole', 'ciamManagedBy'),
             'A managed database an environment runs for the stack (a repository, a session or token store): its '
             'engine and version, endpoint, availability, encryption and backups (ciamRetentionDays: automated '
             'backups kept), parameters and the secret role of its credentials'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
