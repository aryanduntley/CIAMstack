"""Data domain: the data services the stack keeps its state in. Managed databases (PingFederate's, AM's and IDM's
repositories, session and token stores) are bindings each environment runs: their engine and version, endpoint,
availability, encryption, backups and parameters, read in by the cloud importers and rendered by the cloud adapters;
products name them by role. Object stores (infrastructure's buckets and containers, backup targets among them) record
here how they keep what they hold: versioning, immutability, encryption, lifecycle, public access and replication.
Each server role's disks (boot disk, data volumes) and the snapshot policies that copy them are bindings too.
Vendor-neutral."""
from ...core.contract import Domain, ImportKind, directory_report
from .databases import DATABASE_HEADERS, check_databases, database_rows
from .schema import FRAGMENT
from .storage import OBJECT_STORE_HEADERS, check_object_stores, object_store_rows
from .volumes import VOLUME_HEADERS, check_volumes, volume_rows

DOMAIN = Domain(name="data", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"databases": directory_report(DATABASE_HEADERS, database_rows),
                         "object-stores": directory_report(OBJECT_STORE_HEADERS, object_store_rows),
                         "volumes": directory_report(VOLUME_HEADERS, volume_rows)},
                checks=(check_databases, check_object_stores, check_volumes), order=68, vocabulary={},
                import_kinds=(ImportKind("database", "ciamDatabase", ("ciamDbEngine",)),
                              ImportKind("volume", "ciamVolume", ("ciamTargetRole", "ciamVolumeKind"), match="name"),
                              ImportKind("snapshot-policy", "ciamSnapshotPolicy", ("ciamRetentionDays",), match="name")),
                role_links={"ciamDbCredentialRole": "secret", "ciamSnapshotPolicyRole": "snapshot-policy"})
