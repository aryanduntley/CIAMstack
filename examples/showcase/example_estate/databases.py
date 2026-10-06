"""Managed database fixture data, per environment (DATABASES below, used by infrastructure: SOURCE / TARGET / STANDBY
and stage): PingFederate's OAuth grant store, the PostgreSQL database its JDBC data store (`grant-store`) reaches, as
a database each environment runs by role (pf-grants-db), so the imported data store names that role and renders each
environment's own endpoint. Each admits PingFederate's subnets to its port (ciamSourceCidr: the database's security
group, network security group, or on Google Cloud the private services access peering). Each is (object class, cn,
binding role, attributes), rendered by the cloud adapters into the stack's own Terraform and read back from what each
cloud reports (cloud.py).

  source   RDS for PostgreSQL 16.4, Multi-AZ, TLS required (RDS's default from 15 on), 14 days of backups with
           point-in-time restore, deletion protection, encrypted with the platform's key; RDS keeps the master
           password in Secrets Manager (the credential role names that secret)
  stage    its own smaller RDS instance in one zone, 7 days of backups, no deletion protection (stage is rebuilt)
  target   Azure Database for PostgreSQL Flexible Server 16 in its own delegated subnet, encrypted with the target's
           key (Azure keeps the minor version current: the record holds the major version)
  standby  Cloud SQL for PostgreSQL 16, regional, as production keeps it

Planted for the planner to find (the target was set up from a sandbox template):
  - no zone-redundant standby: the database fails with its zone
  - backups kept 7 days where the source keeps 14
  - no deletion protection (no lock on the server)
Approved change CHG-2016 restores the backups and the lock; the zone-redundant standby stays open (its cost is the
platform team's to approve).
"""
from .common import owner

ROLE, CREDENTIAL, KEY = "pf-grants-db", "pf-grants-db-password", "disk-encryption"
PARAMETERS = ["log_min_duration_statement=1000", "idle_in_transaction_session_timeout=60000"]
SHARED = {"ciamDbEngine": "postgresql", "ciamDbTlsRequired": "TRUE", "ciamDbPointInTime": "TRUE",
          "ciamEncryptedByRole": KEY, "ciamDbCredentialRole": CREDENTIAL, "ciamPort": "5432",
          "ciamDbParameter": PARAMETERS, "ciamOwner": owner("ciam-platform")}
DATABASES = {
    "source": (
        ("ciamDatabase", "pf-grants", ROLE,
         {**SHARED, "ciamDbEngineVersion": "16.4", "ciamDbService": "rds", "ciamInstanceSize": "db.m6i.large",
          "ciamDbStorageGb": "100", "ciamDbHighAvailability": "zone-redundant", "ciamRetentionDays": "14",
          "ciamDbDeletionProtection": "TRUE", "ciamSubnetRole": "subnet-pf",
          "ciamSourceCidr": ["10.20.4.0/24", "10.20.5.0/24"],
          "ciamFqdn": "pf-grants.db.aws.internal.example-aero.test",
          "ciamProviderRef": "arn:aws:rds:us-east-1:111122223333:db:pf-grants"}),
    ),
    "stage": (
        ("ciamDatabase", "pf-grants-stage", ROLE,
         {**SHARED, "ciamDbEngineVersion": "16.4", "ciamDbService": "rds", "ciamInstanceSize": "db.t4g.medium",
          "ciamDbStorageGb": "20", "ciamDbHighAvailability": "none", "ciamZone": "us-east-1a",
          "ciamRetentionDays": "7", "ciamDbDeletionProtection": "FALSE", "ciamSubnetRole": "subnet-pf",
          "ciamSourceCidr": ["10.20.4.0/24", "10.20.5.0/24"],
          "ciamFqdn": "pf-grants.stage.db.aws.internal.example-aero.test",
          "ciamProviderRef": "arn:aws:rds:us-east-1:111122223333:db:pf-grants-stage"}),
    ),
    "target": (
        ("ciamDatabase", "psql-ciam-prod-pf-grants", ROLE,
         {**SHARED, "ciamDbEngineVersion": "16", "ciamDbService": "flexible-server",
          "ciamInstanceSize": "GP_Standard_D2ds_v5", "ciamDbStorageGb": "128", "ciamZone": "1",
          "ciamDbHighAvailability": "none", "ciamRetentionDays": "7", "ciamDbDeletionProtection": "FALSE",
          "ciamSubnetRole": "subnet-db", "ciamSourceCidr": ["10.60.2.0/24"],
          "ciamFqdn": "psql-ciam-prod-pf-grants.postgres.database.azure.com",
          "ciamProviderRef": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/"
                             "providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-ciam-prod-pf-grants"}),
    ),
    "standby": (
        ("ciamDatabase", "ciam-standby-pf-grants", ROLE,
         {**SHARED, "ciamDbEngineVersion": "16", "ciamDbService": "cloud-sql", "ciamInstanceSize": "db-custom-2-8192",
          "ciamDbStorageGb": "100", "ciamZone": "us-central1-a", "ciamDbHighAvailability": "zone-redundant",
          "ciamRetentionDays": "14", "ciamDbDeletionProtection": "TRUE", "ciamSourceCidr": ["10.70.2.0/24"],
          "ciamFqdn": "pf-grants.db.gcp.internal.example-aero.test",
          "ciamProviderRef": "projects/example-aero-ciam-standby/instances/ciam-standby-pf-grants"}),
    ),
}
