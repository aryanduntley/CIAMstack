# Running the record's database in production

The record is a PostgreSQL database. Each company keeps its own: a parent organization and each subsidiary run their own record, on their own Linux server, inside their own compliance boundary. This runbook covers setting one up, keeping it safe, restoring it and upgrading it. The facts about managed services come from the vendors' documentation as of October 2026; check the target region before relying on one, especially in AWS GovCloud and Azure Government, where engine versions and features can differ by region.

## What it needs

- **PostgreSQL 17 or later.** `opsdir init` and `opsdir upgrade` refuse an older server. RDS, Aurora and Azure Database for PostgreSQL flexible server all offer 17 and 18. Check the region: neither GovCloud nor Azure Government publishes a per-region version list, so ask the region itself (`aws rds describe-db-engine-versions --engine postgres --region <region>`, or the versions the Azure portal offers when creating a server there).
- **A Linux server for CIAMstack** that reaches the database. The CLI, and later the API and console, run there.
- **TLS** whenever the database isn't on that server. `opsdir` refuses an off-host connection that doesn't verify the server's certificate and name (`sslmode=verify-full` with `sslrootcert`), unless `OPSDIR_DB_TLS` names a weaker mode on purpose.

## Setting it up

1. **Create the database and roles.** Run `opsdir db-roles --database <db> --login <password|certificate|kerberos>` and give the script to the DBA. They review it and run it connected to the new database. It creates three roles:
   - `opsdir_owner`, which owns the schema and never signs in;
   - `opsdir_migrate`, which runs init and upgrade;
   - `opsdir_app`, the day-to-day login, which has rows only.

   On RDS with IAM authentication, also `GRANT rds_iam TO opsdir_app` (and to `opsdir_migrate`). On Azure with Entra ID, the server's Entra administrator maps the principals with `pgaadauth_create_principal` instead of creating password logins.
2. **Allow the logins in `pg_hba.conf`** (self-managed servers) with the `hostssl` lines the script prints, narrowed to the CIAMstack server's address. Managed services set this through their own settings: TLS required, IAM or Entra authentication on.
3. **Configure the CIAMstack server**:
   - `OPSDIR_DSN` (or a `PGSERVICEFILE` service), with `sslmode=verify-full sslrootcert=<CA file>`. RDS's CA bundle is per region, and GovCloud's (`rds-ca-rsa4096-g1`) isn't in the system's roots.
   - How the logins sign in: a password file (`PGPASSFILE`, mode 0600), a client certificate (`sslcert`, `sslkey`), a Kerberos ticket, or a cloud token (`OPSDIR_DB_AUTH=aws-rds-iam` or `azure-entra`; see the AWS and Azure adapters' READMEs). Never a password in the environment.
   - `OPSDIR_DB_OWNER=opsdir_owner` and `OPSDIR_DB_RUNTIME=opsdir_app` for the init and upgrade runs.
4. **Build the schema** as the migration login: `opsdir init`. It runs as the owner and leaves the runtime its grants.
5. **Give the record its identity and say it is production**, under approved changes:
   - `opsdir identity --org <code> [--parent <group code>] --name "<company>" --change <change>`. From then on, change records are named `<code>-…`.
   - `opsdir setting deployment production --change <code>-…`.
6. **Check it**: run `opsdir posture` as the runtime login. Every check should be `ok`, apart from information rows. A production record fails on:
   - a password in the environment;
   - the development defaults;
   - a day-to-day login that can change the schema;
   - a missing identity.
7. **Name clouds with the org code** (`collins-aws`, `collins-azure-gov`). Environment names appear in rendered files (resource tags). Names that are unique across the group's companies mean nothing has to be renamed if two companies' records are ever combined. `opsdir posture` lists the cloud names that don't follow the convention.

## Keeping it safe: backups, point-in-time restore, high availability

| Placement | Backups and point-in-time restore | High availability |
|---|---|---|
| Amazon RDS for PostgreSQL | Automated backups kept 1 to 35 days (0 turns them off: don't), restore to any point in the window | Multi-AZ instance (a standby in another zone). Multi-AZ DB clusters exist in commercial regions; GovCloud doesn't offer them |
| Amazon Aurora PostgreSQL | Continuous backups, 1 to 35 days, always on | Storage across three zones; add an Aurora replica for compute failover |
| Azure Database for PostgreSQL flexible server | Automatic, 7 to 35 days (default 7), restore to any point. Geo-redundant backup only if chosen when the server is created | Same-zone or zone-redundant standby. In Azure Government, US Gov Virginia offers zone-redundant HA and geo-redundant backup; US Gov Arizona and US Gov Texas offer same-zone HA only, and no geo-redundant backup |
| Self-managed (Linux) | Physical base backups (`pg_basebackup`) plus continuous WAL archiving, kept outside the server's failure domain. pgBackRest (2.60.0) and Barman (3.20.1) do both and verify them | A streaming standby and a failover arrangement; backups alone don't give availability |

Whatever the placement:

- **Keep a logical backup too** (below) before every upgrade, and on the schedule the company's records policy sets. It is small, portable between placements, and it is the procedure the tests exercise.
- **Test a restore.** The record's `restore-test-interval-days` setting (90 by default) is how often the data domain expects one.
- **Record the database itself, if you want its checks.** The record can describe its own database as a `ciamDatabase` binding of the CIAMstack server's environment, with its engine, version, high availability, retention, point-in-time restore and deletion protection. The data domain's checks and the `databases` report then cover it like any other managed database.

## Logical backup and restore

The migration login takes and restores the backup acting as the owner, so everything keeps its owner and the runtime keeps its grants:

```bash
# back up the record's schema (entries, history, registry, migration state)
pg_dump -h <host> -U opsdir_migrate --role opsdir_owner -Fc -n opsdir -f record-$(date +%Y%m%d).dump <db>

# restore into a new, empty database prepared like the first (an admin grants CONNECT and CREATE as db-roles prints)
pg_restore -h <host> -U opsdir_migrate --role opsdir_owner --exit-on-error -d <new db> record-YYYYMMDD.dump
```

Then point `OPSDIR_DSN` at the new database and run `opsdir posture`. The restore brings back every entry and every history row, the migration state (`opsdir upgrade` finds nothing to apply), the runtime's rights and the store's rules (governed writes, append-only history). The integration suite runs exactly this against a scratch PostgreSQL 17 server (`opsdir/tests/integration/test_record_roles.py`).

The dump holds the whole record: owners, configuration, history. It holds no secret values, because the record never does, but treat it as the company's configuration data: keep it encrypted and access-controlled.

## Upgrading

1. Take a logical backup (above).
2. Install the new CIAMstack release on the server.
3. Run `opsdir upgrade` as the migration login, with `OPSDIR_DB_OWNER` and `OPSDIR_DB_RUNTIME` set. Pending migrations, definitions, the schema registry and the runtime's grants are applied in one transaction, one upgrade at a time. If anything fails, nothing changes, and the stored entries are re-checked against the new schema before it commits.
4. Run `opsdir posture`.

`opsdir init` is never part of an upgrade: it drops the schema and its history.

## Development and test databases

`scripts/dev-env.sh` points at a local development database (`opsdir` on localhost, development password). The test suites use their own databases (`OPSDIR_TEST_DSN`, `OPSDIR_TEST_WORKSPACE_DSN`) and never `OPSDIR_DSN`. On a production record, `opsdir posture` fails while any of the development defaults are in use.
