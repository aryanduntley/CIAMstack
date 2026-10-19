# Running the record's database in production

The record is a PostgreSQL database. Each company keeps its own: a parent organization and each subsidiary run their own record, on their own Linux server, inside their own compliance boundary. This runbook covers setting one up, keeping it safe, restoring it and upgrading it. The facts about managed services come from the vendors' documentation as of October 2026; check the target region before relying on one, especially in AWS GovCloud and Azure Government, where engine versions and features can differ by region.

## What it needs

- **PostgreSQL 17 or later.** `opsdir init` and `opsdir upgrade` refuse an older server. RDS, Aurora and Azure Database for PostgreSQL flexible server all offer 17 and 18. Check the region: neither GovCloud nor Azure Government publishes a per-region version list, so ask the region itself (`aws rds describe-db-engine-versions --engine postgres --region <region>`, or the versions the Azure portal offers when creating a server there).
- **A Linux server for CIAMstack** that reaches the database: one company-wide server. The CLI, and later the API and console, run there. People on any OS reach it through the API, the console or MCP as they arrive; the CLI also runs directly on Linux, on macOS (POSIX; expected to work, not yet tested) and on Windows through WSL2. Every file CIAMstack reads and writes is UTF-8 with LF line endings, whatever the server's locale.
- **TLS** whenever the database isn't on that server. `opsdir` refuses an off-host connection that doesn't verify the server's certificate and name (`sslmode=verify-full` with `sslrootcert`), unless `OPSDIR_DB_TLS` names a weaker mode on purpose.

## Setting it up

1. **Create the database and roles.** Run `opsdir db-roles --database <db> --login <password|certificate|kerberos>` and give the script to the DBA. They review it and run it connected to the new database. It creates three roles:
   - `opsdir_owner`, which owns the schema and never signs in;
   - `opsdir_migrate`, which runs init and upgrade;
   - `opsdir_app`, the day-to-day login, which has rows only.

   With the HTTP API, add `--api-login opsdir_api`: the API server's own login, a member of `opsdir_app` (rows only). The API server acts for the person each verified token names, and the store believes it only once the record's `api-login` setting names that login (step 5). Only the API server holds its credentials.

   The script also takes the right to create temporary tables away from PUBLIC (`revoke temporary on database`), and every store function runs with its search path pinned (`opsdir, pg_temp`), so no login can stand a temporary table in for the record inside the store's own rules.

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
   - With the HTTP API: `opsdir setting api-login opsdir_api --change <code>-…`. The rest of the API's setup is in [Running the HTTP API](API-DEPLOYMENT.md).
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

## FIPS 140-3 for the database connection

Where the company's authorization requires FIPS-validated cryptography, "TLS on" and "the server is in FIPS mode" aren't enough: validation covers a specific cryptographic module used in its approved mode, on both ends of the connection and on every hop between them (proxies, poolers). What CIAMstack's side needs:

- **A system-linked database driver.** psycopg's binary build bundles its own libpq and OpenSSL, and no validation of those bundled copies is established. On a FIPS host, install the core with `opsdir[c]` (psycopg built against the operating system's libpq, which uses the system OpenSSL and its FIPS provider) and set `PSYCOPG_IMPL=c`. Development and the showcase use `opsdir[binary]` (`opsdir/scripts/dev-install.sh`).
- **An operating system whose FIPS module is validated, in FIPS mode**, following the vendor's procedure. As of the research (2026-10-19): RHEL 9 (OpenSSL provider, CMVP #4857), Ubuntu Pro 22.04 (#4794) and Amazon Linux 2023 (#5021) have FIPS 140-3 certificates, with interim-validation and approved-mode caveats. RHEL 10's operating-environment update and Ubuntu 24.04's validation were still pending on the vendors' pages. Choose and document an update policy: patched packages aren't automatically the validated binary.
- **Connection settings:** `sslmode=verify-full` with the CA file, `ssl_min_protocol_version=TLSv1.2` (or 1.3 if mandated and tested), `gssencmode=disable` when the required transport is verified TLS, and `channel_binding=require` for SCRAM password sign-in (not with cloud tokens). On a self-managed server: `ssl=on`, `password_encryption=scram-sha-256` and `hostssl` SCRAM rules. On Azure, `require_secure_transport` on.
- **The managed database's side:** what is established is AWS's adoption of AWS-LC in RDS/Aurora PostgreSQL releases. A FIPS 140-3 certificate mapping for the exact GovCloud instances, or for Azure Database for PostgreSQL Flexible Server's client-facing TLS in Azure Government, isn't established. Obtain the provider's attestation before declaring the connection compliant.

`opsdir posture` reports what the running process can see. The **client library** row gives libpq's version and psycopg's build. The **fips** row gives the kernel's FIPS flag, the libpq, libssl, libcrypto and FIPS provider files the process has loaded, and the TLS version and cipher the connection negotiated. It warns on a production record when the kernel is in FIPS mode but psycopg's bundled libraries are in use. This is evidence, never proof of validation. The operator keeps the records only they can: the module's certificate and security policy, the covered binaries and environment, approved-mode and self-test evidence, the update policy, the cloud provider's data-plane attestations, and each TLS hop.

Sources: [psycopg installation](https://www.psycopg.org/psycopg3/docs/basic/install.html), [CMVP #4857 (RHEL 9)](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857), [CMVP #4794 (Ubuntu 22.04)](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4794), [CMVP #5021 (Amazon Linux 2023)](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5021), [Red Hat FIPS status](https://access.redhat.com/compliance/fips), [OpenSSL FIPS module](https://docs.openssl.org/3.0/man7/fips_module/), [libpq connection parameters](https://www.postgresql.org/docs/17/libpq-connect.html), [Azure FIPS offering](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-fips-140-2).

## Recovery targets and losing a region

Agree two numbers for the record's database with the company's continuity owners, and record them:

```bash
opsdir setting recovery-rpo 15m --change <code>-…   # the most recent writes you accept losing (m, h or d)
opsdir setting recovery-rto 4h --change <code>-…    # how long the record may be unavailable
```

`opsdir posture` reports them, and asks for them on a production record. Then choose the placement's protection so it meets them. High availability within a region (above) covers losing a server or a zone. Losing a whole region needs a copy outside it:

| Placement | What survives a region loss | What it costs you |
|---|---|---|
| Self-managed | A WAL archive in another region's storage (pgBackRest or Barman repository), optionally a streaming standby there | RPO: the archive interval or replication lag. RTO: restoring or promoting, then repointing the CIAMstack server |
| Amazon RDS / Aurora | Not established here for each partition: check AWS's current documentation for cross-region automated backup replication and cross-region replicas. GovCloud documentation excludes Aurora PostgreSQL cross-region read replicas | Depends on the option your partition offers; GovCloud's regional CA bundles differ per region |
| Azure Flexible Server | Geo-redundant backup, which must be chosen when the server is created. It replicates asynchronously and restores the latest available copy (no point-in-time choice in the other region) | Microsoft documents an RPO that can reach one hour. In Azure Government, only US Gov Virginia lists geo-redundant backup |

**When a region is lost:**

1. Stop writes: stop the HTTP API and pause scheduled jobs on the CIAMstack server, so nothing writes to a half-available record.
2. Bring the database up in the surviving region: promote the standby, restore from the WAL archive to the latest point, or geo-restore (Azure).
3. Point the CIAMstack server at it: `OPSDIR_DSN` (or the service file) with that region's host and CA file. On a managed service, the cloud token's audience or region changes with the host.
4. Check it before letting anyone back in: `opsdir posture` (every row as before), `opsdir check`, and `opsdir history` to see the last change that survived. Compare it with the last change the company knows was applied: the difference is the data lost.
5. Restart the API and the jobs, then record the incident, with the measured data loss and downtime against `recovery-rpo` and `recovery-rto`.
6. Re-establish protection: a new standby or archive outside the new primary's region.

A restore drill (`restore-test-interval-days`) should include this procedure at least once a year, timed, in the regions you would really use. Showing the targets met on real infrastructure is part of validation against real accounts (milestone 7.2).

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

A database set up before 2026-10-18: also have the DBA run `revoke temporary on database <db> from public;` (the current `opsdir db-roles` script includes it); `opsdir upgrade` pins the store functions' search path itself.

`opsdir init` is never part of an upgrade: it drops the schema and its history.

## Development and test databases

`scripts/dev-env.sh` points at a local development database (`opsdir` on localhost, development password). The test suites use their own databases (`OPSDIR_TEST_DSN`, `OPSDIR_TEST_WORKSPACE_DSN`) and never `OPSDIR_DSN`. On a production record, `opsdir posture` fails while any of the development defaults are in use.
