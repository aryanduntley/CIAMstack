"""The database roles the record runs under, none of them tiers among operators (decision 1931): an owner (no login)
that owns the opsdir schema and everything in it, a migration login that becomes the owner to run init and upgrade,
and the runtime login the tool runs as day to day, which reads and writes entries under the store's rules but can't
change the schema (no CREATE, no ownership), the secret patterns or the history. An admin creates the roles once, from
the script db_roles_sql writes; init and upgrade then keep the runtime's grants on the schema's objects themselves
(runtime_grants), so they survive init and the views re-created on every upgrade. CIAMstack never needs admin rights.
Pure: the SQL is built here and run by store.migrations, or by the admin."""
from typing import NamedTuple

from ..core.naming import role_name_problem

Roles = NamedTuple("Roles", [("owner", str), ("runtime", str)])
DEFAULTS = {"owner": "opsdir_owner", "migrator": "opsdir_migrate", "runtime": "opsdir_app"}
LOGINS = ("password", "certificate", "kerberos", "peer")
OWNER_ENV, RUNTIME_ENV = "OPSDIR_DB_OWNER", "OPSDIR_DB_RUNTIME"
# Tables the runtime only reads: written by upgrade alone (the migrations applied, the secret patterns the store
# refuses, the vocabulary and the reference schemes the installed parts declare)
READ_ONLY = ("schema_migration", "secret_pattern", "vocabulary", "ref_scheme")
HISTORY = "entry_history"            # the runtime adds to it (through the write trigger) and reads it; never changes it
HBA = {"password": "scram-sha-256", "certificate": "cert", "kerberos": "gss include_realm=0", "peer": "peer"}


name_problem = role_name_problem         # a role or database name's problem (core.naming), or None


def db_roles(env):
    """The Roles init and upgrade apply, from OPSDIR_DB_OWNER and OPSDIR_DB_RUNTIME in env (each optional: no owner
    leaves objects to the connecting login, no runtime grants nothing), or None when neither is set; ValueError for an
    invalid name."""
    owner, runtime = env.get(OWNER_ENV) or None, env.get(RUNTIME_ENV) or None
    if owner is None and runtime is None:
        return None
    problems = [p for p, n in ((owner and name_problem(owner), owner), (runtime and name_problem(runtime), runtime))
                if p]
    if problems:
        raise ValueError("; ".join(problems))
    return Roles(owner, runtime)


def owner_sql(roles):
    """The statement making the connection run as the owner from here on (none without one): the migration login
    holds none of the owner's rights itself, so what init and upgrade read afterwards needs the owner too."""
    return (f"set role {roles.owner}",) if roles and roles.owner else ()


def runtime_grants(roles, schema="opsdir"):
    """The statements giving the runtime login its rights on the schema's objects (none without one): use of the
    schema, rows of every table, only reading the tables upgrade alone writes, only adding to and reading the
    history, its sequences and its functions. Idempotent: run at the end of every init and upgrade."""
    if not roles or not roles.runtime:
        return ()
    r, s = roles.runtime, schema
    return (f"grant usage on schema {s} to {r}",
            f"grant select, insert, update, delete on all tables in schema {s} to {r}",
            f"revoke insert, update, delete on {', '.join(f'{s}.{t}' for t in READ_ONLY)} from {r}",
            f"revoke update, delete, truncate on {s}.{HISTORY} from {r}",
            f"grant usage, select on all sequences in schema {s} to {r}",
            f"grant execute on all functions in schema {s} to {r}")


def db_roles_sql(owner, migrator, runtime, database, login="password", persons=(), api=None):
    """The script an admin reviews and runs once (as a role with CREATEROLE on the record's server): the owner (no
    login), the migration login (a member able to become the owner, not inheriting its rights), the runtime login,
    their database rights, PUBLIC's CREATE on schema public revoked, each person's own login (a member of the
    runtime login, so it has the runtime's rights and the store knows who wrote and approved), the HTTP API server's
    login when named (a member of the runtime login; the store trusts it to say which person a write is for once the
    record's api-login setting names it), and the pg_hba.conf lines for the login method (peer: the person's
    operating-system account on the CIAMstack server, reached over SSH with their key, signs in as the login of the
    same name over the local socket). ValueError for an invalid name or an unknown login method."""
    problems = [p for p in (name_problem(owner), name_problem(migrator), name_problem(runtime),
                            name_problem(database, "database"), *(name_problem(p, "person") for p in persons),
                            api is not None and name_problem(api, "API login")) if p]
    if len({owner, migrator, runtime}) < 3:
        problems.append("the owner, migration and runtime roles must be three different roles")
    if api is not None and api in {owner, migrator, runtime, *persons}:
        problems.append(f"the API login {api!r} must be a role of its own")
    if login not in LOGINS:
        problems.append(f"login method {login!r} isn't one of {', '.join(LOGINS)}")
    if problems:
        raise ValueError("; ".join(problems))
    method = HBA[login]
    return "\n".join((
        f"-- Database roles for the record in database {database} (opsdir db-roles). Review, then run as an admin",
        f"-- connected to {database} (psql -d {database}).",
        "-- The owner owns the schema and everything in it; nobody signs in as it.",
        f"create role {owner} nologin;",
        "-- The migration login runs `opsdir init` and `opsdir upgrade` (OPSDIR_DB_OWNER=" + owner + "): it becomes",
        "-- the owner for them, without holding the owner's rights otherwise.",
        f"create role {migrator} login;",
        f"grant {owner} to {migrator} with inherit false, set true;",
        "-- The runtime login is what opsdir runs as day to day (OPSDIR_DB_RUNTIME=" + runtime + " on init and",
        "-- upgrade keeps its grants): rows only, never the schema, the secret patterns or the history.",
        f"create role {runtime} login;",
        f"grant connect on database {database} to {migrator}, {runtime};",
        f"grant create on database {database} to {owner};",
        f"revoke create on schema public from public;",
        f"revoke temporary on database {database} from public;",   # no temporary tables to shadow the store's
        *(line for p in persons for line in (f"-- {p}: a person, signing in as themselves with the runtime's rights",
                                             f"create role {p} login in role {runtime};")),
        *_api(api, runtime, database),
        *_login_notes(login, migrator, runtime),
        *_hba(login, database, (migrator, runtime, *persons, *((api,) if api else ())), method),
    )) + "\n"


def _api(api, runtime, database):
    if not api:
        return ()
    return ("-- The HTTP API server's login: the runtime's rights (rows only), acting for the person each verified",
            "-- token names. The store trusts that only once the record's api-login setting names it:",
            f"--   opsdir setting api-login {api} --change CHG-...",
            "-- Only the API server holds its credentials.",
            f"create role {api} login in role {runtime};",
            f"grant connect on database {database} to {api};")


def _hba(login, database, roles, method):
    if login == "peer":
        return ("-- pg_hba.conf (the database on the CIAMstack server itself; each operating-system account signs in",
                "-- as the login of the same name):", *(f"--   local {database} {r} peer" for r in roles))
    return ("-- pg_hba.conf (TLS only; narrow the address to the CIAMstack server's):",
            *(f"--   hostssl {database} {r} 0.0.0.0/0 {method}" for r in roles))


def _login_notes(login, migrator, runtime):
    if login == "password":
        return ("-- Give each login a password with \\password (SCRAM), kept in a password file (PGPASSFILE) on the",
                "-- CIAMstack server, never in the environment.")
    if login == "certificate":
        return (f"-- Each login presents a client certificate whose CN is its role name ({migrator}, {runtime}), or",
                "-- a pg_ident.conf map names it; the client sets sslcert and sslkey.")
    if login == "kerberos":
        return (f"-- Each login is a Kerberos principal named as its role ({migrator}, {runtime}) in the server's "
                "realm;", "-- the client holds a ticket (kinit, or a keytab).")
    return ("-- Each login is the operating-system account of the same name on the CIAMstack server (people reach it",
            "-- over SSH with their keys); the database runs on that server and they connect over the local socket.")
