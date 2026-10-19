"""The record database's posture: whether the database CIAMstack runs on, and the way it is reached, are fit for what
the record is (its deployment setting). Each check is a row (check, status, detail): ok, info, warn, or fail (the
posture command exits non-zero). A production record fails on what a development one only notes: a password given in
the environment or the connection string, the local development defaults, a day-to-day login that can change the
schema, no record identity. Pure: the connection's facts come from store.postgres.posture_facts, the record from the
directory snapshot."""
from ..core.settings import setting_value
from ..domains.governance.identity import record_identity
from ..domains.governance.settings import (APPROVAL_SEPARATION, APPROVALS_REQUIRED, DEPLOYMENT, RECOVERY_RPO,
                                           RECOVERY_RTO)
from ..store.policy import MIN_SERVER_VERSION, is_local, tls_problem
from .registry import environment_specs

HEADERS = ("check", "status", "detail")
FAIL, WARN, INFO, OK = "fail", "warn", "info", "ok"
DEV_DATABASE = ("opsdir", "opsdir")      # scripts/dev-env.sh's database and login


def _version(f):
    major = f.server_version // 10000
    if f.server_version >= MIN_SERVER_VERSION:
        return ("server version", OK, f"PostgreSQL {major}")
    return ("server version", FAIL, f"PostgreSQL {major}; the store needs {MIN_SERVER_VERSION // 10000} or later")


def _tls(f, allowed):
    if is_local(f.host):
        return ("tls", OK, f"local ({f.host or 'default socket'}){', TLS in use' if f.ssl_in_use else ''}")
    problem = tls_problem(f.host, f.sslmode, f.sslrootcert, f.ssl_in_use, allowed)
    if problem:
        return ("tls", FAIL, problem)
    mode = "verify-full" if f.sslrootcert == "system" else f.sslmode
    if mode != "verify-full":
        return ("tls", WARN, f"{f.host}: sslmode={mode}, accepted because OPSDIR_DB_TLS names it")
    return ("tls", OK, f"{f.host}: verify-full")


def _sign_in(f, production, token):
    if token:
        return ("sign-in", OK, f"cloud database token ({token})")
    if f.used_gssapi:
        return ("sign-in", OK, "Kerberos (GSSAPI)")
    if f.client_certificate:
        return ("sign-in", OK, "client certificate")
    if not f.used_password:
        return ("sign-in", INFO, "no password asked (trust or peer authentication on the server)")
    if f.password_given:
        return ("sign-in", FAIL if production else INFO,
                "a password given in the connection string or the environment: use a password file (PGPASSFILE), "
                "a client certificate, Kerberos or a cloud token instead")
    return ("sign-in", OK, "password from a password file, or a cloud token")


def _dev_defaults(f, production):
    found = [w for w, hit in (("the development password", f.dev_password),
                              (f"the development database and login ({DEV_DATABASE[0]}/{DEV_DATABASE[1]} on "
                               f"{f.host or 'the default socket'})",
                               (f.dbname, f.user) == DEV_DATABASE and is_local(f.host))) if hit]
    if not found:
        return ("development defaults", OK, "none")
    return ("development defaults", FAIL if production else INFO, "uses " + " and ".join(found))


def _privileges(f, production):
    if f.superuser:
        return ("login privileges", FAIL if production else WARN, f"{f.user} is a superuser")
    if f.owns_schema or f.can_create:
        how = (f"owns the schema (as {f.schema_owner})" if f.owns_schema else "can create objects in the schema")
        return ("login privileges", FAIL if production else INFO,
                f"{f.user} {how}: fine for init and upgrade; run day to day as the runtime login (opsdir db-roles)")
    return ("login privileges", OK, f"{f.user}: rows only, no schema rights")


TLS_ORDER = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
LOGIN_FLAGS = {"createrole": "create roles", "createdb": "create databases", "bypassrls": "bypass row security"}


def _tls_minimum(f, production):
    if not f.ssl_min_version:
        return ("tls minimum", INFO, "the server's ssl_min_protocol_version isn't readable here")
    if f.ssl_min_version in TLS_ORDER and TLS_ORDER.index(f.ssl_min_version) < TLS_ORDER.index("TLSv1.2"):
        return ("tls minimum", FAIL if production else WARN,
                f"the server accepts {f.ssl_min_version}: set ssl_min_protocol_version to TLSv1.2 or later")
    return ("tls minimum", OK, f.ssl_min_version)


def _password_hashing(f, production):
    if not f.password_encryption:
        return ("password hashing", INFO, "the server's password_encryption isn't readable here")
    if f.password_encryption != "scram-sha-256":
        return ("password hashing", FAIL if production else WARN,
                f"password_encryption is {f.password_encryption}: set it to scram-sha-256 (and reset the passwords)")
    return ("password hashing", OK, "scram-sha-256")


def _login_flags(f, production):
    if not f.role_flags:
        return ("login attributes", OK, f"{f.user}: no createrole, createdb or bypassrls")
    return ("login attributes", FAIL if production else WARN,
            f"{f.user} can {', '.join(LOGIN_FLAGS[x] for x in f.role_flags)}: no login CIAMstack runs as needs that "
            "(opsdir db-roles creates them without)")


def _public_rights(f, production):
    if not f.public_rights:
        return ("public rights", OK, "PUBLIC can't create objects or temporary tables in the database")
    return ("public rights", WARN if production else INFO,
            f"PUBLIC holds {' and '.join(f.public_rights)} on database {f.dbname}: revoke them "
            f"(revoke {', '.join(r.lower() for r in f.public_rights)} on database {f.dbname} from public); the "
            "store's functions are pinned against temporary tables, but nothing needs these rights")


OBJECT_TYPES = {"r": "tables", "S": "sequences", "f": "functions", "T": "types", "n": "schemas", "L": "large objects"}
SYSTEM_ROOTS_LIBPQ = 160000            # sslrootcert=system needs libpq 16 or later


def _default_acls(f, production):
    if not f.default_acls:
        return ("default privileges", OK, "none hand future objects to PUBLIC or within the opsdir schema")
    listed = "; ".join(f"{priv} on new {OBJECT_TYPES.get(kind, kind)} in {schema} to {grantee}"
                       for schema, kind, grantee, priv in f.default_acls)
    return ("default privileges", WARN if production else INFO,
            f"{listed}: future objects get these rights without a grant anyone reviews; remove them "
            "(alter default privileges ... revoke ...); opsdir db-roles grants what each login needs explicitly")


def _client_library(f):
    if not f.libpq_version:
        return ("client library", INFO, "the libpq version isn't known here")
    version = f"libpq {f.libpq_version // 10000}.{f.libpq_version % 10000} ({f.psycopg_impl or 'psycopg'})"
    if f.libpq_version < SYSTEM_ROOTS_LIBPQ and f.sslrootcert == "system":
        return ("client library", FAIL, f"{version}: sslrootcert=system needs libpq 16 or later; upgrade libpq or "
                                        "name the CA file")
    if f.psycopg_impl == "binary":
        return ("client library", INFO, f"{version}: psycopg's binary build bundles its own libpq and OpenSSL; "
                                        "where the deployment needs the operating system's validated cryptography, "
                                        "install opsdir[c] against the system libpq (documentation/RECORD-DATABASE.md, "
                                        "FIPS)")
    return ("client library", OK, version)


def _fips(f, production):
    kernel = {"1": "on", "0": "off"}.get(f.fips_kernel, "unknown")
    tls = f"; TLS {f.tls_version} {f.tls_cipher}" if f.tls_version else ""
    libraries = ", ".join(p.rsplit("/", 1)[-1] for p in f.crypto_libraries) or "not visible"
    detail = (f"kernel FIPS mode {kernel}; loaded: {libraries}{tls}. Evidence only, not validation: the operator "
              "keeps the module's certificate and approved-mode records (documentation/RECORD-DATABASE.md, FIPS)")
    if kernel == "on" and f.psycopg_impl == "binary":
        return ("fips", WARN if production else INFO,
                "kernel FIPS mode on, but psycopg's binary build brings its own libpq and OpenSSL: install opsdir[c] "
                f"against the system libpq (PSYCOPG_IMPL=c); loaded: {libraries}{tls}")
    return ("fips", INFO, detail)


def _migrations(f, known):
    if not f.schema_owner:
        return ("schema", FAIL, "no opsdir schema in this database: run opsdir init")
    applied = {v for v, _ in f.applied}
    versions = {m.version for m in known}
    unknown = sorted(applied - versions)
    if unknown:
        return ("schema", FAIL, f"migrations this code doesn't know: {', '.join(f'{v:04d}' for v in unknown)}")
    pending = sorted(versions - applied)
    if pending:
        return ("schema", FAIL, f"{len(pending)} migration(s) pending, from {pending[0]:04d}: run opsdir upgrade")
    return ("schema", OK, f"at migration {max(applied):04d}" if applied else "no migrations applied")


def _identity(identity, production):
    if identity is None:
        return ("record identity", FAIL if production else WARN,
                "none: opsdir identity --org CODE --change CHG gives the record its company's org code")
    group = f", in {identity.parent}" if identity.parent else ""
    return ("record identity", OK, f"{identity.org} ({identity.record_id}{group})")


def _separation(d, production):
    if setting_value(d, APPROVAL_SEPARATION):
        return ("approval separation", OK, "a change's approver is never its author")
    return ("approval separation", FAIL if production else WARN,
            "off: an author may approve their own change (approval-separation FALSE, for a one-person install)")


def _approval_tiers(d):
    tiers = setting_value(d, APPROVALS_REQUIRED)
    return ("approval tiers", INFO if not tiers else OK, f"approvals-required {tiers}" if tiers else
            "one approver for every change (approvals-required unset)")


def _recovery(d, production):
    rpo, rto = setting_value(d, RECOVERY_RPO), setting_value(d, RECOVERY_RTO)
    if rpo and rto:
        return ("recovery targets", OK, f"RPO {rpo}, RTO {rto}: show them met by a restore drill "
                                        "(documentation/RECORD-DATABASE.md)")
    missing = " and ".join(n for n, v in (("recovery-rpo", rpo), ("recovery-rto", rto)) if not v)
    return ("recovery targets", WARN if production else INFO,
            f"no {missing}: agree the record database's recovery targets and set them (opsdir setting "
            "recovery-rpo 15m --change ...), then choose backups and replicas that meet them")


def _cloud_names(d, identity):
    if identity is None:
        return ()
    clouds = sorted({spec.split("/", 1)[0] for spec in environment_specs(d)})
    other = [c for c in clouds if not c.lower().startswith(f"{identity.org}-")]
    if not other:
        return (("cloud names", OK, f"all start with {identity.org}-"),)
    return (("cloud names", INFO, f"not starting with {identity.org}-: {', '.join(other)} (a merger with another "
                                  "company's record would rename them)"),)


def posture_rows(facts, d, known_migrations, allowed=None, token=None):
    """The posture rows of a connection's facts (store.postgres.PostureFacts) and the record d: the deployment
    setting, then each check. known_migrations: this code's migrations; allowed: the weaker sslmode OPSDIR_DB_TLS
    accepts; token: the database token scheme it signed in with (OPSDIR_DB_AUTH), or None."""
    deployment = setting_value(d, DEPLOYMENT)
    production = deployment == "production"
    identity = record_identity(d)
    return (("deployment", INFO, deployment), _version(facts), _tls(facts, allowed), _sign_in(facts, production, token),
            _dev_defaults(facts, production), _privileges(facts, production), _tls_minimum(facts, production),
            _password_hashing(facts, production), _login_flags(facts, production), _public_rights(facts, production),
            _default_acls(facts, production), _client_library(facts), _fips(facts, production),
            _migrations(facts, known_migrations),
            _identity(identity, production), _separation(d, production), _approval_tiers(d), _recovery(d, production),
            *_cloud_names(d, identity))


def failed(rows):
    """How many rows fail."""
    return sum(1 for _, status, _ in rows if status == FAIL)
