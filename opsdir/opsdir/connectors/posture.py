"""The record database's posture: whether the database CIAMstack runs on, and the way it is reached, are fit for what
the record is (its deployment setting). Each check is a row (check, status, detail): ok, info, warn, or fail (the
posture command exits non-zero). A production record fails on what a development one only notes: a password given in
the environment or the connection string, the local development defaults, a day-to-day login that can change the
schema, no record identity. Pure: the connection's facts come from store.postgres.posture_facts, the record from the
directory snapshot."""
from ..core.settings import setting_value
from ..domains.governance.identity import record_identity
from ..domains.governance.settings import APPROVAL_SEPARATION, DEPLOYMENT
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
            _dev_defaults(facts, production), _privileges(facts, production), _migrations(facts, known_migrations),
            _identity(identity, production), _separation(d, production), *_cloud_names(d, identity))


def failed(rows):
    """How many rows fail."""
    return sum(1 for _, status, _ in rows if status == FAIL)
