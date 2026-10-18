"""How the record's own database may be reached: the oldest PostgreSQL server the store accepts, and the TLS a
connection needs. A server reached over a local socket or the loopback address needs nothing more; any other needs
TLS that verifies the server's certificate and name (sslmode=verify-full, or sslrootcert=system, with which libpq
refuses weaker modes). A weaker mode is accepted only when the operator names it (OPSDIR_DB_TLS), so the choice is
explicit and visible. Pure: the connection's effective options are read by store.postgres."""
import getpass
import ipaddress

from psycopg.conninfo import conninfo_to_dict

from ..core.contract import DbTarget

MIN_SERVER_VERSION = 170000          # PostgreSQL 17 (libpq's server_version form: major * 10000 + minor)
VERIFIED = "verify-full"
TLS_CHOICE = "OPSDIR_DB_TLS"         # the environment variable naming an accepted weaker sslmode


def is_local(host):
    """Whether a libpq host (one, or several comma-separated) is reached over a local socket or the loopback
    address: none given (the default socket), a socket directory (an absolute path), an abstract socket (@name),
    localhost or a loopback address (127.0.0.0/8, ::1)."""
    hosts = [h.strip() for h in (host or "").split(",")]
    return all(not h or h.startswith(("/", "@")) or h.lower() == "localhost" or _loopback(h) for h in hosts)


def _loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def tls_problem(host, sslmode, sslrootcert, ssl_in_use, allowed=None):
    """Why a connection to the record's database isn't acceptable, or None: an off-host server needs verify-full
    TLS unless the operator named the weaker mode it uses (allowed), and TLS in use unless that mode is disable."""
    if is_local(host):
        return None
    mode = VERIFIED if sslrootcert == "system" else (sslmode or "prefer")
    if mode == VERIFIED and ssl_in_use:
        return None
    if allowed and allowed == mode and (ssl_in_use or mode == "disable"):
        return None
    reached = "without TLS" if not ssl_in_use else f"with sslmode={mode}"
    return (f"the record's database at {host} is reached {reached}: set sslmode=verify-full and sslrootcert (the "
            f"server's CA, or system), or accept sslmode={mode} explicitly with {TLS_CHOICE}={mode}")


def db_target(dsn, env):
    """The DbTarget a connection string reaches, as libpq would: host, port, user and database from dsn, else the PG*
    variables in env, else libpq's defaults (the local socket, 5432, the operating-system user, a database named as
    the user); the first of several hosts."""
    params = conninfo_to_dict(dsn or "")
    host = (params.get("host") or env.get("PGHOST") or "").split(",")[0].strip()
    port = int(str(params.get("port") or env.get("PGPORT") or "5432").split(",")[0])
    user = params.get("user") or env.get("PGUSER") or getpass.getuser()
    return DbTarget(host, port, user, params.get("dbname") or env.get("PGDATABASE") or user)


def version_problem(server_version):
    """Why the server is too old for the store, or None."""
    if server_version >= MIN_SERVER_VERSION:
        return None
    major = server_version // 10000
    return (f"the record's database runs PostgreSQL {major}; the store needs {MIN_SERVER_VERSION // 10000} or "
            f"later")
