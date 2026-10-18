"""Read queries over the store's SQL views and functions (effects: they run SQL)."""
import datetime as dt


def fetch_rows(conn, sql, params=()):
    return conn.execute(sql, params).fetchall()


def _with_owners(rows, owners):
    return [(depth, dn, via, owners.get(dn, "")) for depth, dn, via in rows]


def fetch_blast_radius(conn, dn):
    """Everything that depends on dn (transitively, SQL dependents()), with each dependent's owners."""
    rows = fetch_rows(conn, "select depth, dn, via_attr from dependents(%s)", (dn,))
    owners = dict(fetch_rows(conn, "select dn, string_agg(split_part(split_part(owner, ',', 1), '=', 2), ',')"
                                   " from owners_of(%s) group by dn", ([r[1] for r in rows],)))
    return _with_owners(rows, owners)


def fetch_history(conn, dn=None):
    """Governed changes after the bootstrap load, optionally for one DN: when, under which change, what, the person
    or login that wrote it, the API client it came through and the identity provider-mapped teams the person held
    (both empty for a direct login), and on which entry (last, so a table never cuts it short)."""
    where = " and lower(dn) = lower(%s)" if dn else ""
    return fetch_rows(conn, "select at::timestamp(0), change_id, op, db_user, coalesce(client, ''),"
                            " array_to_string(coalesce(teams, '{}'), ', '), dn from entry_history"
                            f" where change_id <> 'BOOTSTRAP'{where} order by id", (dn,) if dn else ())


def fetch_change_writes(conn, until, branch):
    """Effect (reads history): {change id: (first, last, count)} of when each governed change's writes landed before
    until (a UTC datetime), as UTC datetimes (the session's time zone is the server's), the bootstrap load and each
    change's own change record (cn=<id>,<branch>) left out."""
    rows = fetch_rows(conn, "select change_id, min(at), max(at), count(*) from entry_history"
                            " where change_id <> 'BOOTSTRAP' and at < %s"
                            " and norm_dn(dn) <> norm_dn('cn=' || change_id || ',' || %s) group by change_id",
                      (until, branch))
    utc = dt.timezone.utc
    return {change: (first.astimezone(utc), last.astimezone(utc), n) for change, first, last, n in rows}
