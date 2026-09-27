"""Read queries over the store's SQL views and functions (effects: they run SQL)."""


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
    """Governed changes after the bootstrap load, optionally for one DN."""
    where = " and lower(dn) = lower(%s)" if dn else ""
    return fetch_rows(conn, "select at::timestamp(0), change_id, op, dn from entry_history"
                            f" where change_id <> 'BOOTSTRAP'{where} order by id", (dn,) if dn else ())
