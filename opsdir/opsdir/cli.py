"""opsdir command line.

  opsdir init                          create the database schema and load the LDAP schema
  opsdir load [files...]               load LDIF content (default: data/*.ldif) under change BOOTSTRAP
  opsdir search [-b base] [-s scope] FILTER [attr...]
  opsdir report expiring|pii|stale|unowned|drift|portability|blast-radius DN
  opsdir render ENV [-o dir]           e.g. aws-current/prod, rtx-next/prod
  opsdir plan FROM TO [-o dir]         migration plan + change-request drafts for external parties
  opsdir modify --change CHG-… FILE    apply LDIF change records under an approved change
  opsdir export [-b base]              dump entries as LDIF (for Git review)
  opsdir history [DN]                  change history
"""
import argparse
import datetime as dt
import pathlib
import sys

from . import db, ldif, plan as planmod, reports
from .render import render_env

ROOT = db.ROOT


def table(rows, headers):
    rows = [[("" if v is None else str(v)) for v in r] for r in rows]
    w = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]
    w = [min(x, 70) for x in w]
    fmt = lambda r: "  ".join(c[:70].ljust(w[i]) for i, c in enumerate(r))  # noqa: E731
    print(fmt(headers))
    print("  ".join("-" * x for x in w))
    for r in rows:
        print(fmt(r))
    print(f"({len(rows)} rows)")


def write_tree(outdir, files):
    outdir = pathlib.Path(outdir)
    for p, content in files.items():
        f = outdir / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
        if p.endswith(".sh"):
            f.chmod(0o755)
    return outdir


def main(argv=None):
    ap = argparse.ArgumentParser(prog="opsdir", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as-of", help="evaluate dates as of YYYY-MM-DD (default: today)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    p = sub.add_parser("load"); p.add_argument("files", nargs="*")
    p = sub.add_parser("search"); p.add_argument("-b", "--base", default=db.SUFFIX)
    p.add_argument("-s", "--scope", default="sub", choices=["base", "one", "sub"])
    p.add_argument("filter"); p.add_argument("attrs", nargs="*")
    p = sub.add_parser("report"); p.add_argument("name"); p.add_argument("dn", nargs="?")
    p = sub.add_parser("render"); p.add_argument("env"); p.add_argument("-o", "--out")
    p = sub.add_parser("plan"); p.add_argument("src"); p.add_argument("dst"); p.add_argument("-o", "--out")
    p = sub.add_parser("modify"); p.add_argument("--change", required=True); p.add_argument("file")
    p = sub.add_parser("export"); p.add_argument("-b", "--base", default=db.SUFFIX)
    p = sub.add_parser("history"); p.add_argument("dn", nargs="?")
    a = ap.parse_args(argv)

    as_of = dt.date.fromisoformat(a.as_of) if a.as_of else dt.date.today()
    conn = db.connect()
    conn.execute("select set_config('opsdir.as_of', %s, false)", (as_of.isoformat(),))

    if a.cmd == "init":
        db.init(conn)
        n = conn.execute("select (select count(*) from attribute_type), (select count(*) from object_class)").fetchone()
        print(f"initialized: {n[0]} attribute types, {n[1]} object classes")
    elif a.cmd == "load":
        files = a.files or sorted(str(p) for p in (ROOT / "data").glob("*.ldif"))
        n = db.load_ldif(conn, files)
        refs = conn.execute("select count(*) from entry_ref").fetchone()[0]
        print(f"loaded {n} entries from {len(files)} files; {refs} DN references verified")
    elif a.cmd == "search":
        d = db.Directory(conn)
        hits = d.search(a.base, a.filter, a.scope)
        if a.attrs:
            table([[e.dn] + ["|".join(e.all(x)) for x in a.attrs] for e in hits], ["dn"] + a.attrs)
        else:
            for e in hits:
                print(ldif.write_entry(e.dn, e.classes, e.attrs))
            print(f"# {len(hits)} entries")
    elif a.cmd == "report":
        report(conn, a.name, a.dn)
    elif a.cmd == "render":
        d = db.Directory(conn)
        m, files = render_env(d, a.env)
        out = write_tree(a.out or ROOT / "out" / m.label.replace("/", "-"), files)
        print(f"rendered {len(files)} files for {m.dn} ({m.provider}) → {out}")
        for r in m.unbound:
            print(f"  UNBOUND role: {r}")
    elif a.cmd == "plan":
        d = db.Directory(conn)
        p = planmod.plan(d, a.src, a.dst, as_of)
        md = planmod.to_markdown(p)
        out = pathlib.Path(a.out or ROOT / "out" / f"plan-{p['src'].label.replace('/', '-')}-to-{p['dst'].label.replace('/', '-')}")
        write_tree(out, {"PLAN.md": md, **planmod.request_drafts(p)})
        print(md)
        print(f"\n(written to {out}/PLAN.md and {len(p['requests'])} request drafts in {out}/requests/)")
    elif a.cmd == "modify":
        for line in db.apply_changes(conn, a.file, a.change):
            print(f"{a.change}: {line}")
    elif a.cmd == "export":
        d = db.Directory(conn)
        for e in sorted(d.subtree(a.base), key=lambda e: (e.norm.count(","), e.norm)):
            print(ldif.write_entry(e.dn, e.classes, e.attrs))
    elif a.cmd == "history":
        q = "select at::timestamp(0), change_id, op, dn from entry_history where change_id <> 'BOOTSTRAP'"
        args = ()
        if a.dn:
            q += " and lower(dn) = lower(%s)"
            args = (a.dn,)
        table(conn.execute(q + " order by id", args).fetchall(), ["at", "change", "op", "dn"])


def report(conn, name, dn):
    if name == "expiring":
        table(conn.execute("select cert, purpose, not_after, days_left, array_to_string(names, ','),"
                           " (select string_agg(split_part(split_part(u, ',', 1), '=', 2), ',') from unnest(used_by) u)"
                           " from v_certificates order by not_after").fetchall(),
              ["certificate", "purpose", "not_after", "days_left", "names", "used_by"])
    elif name == "pii":
        table(conn.execute("select attribute, pii_class, export_controlled, consumer, owner, aci, justification"
                           " from v_pii_exposure order by pii_class, attribute, consumer").fetchall(),
              ["attribute", "pii", "export", "consumer", "owner", "aci", "justification"])
    elif name == "stale":
        table(conn.execute("select runbook, title, last_validated, changed_on, changed_dependency"
                           " from v_stale_runbooks").fetchall(),
              ["runbook", "title", "validated", "dep_changed", "dependency"])
    elif name == "unowned":
        table(conn.execute("select dn, kind, problem from v_unowned order by 1").fetchall(), ["dn", "kind", "problem"])
    elif name == "portability":
        table(conn.execute("select * from v_portability").fetchall(), ["portability", "values"])
    elif name == "drift":
        table(reports.drift(db.Directory(conn)), ["server", "finding", "entry (relative to declared config)", "detail"])
    elif name == "blast-radius":
        if not dn:
            sys.exit("usage: opsdir report blast-radius DN")
        rows = conn.execute("select depth, dn, via_attr from dependents(%s)", (dn,)).fetchall()
        owners = dict(conn.execute("select dn, string_agg(split_part(split_part(owner, ',', 1), '=', 2), ',')"
                                   " from owners_of(%s) group by dn", ([r[1] for r in rows],)).fetchall())
        table([(r[0], r[1], r[2], owners.get(r[1], "")) for r in rows], ["depth", "dependent", "via", "owner"])
    else:
        sys.exit(f"unknown report {name}")


def run():
    import psycopg
    try:
        main()
    except psycopg.Error as e:
        msg = (e.diag.message_primary or str(e)).strip()
        detail = f" ({e.diag.message_detail})" if e.diag.message_detail else ""
        sys.exit(f"REJECTED by the directory: {msg}{detail}")


if __name__ == "__main__":
    run()
