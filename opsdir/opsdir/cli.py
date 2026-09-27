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

from .connectors import plan as planmod, reports
from .connectors.registry import ref_schemes, sql_files
from .connectors.render import render_env
from .core import search as ldap_search
from .core.directory import subtree, values
from .core.interchange import ldif
from .core.naming import SUFFIX
from .core.paths import ROOT
from .store import postgres as db
from .store.queries import fetch_history

# subcommand → ((argument flags, argparse options), …)
SUBCOMMANDS = (
    ("init", ()),
    ("load", ((("files",), {"nargs": "*"}),)),
    ("search", ((("-b", "--base"), {"default": SUFFIX}),
                (("-s", "--scope"), {"default": "sub", "choices": ["base", "one", "sub"]}),
                (("filter",), {}), (("attrs",), {"nargs": "*"}))),
    ("report", ((("name",), {}), (("dn",), {"nargs": "?"}))),
    ("render", ((("env",), {}), (("-o", "--out"), {}))),
    ("plan", ((("src",), {}), (("dst",), {}), (("-o", "--out"), {}))),
    ("modify", ((("--change",), {"required": True}), (("file",), {}))),
    ("export", ((("-b", "--base"), {"default": SUFFIX}),)),
    ("history", ((("dn",), {"nargs": "?"}),)),
)


def format_table(rows, headers):
    """Rows as aligned text columns (each capped at 70 characters) with a row count."""
    cells = [[("" if v is None else str(v)) for v in r] for r in rows]
    widths = [min(max([len(h)] + [len(r[i]) for r in cells]), 70) for i, h in enumerate(headers)]
    fmt = lambda r: "  ".join(c[:70].ljust(widths[i]) for i, c in enumerate(r))  # noqa: E731
    return "\n".join((fmt(headers), "  ".join("-" * w for w in widths), *(fmt(r) for r in cells),
                      f"({len(cells)} rows)"))


def write_tree(outdir, files):
    """Effect: write {relative path: content} under outdir; shell scripts are made executable."""
    outdir = pathlib.Path(outdir)
    for p, content in files.items():
        f = outdir / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
        if p.endswith(".sh"):
            f.chmod(0o755)
    return outdir


# ------------------------------------------------------------------ commands: each returns the text to print
def _cmd_init(conn, a, as_of):
    db.init(conn, sql_files(), ref_schemes())
    n = db.registry_counts(conn)
    return f"initialized: {n[0]} attribute types, {n[1]} object classes"


def _cmd_load(conn, a, as_of):
    files = a.files or sorted(str(p) for p in (ROOT / "data").glob("*.ldif"))
    n = db.load_ldif(conn, files)
    return f"loaded {n} entries from {len(files)} files; {db.reference_count(conn)} DN references verified"


def _cmd_search(conn, a, as_of):
    hits = ldap_search.search(db.load_directory(conn), a.base, a.filter, a.scope)
    if a.attrs:
        return format_table([[e.dn] + ["|".join(values(e, x)) for x in a.attrs] for e in hits], ["dn"] + a.attrs)
    return "\n".join((*(ldif.write_entry(e.dn, e.classes, e.attrs) for e in hits), f"# {len(hits)} entries"))


def _cmd_report(conn, a, as_of):
    return format_table(*reports.report_rows(conn, a.name, a.dn))


def _cmd_render(conn, a, as_of):
    m, files = render_env(db.load_directory(conn), a.env)
    out = write_tree(a.out or ROOT / "out" / m.label.replace("/", "-"), files)
    return "\n".join((f"rendered {len(files)} files for {m.dn} ({m.provider}) → {out}",
                      *(f"  UNBOUND role: {r}" for r in m.unbound)))


def _cmd_plan(conn, a, as_of):
    p = planmod.plan(db.load_directory(conn), a.src, a.dst, as_of)
    md = planmod.to_markdown(p)
    label = f"plan-{p.src.label.replace('/', '-')}-to-{p.dst.label.replace('/', '-')}"
    out = pathlib.Path(a.out or ROOT / "out" / label)
    write_tree(out, {"PLAN.md": md, **planmod.request_drafts(p)})
    return md + f"\n\n(written to {out}/PLAN.md and {len(p.requests)} request drafts in {out}/requests/)"


def _cmd_modify(conn, a, as_of):
    return "\n".join(f"{a.change}: {line}" for line in db.apply_changes(conn, a.file, a.change))


def _cmd_export(conn, a, as_of):
    entries = sorted(subtree(db.load_directory(conn), a.base), key=lambda e: (e.norm.count(","), e.norm))
    return "\n".join(ldif.write_entry(e.dn, e.classes, e.attrs) for e in entries)


def _cmd_history(conn, a, as_of):
    return format_table(fetch_history(conn, a.dn), reports.HISTORY_HEADERS)


COMMANDS = {"init": _cmd_init, "load": _cmd_load, "search": _cmd_search, "report": _cmd_report,
            "render": _cmd_render, "plan": _cmd_plan, "modify": _cmd_modify, "export": _cmd_export,
            "history": _cmd_history}


def parser():
    ap = argparse.ArgumentParser(prog="opsdir", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as-of", help="evaluate dates as of YYYY-MM-DD (default: today)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, arguments in SUBCOMMANDS:
        command = sub.add_parser(name)
        for flags, options in arguments:
            command.add_argument(*flags, **options)
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    as_of = dt.date.fromisoformat(a.as_of) if a.as_of else dt.date.today()
    conn = db.connect()
    db.set_as_of(conn, as_of)
    text = COMMANDS[a.cmd](conn, a, as_of)
    if text:
        print(text)


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
