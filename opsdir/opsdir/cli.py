"""opsdir command line.

  opsdir init                          DROP the opsdir schema and create it from nothing (all migrations)
  opsdir upgrade                       upgrade the schema in place (pending migrations), keeping data and history
  opsdir load FILE...                  load LDIF content under change BOOTSTRAP
  opsdir check [ENV...]                each environment's declared stack against the installed adapters
  opsdir search [-b base] [-s scope] FILTER [attr...]
  opsdir report expiring|pii|stale|unowned|drift|portability|blast-radius DN
  opsdir render ENV [-o dir]           e.g. prod environment of a cloud: CLOUD/ENV (default out/ here)
  opsdir plan FROM TO [-o dir]         migration plan + change-request drafts for external parties
  opsdir migrate FROM TO [-o dir]      check both stacks, plan, render the target; exit 1 unless ready
  opsdir modify --change CHG-… FILE    apply LDIF change records under an approved change
  opsdir export [-b base]              dump entries as LDIF (for Git review)
  opsdir history [DN]                  change history
  opsdir workspace create [--replace]  copy the live record (OPSDIR_DSN) into the migration workspace
  opsdir workspace status|diff         what the workspace changed since its copy (diff: as LDIF change records)
  opsdir workspace cutover --change CHG-…   apply the workspace's changes to the live record, then re-copy
  opsdir --workspace COMMAND …         run any command against the workspace (OPSDIR_WORKSPACE_DSN)
"""
import argparse
import datetime as dt
import os
import pathlib
import sys

from .connectors import migration, plan as planmod, reports, workspace
from .connectors.registry import ADAPTER_VERSIONS, ADAPTERS, environment_specs, store_parts
from .connectors.stack import STATUS_HEADERS, stack_rows
from .core.environment import env_model
from .connectors.render import render_env
from .core import search as ldap_search
from .core.directory import subtree, values
from .core.interchange import ldif
from .core.interchange.export import export_text
from .core.naming import SUFFIX
from .store import migrations, postgres as db
from .store.queries import fetch_history

# subcommand → ((argument flags, argparse options), …)
SUBCOMMANDS = (
    ("init", ()),
    ("upgrade", ()),
    ("load", ((("files",), {"nargs": "+"}),)),
    ("check", ((("envs",), {"nargs": "*"}),)),
    ("search", ((("-b", "--base"), {"default": SUFFIX}),
                (("-s", "--scope"), {"default": "sub", "choices": ["base", "one", "sub"]}),
                (("filter",), {}), (("attrs",), {"nargs": "*"}))),
    ("report", ((("name",), {}), (("dn",), {"nargs": "?"}))),
    ("render", ((("env",), {}), (("-o", "--out"), {}))),
    ("plan", ((("src",), {}), (("dst",), {}), (("-o", "--out"), {}))),
    ("migrate", ((("src",), {}), (("dst",), {}), (("-o", "--out"), {}))),
    ("modify", ((("--change",), {"required": True}), (("file",), {}))),
    ("export", ((("-b", "--base"), {"default": SUFFIX}),)),
    ("history", ((("dn",), {"nargs": "?"}),)),
    ("workspace", ((("action",), {"choices": ["create", "status", "diff", "cutover"]}),
                   (("--change",), {}), (("--replace",), {"action": "store_true"}))),
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


def search_text(d, base, filt, scope="sub", attrs=()):
    """Search hits as a table of the requested attributes, or as LDIF with an entry count when none are given."""
    hits = ldap_search.search(d, base, filt, scope)
    if attrs:
        return format_table([[e.dn] + ["|".join(values(e, x)) for x in attrs] for e in hits], ["dn", *attrs])
    return "\n".join((*(ldif.write_entry(e.dn, e.classes, e.attrs) for e in hits), f"# {len(hits)} entries"))


# ------------------------------------------------------------------ commands: each returns the text to print
def _cmd_init(conn, a, as_of):
    migrations.init(conn, *store_parts())
    n = db.registry_counts(conn)
    return f"initialized: {n[0]} attribute types, {n[1]} object classes"


def _cmd_upgrade(conn, a, as_of):
    applied = migrations.upgrade(conn, *store_parts())
    n = db.registry_counts(conn)
    return "\n".join((*(f"applied migration {migrations.label(m)}" for m in applied),
                      f"schema at migration {migrations.current_version(conn):04d}"
                      f"{'' if applied else ' (up to date)'}: {n[0]} attribute types, {n[1]} object classes"))


def _cmd_load(conn, a, as_of):
    files = a.files
    n = db.load_ldif(conn, files)
    return f"loaded {n} entries from {len(files)} files; {db.reference_count(conn)} DN references verified"


def check_text(d, specs):
    """(text, exit status): every environment's declared stack against the installed adapters."""
    results = [stack_rows(env_model(d, spec), ADAPTERS, ADAPTER_VERSIONS) for spec in specs]
    problems = sum(n for _, n in results)
    table = format_table([row for rows, _ in results for row in rows], STATUS_HEADERS)
    return f"{table}\n{problems} problem(s)", (1 if problems else 0)


def _cmd_check(conn, a, as_of):
    d = db.load_directory(conn)
    return check_text(d, a.envs or environment_specs(d))


def _cmd_search(conn, a, as_of):
    return search_text(db.load_directory(conn), a.base, a.filter, a.scope, a.attrs)


def _cmd_report(conn, a, as_of):
    return format_table(*reports.report_rows(conn, a.name, a.dn))


def _cmd_render(conn, a, as_of):
    m, files = render_env(db.load_directory(conn), a.env)
    out = write_tree(a.out or pathlib.Path("out") / m.label.replace("/", "-"), files)
    return "\n".join((f"rendered {len(files)} files for {m.dn} ({m.provider}) → {out}",
                      *(f"  UNBOUND role: {r}" for r in m.unbound)))


def _cmd_plan(conn, a, as_of):
    p = planmod.plan(db.load_directory(conn), a.src, a.dst, as_of)
    md = planmod.to_markdown(p)
    label = f"plan-{p.src.label.replace('/', '-')}-to-{p.dst.label.replace('/', '-')}"
    out = pathlib.Path(a.out or pathlib.Path("out") / label)
    write_tree(out, {"PLAN.md": md, **planmod.request_drafts(p)})
    return md + f"\n\n(written to {out}/PLAN.md and {len(p.requests)} request drafts in {out}/requests/)"


def migrate_text(d, src, dst, as_of, out):
    """(text, files to write, exit status) of `opsdir migrate`."""
    r = migration.run(d, src, dst, as_of, ADAPTERS, ADAPTER_VERSIONS)
    text = f"{format_table(r.stack_rows, STATUS_HEADERS)}\n{migration.summary(r, out)}"
    return text, migration.output_files(r), (0 if r.ready else 1)


def _cmd_migrate(conn, a, as_of):
    label = f"migration-{a.src.replace('/', '-')}-to-{a.dst.replace('/', '-')}"
    out = pathlib.Path(a.out or pathlib.Path("out") / label)
    text, files, status = migrate_text(db.load_directory(conn), a.src, a.dst, as_of, out)
    write_tree(out, files)
    return text, status


def _cmd_modify(conn, a, as_of):
    return "\n".join(f"{a.change}: {line}" for line in db.apply_changes(conn, a.file, a.change))


def _cmd_export(conn, a, as_of):
    return export_text(db.load_directory(conn), a.base)


def _cmd_history(conn, a, as_of):
    return format_table(fetch_history(conn, a.dn), reports.HISTORY_HEADERS)


def _cmd_workspace(conn, a, as_of):
    if a.workspace:
        raise SystemExit("workspace commands run against the live record (OPSDIR_DSN); drop --workspace")
    ws_dsn = workspace.workspace_dsn()
    ws, source = db.connect(ws_dsn), os.environ["OPSDIR_DSN"]
    if a.action == "create":
        n = workspace.create(conn, ws, store_parts(), source, a.replace)
        return f"workspace created: {n} entries copied from {workspace.safe_source(source)}"
    if a.action == "status":
        return workspace.status(conn, ws)
    if a.action == "diff":
        return workspace.diff_text(conn, ws) or "# no changes"
    if not a.change:
        raise SystemExit("usage: opsdir workspace cutover --change CHG-… (an approved change in the live record)")
    applied = workspace.cutover(conn, ws, store_parts(), source, a.change)
    return "\n".join((*(f"{a.change}: {line}" for line in applied),
                      f"cutover: {len(applied)} change(s) applied to the live record; workspace re-copied"))


COMMANDS = {"init": _cmd_init, "upgrade": _cmd_upgrade, "load": _cmd_load, "check": _cmd_check, "search": _cmd_search, "report": _cmd_report,
            "render": _cmd_render, "plan": _cmd_plan, "migrate": _cmd_migrate, "modify": _cmd_modify, "export": _cmd_export,
            "history": _cmd_history,
            "workspace": _cmd_workspace}


def parser():
    ap = argparse.ArgumentParser(prog="opsdir", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as-of", help="evaluate dates as of YYYY-MM-DD (default: today)")
    ap.add_argument("--workspace", action="store_true",
                    help="run against the migration workspace (OPSDIR_WORKSPACE_DSN) instead of the live record")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, arguments in SUBCOMMANDS:
        command = sub.add_parser(name)
        for flags, options in arguments:
            command.add_argument(*flags, **options)
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    as_of = dt.date.fromisoformat(a.as_of) if a.as_of else dt.date.today()
    conn = db.connect(workspace.workspace_dsn() if a.workspace else None)
    db.set_as_of(conn, as_of)
    result = COMMANDS[a.cmd](conn, a, as_of)          # text, or (text, exit status)
    text, status = result if isinstance(result, tuple) else (result, 0)
    if text:
        print(text)
    if status:
        sys.exit(status)


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
