"""opsdir command line: parses arguments, calls operations (opsdir.operations), presents their results.

  opsdir init                          DROP the opsdir schema and create it from nothing (all migrations)
  opsdir upgrade                       upgrade the schema in place (pending migrations), keeping data and history
  opsdir load FILE...                  load LDIF content under change BOOTSTRAP
  opsdir check [ENV...]                each environment's declared stack against the installed adapters
  opsdir search [-b base] [-s scope] FILTER [attr...]
  opsdir report NAME [DN]              portability, unowned, blast-radius DN, and every domain's reports (expiring, keys ENV, …)
  opsdir render ENV [-o dir]           e.g. prod environment of a cloud: CLOUD/ENV (default out/ here)
  opsdir plan FROM TO [-o dir]         migration plan + change-request drafts for external parties
  opsdir migrate FROM TO [-o dir]      check both stacks, plan, render the target; exit 1 unless ready
  opsdir modify --change CHG-… FILE    apply LDIF change records under an approved change
  opsdir capture --change CHG-… FILE [--name N] [--repo-path P] [--format F] [--role R] [--deploy-path D]
                                       hold a config file in the record (setting by setting; whole when it can't be
                                       parsed; only a reference when it may hold secrets, unless --accept-concerns)
  opsdir file NAME [--env ENV] [-o PATH]  rebuild a captured file from the record (links resolved for ENV)
  opsdir bundle --change CHG-… --kind K PATH [--root R] [--name N] [--version V] [--format F] [--role R]
                                       record code, scripts, templates or a package (a file or a directory under the
                                       repo checkout R) by repo path and SHA-256; its content is not stored
  opsdir verify [--root R]             bundles and captured files against a repo checkout (exit 1 if anything differs)
  opsdir import [--change CHG-…] ADAPTER[/IMPORTER] PATH [--dry-run]
                                       read a product's export (a directory or a file) into the record with an
                                       adapter's importer; without --change (or with --dry-run) only lists the changes
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
import re
import sys

from . import operations as ops
from .connectors import migration, workspace
from .connectors.registry import ADAPTER_VERSIONS, ADAPTERS
from .connectors.stack import STATUS_HEADERS
from .core import search as ldap_search
from .core.directory import values
from .core.interchange import ldif
from .core.interchange.export import export_text  # noqa: F401  (callers import it from here)
from .core.naming import SUFFIX
from .store import postgres as db

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
    ("capture", ((("--change",), {"required": True}), (("file",), {}), (("--name",), {}), (("--repo-path",), {}),
                 (("--format",), {}), (("--role",), {}), (("--deploy-path",), {}),
                 (("--accept-concerns",), {"action": "store_true",
                                           "help": "store a text flagged as possibly secret (after review)"}))),
    ("file", ((("name",), {}), (("--env",), {}), (("-o", "--out"), {}))),
    ("bundle", ((("--change",), {"required": True}), (("path",), {}), (("--root",), {}), (("--name",), {}),
                (("--kind",), {"required": True, "choices": ["code", "script", "template", "package", "dashboard",
                                                             "other"]}),
                (("--version",), {}), (("--format",), {}), (("--role",), {}), (("--deploy-path",), {}))),
    ("verify", ((("--root",), {}),)),
    ("import", ((("--change",), {}), (("importer",), {"help": "adapter[/importer]"}), (("path",), {}),
                (("--dry-run",), {"action": "store_true", "help": "list the change records; apply nothing"}))),
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


def entries_text(entries, attrs=()):
    """Entries as a table of the requested attributes, or as LDIF with an entry count when none are given."""
    if attrs:
        return format_table([[e.dn] + ["|".join(values(e, x)) for x in attrs] for e in entries], ["dn", *attrs])
    return "\n".join((*(ldif.write_entry(e.dn, e.classes, e.attrs) for e in entries), f"# {len(entries)} entries"))


def search_text(d, base, filt, scope="sub", attrs=()):
    """Search hits as a table of the requested attributes, or as LDIF with an entry count when none are given."""
    return entries_text(ldap_search.search(d, base, filt, scope), attrs)


def stack_text(result):
    """(text, exit status) of a stack check."""
    return f"{format_table(result.rows, result.headers)}\n{result.problems} problem(s)", (1 if result.problems else 0)


def check_text(d, specs):
    """(text, exit status): every environment's declared stack against the installed adapters."""
    return stack_text(ops.stack_check(d, specs))


def migrate_text(d, src, dst, as_of, out):
    """(text, files to write, exit status) of `opsdir migrate`."""
    r = migration.run(d, src, dst, as_of, ADAPTERS, ADAPTER_VERSIONS)
    return migrated_text(r, out), migration.output_files(r), (0 if r.ready else 1)


def migrated_text(r, out):
    return f"{format_table(r.stack_rows, STATUS_HEADERS)}\n{migration.summary(r, out)}"


def capture_name(path):
    """A captured file's default name: its file name, with anything but letters, digits, '.', '_' and '-' as '-'."""
    return re.sub(r"[^A-Za-z0-9._-]", "-", pathlib.Path(path).name)


# ------------------------------------------------------------------ commands: parse, call an operation, present
def _cmd_init(conn, a, as_of):
    r = ops.init(conn)
    return f"initialized: {r.attribute_types} attribute types, {r.object_classes} object classes"


def _cmd_upgrade(conn, a, as_of):
    r = ops.upgrade(conn)
    return "\n".join((*(f"applied migration {label}" for label in r.applied),
                      f"schema at migration {r.version:04d}{'' if r.applied else ' (up to date)'}: "
                      f"{r.attribute_types} attribute types, {r.object_classes} object classes"))


def _cmd_load(conn, a, as_of):
    r = ops.load(conn, db.read_ldif_files(a.files))
    return f"loaded {r.entries} entries from {len(a.files)} files; {r.references} DN references verified"


def _cmd_check(conn, a, as_of):
    return stack_text(ops.check(conn, a.envs))


def _cmd_search(conn, a, as_of):
    return entries_text(ops.search(conn, a.base, a.filter, a.scope), a.attrs)


def _cmd_report(conn, a, as_of):
    r = ops.report(conn, a.name, a.dn)
    return format_table(r.rows, r.headers)


def _cmd_render(conn, a, as_of):
    r = ops.render(conn, a.env)
    out = write_tree(a.out or pathlib.Path("out") / r.label.replace("/", "-"), r.files)
    return "\n".join((f"rendered {len(r.files)} files for {r.dn} ({r.provider}) → {out}",
                      *(f"  UNBOUND role: {role}" for role in r.unbound)))


def _cmd_plan(conn, a, as_of):
    r = ops.plan(conn, a.src, a.dst, as_of)
    label = f"plan-{r.plan.src.label.replace('/', '-')}-to-{r.plan.dst.label.replace('/', '-')}"
    out = pathlib.Path(a.out or pathlib.Path("out") / label)
    write_tree(out, {"PLAN.md": r.markdown, **r.drafts})
    return r.markdown + f"\n\n(written to {out}/PLAN.md and {len(r.plan.requests)} request drafts in {out}/requests/)"


def _cmd_migrate(conn, a, as_of):
    label = f"migration-{a.src.replace('/', '-')}-to-{a.dst.replace('/', '-')}"
    out = pathlib.Path(a.out or pathlib.Path("out") / label)
    r = ops.migrate(conn, a.src, a.dst, as_of)
    write_tree(out, r.files)
    return migrated_text(r.run, out), (0 if r.run.ready else 1)


def _applied_text(r):
    return "\n".join(f"{r.change_id}: {line}" for line in r.lines)


def _cmd_modify(conn, a, as_of):
    return _applied_text(ops.modify(conn, db.read_ldif_files([a.file]), a.change))


def _cmd_capture(conn, a, as_of):
    preview = ops.preview_capture(conn, pathlib.Path(a.file).read_text(), a.name or capture_name(a.file),
                                  a.repo_path or a.file, a.format, a.role, a.deploy_path, a.accept_concerns)
    r = ops.apply_preview(conn, preview, a.change)
    return "\n".join((*preview.notices, f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else "no changes"))


def read_content(path):
    """Effect: a bundle's content, {relative path: bytes} ({"": bytes} for a single file), or None when absent."""
    p = pathlib.Path(path)
    if p.is_file():
        return {"": p.read_bytes()}
    if p.is_dir():
        return {f.relative_to(p).as_posix(): f.read_bytes() for f in sorted(p.rglob("*")) if f.is_file()}
    return None


def _cmd_bundle(conn, a, as_of):
    root = pathlib.Path(a.root or ".")
    content = read_content(root / a.path)
    if content is None:
        raise SystemExit(f"nothing at {root / a.path}")
    preview = ops.preview_bundle(conn, a.name or capture_name(a.path), a.path, a.kind, content, a.format, a.version,
                                 a.role, a.deploy_path)
    r = ops.apply_preview(conn, preview, a.change)
    return "\n".join((*preview.notices, f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else "no changes"))


def read_texts(path):
    """Effect: an export's files as text, {relative path: text} ({name: text} for a single file); files that aren't
    UTF-8 text are left out and named."""
    p = pathlib.Path(path)
    files = ({p.name: p} if p.is_file() else
             {f.relative_to(p).as_posix(): f for f in sorted(p.rglob("*")) if f.is_file()} if p.is_dir() else None)
    if files is None:
        raise SystemExit(f"nothing at {p}")
    read = {rel: _text(f) for rel, f in files.items()}
    return {rel: t for rel, t in read.items() if t is not None}, tuple(rel for rel, t in read.items() if t is None)


def _text(f):
    try:
        return f.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def _cmd_import(conn, a, as_of):
    files, skipped = read_texts(a.path)
    preview = ops.preview_import(conn, a.importer, files)
    notes = (*(f"skipped (not UTF-8 text): {rel}" for rel in skipped), *preview.notices)
    if a.dry_run or not a.change:
        listed = (f"{r.changetype} {r.dn}" for r in preview.changes)
        return "\n".join((*notes, *listed, f"{len(preview.changes)} change(s) (not applied"
                          f"{'' if a.dry_run else '; give --change to apply'})"))
    r = ops.apply_preview(conn, preview, a.change)
    return "\n".join((*notes, f"{a.change}: {len(r.lines)} change(s) applied" if r.lines else "no changes"))


def _cmd_verify(conn, a, as_of):
    root = pathlib.Path(a.root or ".")
    r = ops.verify(conn, {path: read_content(root / path) for path in ops.verify_paths(conn)})
    fine = ("unchanged", "same as the record")
    problems = sum(row[3] not in fine or bool(row[4]) for row in r.rows)
    return f"{format_table(r.rows, r.headers)}\n{problems} to look at", (1 if problems else 0)


def _cmd_file(conn, a, as_of):
    r = ops.rebuild_file(conn, a.name, a.env)
    if not a.out:
        return r.text.rstrip("\n") if r.text.endswith("\n") else r.text
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(r.text)
    return f"rebuilt {a.name} ({r.repo_path}) → {out}"


def _cmd_export(conn, a, as_of):
    return ops.export(conn, a.base)


def _cmd_history(conn, a, as_of):
    r = ops.history(conn, a.dn)
    return format_table(r.rows, r.headers)


def _cmd_workspace(conn, a, as_of):
    if a.workspace:
        raise SystemExit("workspace commands run against the live record (OPSDIR_DSN); drop --workspace")
    ws, source = db.connect(workspace.workspace_dsn()), os.environ["OPSDIR_DSN"]
    if a.action == "create":
        n = ops.workspace_create(conn, ws, source, a.replace)
        return f"workspace created: {n} entries copied from {workspace.safe_source(source)}"
    if a.action == "status":
        return workspace.status_text(*ops.workspace_state(conn, ws))
    if a.action == "diff":
        return ldif.write_records(ops.workspace_state(conn, ws).changes) or "# no changes"
    if not a.change:
        raise SystemExit("usage: opsdir workspace cutover --change CHG-… (an approved change in the live record)")
    r = ops.workspace_cutover(conn, ws, source, a.change)
    return "\n".join((*(f"{a.change}: {line}" for line in r.lines),
                      f"cutover: {len(r.lines)} change(s) applied to the live record; workspace re-copied"))


COMMANDS = {"init": _cmd_init, "upgrade": _cmd_upgrade, "load": _cmd_load, "check": _cmd_check, "search": _cmd_search, "report": _cmd_report,
            "render": _cmd_render, "plan": _cmd_plan, "migrate": _cmd_migrate, "modify": _cmd_modify, "export": _cmd_export,
            "history": _cmd_history, "capture": _cmd_capture, "import": _cmd_import, "file": _cmd_file, "bundle": _cmd_bundle,
            "verify": _cmd_verify,
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
