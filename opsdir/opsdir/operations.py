"""Operations: everything opsdir does, as functions over the store that return structured results.

The one API every front end calls: the command line now, an MCP server for AI control later (SPEC 7.4). An operation
takes a connection and plain arguments (parsed records, text, names; never paths) and returns records or rows,
never text for a terminal; reading and writing files on disk and presenting results stay in the front ends. Every
write is previewable: its change records are computed first (preview_*), and applied only under a change id the store
accepts (an approved change record). Effects are the store's; everything else is the connectors' and domains'.
"""
from typing import NamedTuple

from .connectors import capture as capturemod, importing, migration, plan as planmod, profiling, reports, workspace
from .connectors import fixes as fixmod
from .connectors.registry import ADAPTER_VERSIONS, ADAPTERS, environment_specs, schema_sync, store_parts
from .connectors.render import render_env
from .connectors.stack import STATUS_HEADERS, stack_rows
from .core import search as ldap_search
from .core.environment import env_model
from .core.interchange.export import export_text
from .store import migrations, postgres as db
from .store.queries import fetch_history

Initialized = NamedTuple("Initialized", [("attribute_types", int), ("object_classes", int)])
Upgraded = NamedTuple("Upgraded", [("applied", tuple), ("version", int), ("attribute_types", int),
                                   ("object_classes", int)])                 # applied: migration labels
Loaded = NamedTuple("Loaded", [("entries", int), ("references", int)])
StackCheck = NamedTuple("StackCheck", [("headers", tuple), ("rows", tuple), ("problems", int)])
Rows = NamedTuple("Rows", [("headers", tuple), ("rows", tuple)])
Rendered = NamedTuple("Rendered", [("label", str), ("dn", str), ("provider", str), ("files", dict),
                                   ("unbound", tuple)])                      # files: {relative path: text}
Planned = NamedTuple("Planned", [("plan", object), ("markdown", str), ("drafts", dict)])
Migrated = NamedTuple("Migrated", [("run", object), ("files", dict)])       # run: connectors.migration.MigrationRun
Applied = NamedTuple("Applied", [("change_id", str), ("lines", tuple)])      # one line per applied change record
Preview = NamedTuple("Preview", [("name", str), ("changes", tuple), ("notices", tuple)])  # a write, not applied
Rebuilt = NamedTuple("Rebuilt", [("name", str), ("repo_path", str), ("text", str)])
WorkspaceState = NamedTuple("WorkspaceState", [("base", object), ("changes", tuple), ("live_changed", bool)])


# ------------------------------------------------------------------ the store
def init(conn):
    """Effect: DROP the opsdir schema and create it from nothing (all migrations)."""
    migrations.init(conn, *store_parts())
    return Initialized(*db.registry_counts(conn))


def upgrade(conn):
    """Effect: apply pending migrations, keeping data and history."""
    applied = migrations.upgrade(conn, *store_parts())
    return Upgraded(tuple(migrations.label(m) for m in applied), migrations.current_version(conn),
                    *db.registry_counts(conn))


def load(conn, records, change_id="BOOTSTRAP"):
    """Effect: load content records in one transaction under a change id."""
    n = db.load_records(conn, tuple(records), change_id, schema_sync())
    return Loaded(n, db.reference_count(conn))


def modify(conn, records, change_id):
    """Effect: apply change records atomically under an approved change."""
    return Applied(change_id, tuple(db.apply_records(conn, tuple(records), change_id, schema_sync())))


# ------------------------------------------------------------------ reading the record
def stack_check(d, specs=()):
    """Every environment's declared stack against the installed adapters (all environments when none are named)."""
    results = [stack_rows(env_model(d, spec), ADAPTERS, ADAPTER_VERSIONS) for spec in specs or environment_specs(d)]
    return StackCheck(STATUS_HEADERS, tuple(row for rows, _ in results for row in rows), sum(n for _, n in results))


def check(conn, specs=()):
    """Effect (reads the record): stack_check over the store."""
    return stack_check(db.load_directory(conn), specs)


def search(conn, base, filt, scope="sub"):
    """Effect (reads the record): the entries an LDAP filter matches."""
    return tuple(ldap_search.search(db.load_directory(conn), base, filt, scope))


def report(conn, name, dn=None, as_of=None):
    """Effect (reads the record): a named report's rows, dates evaluated as of as_of (today when not given)."""
    rows, headers = reports.report_rows(conn, name, dn, as_of)
    return Rows(tuple(headers), tuple(rows))


def history(conn, dn=None):
    """Effect (reads the record): the change history, of one entry or of all."""
    return Rows(tuple(reports.HISTORY_HEADERS), tuple(fetch_history(conn, dn)))


def export(conn, base):
    """Effect (reads the record): entries under base as LDIF, for review."""
    return export_text(db.load_directory(conn), base)


# ------------------------------------------------------------------ rendering and moving
def render(conn, spec):
    """Effect (reads the record): an environment's rendered files."""
    m, files = render_env(db.load_directory(conn), spec)
    return Rendered(m.label, m.dn, m.provider, files, tuple(m.unbound))


def plan(conn, src, dst, as_of):
    """Effect (reads the record): the plan for moving src to dst, as markdown and external-party request drafts."""
    p = planmod.plan(db.load_directory(conn), src, dst, as_of)
    return Planned(p, planmod.to_markdown(p), planmod.request_drafts(p))


def migrate(conn, src, dst, as_of):
    """Effect (reads the record): check both stacks, plan and render the target."""
    r = migration.run(db.load_directory(conn), src, dst, as_of, ADAPTERS, ADAPTER_VERSIONS)
    return Migrated(r, migration.output_files(r))


# ------------------------------------------------------------------ assisted fixes
def fixes(conn, src, dst, as_of):
    """Effect (reads the record): the record changes the plan's findings offer (core.findings.Fix), each with its
    change records, the steps outside the record and what it could hide. Against the workspace connection they are the
    workspace's (reaching the live record at cutover)."""
    return planmod.plan(db.load_directory(conn), src, dst, as_of).fixes


def propose_fix(conn, src, dst, as_of, key, change_id, title=None, option=None, inputs=None):
    """Effect: record a fix (its option chosen, when it offers a choice, and its inputs given, {key: values}) as change
    change_id with status proposed, holding the records it applies, for a person to approve (what an AI may do).
    Nothing else is written; ValueError when the store would refuse the records (a value of the wrong type, two
    values for a SINGLE-VALUE attribute, an attribute the entry's classes don't allow): a proposal applies as held."""
    fix = fixmod.chosen(fixmod.find_fix(fixes(conn, src, dst, as_of), key), option, inputs)
    problems = db.record_problems(conn, fix.records)
    if problems:
        raise ValueError(f"fix {key}: the store would refuse its records: " + "; ".join(problems))
    return modify(conn, (fixmod.proposal(fix, change_id, title),), change_id)


def apply_fix(conn, src, dst, as_of, key, change_id, option=None, inputs=None):
    """Effect: apply a fix's records (its option chosen, when it offers a choice, and its inputs given, {key: values})
    under an approved change."""
    fix = fixmod.chosen(fixmod.find_fix(fixes(conn, src, dst, as_of), key), option, inputs)
    return modify(conn, fix.records, change_id)


def apply_proposed(conn, change_id):
    """Effect: apply the records a proposed change holds once a person approved it, and mark it applied."""
    records, applied = fixmod.proposed_records(db.load_directory(conn), change_id)
    return modify(conn, (*records, applied), change_id)


# ------------------------------------------------------------------ config files
def preview_capture(conn, text, name, repo_path, format_name=None, role=None, deploy_path=None,
                    accept_concerns=False):
    """Effect (reads the record): the change records capturing a config file would apply, and the notices (level,
    withheld values). format_name defaults to the format the repo path's extension says."""
    fmt = capturemod.capture_format(repo_path, format_name)
    changes, notices = capturemod.capture_changes(db.load_directory(conn), fmt, text, name, repo_path, role,
                                                  deploy_path, accept_concerns)
    return Preview(name, tuple(changes), tuple(notices))


def preview_bundle(conn, name, repo_path, kind, content, format_name=None, version=None, role=None,
                   deploy_path=None):
    """Effect (reads the record): the change records recording a bundle would apply. content: its files'
    bytes, {relative path: bytes} ({"": bytes} for one file); digested, never stored."""
    changes, notices = capturemod.bundle_changes(db.load_directory(conn), name, repo_path, kind, content, format_name,
                                                 version, role, deploy_path)
    return Preview(name, tuple(changes), tuple(notices))


def preview_census(conn, files, replace=False):
    """Effect (reads the record): the change records recording where the record's values occur in files ({relative
    path: text}), and notices (how many found, which files may hold secret material, which recorded files a replacing
    scan removes)."""
    changes, notices = capturemod.census_changes(db.load_directory(conn), files, replace=replace)
    return Preview("census", tuple(changes), tuple(notices))


def data_profile(lines, label, as_of, captured, definitions=()):
    """The profile file (JSON text) of environment 'cloud/env's directory data, an LDIF line stream read once: counts
    only, nothing the lines hold is kept. definitions: the estate's own terms (NAME=ATTRIBUTE[=VALUE]; ValueError
    names those that aren't). Needs no connection: it runs wherever the directory can be read; the file is recorded
    with preview_import('ldap/data-profile', ...)."""
    return profiling.profile_file(lines, label, as_of, captured, definitions)


def preview_import(conn, spec, files, at=None):
    """Effect (reads the record): the change records importing a product's export would apply, and the importer's
    notices (what it withheld, what it couldn't place). spec: 'adapter[/importer]'; files: {relative path: text};
    at: when the import runs (a UTC datetime), for importers that date what they observe."""
    changes, notices = importing.preview_import(db.load_directory(conn), spec, files, at=at)
    return Preview(spec, tuple(changes), tuple(notices))


def apply_preview(conn, preview, change_id):
    """Effect: apply a previewed write (a capture, a bundle, an import) under an approved change."""
    return modify(conn, preview.changes, change_id) if preview.changes else Applied(change_id, ())


def verify_paths(conn):
    """Effect (reads the record): the repo paths verification needs read (bundles' and captured files')."""
    return capturemod.verify_paths(db.load_directory(conn))


def verify(conn, contents):
    """Effect (reads the record): every bundle and captured file against a checkout of the repo. contents: {repo
    path: {relative path: bytes} ({"": bytes} for one file), or None when the checkout has nothing there}."""
    headers, rows = capturemod.verification(db.load_directory(conn), contents)
    return Rows(tuple(headers), tuple(rows))


def rebuild_file(conn, name, spec=None):
    """Effect (reads the record): a captured file rebuilt from the record (links resolved for environment spec)."""
    text, repo_path = capturemod.rebuilt_file(db.load_directory(conn), name, spec)
    return Rebuilt(name, repo_path, text)


# ------------------------------------------------------------------ the migration workspace
def workspace_create(live, ws, source, replace=False):
    """Effect: copy the live record into the workspace database. Returns the entries copied."""
    return workspace.create(live, ws, store_parts(), source, replace, schema_sync())


def workspace_state(live, ws):
    """Effect (reads both): the workspace's base, its change records since the copy, whether live changed since."""
    return WorkspaceState(*workspace.state(live, ws))


def workspace_cutover(live, ws, source, change_id):
    """Effect: apply the workspace's changes to the live record under an approved change, then re-copy."""
    return Applied(change_id, tuple(workspace.cutover(live, ws, store_parts(), source, change_id, schema_sync())))
