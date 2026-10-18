"""Operations: everything opsdir does, as functions over the store that return structured results.

The one API every front end calls: the command line now, an MCP server for AI control later (SPEC 7.4). An operation
takes a connection and plain arguments (parsed records, text, names; never paths) and returns records or rows,
never text for a terminal; reading and writing files on disk and presenting results stay in the front ends. Every
write is previewable: its change records are computed first (preview_*), and applied only under a change id the store
accepts (an approved change record). Effects are the store's; everything else is the connectors' and domains'.
"""
import datetime as dt
import uuid
from typing import NamedTuple

from .connectors import capture as capturemod, importing, migration, onboarding, plan as planmod, profiling, reports
from .connectors import answers as answersmod, workspace
from .connectors import posture as posturemod
from .connectors import evidence as evidencemod, fixes as fixmod, prerequisites as prereqmod, settings as settingsmod
from .connectors.registry import ADAPTER_VERSIONS, ADAPTERS, environment_specs, host_files_of, schema_sync, store_parts
from .connectors.render import environment_notes, render_env
from .connectors.application import application_view, my_view
from .connectors.handoff import handoff_files
from .connectors.graph import dependency_graph
from .connectors.stack import STATUS_HEADERS, note_rows, stack_rows
from .connectors.summary import estate_counts, plan_counts
from .core import search as ldap_search
from .core.directory import get, make_directory, rdn_value
from .core.environment import ENVIRONMENT, env_model
from .core.naming import SUFFIX
from .core.notes import parsed
from .core.interchange.export import export_text
from .domains.estate.evidence import boundary_named, run_records
from .domains.governance.attempts import attempt_records
from .domains.governance import changes as changesmod, focus as focusmod, grants as grantsmod, people as peoplemod
from .domains.governance.identity import change_name_problem, identity_changes, identity_line, record_identity
from .domains.governance.authorization import Area, allow_all, refusal
from .domains.governance.naming import APPLICATIONS
from .store import migrations, postgres as db
from .store.queries import fetch_history

Initialized = NamedTuple("Initialized", [("attribute_types", int), ("object_classes", int)])
Upgraded = NamedTuple("Upgraded", [("applied", tuple), ("version", int), ("attribute_types", int),
                                   ("object_classes", int)])                 # applied: migration labels
Loaded = NamedTuple("Loaded", [("entries", int), ("references", int)])
StackCheck = NamedTuple("StackCheck", [("headers", tuple), ("rows", tuple), ("problems", int)])
Rows = NamedTuple("Rows", [("headers", tuple), ("rows", tuple)])
Rendered = NamedTuple("Rendered", [("label", str), ("dn", str), ("provider", str), ("files", dict),
                                   ("unbound", tuple), ("notes", tuple)])    # files: {relative path: text};
                                                                             # notes: core.notes RenderNotes
Planned = NamedTuple("Planned", [("plan", object), ("markdown", str), ("drafts", dict)])
Migrated = NamedTuple("Migrated", [("run", object), ("files", dict)])       # run: connectors.migration.MigrationRun
Applied = NamedTuple("Applied", [("change_id", str), ("lines", tuple)])      # one line per applied change record
Preview = NamedTuple("Preview", [("name", str), ("changes", tuple), ("notices", tuple)])  # a write, not applied
Rebuilt = NamedTuple("Rebuilt", [("name", str), ("repo_path", str), ("text", str)])
Evidence = NamedTuple("Evidence", [("boundary", str), ("files", dict), ("applied", object)])
# files: {path: text}, the package and its MANIFEST.json; applied: the run recorded (Applied), or None when not asked
WorkspaceState = NamedTuple("WorkspaceState", [("base", object), ("changes", tuple), ("live_changed", bool)])


# ------------------------------------------------------------------ the store
def init(conn, roles=None):
    """Effect: DROP the opsdir schema and create it from nothing (all migrations), as roles' owner with the runtime's
    grants when given (store.roles)."""
    migrations.init(conn, *store_parts(), roles)
    return Initialized(*db.registry_counts(conn))


def upgrade(conn, roles=None):
    """Effect: apply pending migrations, keeping data and history (as roles' owner with the runtime's grants when
    given)."""
    applied = migrations.upgrade(conn, *store_parts(), roles)
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
    """Every environment's declared stack against the installed adapters (all environments when none are named), and
    after each its render's blockers and actions (render notes, rendering nothing: they aren't stack problems)."""
    results = [(*stack_rows(m, ADAPTERS, ADAPTER_VERSIONS, host_files_of(m)), spec)
               for spec in specs or environment_specs(d) for m in (env_model(d, spec),)]
    return StackCheck(STATUS_HEADERS, tuple(row for rows, _, spec in results
                                            for row in (*rows, *note_rows(*environment_notes(d, spec)))),
                      sum(n for _, n, _ in results))


def check(conn, specs=()):
    """Effect (reads the record): stack_check over the store."""
    return stack_check(db.load_directory(conn), specs)


def prerequisites(conn):
    """Effect (reads the record): the data the installed adapters need fetched from their providers
    (connectors.prerequisites): each with its status (met, pending, not needed yet) and how to fetch it."""
    return Rows(prereqmod.HEADERS, prereqmod.prerequisite_rows(db.load_directory(conn), ADAPTERS))


def pending_prerequisites(conn):
    """Effect (reads the record): the provider prerequisites still pending (prerequisites' rows)."""
    return Rows(prereqmod.HEADERS, prereqmod.pending_prerequisites(db.load_directory(conn), ADAPTERS))


def search(conn, base, filt, scope="sub"):
    """Effect (reads the record): the entries an LDAP filter matches."""
    return tuple(ldap_search.search(db.load_directory(conn), base, filt, scope))


def my_teams(conn):
    """Effect (reads the record): the session login's teams ('my area'); SystemExit for a login that isn't a
    recorded person."""
    d, who = db.load_directory(conn), db.session_user(conn)
    if not any(rdn_value(p).lower() == who.lower() for p in peoplemod.people(d)):
        raise SystemExit(f"--mine: {who} isn't a recorded person (opsdir person {who} --team ... --change ...)")
    return peoplemod.teams_of(d, who)


def report(conn, name, dn=None, as_of=None):
    """Effect (reads the record): a named report's rows, dates evaluated as of as_of (today when not given)."""
    rows, headers = reports.report_rows(conn, name, dn, as_of)
    return Rows(tuple(headers), tuple(rows))


def my_report(conn, name, dn=None, as_of=None):
    """Effect (reads the record): a named report narrowed to the session login's teams (governance.focus), and a note
    when it has no owner or keeper column to narrow by (every row then)."""
    r = report(conn, name, dn, as_of)
    kept, note = focusmod.focus_rows(r.headers, r.rows, my_teams(conn))
    return r._replace(rows=kept), note


def mine(conn):
    """Effect (reads the record): the session login's open items (governance.focus.open_items)."""
    teams = my_teams(conn)
    return focusmod.open_items(db.load_directory(conn), db.session_user(conn), teams)


def history(conn, dn=None):
    """Effect (reads the record): the change history, of one entry or of all."""
    return Rows(tuple(reports.HISTORY_HEADERS), tuple(fetch_history(conn, dn)))


def _entry_dn(dn):
    """An entry named on the command line: a DN as it is, a bare name an application's (cn=NAME,ou=applications)."""
    return dn if "=" in dn else f"cn={dn},{APPLICATIONS}"


def application(conn, dn, as_of, env=None, mine=False):
    """Effect (reads the record): the application view of an entry (connectors.application.ApplicationView; a bare
    name an application's), its roles realized in environment env (CLOUD/ENV) when given, else in every one; with
    mine, only what the session login's teams own or keep (connectors.application.my_view)."""
    teams, d = my_teams(conn) if mine else None, db.load_directory(conn)
    v = application_view(d, _entry_dn(dn), as_of, env_model(d, env) if env else None)
    return my_view(d, v, teams) if mine else v


def dependencies(conn, dn, direction="both", depth=3, env=None):
    """Effect (reads the record): the dependency graph around an entry (connectors.graph.Graph; a bare name an
    application's): what it depends on (down), what depends on it (up) or both, depth steps out; role nodes linked to
    their bindings in environment env (CLOUD/ENV) when given."""
    d = db.load_directory(conn)
    return dependency_graph(d, _entry_dn(dn), direction, depth, env_model(d, env) if env else None)


def summary(conn, as_of, src=None, dst=None):
    """Effect (reads the record): the estate in counts, each with its evidence (connectors.summary.Count), and the
    blockers, actions and ok lines of the plan from src to dst when both are given. No percentages."""
    d = db.load_directory(conn)
    planned = planmod.plan(d, src, dst, as_of, writes=reports.change_writes(conn, as_of)) if src and dst else None
    return (*estate_counts(d, as_of), *(plan_counts(planned) if planned else ()))


def export(conn, base):
    """Effect (reads the record): entries under base as LDIF, for review; headed by a comment naming the record's
    identity when it has one."""
    d = db.load_directory(conn)
    line = identity_line(record_identity(d))
    return (f"# {line}\n" if line else "") + export_text(d, base)


def evidence(conn, boundary, as_of, controls=(), change_id=None, kept_at=None):
    """Effect (reads the record): a system boundary's evidence package as of a day (connectors.evidence): per control
    its queries' outputs and MANIFEST.json; only these controls when named. Under an approved change the run is
    recorded on the boundary (when, each file's SHA-256, the queries, where it is kept: kept_at); without one nothing is
    written. ValueError for an unknown boundary or a query naming no report."""
    d = db.load_directory(conn)
    b = boundary_named(d, boundary)
    if b is None:
        raise ValueError(f"no system boundary {boundary}")
    p = evidencemod.evidence_package(conn, d, b, tuple(controls), as_of)
    files = {**p.files, "MANIFEST.json": p.manifest}
    applied = modify(conn, run_records(d, b, as_of, files, p.plan, change_id, kept_at), change_id) \
        if change_id else None
    return Evidence(b.dn, files, applied)


# ------------------------------------------------------------------ authorization
def authorize(policy, requester, action, area):
    """Effect (refuses): SystemExit naming requester, action and area when policy refuses (governance.authorization;
    7.7 plugs its grants in as the policy). Every operation that acts on an environment asks it first, before the
    record is loaded."""
    why = refusal(policy, requester, action, area)
    if why is not None:
        raise SystemExit(why)


GOVERNED_CLASSES = ("ciamGrant", "ciamPerson")      # what turns the permissive default into the record's policy


def authorize_command(conn, action, area, claimed=None):
    """Effect (refuses): check the session's login against the record's permissions (governance.grants) for an
    action over an area, before an operation runs; every front end asks it. claimed: a requester named by the caller
    (render and migrate --as), refused once people are recorded unless it is the login. With no people or grants
    recorded, everything is allowed and the record isn't loaded."""
    if not db.rows_of_classes(conn, GOVERNED_CLASSES):
        return
    d, who = db.load_directory(conn), db.session_user(conn)
    if claimed and claimed != who and peoplemod.people(d):
        raise SystemExit(f"--as {claimed}: once people are recorded, the requester is the login ({who})")
    authorize(grantsmod.policy_for(d), who, action, area)


def preview_grant(conn, name, actions, grantees, environments=(), owners=()):
    """Effect (reads the record): the change records recording or replacing a grant (applied with apply_preview
    under an approved change); ValueError for an unknown action, grantee or owner."""
    return Preview(f"grant {name}", grantsmod.grant_changes(db.load_directory(conn), name, actions, grantees,
                                                           environments, owners), ())


# ------------------------------------------------------------------ rendering and moving
def render(conn, spec, targets=None, scope=ENVIRONMENT, requester=None, policy=allow_all):
    """Effect (reads the record): an environment's rendered files; targets: {adapter: (render target, ...)} chosen
    (default: every target of every adapter); scope (core.environment.Scope): the whole environment, or a keeper's,
    an object class's or named bindings' infrastructure (5.7); requester: who asks (default: the database login),
    authorized by policy (default: everyone) and recorded in the MANIFEST; with the render's notes (NOTES.json)."""
    who = requester or db.session_user(conn)
    authorize(policy, who, "render", Area(spec, scope))
    m, files = render_env(db.load_directory(conn), spec, wanted=targets, scope=scope, requester=who)
    return Rendered(m.label, m.dn, m.provider, files, tuple(m.unbound), parsed(files["NOTES.json"]))


def plan(conn, src, dst, as_of, mine=False):
    """Effect (reads the record and its history): the plan for moving src to dst, as markdown and external-party
    request drafts; with mine, only the blockers and actions of the session login's teams (governance.focus)."""
    p = planmod.plan(db.load_directory(conn), src, dst, as_of, writes=reports.change_writes(conn, as_of))
    if mine:
        teams = my_teams(conn)
        p = p._replace(blockers=focusmod.focus_findings(p.blockers, teams),
                       actions=focusmod.focus_findings(p.actions, teams))
    return Planned(p, planmod.to_markdown(p), planmod.request_drafts(p))


def tickets(conn, src, dst, as_of, mine=False):
    """Effect (reads the record and its history): the work-ticket drafts handing the plan src->dst's findings to their
    owning teams through the installed ITSM add-ons, with their README ({path under tickets/: text},
    connectors.handoff); with mine, only the session login's teams' drafts. Nothing is sent to ITSM."""
    teams, d = my_teams(conn) if mine else None, db.load_directory(conn)
    p = planmod.plan(d, src, dst, as_of, writes=reports.change_writes(conn, as_of))
    return handoff_files(d, p, ADAPTERS, teams)


def migrate(conn, src, dst, as_of, requester=None, policy=allow_all):
    """Effect (reads the record): check both stacks, plan and render the target; requester: who asks (default: the
    database login), authorized by policy (default: everyone) and recorded in the target's MANIFEST."""
    who = requester or db.session_user(conn)
    authorize(policy, who, "migrate", Area(dst, ENVIRONMENT, src))
    r = migration.run(db.load_directory(conn), src, dst, as_of, ADAPTERS, ADAPTER_VERSIONS, who,
                      reports.change_writes(conn, as_of))
    return Migrated(r, migration.output_files(r))


# ------------------------------------------------------------------ assisted fixes
def fixes(conn, src, dst, as_of, mine=False):
    """Effect (reads the record): the record changes the plan's findings offer (core.findings.Fix), each with its
    change records, the steps outside the record and what it could hide. Against the workspace connection they are the
    workspace's (reaching the live record at cutover). With mine, only those changing what the session login's teams
    own or keep (governance.focus.focus_fixes)."""
    teams, d = my_teams(conn) if mine else None, db.load_directory(conn)
    found = planmod.plan(d, src, dst, as_of, writes=reports.change_writes(conn, as_of)).fixes
    return focusmod.focus_fixes(d, found, teams) if mine else found


def _ready(conn, fix):
    """Effect (reads the record and its history): the fix, once what it requires happened (a fresh import of what it
    changes); ValueError saying what it still waits for."""
    waiting = fixmod.unmet(fix, db.load_directory(conn), lambda dns, excluded: db.last_change(conn, dns, excluded))
    if waiting:
        raise ValueError(f"fix {fix.key} waits: " + "; ".join(waiting))
    return fix


def propose_fix(conn, src, dst, as_of, key, change_id, title=None, option=None, inputs=None):
    """Effect: record a fix (its option chosen, when it offers a choice, and its inputs given, {key: values}) as change
    change_id with status proposed, holding the records it applies, for a person to approve (what an AI may do).
    Nothing else is written; ValueError when what the fix requires hasn't happened (a fresh import first) or the store
    would refuse the records (a value of the wrong type, two values for a SINGLE-VALUE attribute, an attribute the
    entry's classes don't allow), or change_id isn't named with the record's org code: a proposal applies as held."""
    named = change_name_problem(record_identity(db.load_directory(conn)), change_id)
    if named:
        raise ValueError(named)
    fix = _ready(conn, fixmod.chosen(fixmod.find_fix(fixes(conn, src, dst, as_of), key), option, inputs))
    problems = db.record_problems(conn, fix.records)
    if problems:
        raise ValueError(f"fix {key}: the store would refuse its records: " + "; ".join(problems))
    return modify(conn, (fixmod.proposal(fix, change_id, title),), change_id)


def apply_fix(conn, src, dst, as_of, key, change_id, option=None, inputs=None):
    """Effect: apply a fix's records (its option chosen, when it offers a choice, and its inputs given, {key: values})
    under an approved change; ValueError when what it requires hasn't happened (a fresh import first)."""
    fix = _ready(conn, fixmod.chosen(fixmod.find_fix(fixes(conn, src, dst, as_of), key), option, inputs))
    return modify(conn, fix.records, change_id)


def apply_proposed(conn, change_id):
    """Effect: apply the records a proposed change holds once a person approved it, and mark it applied."""
    records, applied = fixmod.proposed_records(db.load_directory(conn), change_id)
    return modify(conn, (*records, applied), change_id)


def preview_setting(conn, name, value):
    """Effect (reads the record): the change records giving estate setting name a value (applied with apply_preview
    under an approved change); ValueError when no installed domain declares it or the value isn't valid for it."""
    return Preview(name, tuple(settingsmod.changes_for_setting(db.load_directory(conn), name, value)), ())


def posture(conn, allowed=None, token=None):
    """Effect (reads the connection, the server and the record): the record database's posture rows
    (connectors.posture) and how many fail; allowed: the weaker sslmode OPSDIR_DB_TLS accepts; token: the database
    token scheme the connection signed in with (OPSDIR_DB_AUTH)."""
    facts = db.posture_facts(conn)
    d = db.load_directory(conn) if facts.schema_owner else make_directory((), (), ())
    rows = posturemod.posture_rows(facts, d, migrations.read_migrations(), allowed, token)
    return Rows(posturemod.HEADERS, rows), posturemod.failed(rows)


def new_change(conn, change_id, title, ticket=None):
    """Effect: record a proposed change (its author the session's login, set by the store); ValueError when it
    exists or isn't named with the record's org code."""
    d = db.load_directory(conn)
    named = change_name_problem(record_identity(d), change_id)
    if named:
        raise ValueError(named)
    return modify(conn, changesmod.new_change(d, change_id, title, ticket), change_id)


def change_status(conn, change_id, status):
    """Effect: move a change to approved, rejected or applied (its approver the session's login, set and checked by
    the store: never its author while approval-separation is on, a recorded person once people are recorded);
    ValueError when it can't move there."""
    return modify(conn, (changesmod.status_change(db.load_directory(conn), change_id, status),), change_id)


def change_lines(conn, change_id):
    """Effect (reads the record): a change record in lines; ValueError when there is none."""
    change = changesmod.change_record(db.load_directory(conn), change_id)
    if change is None:
        raise ValueError(f"no change {change_id}")
    return changesmod.change_lines(change)


def preview_person(conn, login, name=None, mail=None, teams=None):
    """Effect (reads the record): the change records recording a person or updating their name, mail and teams
    (applied with apply_preview under an approved change); ValueError for a bad login or an unknown team."""
    return Preview(f"person {login}", peoplemod.person_changes(db.load_directory(conn), login, name, mail, teams), ())


def person_lines(conn, login):
    """Effect (reads the record): a recorded person in lines, or None."""
    return peoplemod.person_lines(db.load_directory(conn), login)


def identity(conn):
    """Effect (reads the record): the record's identity (governance.identity.Identity), or None when it has none."""
    return record_identity(db.load_directory(conn))


def preview_identity(conn, org, parent=None, name=None):
    """Effect (reads the record; a new UUID): the change records giving the record its identity, or updating its
    parent and name (applied with apply_preview under an approved change); ValueError for an invalid code or a changed
    org code."""
    return Preview("record identity", identity_changes(db.load_directory(conn), org, str(uuid.uuid4()), parent, name),
                   ())


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
    """Effect (reads the record): what importing a product's export would do (connectors.importing.ImportPlan): the
    change records, the importer's notices (what it withheld, what it couldn't place), the conflicts with what the
    record holds, and the scopes it reads. spec: 'adapter[/importer]'; files: {relative path: text}; at: when the
    export was taken (a UTC datetime; default now), for importers that date what they observe and for the import run."""
    at = at or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return importing.import_plan(db.load_directory(conn), spec, files, at=at)


def apply_import(conn, plan, change_id, take=(), keep=(), evidence=None):
    """Effect: apply an import (preview_import) under an approved change: each conflict decided, the live value taken
    or the record's kept (keys, or 'all'; ValueError while any is undecided), and an import run recorded for each
    scope it read (domains.governance.imports), even when nothing else changed, with how opsdir collected the export
    when it did (evidence: connectors.collecting.evidence)."""
    return modify(conn, importing.import_records(db.load_directory(conn), plan, change_id, take, keep, evidence),
                  change_id)


def record_attempts(conn, attempts, at, change_id):
    """Effect: record collection attempts (domains.governance.attempts: Attempts run at `at`, a UTC datetime) under an
    approved change, whatever their outcome: a failed collection stays visible with its problems and calls."""
    return modify(conn, attempt_records(db.load_directory(conn), attempts, at, change_id), change_id)


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


def preview_setup(conn, answers):
    """Effect (reads the record; a new UUID for a new identity): what applying onboarding answers (connectors.answers)
    would write, as a Preview applied with apply_preview: under BOOTSTRAP as the initial load of a new record
    (new_record), else under an approved change. Its notices: what is worth knowing (adapters not installed) and what
    the record holds beyond the answers (left as it is). ValueError listing what keeps the answers from being
    applied."""
    problems = answersmod.answers_problems(answers)
    if problems:
        raise ValueError("the answers can't be applied:\n" + "\n".join(f"  {p}" for p in problems))
    changes, beyond = answersmod.setup_records(db.load_directory(conn), answers, str(uuid.uuid4()))
    return Preview("onboarding setup", changes, (*answersmod.answers_notices(answers), *beyond))


def new_record(conn):
    """Effect (reads the record): whether it holds nothing yet (not even its suffix): what `opsdir init` leaves."""
    return get(db.load_directory(conn), SUFFIX) is None


def onboard_verify(conn, sources, at=None):
    """Effect (reads the record): onboarding verification (connectors.onboarding.Verification) of the record against
    the operator's original exports: sources ((spec 'adapter[/importer]', {relative path: text}), ...), taken at `at`
    (a UTC datetime; default now). Every environment is rendered and read back; nothing is written."""
    at = at or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return onboarding.verify(db.load_directory(conn), tuple(sources), at=at)


def rebuild_file(conn, name, spec=None):
    """Effect (reads the record): a captured file rebuilt from the record (links resolved for environment spec)."""
    text, repo_path = capturemod.rebuilt_file(db.load_directory(conn), name, spec)
    return Rebuilt(name, repo_path, text)


# ------------------------------------------------------------------ the migration workspace
def workspace_create(live, ws, source, replace=False, roles=None):
    """Effect: copy the live record into the workspace database. Returns the entries copied."""
    return workspace.create(live, ws, store_parts(), source, replace, schema_sync(), roles)


def workspace_state(live, ws):
    """Effect (reads both): the workspace's base, its change records since the copy, whether live changed since."""
    return WorkspaceState(*workspace.state(live, ws))


def workspace_cutover(live, ws, source, change_id):
    """Effect: apply the workspace's changes to the live record under an approved change, then re-copy."""
    return Applied(change_id, tuple(workspace.cutover(live, ws, store_parts(), source, change_id, schema_sync())))
